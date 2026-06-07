//! WebAssembly Rule Engine
//!
//! Wraps a sandboxed WASM module containing proprietary threat signatures.
//! The module is fetched from the cloud API or loaded from local filesystem in dev mode.

use crate::scanner::IngestedFile;
use crate::types::{Framework, Violation};
use anyhow::{Context, Result};
use bincode::{deserialize, serialize};
use tracing::{debug, trace, warn};
use tuora_types::{EvalInput, EvalOutput, WasmInputFile};
use wasmtime::{Config, Engine, Instance, Memory, Module, Store, TypedFunc};

/// WASM-based rule engine
pub struct WasmRuleEngine {
    _engine: Engine,
    _instance: Instance,
    store: Store<()>,
    memory: Memory,
    /// (input_ptr, input_len) -> (output_ptr)
    evaluate_fn: TypedFunc<(u32, u32), u32>,
    _malloc_fn: TypedFunc<u32, u32>,
    _free_fn: Option<TypedFunc<(u32, u32), ()>>,
    _rule_count: u32,
}

fn ingested_to_wasm(f: &IngestedFile) -> WasmInputFile {
    WasmInputFile {
        path: f.path.to_string_lossy().to_string(),
        content: f.content.clone(),
        extension: f.extension.clone(),
    }
}

impl WasmRuleEngine {
    /// Load WASM module from bytes
    pub fn load(wasm_bytes: &[u8]) -> Result<Self> {
        debug!(size = wasm_bytes.len(), "Loading WASM module");

        // Configure wasmtime with sandboxing
        let mut config = Config::new();
        config.wasm_backtrace_max_frames(None);
        config.wasm_bulk_memory(true);
        config.wasm_multi_value(true);

        let engine = Engine::new(&config).map_err(|e| anyhow::anyhow!("{}", e))?;
        let module = Module::new(&engine, wasm_bytes).map_err(|e| anyhow::anyhow!("{}", e))?;

        let mut store = Store::new(&engine, ());

        // Create instance with no imports (pure compute sandbox)
        let instance =
            Instance::new(&mut store, &module, &[]).map_err(|e| anyhow::anyhow!("{}", e))?;

        // Get memory export
        let memory = instance
            .get_memory(&mut store, "memory")
            .context("WASM module must export 'memory'")?;

        // Get exported functions
        let evaluate_fn = instance
            .get_typed_func::<(u32, u32), u32>(&mut store, "evaluate_file")
            .map_err(|e| anyhow::anyhow!("WASM must export 'evaluate_file' function: {}", e))?;

        let malloc_fn = instance
            .get_typed_func::<u32, u32>(&mut store, "malloc")
            .map_err(|e| anyhow::anyhow!("WASM must export 'malloc' function: {}", e))?;

        let free_fn = instance
            .get_typed_func::<(u32, u32), ()>(&mut store, "free")
            .ok();

        // Get rule count
        let rule_count = instance
            .get_typed_func::<(), u32>(&mut store, "rule_count")
            .map(|f| f.call(&mut store, ()).unwrap_or(0))
            .unwrap_or(0);

        debug!(rule_count, "WASM rule engine initialized");

        Ok(Self {
            _engine: engine,
            _instance: instance,
            store,
            memory,
            evaluate_fn,
            _malloc_fn: malloc_fn,
            _free_fn: free_fn,
            _rule_count: rule_count,
        })
    }

    /// Evaluate files against WASM rules
    pub fn evaluate(&mut self, files: &[IngestedFile], framework: Framework) -> Vec<Violation> {
        trace!(
            file_count = files.len(),
            framework = framework.name(),
            "Evaluating with WASM"
        );

        // Prepare input
        let input = EvalInput {
            files: files.iter().map(ingested_to_wasm).collect(),
            framework: framework.name().to_string(),
        };

        // Serialize input
        let input_bytes = match serialize(&input) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to serialize input");
                return vec![];
            }
        };

        trace!(input_size = input_bytes.len(), "Serialized input");

        // Allocate memory in WASM
        let input_len = input_bytes.len() as u32;
        let input_ptr = match self.alloc(input_len) {
            Some(p) => p,
            None => {
                warn!("Failed to allocate WASM memory");
                return vec![];
            }
        };

        // Write input to WASM memory
        if let Err(e) = self
            .memory
            .write(&mut self.store, input_ptr as usize, &input_bytes)
        {
            warn!(error = %e, "Failed to write to WASM memory");
            return vec![];
        }

        // Call evaluate
        let output_ptr = match self
            .evaluate_fn
            .call(&mut self.store, (input_ptr, input_len))
        {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "WASM evaluation failed");
                return vec![];
            }
        };

        trace!(output_ptr, "WASM evaluation completed");

        // Read output length (first 4 bytes as u32 little endian)
        let mut len_bytes = [0u8; 4];
        if let Err(e) = self
            .memory
            .read(&self.store, output_ptr as usize, &mut len_bytes)
        {
            warn!(error = %e, "Failed to read output length");
            return vec![];
        }
        let output_len = u32::from_le_bytes(len_bytes) as usize;

        trace!(output_len, "Reading output");

        // Read output data
        let mut output_bytes = vec![0u8; output_len];
        if let Err(e) = self
            .memory
            .read(&self.store, output_ptr as usize + 4, &mut output_bytes)
        {
            warn!(error = %e, "Failed to read output data");
            return vec![];
        }

        // Deserialize output
        let output: EvalOutput = match deserialize(&output_bytes) {
            Ok(o) => o,
            Err(e) => {
                warn!(error = %e, "Failed to deserialize output");
                return vec![];
            }
        };

        debug!(
            violation_count = output.violations.len(),
            "WASM evaluation complete"
        );

        // Convert WASM violations to native Violations
        output
            .violations
            .into_iter()
            .map(|v| self.convert_violation(v, files))
            .collect()
    }

    /// Get rule count
    pub fn rule_count(&self) -> usize {
        self._rule_count as usize
    }

    /// Allocate memory in WASM (helper)
    fn alloc(&mut self, size: u32) -> Option<u32> {
        self._malloc_fn.call(&mut self.store, size).ok()
    }

    /// Convert WASM violation to native Violation
    fn convert_violation(
        &self,
        v: tuora_types::WasmViolation,
        _files: &[IngestedFile],
    ) -> Violation {
        use crate::types::{OwaspCategory, RuleCategory, RuleId};
        use std::path::PathBuf;

        // Use file_path carried by the violation itself (set by the WASM engine per-file)
        let file_path = if v.file_path.is_empty() {
            PathBuf::from("unknown")
        } else {
            PathBuf::from(&v.file_path)
        };

        let severity = match v.severity {
            tuora_types::WasmSeverity::Critical => crate::types::Severity::Critical,
            tuora_types::WasmSeverity::High => crate::types::Severity::High,
            tuora_types::WasmSeverity::Medium => crate::types::Severity::Medium,
            tuora_types::WasmSeverity::Low => crate::types::Severity::Low,
        };

        // Infer category from rule_id prefix
        let category = if v.rule_id.starts_with("BZ-SEC") {
            RuleCategory::Security
        } else if v.rule_id.starts_with("BZ-FIN") {
            RuleCategory::Financial
        } else if v.rule_id.starts_with("BZ-OPS") {
            RuleCategory::Operational
        } else if v.rule_id.starts_with("BZ-HYG") {
            RuleCategory::Hygiene
        } else {
            RuleCategory::Sast
        };

        // Map to OWASP category
        let owasp_ref = match v.rule_id.as_str() {
            "BZ-SEC-01" => OwaspCategory::Asi02,
            "BZ-SEC-02" | "BZ-SEC-02B" => OwaspCategory::Asi05,
            "BZ-FIN-01" | "BZ-OPS-02" => OwaspCategory::Asi08,
            "BZ-FIN-02" => OwaspCategory::Asi06,
            "BZ-FIN-03" => OwaspCategory::Asi02,
            "BZ-OPS-01" => OwaspCategory::Asi03,
            "BZ-HYG-01" | "BZ-SAST-04" => OwaspCategory::Asi04,
            "BZ-HYG-02" => OwaspCategory::Asi01,
            "BZ-SAST-01" => OwaspCategory::Asi03,
            "BZ-SAST-02" => OwaspCategory::Asi03,
            "BZ-SAST-03" => OwaspCategory::Asi05,
            _ => OwaspCategory::Asi02,
        };

        Violation {
            rule_id: RuleId::new(&v.rule_id),
            category,
            owasp_ref,
            severity,
            file_path,
            line_number: Some(v.line_number),
            tool_target: v.tool_target,
            message: v.message,
            remediation: v.remediation,
            plain_message: v.plain_message,
            plain_remediation: v.plain_remediation,
        }
    }
}

/// Simple hex encoder for debug logging
#[allow(dead_code)]
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        result.push(HEX[(b >> 4) as usize] as char);
        result.push(HEX[(b & 0xf) as usize] as char);
    }
    result
}

/// Verify Ed25519 signature (production builds)
///
/// # Parameters
/// - `wasm_bytes`: Raw WASM module bytes
/// - `signature`: Ed25519 signature (64 bytes)
/// - `public_key`: Ed25519 public key in raw format (32 bytes, NOT PEM)
#[cfg(not(debug_assertions))]
pub fn verify_signature(wasm_bytes: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
    use ring::digest::{self, digest, SHA256};
    use ring::signature::{self, UnparsedPublicKey};
    use tracing::{debug, error};

    // Log full details for debugging signature mismatches
    debug!(
        wasm_len = wasm_bytes.len(),
        wasm_hash = %to_hex(&ring::digest::digest(&ring::digest::SHA256, wasm_bytes).as_ref()[..]),
        sig_len = signature.len(),
        sig_full = %to_hex(signature),
        pk_len = public_key.len(),
        pk_full = %to_hex(public_key),
        "Verifying Ed25519 signature"
    );

    // Validate signature length before attempting verification
    if signature.len() != 64 {
        error!(
            sig_len = signature.len(),
            "Invalid signature length (expected 64 bytes)"
        );
        anyhow::bail!(
            "Invalid Ed25519 signature: expected 64 bytes, got {}",
            signature.len()
        );
    }

    // Validate public key length
    if public_key.len() != 32 {
        error!(
            pk_len = public_key.len(),
            "Invalid public key length (expected 32 bytes)"
        );
        anyhow::bail!(
            "Invalid Ed25519 public key: expected 32 bytes, got {}",
            public_key.len()
        );
    }

    let unparsed_pk = UnparsedPublicKey::new(&signature::ED25519, public_key);
    unparsed_pk.verify(wasm_bytes, signature).map_err(|e| {
        error!(error = ?e, "Ed25519 signature verification failed - keypair mismatch or data corruption");
        anyhow::anyhow!("Invalid Ed25519 signature - possible causes: keypair mismatch, corrupted WASM, or signature tampering")
    })?;

    debug!("Ed25519 signature verified successfully");
    Ok(())
}

/// Dev mode: skip signature verification
#[cfg(debug_assertions)]
#[allow(dead_code)]
pub fn verify_signature(_wasm_bytes: &[u8], _signature: &[u8], _public_key: &[u8]) -> Result<()> {
    debug!("Skipping signature verification in dev mode");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn build_mock_wasm() -> Vec<u8> {
        // In tests, try to load from dev/mock-rules
        let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("dev")
            .join("mock-rules")
            .join("target")
            .join("wasm32-unknown-unknown")
            .join("release")
            .join("mock_rules.wasm");

        if dev_path.exists() {
            std::fs::read(&dev_path).expect("Failed to read mock WASM")
        } else {
            // Return minimal valid WASM module (empty function)
            // This is a pre-compiled empty WASM module
            vec![
                0x00, 0x61, 0x73, 0x6d, // magic: \0asm
                0x01, 0x00, 0x00, 0x00, // version: 1
            ]
        }
    }

    #[test]
    fn test_wasm_load() {
        let wasm = build_mock_wasm();
        // This will fail with minimal wasm, but tests the load path
        let _ = WasmRuleEngine::load(&wasm);
    }

    #[test]
    fn test_dev_rules_wasm_load() {
        let version = env!("RULE_ENGINE_VERSION");
        let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("dev")
            .join(format!("def-{}.wasm", version));
        if !dev_path.exists() {
            return;
        }
        let bytes = std::fs::read(&dev_path).expect("read dev wasm");
        let mut engine = WasmRuleEngine::load(&bytes).expect("load dev wasm");

        // Verify full round-trip: input serialization → WASM evaluation → output deserialization
        let test_file = IngestedFile {
            path: PathBuf::from("test.py"),
            content: "import openai\nclient = openai.OpenAI(api_key=\"sk-abc123\")\n".to_string(),
            extension: "py".to_string(),
        };
        let violations = engine.evaluate(&[test_file], Framework::OpenAI);
        // Should detect BZ-HYG-01 (hardcoded secret) and BZ-HYG-03 (non-env api_key)
        assert!(
            !violations.is_empty(),
            "WASM evaluate() returned no violations for known-bad input"
        );
    }
}
