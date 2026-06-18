//! Build script for tuora CLI.
//!
//! On debug builds, automatically compiles the `rule-engine` crate to
//! wasm32-unknown-unknown and places the stripped WASM at `dev/def-{version}.wasm`
//! so the CLI can load it without a network fetch.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    inject_signing_key();
    inject_ledger_url();

    let profile = std::env::var("PROFILE").unwrap_or_default();
    if profile != "debug" {
        return;
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.join("..");
    let rule_engine_dir = repo_root.join("cloud").join("rules").join("rule-engine");

    let rule_engine_toml = rule_engine_dir.join("Cargo.toml");
    if !rule_engine_toml.exists() {
        println!(
            "cargo::warning=rule-engine crate not found at {}, skipping WASM build",
            rule_engine_dir.display()
        );
        println!("cargo::rustc-env=RULE_ENGINE_VERSION=0.0.0");
        return;
    }

    // Re-run if rule-engine source changes (cloud/ paths removed - tracked in separate repo)
    // Re-run if the shared wire-protocol types change (WASM ABI boundary)
    println!("cargo::rerun-if-changed=../types/src/lib.rs");

    let version = read_cargo_version(&rule_engine_toml);
    let bundle_name = format!("rule-engine-v{}.wasm", version);

    // Expose version to the CLI crate so remote.rs can find the file
    println!("cargo::rustc-env=RULE_ENGINE_VERSION={}", version);

    let dest = manifest_dir.join("dev").join(&bundle_name);

    eprintln!("build.rs: Building rule-engine WASM...");

    let workspace_manifest = repo_root.join("Cargo.toml");
    let status = Command::new("cargo")
        .args([
            "build",
            "--manifest-path",
            &workspace_manifest.to_string_lossy(),
            "--target",
            "wasm32-unknown-unknown",
            "--release",
            "-p",
            "rule-engine",
        ])
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            println!("cargo::warning=rule-engine WASM build failed with {s}");
            return;
        }
        Err(e) => {
            println!("cargo::warning=Failed to run cargo for WASM build: {e}");
            return;
        }
    }

    let source = repo_root
        .join("target")
        .join("wasm32-unknown-unknown")
        .join("release")
        .join("rule_engine.wasm");

    let raw = match std::fs::read(&source) {
        Ok(b) => b,
        Err(e) => {
            println!(
                "cargo::warning=Failed to read built WASM from {}: {e}",
                source.display()
            );
            return;
        }
    };

    let stripped = strip_wasm_custom_sections(&raw);

    // Ensure dev/ directory exists
    let dev_dir = manifest_dir.join("dev");
    let _ = std::fs::create_dir_all(&dev_dir);

    if let Err(e) = std::fs::write(&dest, &stripped) {
        println!(
            "cargo::warning=Failed to write WASM to {}: {e}",
            dest.display()
        );
        return;
    }

    eprintln!("build.rs: rule-engine WASM → {}", dest.display());
}

/// Parse the `version` field from a Cargo.toml without pulling in toml crate.
fn read_cargo_version(path: &std::path::Path) -> String {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("version")
            && let Some(val) = trimmed.split('=').nth(1)
        {
            return val.trim().trim_matches('"').to_string();
        }
    }
    "0.0.0".to_string()
}

/// Strip all WASM custom sections (id=0) from a binary.
///
/// Newer Rust/LLVM toolchains emit `target_features`, `producers`, and `name`
/// custom sections that some wasmtime versions reject during translation.
fn strip_wasm_custom_sections(data: &[u8]) -> Vec<u8> {
    if data.len() < 8 {
        return data.to_vec();
    }
    let mut out = data[..8].to_vec(); // keep WASM magic + version
    let mut i = 8usize;
    while i < data.len() {
        let sec_id = data[i];
        let (size, n) = read_leb128(data, i + 1);
        let sec_start = i + 1 + n;
        let sec_end = sec_start + size;
        if sec_id != 0 {
            out.push(sec_id);
            out.extend_from_slice(&encode_leb128(size));
            out.extend_from_slice(&data[sec_start..sec_end]);
        }
        i = sec_end;
    }
    out
}

fn read_leb128(data: &[u8], offset: usize) -> (usize, usize) {
    let (mut result, mut shift, mut n) = (0usize, 0usize, 0usize);
    loop {
        let b = data[offset + n] as usize;
        result |= (b & 0x7f) << shift;
        n += 1;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
    }
    (result, n)
}

fn encode_leb128(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

/// Resolve the ledger service base URL and forward it as TUORA_LEDGER_URL_VALUE.
///
/// Resolution order:
///   1. `TUORA_LEDGER_URL` environment variable (set by CI or local dev override)
///
/// Release builds panic at compile time if the variable is absent or empty.
fn inject_ledger_url() {
    println!("cargo::rerun-if-env-changed=TUORA_LEDGER_URL");

    let profile = std::env::var("PROFILE").unwrap_or_default();

    let url = std::env::var("TUORA_LEDGER_URL")
        .ok()
        .filter(|v| !v.trim().is_empty());

    match url {
        Some(u) => {
            println!("cargo::rustc-env=TUORA_LEDGER_URL_VALUE={}", u.trim());
        }
        None if profile == "release" => {
            panic!(
                "\n\nERROR: TUORA_LEDGER_URL is not set.\nRelease builds require the ledger \
                 service URL to be injected via the TUORA_LEDGER_URL environment variable \
                 (set it as a GitHub Actions secret).\n"
            );
        }
        None => {
            println!("cargo::rustc-env=TUORA_LEDGER_URL_VALUE=");
        }
    }
}

/// Resolve the Ed25519 public key and forward it as TUORA_SIGNING_PUBKEY_VALUE.
///
/// Resolution order:
///   1. `TUORA_SIGNING_PUBKEY` environment variable (set by CI from a GitHub secret)
///   2. `core/assets/signing_key.pub` on disk (local dev fallback only)
///
/// Release builds panic at compile time if neither source yields a non-empty value.
///
/// # Key Format Requirements
///
/// The public key MUST be in raw Ed25519 format:
/// - Exactly 32 bytes when decoded
/// - Base64-encoded for embedding (44 characters)
/// - NOT in PEM format (no BEGIN/END headers)
///
/// To extract the correct format from an Ed25519 private key (32 raw bytes, not 44-byte DER):
/// ```bash
/// openssl pkey -in signing_key.pem -pubout -outform DER | tail -c 32 | base64
/// ```
fn inject_signing_key() {
    println!("cargo::rerun-if-env-changed=TUORA_SIGNING_PUBKEY");
    println!("cargo::rerun-if-changed=assets/signing_key.pub");
    // Also re-run if build.rs itself changes
    println!("cargo::rerun-if-changed=build.rs");

    let profile = std::env::var("PROFILE").unwrap_or_default();

    // Debug: log what we see
    let env_var_result = std::env::var("TUORA_SIGNING_PUBKEY");
    match &env_var_result {
        Ok(v) => println!(
            "cargo::warning=TUORA_SIGNING_PUBKEY found: len={}, trimmed_len={}",
            v.len(),
            v.trim().len()
        ),
        Err(e) => println!("cargo::warning=TUORA_SIGNING_PUBKEY not found: {:?}", e),
    }

    let key = env_var_result
        .ok()
        .filter(|v| {
            let trimmed = v.trim();
            let is_non_empty = !trimmed.is_empty();
            println!("cargo::warning=TUORA_SIGNING_PUBKEY filter: raw_len={}, trimmed_len={}, non_empty={}", v.len(), trimmed.len(), is_non_empty);
            is_non_empty
        })
        .or_else(|| {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/signing_key.pub");
            println!("cargo::warning=Checking fallback file: {}", path.display());
            let file_result = std::fs::read_to_string(&path);
            match &file_result {
                Ok(content) => println!("cargo::warning=Fallback file found: len={}", content.len()),
                Err(e) => println!("cargo::warning=Fallback file not found: {:?}", e),
            }
            file_result
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| {
                    let is_non_empty = !s.is_empty();
                    println!("cargo::warning=Fallback file filter: len={}, non_empty={}", s.len(), is_non_empty);
                    is_non_empty
                })
        });

    match key {
        Some(k) => {
            let trimmed = k.trim();
            println!(
                "cargo::warning=EMBEDDING KEY: len={}, first_10={}, last_10={}",
                trimmed.len(),
                &trimmed[..trimmed.len().min(10)],
                &trimmed[trimmed.len().saturating_sub(10)..]
            );
            println!("cargo::rustc-env=TUORA_SIGNING_PUBKEY_VALUE={}", trimmed);
        }
        None if profile == "release" => {
            panic!(
                "\n\nERROR: TUORA_SIGNING_PUBKEY is not set and assets/signing_key.pub does not \
                 exist.\nRelease builds require the signing public key to be injected via the \
                 TUORA_SIGNING_PUBKEY environment variable (set it as a GitHub Actions secret).\n"
            );
        }
        None => {
            println!("cargo::warning=EMBEDDING EMPTY KEY (debug build fallback)");
            println!("cargo::rustc-env=TUORA_SIGNING_PUBKEY_VALUE=");
        }
    }
}
