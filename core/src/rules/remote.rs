//! Remote WASM Rule Bundle Fetching
//!
//! Handles fetching signed WASM modules from the cloud API in production,
//! and loading from local filesystem in development mode.

use super::wasm_engine::WasmRuleEngine;
use crate::types::AuthResponse;
use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;
use tracing::{debug, info, trace, warn};

/// Response from rules bundle API
#[derive(Debug, Deserialize)]
pub struct RulesBundleResponse {
    /// Base64-encoded WASM bytes
    pub wasm: String,
    /// Base64-encoded Ed25519 signature
    pub signature: String,
    /// Bundle version
    pub version: String,
    /// Expiration timestamp (Unix seconds)
    pub expires_at: u64,
}

/// Request to rules bundle API
#[derive(Debug, Serialize)]
pub struct RulesBundleRequest {
    pub platform: String,
}

/// Request to server-side analysis API
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct AnalyzeRequest {
    pub files: Vec<tuora_types::WasmInputFile>,
    pub framework: String,
    pub context: Option<AnalyzeContext>,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct AnalyzeContext {
    pub previous_scan_id: Option<String>,
    pub repo_fingerprint: Option<String>,
}

/// Response from server-side analysis API
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AnalyzeResponse {
    pub violations: Vec<crate::types::Violation>,
    pub meta: AnalyzeMeta,
    pub recommendation: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AnalyzeMeta {
    pub server_rules_evaluated: u32,
    pub analysis_duration_ms: u32,
    pub ai_enhanced: bool,
    pub intel_hits: u32,
}

/// Lightweight response from the version-check endpoint
#[derive(Debug, Deserialize)]
struct BundleVersionResponse {
    version: String,
}

/// Rule bundle fetcher
pub struct RuleBundleFetcher {
    ledger_url: String,
    api_key: String,
    client: reqwest::Client,
}

impl RuleBundleFetcher {
    /// Create new fetcher with the raw API key
    pub fn new(ledger_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client for rule bundle fetcher");
        Self {
            ledger_url: ledger_url.into(),
            api_key: api_key.into(),
            client,
        }
    }

    /// Fetch and load WASM rule engine.
    ///
    /// On debug builds, loads from `dev/rules.wasm` (built by build.rs).
    /// On release builds:
    ///   1. Check the current server version via GET /v1/bundle-version.
    ///   2. If a matching cached bundle exists on disk, decrypt and load it.
    ///   3. Otherwise, download, verify, cache, then load.
    pub async fn fetch(&self, auth: &AuthResponse) -> Result<WasmRuleEngine> {
        // Dev mode: load from filesystem (build.rs compiles it at build time)
        #[cfg(debug_assertions)]
        {
            match self.try_load_dev().await {
                Ok(engine) => {
                    info!("Loaded rules from dev/ directory");
                    return Ok(engine);
                }
                Err(e) => {
                    warn!(error = %e, "Dev WASM not found — was build.rs skipped? Falling back to API");
                }
            }
        }

        // Production: check cache before downloading
        self.fetch_with_cache(auth).await
    }

    /// Cache-aware fetch: version check → cache hit → download fallback.
    #[cfg_attr(debug_assertions, allow(dead_code))]
    async fn fetch_with_cache(&self, auth: &AuthResponse) -> Result<WasmRuleEngine> {
        match self.check_server_version().await {
            Ok(server_version) => {
                debug!(version = %server_version, "Server bundle version");
                match self.try_load_cache(&server_version).await {
                    Ok(engine) => {
                        info!(version = %server_version, "Loaded rules from disk cache");
                        return Ok(engine);
                    }
                    Err(e) => {
                        debug!(error = %e, "Cache miss, downloading bundle");
                    }
                }
                self.fetch_from_api(auth).await
            }
            Err(e) => {
                warn!(error = %e, "Version check failed, downloading bundle directly");
                self.fetch_from_api(auth).await
            }
        }
    }

    /// GET /v1/bundle-version — cheap call to retrieve the current version string.
    async fn check_server_version(&self) -> Result<String> {
        let url = format!("{}/bundle-version", self.ledger_url);
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.api_key)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!("Version check error {}: {}", status, body);
        }

        let parsed: BundleVersionResponse = response.json().await?;
        Ok(parsed.version)
    }

    /// Try to load a cached bundle from disk for the given version.
    async fn try_load_cache(&self, version: &str) -> Result<WasmRuleEngine> {
        let cache_path = self.cache_path(version)?;

        if !cache_path.exists() {
            bail!("No cached bundle at {}", cache_path.display());
        }

        debug!(path = %cache_path.display(), "Reading cached bundle");

        let data = fs::read(&cache_path).await?;

        #[cfg(not(debug_assertions))]
        let wasm_bytes = {
            let bytes = decrypt_with_api_key(&data, &self.api_key)?;
            let public_key = get_signing_public_key()?;
            // Cached bundles carry the signature in the first 64 bytes
            if bytes.len() < 64 {
                bail!("Cached bundle too short to contain signature");
            }
            let (sig_bytes, wasm) = bytes.split_at(64);
            super::wasm_engine::verify_signature(wasm, sig_bytes, &public_key)?;
            debug!("Cached bundle signature verified");
            wasm.to_vec()
        };

        #[cfg(debug_assertions)]
        let wasm_bytes = data;

        tokio::task::block_in_place(|| WasmRuleEngine::load(&wasm_bytes))
    }

    /// Try to load from dev/rules.wasm
    #[cfg(debug_assertions)]
    async fn try_load_dev(&self) -> Result<WasmRuleEngine> {
        let dev_path = self.dev_wasm_path();

        if !dev_path.exists() {
            bail!("Dev WASM not found at {}", dev_path.display());
        }

        debug!(path = %dev_path.display(), "Loading dev WASM");

        let wasm_bytes = fs::read(&dev_path)
            .await
            .with_context(|| format!("Failed to read dev WASM from {}", dev_path.display()))?;

        // In dev mode, skip signature verification.
        // block_in_place: wasmtime JIT (CLIF) is synchronous and CPU-heavy.
        tokio::task::block_in_place(|| WasmRuleEngine::load(&wasm_bytes))
    }

    /// Path to dev WASM file (e.g. `dev/def-0.1.0.wasm`)
    #[cfg(debug_assertions)]
    fn dev_wasm_path(&self) -> PathBuf {
        let filename = format!("def-{}.wasm", env!("RULE_ENGINE_VERSION"));
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("dev")
            .join(filename)
    }

    /// Fetch from cloud API
    async fn fetch_from_api(&self, _auth: &AuthResponse) -> Result<WasmRuleEngine> {
        let url = format!("{}/rules-bundle", self.ledger_url);

        debug!(url = %url, "Fetching rules bundle from API");

        let request = RulesBundleRequest {
            platform: get_platform_string(),
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&request)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!("API error {}: {}", status, body);
        }

        let bundle: RulesBundleResponse = response.json().await?;

        trace!(version = %bundle.version, "Got rules bundle response");

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        if bundle.expires_at < now {
            bail!(
                "Rules bundle expired at {} (now: {})",
                bundle.expires_at,
                now
            );
        }

        // Decode WASM and signature
        let wasm_bytes = base64::engine::general_purpose::STANDARD.decode(&bundle.wasm)?;
        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(&bundle.signature)?;

        debug!(wasm_size = wasm_bytes.len(), "Decoded WASM bundle");

        // Verify signature (skipped in dev, enforced in release)
        #[cfg(not(debug_assertions))]
        {
            let public_key = get_signing_public_key()?;
            super::wasm_engine::verify_signature(&wasm_bytes, &sig_bytes, &public_key)?;
            debug!("WASM signature verified");
        }

        // Cache to local disk (signature prepended so try_load_cache can re-verify)
        if let Err(e) = self
            .cache_bundle(&bundle.version, &sig_bytes, &wasm_bytes)
            .await
        {
            warn!(error = %e, "Failed to cache bundle");
        }

        tokio::task::block_in_place(|| WasmRuleEngine::load(&wasm_bytes))
    }

    /// Perform server-side analysis on files.
    ///
    /// Sends files to the cloud API for proprietary detection that requires
    /// server-side context, historical data, or computational resources.
    /// Costs 2x regular scan (server-side analysis is more expensive).
    #[allow(dead_code)]
    pub async fn analyze(
        &self,
        files: Vec<tuora_types::WasmInputFile>,
        framework: String,
        context: Option<AnalyzeContext>,
    ) -> Result<AnalyzeResponse> {
        let url = format!("{}/analyze", self.ledger_url);

        debug!(
            file_count = files.len(),
            %framework,
            "Sending files for server-side analysis"
        );

        let request = AnalyzeRequest {
            files,
            framework,
            context,
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&request)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!("Analysis API error {}: {}", status, body);
        }

        let result: AnalyzeResponse = response.json().await?;

        info!(
            violations = result.violations.len(),
            duration_ms = result.meta.analysis_duration_ms,
            intel_hits = result.meta.intel_hits,
            "Server-side analysis complete"
        );

        Ok(result)
    }

    /// Cache bundle to disk, storing [64-byte sig][wasm] before encryption.
    #[cfg_attr(debug_assertions, allow(unused_variables))]
    async fn cache_bundle(&self, version: &str, sig_bytes: &[u8], wasm_bytes: &[u8]) -> Result<()> {
        let cache_path = self.cache_path(version)?;

        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // In production, prepend signature then encrypt the whole blob
        #[cfg(not(debug_assertions))]
        {
            let mut blob = Vec::with_capacity(sig_bytes.len() + wasm_bytes.len());
            blob.extend_from_slice(sig_bytes);
            blob.extend_from_slice(wasm_bytes);
            let encrypted = encrypt_with_api_key(&blob, &self.api_key)?;
            fs::write(&cache_path, encrypted).await?;
        }

        #[cfg(debug_assertions)]
        {
            fs::write(&cache_path, wasm_bytes).await?;
        }

        debug!(path = %cache_path.display(), "Cached rules bundle");
        Ok(())
    }

    /// Returns the path for a versioned cached bundle: ~/.cache/tuora/def-<version>.wasm
    fn cache_path(&self, version: &str) -> Result<PathBuf> {
        let path = dirs::cache_dir()
            .ok_or_else(|| anyhow::anyhow!("No cache directory available"))?
            .join("tuora")
            .join(format!("def-{}.wasm", version));
        Ok(path)
    }
}

/// Get platform string for API request
fn get_platform_string() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    format!("{}-{}", os, arch)
}

/// Get embedded Ed25519 public key for signature verification
#[cfg(not(debug_assertions))]
fn get_signing_public_key() -> Result<Vec<u8>> {
    const PUBLIC_KEY_BASE64: &str = env!("TUORA_SIGNING_PUBKEY_VALUE");
    if PUBLIC_KEY_BASE64.is_empty() {
        anyhow::bail!(
            "Signing public key was not embedded at build time (TUORA_SIGNING_PUBKEY not set)"
        );
    }
    base64::engine::general_purpose::STANDARD
        .decode(PUBLIC_KEY_BASE64.trim())
        .map_err(|e| anyhow::anyhow!("Failed to decode public key: {}", e))
}

/// Encrypt data with AES-256-GCM using a key derived from the API key.
/// Output layout: [12-byte nonce][ciphertext + 16-byte GCM tag]
#[cfg(not(debug_assertions))]
fn encrypt_with_api_key(data: &[u8], api_key: &str) -> Result<Vec<u8>> {
    use ring::aead::{self, AES_256_GCM, BoundKey, SealingKey, UnboundKey};
    use ring::digest::{SHA256, digest};
    use ring::rand::{SecureRandom, SystemRandom};

    // Derive 32-byte AES key via SHA-256 of the API key
    let key_material = digest(&SHA256, api_key.as_bytes());
    let unbound = UnboundKey::new(&AES_256_GCM, key_material.as_ref())
        .map_err(|_| anyhow::anyhow!("Failed to create AES-256-GCM key"))?;

    // Generate a random 12-byte nonce
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to generate nonce"))?;

    struct OneShot([u8; 12]);
    impl aead::NonceSequence for OneShot {
        fn advance(&mut self) -> std::result::Result<aead::Nonce, ring::error::Unspecified> {
            Ok(aead::Nonce::assume_unique_for_key(self.0))
        }
    }

    let mut sealing_key = SealingKey::new(unbound, OneShot(nonce_bytes));
    let mut buf = data.to_vec();
    sealing_key
        .seal_in_place_append_tag(aead::Aad::empty(), &mut buf)
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    // Prepend nonce so decrypt can extract it
    let mut out = Vec::with_capacity(12 + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Decrypt data encrypted by `encrypt_with_api_key`.
/// Expects layout: [12-byte nonce][ciphertext + 16-byte GCM tag]
#[cfg(not(debug_assertions))]
fn decrypt_with_api_key(data: &[u8], api_key: &str) -> Result<Vec<u8>> {
    use ring::aead::{self, AES_256_GCM, BoundKey, OpeningKey, UnboundKey};
    use ring::digest::{SHA256, digest};

    if data.len() < 12 {
        anyhow::bail!("Encrypted bundle too short to contain nonce");
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce_arr: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid nonce length"))?;

    let key_material = digest(&SHA256, api_key.as_bytes());
    let unbound = UnboundKey::new(&AES_256_GCM, key_material.as_ref())
        .map_err(|_| anyhow::anyhow!("Failed to create AES-256-GCM key"))?;

    struct OneShot([u8; 12]);
    impl aead::NonceSequence for OneShot {
        fn advance(&mut self) -> std::result::Result<aead::Nonce, ring::error::Unspecified> {
            Ok(aead::Nonce::assume_unique_for_key(self.0))
        }
    }

    let mut opening_key = OpeningKey::new(unbound, OneShot(nonce_arr));
    let mut buf = ciphertext.to_vec();
    let plaintext = opening_key
        .open_in_place(aead::Aad::empty(), &mut buf)
        .map_err(|_| {
            anyhow::anyhow!("AES-GCM decryption failed — bundle may be corrupt or key mismatch")
        })?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_platform_string() {
        let platform = get_platform_string();
        assert!(!platform.is_empty());
        assert!(platform.contains('-'));
    }
}
