//! Remote WASM Rule Bundle Fetching
//!
//! Handles fetching signed WASM modules from the cloud API in production,
//! and loading from local filesystem in development mode.

use super::wasm_engine::WasmRuleEngine;
use crate::types::AuthResponse;
use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs;
use tracing::{debug, info, trace, warn};

/// Maximum length of error body to display
const MAX_ERROR_BODY_LEN: usize = 200;
/// HTTP status codes that warrant a retry
const RETRYABLE_STATUS_CODES: &[u16] = &[502, 503, 504];
/// Maximum number of retries for transient errors
const MAX_RETRIES: u32 = 3;
/// Base delay for exponential backoff (milliseconds)
const BASE_RETRY_DELAY_MS: u64 = 1000;
/// Ed25519 signature length in bytes (used in release builds only)
#[cfg(not(debug_assertions))]
const ED25519_SIGNATURE_LEN: usize = 64;

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
    /// Content hash (SHA256) for cache validation
    pub content_hash: Option<String>,
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
    content_hash: Option<String>,
    released_at: Option<String>,
}

/// Server version info including content hash for cache validation
#[derive(Debug)]
#[allow(dead_code)]
struct ServerVersionInfo {
    version: String,
    content_hash: Option<String>,
    released_at: Option<String>,
}

/// Rule bundle fetcher
pub struct RuleBundleFetcher {
    ledger_url: String,
    api_key: String,
    client: reqwest::Client,
}

/// Format an API error into a user-friendly message, stripping HTML
fn format_api_error(status: reqwest::StatusCode, body: &str) -> String {
    // Check if body is HTML
    if body.trim().starts_with('<') || body.contains("<!DOCTYPE") {
        // For gateway errors, provide a clean message
        if status.as_u16() >= 502 && status.as_u16() <= 504 {
            return format!(
                "API error {} ({}). The Tuora cloud service is temporarily unavailable. Please try again in a few moments.",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            );
        }
        return format!(
            "API error {} ({}). The server returned an HTML error page instead of JSON.",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown")
        );
    }

    // Truncate long error bodies
    let truncated = if body.len() > MAX_ERROR_BODY_LEN {
        format!("{}... [truncated]", &body[..MAX_ERROR_BODY_LEN])
    } else {
        body.to_string()
    };

    format!("API error {}: {}", status, truncated)
}

/// Check if a status code indicates a potentially transient error
fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    RETRYABLE_STATUS_CODES.contains(&status.as_u16())
        || status.is_server_error() && status.as_u16() != 501 // 501 Not Implemented is permanent
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
    pub async fn fetch(&self, auth: &AuthResponse) -> Result<(WasmRuleEngine, String)> {
        // Dev mode: load from filesystem (build.rs compiles it at build time)
        #[cfg(debug_assertions)]
        {
            match self.try_load_dev().await {
                Ok(engine) => {
                    info!("Loaded rules from dev/ directory");
                    return Ok((engine, "dev".to_string()));
                }
                Err(e) => {
                    warn!(error = %e, "Dev WASM not found — was build.rs skipped? Falling back to API");
                }
            }
        }

        // Production: check cache before downloading
        self.fetch_with_cache(auth).await
    }

    /// Cache-aware fetch: version check → cache hit → download fallback → any cache fallback.
    /// Uses content_hash to detect when same version has new content (cache invalidation).
    /// Falls back to any cached bundle if API is completely unavailable.
    #[cfg_attr(debug_assertions, allow(dead_code))]
    async fn fetch_with_cache(&self, auth: &AuthResponse) -> Result<(WasmRuleEngine, String)> {
        match self.check_server_version().await {
            Ok(server_info) => {
                debug!(
                    version = %server_info.version,
                    content_hash = ?server_info.content_hash,
                    "Server bundle version"
                );

                // Check if cached bundle matches server's content hash
                match self.try_load_cache_with_validation(&server_info).await {
                    Ok(engine) => {
                        info!(version = %server_info.version, "Loaded rules from disk cache");
                        return Ok((engine, server_info.version));
                    }
                    Err(e) => {
                        debug!(error = %e, "Cache miss or content hash mismatch, downloading bundle");
                    }
                }
                self.fetch_from_api(auth).await
            }
            Err(version_err) => {
                warn!(error = %version_err, "Version check failed, trying direct download");
                match self.fetch_from_api(auth).await {
                    Ok(result) => Ok(result),
                    Err(api_err) => {
                        warn!(error = %api_err, "API fetch failed, attempting to load any cached bundle");
                        match self.try_load_any_cache().await {
                            Ok(result) => Ok(result),
                            Err(cache_err) => {
                                bail!(
                                    "Failed to fetch rules bundle and no usable cache available.\n\
                                     API error: {}\n\
                                     Cache error: {}",
                                    api_err,
                                    cache_err
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// GET /v1/bundle-version — cheap call to retrieve the current version and content hash.
    /// Includes retry logic for transient failures.
    async fn check_server_version(&self) -> Result<ServerVersionInfo> {
        let url = format!("{}/bundle-version", self.ledger_url);

        let mut last_error = None;
        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                let delay = BASE_RETRY_DELAY_MS * 2_u64.pow(attempt - 1);
                debug!(
                    "Retrying version check after {}ms (attempt {}/{})",
                    delay,
                    attempt + 1,
                    MAX_RETRIES
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }

            match self
                .client
                .get(&url)
                .bearer_auth(&self.api_key)
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        let parsed: BundleVersionResponse = response.json().await?;
                        return Ok(ServerVersionInfo {
                            version: parsed.version,
                            content_hash: parsed.content_hash,
                            released_at: parsed.released_at,
                        });
                    }

                    let body = response.text().await.unwrap_or_default();
                    let error_msg = format_api_error(status, &body);

                    if is_retryable_status(status) && attempt < MAX_RETRIES - 1 {
                        warn!("Version check failed with retryable error: {}", error_msg);
                        last_error = Some(error_msg);
                        continue;
                    }

                    bail!("Version check failed: {}", error_msg);
                }
                Err(e) => {
                    let is_timeout = e.is_timeout();
                    let error_msg = if is_timeout {
                        format!("Request timed out connecting to {}", self.ledger_url)
                    } else {
                        format!("Request failed: {}", e)
                    };

                    if (is_timeout || e.is_connect()) && attempt < MAX_RETRIES - 1 {
                        warn!("Version check network error (will retry): {}", error_msg);
                        last_error = Some(error_msg);
                        continue;
                    }

                    bail!("Version check failed: {}", error_msg);
                }
            }
        }

        bail!(
            "Version check failed after {} retries: {}",
            MAX_RETRIES,
            last_error.unwrap_or_else(|| "Unknown error".to_string())
        );
    }

    /// Try to load a cached bundle from disk, validating content hash if provided.
    /// Returns Ok if cached bundle matches server's content hash (or if no hash to compare).
    async fn try_load_cache_with_validation(
        &self,
        server_info: &ServerVersionInfo,
    ) -> Result<WasmRuleEngine> {
        let version = &server_info.version;

        // If server provides content hash, validate it against cached hash
        if let Some(ref expected_hash) = server_info.content_hash {
            let hash_path = self.cache_hash_path(version)?;
            if hash_path.exists() {
                let cached_hash = fs::read_to_string(&hash_path).await?;
                let cached_hash = cached_hash.trim();
                if cached_hash != expected_hash {
                    bail!(
                        "Content hash mismatch: cached {} vs server {}. Cache invalidated.",
                        cached_hash,
                        expected_hash
                    );
                }
                debug!(hash = %expected_hash, "Content hash validated");
            } else {
                bail!("No content hash file found, treating as cache miss");
            }
        }

        // Hash matches (or no hash to check), load the cached bundle
        self.try_load_cache(version).await
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
            // Cached bundles carry the signature in the first ED25519_SIGNATURE_LEN bytes
            if bytes.len() < ED25519_SIGNATURE_LEN {
                bail!("Cached bundle too short to contain signature");
            }
            let (sig_bytes, wasm) = bytes.split_at(ED25519_SIGNATURE_LEN);

            if let Err(verify_err) =
                super::wasm_engine::verify_signature(wasm, sig_bytes, &public_key)
            {
                tracing::error!(
                    error = %verify_err,
                    cache_path = %cache_path.display(),
                    "Cached bundle signature verification failed - cache may be corrupted or keys rotated"
                );
                return Err(verify_err).context(
                    "Invalid Ed25519 signature from cache. The cached bundle may be:\n\
                     1. Corrupted (delete cache and retry)\n\
                     2. Signed with old key after key rotation\n\
                     3. Downloaded with different API key\n\
                     Try: rm -rf ~/.cache/tuora/ and retry",
                );
            }
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

    /// Try to load any cached bundle from disk when API is unavailable.
    /// Scans the cache directory for any rule-engine bundle and loads the most recent one.
    async fn try_load_any_cache(&self) -> Result<(WasmRuleEngine, String)> {
        let cache_dir = dirs::cache_dir()
            .ok_or_else(|| anyhow::anyhow!("No cache directory available"))?
            .join("tuora");

        if !cache_dir.exists() {
            bail!("No cache directory found at {}", cache_dir.display());
        }

        // Find all rule-engine-*.wasm files in cache
        let mut entries = fs::read_dir(&cache_dir).await?;
        let mut bundles = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if filename.starts_with("rule-engine-v") && filename.ends_with(".wasm") {
                // Extract version from filename: rule-engine-v{version}.wasm
                let version = filename
                    .strip_prefix("rule-engine-v")
                    .and_then(|s| s.strip_suffix(".wasm"))
                    .unwrap_or("unknown")
                    .to_string();

                let metadata = entry.metadata().await?;
                let modified = metadata.modified()?;
                bundles.push((path, version, modified));
            }
        }

        // Sort by modification time (most recent first)
        bundles.sort_by(|a, b| b.2.cmp(&a.2));

        for (path, version, _) in bundles {
            debug!(path = %path.display(), version = %version, "Attempting to load cached bundle");
            match self.try_load_cache(&version).await {
                Ok(engine) => {
                    warn!(version = %version, "Using cached rules bundle (API unavailable). Rules may be outdated.");
                    return Ok((engine, version));
                }
                Err(e) => {
                    debug!(error = %e, path = %path.display(), "Failed to load cached bundle");
                    continue;
                }
            }
        }

        bail!("No usable cached bundles found in {}", cache_dir.display())
    }

    /// Path to dev WASM file (e.g. `dev/rule-engine-v0.1.0.wasm`)
    #[cfg(debug_assertions)]
    fn dev_wasm_path(&self) -> PathBuf {
        let filename = format!("rule-engine-v{}.wasm", env!("RULE_ENGINE_VERSION"));
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("dev")
            .join(filename)
    }

    /// Fetch from cloud API with retry logic for transient errors
    async fn fetch_from_api(&self, _auth: &AuthResponse) -> Result<(WasmRuleEngine, String)> {
        let url = format!("{}/rules-bundle", self.ledger_url);

        let request = RulesBundleRequest {
            platform: get_platform_string(),
        };

        let mut last_error = None;
        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                let delay = BASE_RETRY_DELAY_MS * 2_u64.pow(attempt - 1);
                info!(
                    "Retrying rules bundle fetch after {}ms (attempt {}/{})",
                    delay,
                    attempt + 1,
                    MAX_RETRIES
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }

            debug!(url = %url, attempt = attempt + 1, "Fetching rules bundle from API");

            match self
                .client
                .post(&url)
                .bearer_auth(&self.api_key)
                .json(&request)
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        return self.process_bundle_response(response).await;
                    }

                    let body = response.text().await.unwrap_or_default();
                    let error_msg = format_api_error(status, &body);

                    if is_retryable_status(status) && attempt < MAX_RETRIES - 1 {
                        warn!(
                            "Rules bundle fetch failed with retryable error: {}",
                            error_msg
                        );
                        last_error = Some(error_msg);
                        continue;
                    }

                    bail!("{}", error_msg);
                }
                Err(e) => {
                    let is_timeout = e.is_timeout();
                    let error_msg = if is_timeout {
                        format!("Request timed out connecting to {}", self.ledger_url)
                    } else {
                        format!("Request failed: {}", e)
                    };

                    if (is_timeout || e.is_connect()) && attempt < MAX_RETRIES - 1 {
                        warn!(
                            "Rules bundle fetch network error (will retry): {}",
                            error_msg
                        );
                        last_error = Some(error_msg);
                        continue;
                    }

                    bail!("{}", error_msg);
                }
            }
        }

        bail!(
            "Rules bundle fetch failed after {} retries: {}",
            MAX_RETRIES,
            last_error.unwrap_or_else(|| "Unknown error".to_string())
        );
    }

    /// Process a successful bundle response
    async fn process_bundle_response(
        &self,
        response: reqwest::Response,
    ) -> Result<(WasmRuleEngine, String)> {
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

        debug!(
            wasm_size = wasm_bytes.len(),
            sig_size = sig_bytes.len(),
            wasm_prefix = %to_hex(&wasm_bytes[..8.min(wasm_bytes.len())]),
            sig_prefix = %to_hex(&sig_bytes[..8.min(sig_bytes.len())]),
            "Decoded WASM bundle"
        );

        // Verify signature (skipped in dev, enforced in release)
        #[cfg(not(debug_assertions))]
        {
            let public_key = get_signing_public_key()?;
            debug!(
                pk_size = public_key.len(),
                pk_prefix = %to_hex(&public_key[..8.min(public_key.len())]),
                "About to verify signature"
            );

            if let Err(verify_err) =
                super::wasm_engine::verify_signature(&wasm_bytes, &sig_bytes, &public_key)
            {
                tracing::error!(
                    error = %verify_err,
                    wasm_size = wasm_bytes.len(),
                    sig_size = sig_bytes.len(),
                    pk_size = public_key.len(),
                    "Signature verification failed - check that TUORA_SIGNING_PUBKEY matches SIGNING_PRIVATE_KEY"
                );
                return Err(verify_err).context(
                    "Invalid Ed25519 signature. Possible causes:\n\
                     1. The signing keypair mismatch: TUORA_SIGNING_PUBKEY doesn't match SIGNING_PRIVATE_KEY\n\
                     2. Corrupted WASM bundle during download\n\
                     3. Wrong public key extracted (must be 32 raw bytes, not 44-byte DER)\n\
                     4. Key rotation without client rebuild\n\
                     Run with RUST_LOG=debug for full signature details."
                );
            }
            debug!("WASM signature verified");
        }

        // Verify server-provided content hash against actual downloaded bytes
        let computed_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&wasm_bytes);
            format!("{:x}", hasher.finalize())
        };

        if let Some(ref server_hash) = bundle.content_hash {
            if server_hash != &computed_hash {
                bail!(
                    "Content hash mismatch: server claims {} but computed {} from downloaded bytes",
                    server_hash,
                    computed_hash
                );
            }
            debug!(hash = %computed_hash, "Server content hash verified");
        }

        // Cache to local disk (signature prepended so try_load_cache can re-verify)
        let content_hash = computed_hash;
        if let Err(e) = self
            .cache_bundle(
                &bundle.version,
                &sig_bytes,
                &wasm_bytes,
                Some(&content_hash),
            )
            .await
        {
            warn!(error = %e, "Failed to cache bundle");
        }

        let version = bundle.version.clone();
        let engine = tokio::task::block_in_place(|| WasmRuleEngine::load(&wasm_bytes))?;
        Ok((engine, version))
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

    /// Cache bundle to disk, storing [64-byte Ed25519 sig][wasm] before encryption.
    /// Also stores content hash in a separate .hash file for cache invalidation.
    #[cfg_attr(debug_assertions, allow(unused_variables))]
    async fn cache_bundle(
        &self,
        version: &str,
        sig_bytes: &[u8],
        wasm_bytes: &[u8],
        content_hash: Option<&str>,
    ) -> Result<()> {
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

        // Store content hash for cache invalidation
        if let Some(hash) = content_hash {
            let hash_path = self.cache_hash_path(version)?;
            fs::write(&hash_path, hash).await?;
            debug!(path = %hash_path.display(), hash = %hash, "Cached content hash");
        }

        debug!(path = %cache_path.display(), "Cached rules bundle");
        Ok(())
    }

    /// Returns the path for a versioned content hash file: ~/.cache/tuora/rule-engine-v<version>.wasm.hash
    fn cache_hash_path(&self, version: &str) -> Result<PathBuf> {
        let path = dirs::cache_dir()
            .ok_or_else(|| anyhow::anyhow!("No cache directory available"))?
            .join("tuora")
            .join(format!("rule-engine-v{}.wasm.hash", version));
        Ok(path)
    }

    /// Returns the path for a versioned cached bundle: ~/.cache/tuora/rule-engine-v<version>.wasm
    fn cache_path(&self, version: &str) -> Result<PathBuf> {
        let path = dirs::cache_dir()
            .ok_or_else(|| anyhow::anyhow!("No cache directory available"))?
            .join("tuora")
            .join(format!("rule-engine-v{}.wasm", version));
        Ok(path)
    }
}

/// Get platform string for API request
fn get_platform_string() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    format!("{}-{}", os, arch)
}

/// Simple hex encoder for debug output
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        result.push(HEX[(b >> 4) as usize] as char);
        result.push(HEX[(b & 0xf) as usize] as char);
    }
    result
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

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(PUBLIC_KEY_BASE64.trim())
        .map_err(|e| anyhow::anyhow!("Failed to decode public key: {}", e))?;

    // Ed25519 public keys must be exactly 32 bytes (raw format, not PEM)
    if decoded.len() != 32 {
        anyhow::bail!(
            "Invalid public key format: expected 32 bytes for Ed25519, got {}. \
             Ensure TUORA_SIGNING_PUBKEY is a base64-encoded raw public key (not PEM).",
            decoded.len()
        );
    }

    debug!(
        pk_base64_len = PUBLIC_KEY_BASE64.len(),
        pk_decoded_len = decoded.len(),
        pk_prefix = %to_hex(&decoded[..8.min(decoded.len())]),
        "Loaded embedded public key"
    );

    Ok(decoded)
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
