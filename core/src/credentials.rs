//! API key storage and credential management
//!
//! Stores the API key encrypted at rest using AES-256-GCM.
//!
//! Files (both mode 0600):
//!   ~/.config/tuora/keyfile      — 32 random bytes (the AES-256 symmetric key)
//!   ~/.config/tuora/credentials  — base64(nonce || ciphertext || tag)
//!
//! Falls back to TUORA_API_KEY environment variable in containerised environments.
//! The decrypted key is cached in a process-local OnceLock so disk I/O happens
//! at most once per invocation.

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ring::aead::{self, BoundKey, NONCE_LEN, Nonce, NonceSequence, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::OnceLock;
use tracing::{debug, info};

/// Process-local cache — credentials file is decrypted at most once per invocation.
static CACHED_API_KEY: OnceLock<Option<String>> = OnceLock::new();

// ── Path helpers ──────────────────────────────────────────────────────────────

fn config_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|d| d.join("tuora"))
        .context("Cannot locate user config directory")
}

fn keyfile_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("keyfile"))
}

fn credentials_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("credentials"))
}

// ── Encryption helpers ────────────────────────────────────────────────────────

/// One-shot nonce backed by a fixed 12-byte array.
struct FixedNonce([u8; NONCE_LEN]);

impl NonceSequence for FixedNonce {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.0))
    }
}

/// Encrypt `plaintext` with AES-256-GCM using `key`.
/// Returns `nonce || ciphertext+tag` as a single Vec.
fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to generate nonce"))?;

    let unbound = UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| anyhow::anyhow!("Failed to create AES-256-GCM key"))?;
    let mut sealing = aead::SealingKey::new(unbound, FixedNonce(nonce_bytes));

    let mut buf = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(aead::Aad::empty(), &mut buf)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Decrypt `nonce || ciphertext+tag` with AES-256-GCM using `key`.
fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        bail!("Credentials file is corrupted (too short)");
    }

    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes.try_into().unwrap();

    let unbound = UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| anyhow::anyhow!("Failed to create AES-256-GCM key"))?;
    let mut opening = aead::OpeningKey::new(unbound, FixedNonce(nonce_bytes));

    let mut buf = ciphertext.to_vec();
    let plaintext = opening
        .open_in_place(aead::Aad::empty(), &mut buf)
        .map_err(|_| anyhow::anyhow!("Decryption failed — credentials may be corrupted"))?;

    Ok(plaintext.to_vec())
}

// ── Keyfile management ────────────────────────────────────────────────────────

/// Load the 32-byte symmetric key from disk, creating it if absent.
fn load_or_create_keyfile() -> Result<[u8; 32]> {
    let path = keyfile_path()?;

    if path.exists() {
        let raw = std::fs::read(&path).context("Failed to read keyfile")?;
        if raw.len() != 32 {
            bail!(
                "Keyfile is corrupted (expected 32 bytes, got {})",
                raw.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        return Ok(key);
    }

    // Generate a fresh 256-bit key
    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key)
        .map_err(|_| anyhow::anyhow!("Failed to generate encryption key"))?;

    std::fs::create_dir_all(path.parent().unwrap()).context("Failed to create config directory")?;

    write_private_file(&path, &key)?;
    Ok(key)
}

/// Write `data` to `path` with mode 0600 (owner read/write only).
fn write_private_file(path: &std::path::Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| f.write_all(data))
            .with_context(|| format!("Failed to write {}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
            .with_context(|| format!("Failed to write {}", path.display()))?;
    }

    Ok(())
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Check if running inside a Docker container.
pub fn is_running_in_docker() -> bool {
    std::path::Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/self/cgroup")
            .map(|c| c.contains("docker"))
            .unwrap_or(false)
}

/// Get API key from available sources (in priority order):
/// 1. CLI argument
/// 2. TUORA_API_KEY environment variable
/// 3. Encrypted credentials file
pub fn get_api_key(cli_key: Option<String>) -> Result<String> {
    if let Some(key) = cli_key
        && !key.is_empty()
    {
        debug!("Using API key from CLI argument");
        return Ok(key);
    }

    if let Some(key) = get_existing_api_key() {
        debug!("Using API key from credentials store");
        return Ok(key);
    }

    if is_running_in_docker() {
        bail!(
            "TUORA_API_KEY environment variable required in Docker.\n\
             Run with: -e TUORA_API_KEY=<your_key> or --env-file .env"
        );
    } else {
        bail!(
            "No API key configured.\n\
             Run `tuora init` to set up your API key, or provide it via:\n\
               --api-key <KEY>  (CLI argument)\n\
               TUORA_API_KEY=<KEY> (environment variable)"
        );
    }
}

/// Encrypt and persist the API key to `~/.config/tuora/credentials`.
pub fn store_api_key(api_key: &str) -> Result<()> {
    if is_running_in_docker() {
        bail!(
            "`tuora init` is not available in Docker containers.\n\
               Use the TUORA_API_KEY environment variable instead."
        );
    }

    let key = load_or_create_keyfile().context("Failed to load encryption key")?;
    let blob = encrypt(&key, api_key.as_bytes()).context("Failed to encrypt API key")?;
    let encoded = B64.encode(&blob);

    let creds_path = credentials_path()?;
    std::fs::create_dir_all(creds_path.parent().unwrap())
        .context("Failed to create config directory")?;
    write_private_file(&creds_path, encoded.as_bytes())?;

    info!("API key stored securely in encrypted credentials file");
    Ok(())
}

/// Return the currently configured API key if one exists, or None.
///
/// Cached in a process-local OnceLock — disk is touched at most once per run.
pub fn get_existing_api_key() -> Option<String> {
    CACHED_API_KEY
        .get_or_init(|| {
            if let Ok(key) = std::env::var("TUORA_API_KEY")
                && !key.is_empty()
            {
                return Some(key);
            }

            if !is_running_in_docker() {
                return load_stored_api_key().ok().flatten();
            }

            None
        })
        .clone()
}

/// Read and decrypt the stored credentials file. Returns None if absent.
fn load_stored_api_key() -> Result<Option<String>> {
    let creds_path = credentials_path()?;
    if !creds_path.exists() {
        return Ok(None);
    }

    let encoded =
        std::fs::read_to_string(&creds_path).context("Failed to read credentials file")?;
    let blob = B64
        .decode(encoded.trim())
        .context("Credentials file is corrupted (invalid base64)")?;

    let key = load_or_create_keyfile().context("Failed to load encryption key")?;
    let plaintext = decrypt(&key, &blob).context("Failed to decrypt API key")?;

    let api_key =
        String::from_utf8(plaintext).context("Credentials file is corrupted (invalid UTF-8)")?;

    if api_key.is_empty() {
        return Ok(None);
    }

    Ok(Some(api_key))
}

/// Prompt user for API key (input hidden on Unix TTYs).
pub fn prompt_for_api_key() -> Result<String> {
    print!("Enter your Tuora API key: ");
    io::stdout().flush().context("Failed to flush stdout")?;

    let input = read_password().context("Failed to read API key input")?;
    let trimmed = input.trim().to_string();

    if trimmed.is_empty() {
        bail!("API key cannot be empty");
    }

    Ok(trimmed)
}

/// Read password input — hidden on Unix TTYs, plain otherwise.
fn read_password() -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::metadata("/dev/stdin").context("Failed to check stdin metadata")?;
        let is_tty = metadata.mode() & 0o020000 != 0;

        if is_tty {
            // Disable terminal echo manually for hidden input
            read_password_unix()
        } else {
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .context("Failed to read input")?;
            Ok(input)
        }
    }

    #[cfg(not(unix))]
    {
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .context("Failed to read input")?;
        Ok(input)
    }
}

/// Hidden password input on Unix without extra dependencies.
/// Disables terminal echo via `stty -echo`, reads from /dev/tty, then restores.
#[cfg(unix)]
fn read_password_unix() -> Result<String> {
    use std::process::Command;

    // Disable echo on the controlling terminal
    Command::new("stty")
        .arg("-echo")
        .stdin(std::process::Stdio::inherit())
        .status()
        .context("Failed to disable terminal echo")?;

    let mut input = String::new();
    let read_result = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .and_then(|tty| {
            use io::BufRead;
            let mut reader = io::BufReader::new(tty);
            reader.read_line(&mut input)
        });

    // Always restore echo before propagating errors
    let _ = Command::new("stty")
        .arg("echo")
        .stdin(std::process::Stdio::inherit())
        .status();
    println!(); // newline after hidden input

    read_result.context("Failed to read password from terminal")?;
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_detection() {
        let _ = is_running_in_docker();
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let rng = ring::rand::SystemRandom::new();
        let mut key = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut key).unwrap();

        let plaintext = b"test-api-key-12345";
        let blob = encrypt(&key, plaintext).unwrap();
        let recovered = decrypt(&key, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let rng = ring::rand::SystemRandom::new();
        let mut key = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut key).unwrap();

        let blob = encrypt(&key, b"secret").unwrap();

        let mut bad_key = key;
        bad_key[0] ^= 0xff;
        assert!(decrypt(&bad_key, &blob).is_err());
    }
}
