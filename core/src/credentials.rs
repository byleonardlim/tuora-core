//! API key storage and credential management
//!
//! Handles secure storage of API keys using OS-native keyring services.
//! Falls back to environment variables in containerized environments.

use anyhow::{bail, Context, Result};
use std::io::{self, Write};
use tracing::{debug, info};

const KEYRING_SERVICE: &str = "tuora";
const KEYRING_ACCOUNT: &str = "api_key";

/// Check if running inside a Docker container
pub fn is_running_in_docker() -> bool {
    std::path::Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/self/cgroup")
            .map(|c| c.contains("docker"))
            .unwrap_or(false)
}

/// Get API key from available sources (in priority order)
///
/// Priority:
/// 1. CLI argument (passed directly)
/// 2. Environment variable (TUORA_API_KEY)
/// 3. OS keyring (native desktop only)
/// 4. Error with helpful message
pub fn get_api_key(cli_key: Option<String>) -> Result<String> {
    // 1. CLI argument (highest priority)
    if let Some(key) = cli_key {
        if !key.is_empty() {
            debug!("Using API key from CLI argument");
            return Ok(key);
        }
    }

    // 2 & 3. Environment variable then OS keyring — single call, one Keychain access
    if let Some(key) = get_existing_api_key() {
        debug!("Using API key from keyring/environment");
        return Ok(key);
    }

    // Nothing found - provide helpful error
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

/// Store API key in OS keyring
pub fn store_api_key(api_key: &str) -> Result<()> {
    if is_running_in_docker() {
        bail!("`tuora init` is not available in Docker containers.\n\
               Use the TUORA_API_KEY environment variable instead.");
    }

    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .context("Failed to access OS keyring")?;

    entry
        .set_password(api_key)
        .context("Failed to store API key in keyring")?;

    info!("API key stored securely in OS keyring");
    Ok(())
}

/// Return the currently configured API key if one exists, or None.
///
/// Reads from the keyring at most once, so callers that need both "does it exist?"
/// and "what is it?" can avoid the double macOS Keychain authorization prompt.
pub fn get_existing_api_key() -> Option<String> {
    if let Ok(key) = std::env::var("TUORA_API_KEY") {
        if !key.is_empty() {
            return Some(key);
        }
    }

    if !is_running_in_docker() {
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT) {
            if let Ok(key) = entry.get_password() {
                if !key.is_empty() {
                    return Some(key);
                }
            }
        }
    }

    None
}

/// Prompt user for API key (with hidden input if possible)
pub fn prompt_for_api_key() -> Result<String> {
    print!("Enter your Tuora API key: ");
    io::stdout().flush().context("Failed to flush stdout")?;

    // Try to use rpassword for secure input if available, fall back to plain read
    let input = read_password().context("Failed to read API key input")?;

    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        bail!("API key cannot be empty");
    }

    Ok(trimmed)
}

/// Read password input (hidden on Unix, plain on others)
fn read_password() -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        
        // Check if stdin is a TTY
        let metadata = std::fs::metadata("/dev/stdin")
            .context("Failed to check stdin metadata")?;
        let is_tty = metadata.mode() & 0o020000 != 0; // S_IFCHR check

        if is_tty {
            // Use rpassword for hidden input
            rpassword::read_password()
                .context("Failed to read password securely")
        } else {
            // Not a TTY, read normally (for piped input)
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .context("Failed to read input")?;
            Ok(input)
        }
    }

    #[cfg(not(unix))]
    {
        // On Windows/non-Unix, use rpassword if available, otherwise plain
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .context("Failed to read input")?;
        Ok(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_detection() {
        // This test will behave differently in Docker vs native
        // Just verify it doesn't panic
        let _ = is_running_in_docker();
    }

    #[test]
    fn test_keyring_service_constants() {
        assert_eq!(KEYRING_SERVICE, "tuora");
        assert_eq!(KEYRING_ACCOUNT, "api_key");
    }
}
