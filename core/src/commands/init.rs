//! `tuora init` command implementation
//!
//! Interactive first-run setup that prompts for API key and stores it
//! securely in the OS keyring.

use crate::auth::AuthClient;
use crate::credentials::{get_existing_api_key, prompt_for_api_key, store_api_key};
use crate::progress::Progress;
use anyhow::{Context, Result};
use std::io::{self, Write};
use tracing::{debug, info};

/// Run the init command
pub async fn run(ledger_url: String) -> Result<()> {
    println!("\n{}Tuora First-Time Setup{}", "\x1b[1m\x1b[36m", "\x1b[0m");
    println!("{}", "─".repeat(50));

    // Check if already configured — single keychain read covers both existence and source
    if get_existing_api_key().is_some() {
        let source = if std::env::var("TUORA_API_KEY").map(|k| !k.is_empty()).unwrap_or(false) {
            "environment variable (TUORA_API_KEY)"
        } else {
            "OS keyring"
        };
        println!(
            "\n{}⚠{} An API key is already stored in the {}.",
            "\x1b[33m", "\x1b[0m", source
        );
        print!("Do you want to reinitialize with a new API key? [y/N]: ");
        io::stdout().flush().context("Failed to flush stdout")?;

        let mut response = String::new();
        io::stdin()
            .read_line(&mut response)
            .context("Failed to read input")?;

        if !response.trim().eq_ignore_ascii_case("y") {
            println!("Initialization cancelled. Existing API key retained.");
            return Ok(());
        }
    }

    // Prompt for API key
    let api_key = prompt_for_api_key().context("Failed to get API key from user")?;

    // Validate the API key with a cloud ping
    Progress::status("validating API key");
    
    match validate_key(&api_key, &ledger_url).await {
        Ok(_) => {
            // Store in keyring
            store_api_key(&api_key).context("Failed to store API key")?;

            println!(
                "\n{}\x2713{} API key validated and stored securely",
                "\x1b[32m", "\x1b[0m"
            );
            println!(
                "{}\x2713{} Ready to scan. Run {}tuora{} to begin.",
                "\x1b[32m", "\x1b[0m", "\x1b[1m", "\x1b[0m"
            );

            info!("API key configured successfully");
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "\n{}\x2717{} API key validation failed: {}{}",
                "\x1b[31m", "\x1b[0m", e, "\x1b[0m"
            );
            eprintln!("\nPlease check your API key and try again.");
            eprintln!("Get your API key from: https://runtuora.com/dashboard");
            std::process::exit(1);
        }
    }
}

/// Validate API key by attempting authentication
async fn validate_key(api_key: &str, ledger_url: &str) -> Result<()> {
    debug!("Validating API key with ledger service");

    let mut auth_client = AuthClient::new(ledger_url)
        .context("Failed to initialize auth client")?;

    match auth_client.verify(api_key).await {
        Ok(_) => {
            debug!("API key validation successful");
            Ok(())
        }
        Err(e) => {
            debug!(error = %e, "API key validation failed");
            Err(e)
        }
    }
}
