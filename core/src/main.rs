//! Tuora: Pre-Deployment Static Analysis for Vibe-Coded Applications
//!
//! 6-Stage Execution Pipeline:
//! 1. Cloud Auth Check - Wallet verification
//! 2. WASM Rule Fetch - Load threat signatures
//! 3. Local File Ingest - Workspace scanning
//! 4. WASM Rule Evaluation - Compliance checking
//! 5. ANSI Rendering - Report output
//! 6. Async Telemetry Flush - Metrics sinking

mod auth;
mod banner;
mod commands;
mod config;
mod credentials;
mod progress;
mod reporter;
mod rules;
mod scanner;
mod telemetry;
mod types;

use crate::{
    banner::print_banner,
    commands::{init, watch},
    config::{Cli, Commands, ScanConfig, ledger_url},
    credentials::get_api_key,
};
use clap::Parser;
use tracing::debug;

#[tokio::main]
async fn main() {
    // Display banner immediately
    print_banner();

    // Initialize logging (only for debug output, not user-facing)
    if let Err(e) = init_logging() {
        eprintln!("Failed to initialize logging: {}", e);
    }

    // Parse CLI arguments
    let cli = Cli::parse();

    debug!(cli = ?cli, "Loaded CLI arguments");

    // Dispatch to appropriate command handler
    match &cli.command {
        Some(Commands::Init) => {
            if let Err(e) = init::run(ledger_url()).await {
                eprintln!("\n\x1b[31mError:\x1b[0m {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Watch { .. }) => {
            let scan_cfg = ScanConfig::from_cli(&cli);
            let api_key = match get_api_key(Some(scan_cfg.api_key.clone())) {
                Ok(key) => key,
                Err(e) => {
                    eprintln!("\n\x1b[31m\x2717\x1b[0m {}", e);
                    std::process::exit(1);
                }
            };
            let mut cfg = scan_cfg;
            cfg.api_key = api_key;
            if let Err(e) = watch::run(cfg).await {
                eprintln!("\n\x1b[31mError:\x1b[0m {}", e);
                std::process::exit(1);
            }
        }
        None => {
            print_help();
        }
    }
}

/// Initialize tracing subscriber
fn init_logging() -> anyhow::Result<()> {
    use std::io;
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .without_time()
                .with_target(false)
                .with_writer(io::stderr),
        )
        .with(EnvFilter::from_default_env().add_directive("tuora=info".parse()?))
        .init();

    Ok(())
}

/// Display the Tuora command list when no subcommand is provided
fn print_help() {
    println!("\n  \x1b[1mUsage:\x1b[0m tuora <command>\n");
    println!("  \x1b[1mCommands:\x1b[0m");
    println!("    \x1b[36mtuora init\x1b[0m            Set up your API key for first use");
    println!("    \x1b[36mtuora watch\x1b[0m           Scan and watch the current directory");
    println!("    \x1b[36mtuora watch <path>\x1b[0m    Scan and watch a specific directory path");
    println!();
    println!("  \x1b[1mOptions:\x1b[0m");
    println!("    \x1b[90m-a, --api-key <KEY>\x1b[0m    Tuora API key (or set TUORA_API_KEY)");
    println!(
        "    \x1b[90m-f, --format <FMT>\x1b[0m     Output format: ansi (default), json, plain"
    );
    println!("    \x1b[90m-V, --version\x1b[0m          Print version");
    println!();
    println!("  \x1b[1mDocs:\x1b[0m https://runtuora.com/docs\n");
}
