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
mod paint;
mod progress;
mod reporter;
mod rules;
mod scanner;
mod telemetry;
mod types;
mod update;

use crate::{
    banner::print_banner,
    commands::{init, upgrade, watch},
    config::{Cli, Commands, ScanConfig, ledger_url},
    credentials::get_api_key,
};
use clap::Parser;
use tracing::debug;

#[tokio::main]
async fn main() {
    // Display banner immediately
    print_banner();

    // Kick off update check in the background — prints immediately when an update is found
    update::spawn_check();

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
                eprintln!("\n{} {}", paint::error("Error:"), e);
                std::process::exit(1);
            }
        }
        Some(Commands::Upgrade) => {
            if let Err(e) = upgrade::run().await {
                eprintln!("\n{} {}", paint::error("Error:"), e);
                std::process::exit(1);
            }
        }
        Some(Commands::Watch { .. }) => {
            let scan_cfg = ScanConfig::from_cli(&cli);
            let api_key = match get_api_key(Some(scan_cfg.api_key.clone())) {
                Ok(key) => key,
                Err(e) => {
                    eprintln!("\n{} {}", paint::error("✗"), e);
                    std::process::exit(1);
                }
            };
            let mut cfg = scan_cfg;
            cfg.api_key = api_key;
            if let Err(e) = watch::run(cfg).await {
                eprintln!("\n{} {}", paint::error("Error:"), e);
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
    println!("\n  {} tuora <command>\n", paint::bold("Usage:"));
    println!("  {}", paint::bold("Commands:"));
    println!(
        "    {}            Set up your API key for first use",
        paint::accent("tuora init")
    );
    println!(
        "    {}           Scan and watch the current directory",
        paint::accent("tuora watch")
    );
    println!(
        "    {}    Scan and watch a specific directory path",
        paint::accent("tuora watch <path>")
    );
    println!(
        "    {}         Upgrade to the latest release",
        paint::accent("tuora upgrade")
    );
    println!();
    println!("  {}", paint::bold("Options:"));
    println!(
        "    {}    Tuora API key (or set TUORA_API_KEY)",
        paint::dim("-a, --api-key <KEY>")
    );
    println!(
        "    {}     Output format: ansi (default), json, plain",
        paint::dim("-f, --format <FMT>")
    );
    println!("    {}          Print version", paint::dim("-V, --version"));
    println!();
    println!("  {} https://runtuora.com/docs\n", paint::bold("Docs:"));
}
