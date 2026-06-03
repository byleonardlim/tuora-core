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
    config::{ledger_url, Cli, Commands, ScanConfig},
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
                eprintln!("\n{}Error:{} {}", "\x1b[31m", "\x1b[0m", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Watch { .. }) => {
            let scan_cfg = ScanConfig::from_cli(&cli);
            let api_key = match get_api_key(Some(scan_cfg.api_key.clone())) {
                Ok(key) => key,
                Err(e) => {
                    eprintln!("\n{}\x2717{} {}", "\x1b[31m", "\x1b[0m", e);
                    std::process::exit(1);
                }
            };
            let mut cfg = scan_cfg;
            cfg.api_key = api_key;
            if let Err(e) = watch::run(cfg).await {
                eprintln!("\n{}Error:{} {}", "\x1b[31m", "\x1b[0m", e);
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
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    tracing_subscriber::registry()
        .with(fmt::layer().without_time().with_target(false).with_writer(io::stderr))
        .with(EnvFilter::from_default_env().add_directive("tuora=info".parse()?))
        .init();

    Ok(())
}

/// Display the Tuora command list when no subcommand is provided
fn print_help() {
    println!(
        "\n  {}Usage:{} tuora <command>\n",
        "\x1b[1m", "\x1b[0m"
    );
    println!("  {}Commands:{}", "\x1b[1m", "\x1b[0m");
    println!(
        "    {}tuora init{}            Set up your API key for first use",
        "\x1b[36m", "\x1b[0m"
    );
    println!(
        "    {}tuora watch{}           Scan and watch the current directory",
        "\x1b[36m", "\x1b[0m"
    );
    println!(
        "    {}tuora watch <path>{}    Scan and watch a specific directory path",
        "\x1b[36m", "\x1b[0m"
    );
    println!();
    println!(
        "  {}Options:{}",
        "\x1b[1m", "\x1b[0m"
    );
    println!("    {}-a, --api-key <KEY>{}    Tuora API key (or set TUORA_API_KEY)", "\x1b[90m", "\x1b[0m");
    println!("    {}-f, --format <FMT>{}     Output format: ansi (default), json, plain", "\x1b[90m", "\x1b[0m");
    println!("    {}-V, --version{}          Print version", "\x1b[90m", "\x1b[0m");
    println!();
    println!(
        "  {}Docs:{} https://runtuora.com/docs\n",
        "\x1b[1m", "\x1b[0m"
    );
}


