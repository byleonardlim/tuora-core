use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Resolve the ledger service URL.
///
/// Resolution order:
///   1. `TUORA_LEDGER_URL` runtime env var (local dev override)
///   2. `TUORA_LEDGER_URL_VALUE` baked in at compile time by `build.rs`
pub fn ledger_url() -> String {
    #[allow(clippy::unwrap_or_default)] // unwrap_or_default() yields "" not the compile-time baked value
    std::env::var("TUORA_LEDGER_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| env!("TUORA_LEDGER_URL_VALUE").to_string())
}

/// Tuora: Pre-Deployment Static Analysis for Vibe-Coded Applications
#[derive(Debug, Clone, Parser)]
#[command(
    name = "tuora",
    about = "Zero-footprint security scanner for AI-generated code"
)]
#[command(version, disable_help_subcommand = true)]
pub struct Cli {
    /// Tuora API key for wallet verification
    #[arg(short, long, env = "TUORA_API_KEY", default_value = "", global = true)]
    pub api_key: String,

    /// Output format for scan results
    #[arg(short, long, value_enum, default_value = "ansi", global = true)]
    pub format: OutputFormat,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Available commands
#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    /// Initialize API key configuration (first-run setup)
    Init,
    /// Watch a directory and re-evaluate on file changes
    Watch {
        /// Path to the workspace directory to watch (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

/// Output format options
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    /// ANSI-colored terminal output (default)
    #[default]
    Ansi,
    /// JSON output for CI/CD integration
    Json,
    /// Minimal text output
    Plain,
}

/// Scan-specific configuration (derived from CLI)
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub path: PathBuf,
    pub api_key: String,
    pub ledger_url: String,
    pub format: OutputFormat,
}

impl ScanConfig {
    /// Create ScanConfig from CLI args
    pub fn from_cli(cli: &Cli) -> Self {
        let path = match &cli.command {
            Some(Commands::Watch { path }) => path.clone(),
            _ => PathBuf::from("."),
        };

        Self {
            path,
            api_key: cli.api_key.clone(),
            ledger_url: ledger_url(),
            format: cli.format,
        }
    }
}
