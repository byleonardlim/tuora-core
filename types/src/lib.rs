//! Tuora shared wire protocol types
//!
//! This crate defines the contract between the open-core CLI (`core/`) and the
//! closed-source SaaS backend (`cloud/`). Both sides depend on this crate to
//! ensure the WASM ABI, auth handshake, rules bundle, and telemetry payloads
//! remain in sync.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────
// Auth Handshake (POST /v1/auth)
// ─────────────────────────────────────────────

/// Request body sent by the CLI during the auth handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub token_identity: String,
    pub client_epoch: u64,
}

/// Response from the ledger service after wallet validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Whether the key is valid and the wallet has sufficient balance
    pub valid: bool,
    pub wallet_balance: f64,
    pub scan_cost: f64,
    pub tier: PricingTier,
    pub historic_scans: u64,
    /// Number of scans the CLI may run before re-verifying (cache window)
    pub cache_allowed_units: u32,
}

/// Pricing tiers for pre-paid wallet
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PricingTier {
    Hobby,          // Free tier — first 100 scans lifetime
    Standard,       // $0.10 per scan (scans 1–999)
    VolumeDiscount, // $0.07 per scan (scans 1000+)
}

// ─────────────────────────────────────────────
// WASM Rule Bundle (POST /v1/rules-bundle)
// ─────────────────────────────────────────────

/// Request body for the rules bundle fetch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesBundleRequest {
    /// Platform string e.g. "macos-aarch64", "linux-x86_64"
    pub platform: String,
}

/// Response containing the signed WASM bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesBundleResponse {
    /// Base64-encoded WASM bytes
    pub wasm: String,
    /// Base64-encoded Ed25519 signature over the raw WASM bytes
    pub signature: String,
    /// SemVer bundle version e.g. "1.2.0"
    pub version: String,
    /// Unix timestamp after which this bundle must be refreshed
    pub expires_at: u64,
}

// ─────────────────────────────────────────────
// WASM Module ABI (bincode across the WASM boundary)
// ─────────────────────────────────────────────

/// File representation passed into the WASM sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmInputFile {
    pub path: String,
    pub content: String,
    pub extension: String,
}

/// Full evaluation input serialized into WASM linear memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalInput {
    pub files: Vec<WasmInputFile>,
    /// Detected framework name e.g. "CrewAI", "Unknown"
    pub framework: String,
}

/// Confidence level of a detected violation
///
/// `Confirmed` — a source-to-sink data-flow trace was established across the file set.
/// `Heuristic` — pattern match only; no cross-file source tracing performed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DetectionConfidence {
    Confirmed,
    Heuristic,
}

/// Violation returned from the WASM sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmViolation {
    pub rule_id: String,
    pub severity: WasmSeverity,
    pub file_path: String,
    pub line_number: usize,
    pub tool_target: String,
    pub message: String,
    pub plain_message: String,
    pub remediation: String,
    pub plain_remediation: String,
    /// Confidence level of this detection (Confirmed = cross-file traced, Heuristic = pattern-only)
    pub confidence: DetectionConfidence,
    /// Multi-framework threat citations e.g. ["CWE-338", "OWASP-API4", "ATLAS-AML.T0051"]
    pub threat_refs: Vec<String>,
}

/// Severity levels used across the WASM boundary
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WasmSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Full evaluation output deserialized from WASM linear memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalOutput {
    pub violations: Vec<WasmViolation>,
    pub rules_evaluated: u32,
}

// ─────────────────────────────────────────────
// Telemetry (POST /telemetry/batch)
// ─────────────────────────────────────────────

/// A single scan event queued for async telemetry sinking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub scan_id: String,
    pub workspace_id: String,
    pub framework: String,
    pub meta_stats: MetaStats,
    pub detected_vulnerabilities: Vec<ViolationSummary>,
}

/// Aggregate scan statistics embedded in a telemetry event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaStats {
    pub rules_evaluated: usize,
    pub anomalies_detected: usize,
    pub code_base_files: usize,
    pub scan_duration_ms: u64,
}

/// Lightweight violation summary for telemetry payloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationSummary {
    pub rule_id: String,
    pub severity: String,
    pub tool_target: String,
    pub message: String,
}
