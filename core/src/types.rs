//! Core type definitions for Tuora static analysis engine

use owo_colors::OwoColorize;
use owo_colors::Stream;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity levels for compliance rule violations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    /// Point deduction for health score calculation
    pub fn weight(&self) -> u32 {
        match self {
            Severity::Critical => 25,
            Severity::High => 15,
            Severity::Medium => 8,
            Severity::Low => 3,
        }
    }

    /// Severity label styled with the appropriate color for terminal output.
    pub fn styled_label(&self) -> String {
        let label = format!("{:?}", self).to_uppercase();
        match self {
            Severity::Critical => {
                format!("{}", label.if_supports_color(Stream::Stdout, |t| t.red()))
            }
            Severity::High => format!(
                "{}",
                label.if_supports_color(Stream::Stdout, |t| t.bright_red())
            ),
            Severity::Medium => format!(
                "{}",
                label.if_supports_color(Stream::Stdout, |t| t.yellow())
            ),
            Severity::Low => format!("{}", label.if_supports_color(Stream::Stdout, |t| t.cyan())),
        }
    }
}

/// OWASP Agentic Top 10 2026 reference categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwaspCategory {
    Asi01, // Agent Goal Hijack
    Asi02, // Tool Misuse & Exploitation
    Asi03, // Identity & Privilege Abuse
    Asi04, // Agentic Supply Chain
    Asi05, // Unexpected Code Execution
    Asi06, // Memory & Context Poisoning
    Asi07, // Insecure Inter-Agent Communication
    Asi08, // Cascading Failures
    Asi09, // Human-Agent Trust Exploitation
    Asi10, // Rogue Agents
}

/// Multi-framework threat reference taxonomy
///
/// Each rule can cite one or more frameworks so output can be mapped
/// to whichever standard the downstream AI analysis layer speaks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatRef {
    /// OWASP Agentic Top 10 (2026) — e.g. ASI01
    OwaspAgentic(OwaspCategory),
    /// OWASP Web Top 10 (2021) — e.g. A03:2021
    OwaspWeb(String),
    /// OWASP API Security Top 10 — e.g. API4
    OwaspApi(String),
    /// CWE weakness identifier — e.g. CWE-338
    Cwe(u32),
    /// MITRE ATLAS tactic/technique — e.g. AML.T0051
    MitreAtlas(String),
    /// NIST AI RMF function — e.g. GOVERN.1, MEASURE.2.5
    NistAiRmf(String),
}

impl ThreatRef {
    /// Parse a string citation (from WASM boundary) back into a structured ThreatRef.
    /// Accepts formats: "CWE-338", "ATLAS-AML.T0051", "OWASP-API4", "OWASP-A03", "ASI01", "NIST-GOVERN.1"
    pub fn from_citation(s: &str) -> Option<Self> {
        if let Some(rest) = s.strip_prefix("CWE-") {
            return rest.parse().ok().map(ThreatRef::Cwe);
        }
        if let Some(rest) = s.strip_prefix("ATLAS-") {
            return Some(ThreatRef::MitreAtlas(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("OWASP-API") {
            return Some(ThreatRef::OwaspApi(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("OWASP-") {
            return Some(ThreatRef::OwaspWeb(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("NIST-") {
            return Some(ThreatRef::NistAiRmf(rest.to_string()));
        }
        None
    }
}

/// Detection confidence level — matches `DetectionConfidence` in the WASM ABI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionConfidence {
    /// Cross-file source-to-sink data-flow trace was established
    Confirmed,
    /// Pattern match only; no cross-file source tracing performed
    Heuristic,
}

/// Rule category for organizing compliance checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleCategory {
    Security,    // BZ-SEC-*
    Financial,   // BZ-FIN-*
    Operational, // BZ-OPS-*
    Hygiene,     // BZ-HYG-*
    Sast,        // BZ-SAST-* (Traditional SAST, non-agentic)
}

/// Unique identifier for a compliance rule
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleId(pub String);

impl RuleId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// A detected vulnerability or compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub rule_id: RuleId,
    pub category: RuleCategory,
    pub owasp_ref: OwaspCategory,
    pub severity: Severity,
    pub file_path: PathBuf,
    pub line_number: Option<usize>,
    pub tool_target: String,
    pub message: String,
    pub remediation: String,
    /// Plain-English description for non-technical terminal output
    pub plain_message: String,
    /// Plain-English fix instruction for non-technical terminal output
    pub plain_remediation: String,
    /// Detection confidence — Confirmed (cross-file traced) or Heuristic (pattern-only)
    pub confidence: DetectionConfidence,
    /// Multi-framework threat citations (CWE, MITRE ATLAS, OWASP API, NIST AI RMF)
    pub threat_refs: Vec<ThreatRef>,
}

/// Framework types that Tuora can detect and analyze
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Framework {
    // Python agentic frameworks
    CrewAI,
    LangGraph,
    LangChain,
    AutoGen,
    // TypeScript / JavaScript agentic frameworks
    VercelAI,
    LlamaIndexTS,
    OpenAIAgentsJS,
    Mastra,
    // Standard AI SDKs
    OpenAI,
    Unknown,
}

impl Framework {
    /// Human-readable framework name
    pub fn name(&self) -> &'static str {
        match self {
            Framework::CrewAI => "CrewAI",
            Framework::LangGraph => "LangGraph",
            Framework::LangChain => "LangChain",
            Framework::AutoGen => "AutoGen",
            Framework::VercelAI => "Vercel AI SDK",
            Framework::LlamaIndexTS => "LlamaIndex.TS",
            Framework::OpenAIAgentsJS => "OpenAI Agents SDK (JS)",
            Framework::Mastra => "Mastra",
            Framework::OpenAI => "OpenAI",
            Framework::Unknown => "Unknown",
        }
    }
}

/// Complete scan result for a workspace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub workspace_path: PathBuf,
    pub framework: Framework,
    pub files_scanned: usize,
    pub rules_evaluated: usize,
    pub violations: Vec<Violation>,
    pub scan_duration_ms: u64,
    pub health_score: u32,
}

impl ScanResult {
    /// Calculate health score from violations
    pub fn calculate_score(&mut self) {
        let total_deduction: u32 = self.violations.iter().map(|v| v.severity.weight()).sum();
        self.health_score = 100u32.saturating_sub(total_deduction);
    }
}

pub use tuora_types::{AuthResponse, MetaStats, TelemetryEvent, ViolationSummary};
