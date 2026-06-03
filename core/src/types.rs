//! Core type definitions for Tuora static analysis engine

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

    /// ANSI color code for terminal output
    pub fn ansi_color(&self) -> &'static str {
        match self {
            Severity::Critical => "\x1b[31m", // Red
            Severity::High => "\x1b[91m",    // Bright Red
            Severity::Medium => "\x1b[33m",  // Yellow
            Severity::Low => "\x1b[36m",     // Cyan
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

/// Rule category for organizing compliance checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleCategory {
    Security,      // BZ-SEC-*
    Financial,     // BZ-FIN-*
    Operational,   // BZ-OPS-*
    Hygiene,       // BZ-HYG-*
    Sast,          // BZ-SAST-* (Traditional SAST, non-agentic)
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
}

/// Framework types that Tuora can detect and analyze
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        let total_deduction: u32 = self.violations.iter()
            .map(|v| v.severity.weight())
            .sum();
        self.health_score = 100u32.saturating_sub(total_deduction);
    }
}

pub use tuora_types::{AuthResponse, TelemetryEvent, MetaStats, ViolationSummary};

