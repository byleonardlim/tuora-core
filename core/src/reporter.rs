//! ANSI report rendering (Stage 4)

use crate::commands::watch::ViolationDelta;
use crate::config::OutputFormat;
use crate::types::{
    DetectionConfidence, Framework, RuleId, ScanResult, Severity, ThreatRef, Violation,
};
use anyhow::Result;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;

const RULE_COUNT_FULL: u32 = 28;
const RULE_COUNT_SAST_ONLY: u32 = 22;

/// Report renderer for scan results
pub struct Reporter {
    format: OutputFormat,
}

/// Build the mode label string used in both ANSI and plain-text outputs.
fn mode_label(framework: Framework) -> String {
    if framework != Framework::Unknown {
        format!(
            "Agentic + SAST ({}) — {} rules active",
            framework.name(),
            RULE_COUNT_FULL
        )
    } else {
        format!(
            "Traditional SAST — {} rules active (AI-specific agentic checks N/A)",
            RULE_COUNT_SAST_ONLY
        )
    }
}

/// Wrap text to specified width, breaking at word boundaries
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        // Check if adding this word would exceed width
        let new_len = if current_line.is_empty() {
            word.len()
        } else {
            current_line.len() + 1 + word.len()
        };

        if new_len > width && !current_line.is_empty() {
            lines.push(current_line);
            current_line = word.to_string();
        } else {
            if !current_line.is_empty() {
                current_line.push(' ');
            }
            current_line.push_str(word);
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

/// ANSI color for a health score value.
fn score_color(score: u32) -> &'static str {
    if score >= 80 {
        "\x1b[32m"
    } else if score >= 50 {
        "\x1b[33m"
    } else {
        "\x1b[31m"
    }
}

impl Reporter {
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }

    /// Render scan results to stdout
    pub fn render(&self, result: &ScanResult) -> Result<()> {
        match self.format {
            OutputFormat::Ansi => self.render_ansi(result),
            OutputFormat::Json => self.render_json(result),
            OutputFormat::Plain => self.render_plain(result),
        }
    }

    /// ANSI-colored terminal output
    fn render_ansi(&self, result: &ScanResult) -> Result<()> {
        let mut stdout = io::stdout();

        // Header
        let header_title = if result.framework != crate::types::Framework::Unknown {
            format!("Tuora AppSec Analysis Report ({})", result.framework.name())
        } else {
            "Tuora AppSec Analysis Report".to_string()
        };

        let border_style = "\x1b[1m\x1b[36m";
        let reset = "\x1b[0m";

        let min_inner_width: usize = 62;
        let inner_width = std::cmp::max(min_inner_width, header_title.len() + 2);
        let top_border = format!("╔{}╗", "═".repeat(inner_width));
        let bottom_border = format!("╚{}╝", "═".repeat(inner_width));

        let total_pad = inner_width.saturating_sub(header_title.len());
        let left_pad = total_pad / 2;
        let right_pad = total_pad - left_pad;
        let header_line = format!(
            "║{}{}{}║",
            " ".repeat(left_pad),
            header_title,
            " ".repeat(right_pad)
        );

        writeln!(stdout, "\n{}{top_border}{}", border_style, reset)?;
        writeln!(stdout, "{}{}{}", border_style, header_line, reset)?;
        writeln!(stdout, "{}{bottom_border}{}\n", border_style, reset)?;

        // Scan metadata
        let dim = "\x1b[90m";
        let meta_label_width: usize = 13;
        writeln!(
            stdout,
            "  {}{:<width$}:{} {}",
            dim,
            "Scan ID",
            reset,
            result.scan_id,
            width = meta_label_width
        )?;
        writeln!(
            stdout,
            "  {}{:<width$}:{} {}",
            dim,
            "Framework",
            reset,
            result.framework.name(),
            width = meta_label_width
        )?;
        writeln!(
            stdout,
            "  {}{:<width$}:{} {}",
            dim,
            "Files Scanned",
            reset,
            result.files_scanned,
            width = meta_label_width
        )?;
        writeln!(
            stdout,
            "  {}{:<width$}:{} {}",
            dim,
            "Rules Checked",
            reset,
            result.rules_evaluated,
            width = meta_label_width
        )?;
        writeln!(
            stdout,
            "  {}{:<width$}:{} {}ms",
            dim,
            "Duration",
            reset,
            result.scan_duration_ms,
            width = meta_label_width
        )?;

        // Mode banner
        let label = mode_label(result.framework);
        let mode_color = if result.framework != Framework::Unknown {
            "\x1b[36m"
        } else {
            "\x1b[33m"
        };
        writeln!(
            stdout,
            "  \x1b[90mMode:\x1b[0m         {}{}\x1b[0m\n",
            mode_color, label
        )?;

        // Health Score
        writeln!(
            stdout,
            "  \x1b[1mHealth Score:  {}{}/100\x1b[0m\n",
            score_color(result.health_score),
            result.health_score
        )?;

        // Violations summary
        if result.violations.is_empty() {
            writeln!(
                stdout,
                "  \x1b[1m\x1b[32m✓\x1b[0m No issues detected! Great job!\n"
            )?;
        } else {
            self.render_violations_ansi(&mut stdout, &result.violations)?;
        }

        // Footer
        writeln!(
            stdout,
            "\n\x1b[90m────────────────────────────────────────────────────────────\x1b[0m\n"
        )?;

        Ok(())
    }

    fn render_violations_ansi(
        &self,
        stdout: &mut io::Stdout,
        violations: &[Violation],
    ) -> Result<()> {
        // Count by severity for summary
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;

        for v in violations {
            match v.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
            }
        }

        // Summary header
        writeln!(
            stdout,
            "  \x1b[1mIssues Found: {} Critical, {} High, {} Medium, {} Low\x1b[0m\n",
            critical, high, medium, low
        )?;

        // Group violations by rule_id
        let mut grouped: HashMap<&RuleId, Vec<&Violation>> = HashMap::new();
        for v in violations {
            grouped.entry(&v.rule_id).or_default().push(v);
        }

        // Sort groups by severity (critical/high first)
        let mut sorted_groups: Vec<_> = grouped.iter().collect();
        sorted_groups.sort_by(|(_, a), (_, b)| {
            let a_sev = a.first().map(|v| v.severity).unwrap_or(Severity::Low);
            let b_sev = b.first().map(|v| v.severity).unwrap_or(Severity::Low);
            b_sev.weight().cmp(&a_sev.weight())
        });

        // Render each group
        for (rule_id, group) in sorted_groups {
            self.render_violation_group(stdout, rule_id, group)?;
        }

        Ok(())
    }

    /// Render a group of violations for the same rule with word wrapping at 88 chars
    fn render_violation_group(
        &self,
        stdout: &mut io::Stdout,
        rule_id: &RuleId,
        violations: &[&Violation],
    ) -> Result<()> {
        let first = violations.first().unwrap();
        let severity = first.severity;

        let icon = match severity {
            Severity::Critical => "🛑",
            Severity::High => "🛑",
            Severity::Medium => "⚠️",
            Severity::Low => "⚠️",
        };

        let severity_str = format!("{:?}", severity).to_uppercase();

        // Confidence badge
        let (conf_badge, conf_color) = match first.confidence {
            DetectionConfidence::Confirmed => ("CONFIRMED", "\x1b[32m"),
            DetectionConfidence::Heuristic => ("HEURISTIC", "\x1b[90m"),
        };

        // Rule header with ID, severity, confidence, and title
        writeln!(
            stdout,
            "{} {} {} [{}] {}[{}]\x1b[0m \x1b[1m\x1b[97m {} \x1b[0m",
            icon,
            rule_id.0,
            severity.ansi_color(),
            severity_str,
            conf_color,
            conf_badge,
            first.tool_target
        )?;

        // Description (wrapped at 88 chars, indented)
        let desc_lines = wrap_text(&first.plain_message, 88);
        for line in &desc_lines {
            writeln!(stdout, "  \x1b[90m│\x1b[0m {}", line)?;
        }

        // Affected locations
        writeln!(stdout, "  \x1b[90m│\x1b[0m")?;
        writeln!(
            stdout,
            "  \x1b[90m│\x1b[0m \x1b[1mAffected locations:\x1b[0m"
        )?;
        for v in violations {
            let line_str = v.line_number.map(|l| format!(":{}", l)).unwrap_or_default();
            writeln!(
                stdout,
                "  \x1b[90m│\x1b[0m   • {}{}",
                v.file_path.display(),
                line_str
            )?;
        }

        // Remediation (wrapped at 88 chars)
        writeln!(stdout, "  \x1b[90m│\x1b[0m")?;
        let fix_lines = wrap_text(&first.plain_remediation, 88);
        if let Some(first_line) = fix_lines.first() {
            writeln!(
                stdout,
                "  \x1b[90m│\x1b[0m \x1b[32m💡 Fix:\x1b[0m {}",
                first_line
            )?;
        }
        for line in fix_lines.iter().skip(1) {
            writeln!(stdout, "  \x1b[90m│\x1b[0m     {}", line)?;
        }

        // Threat framework citations (only shown when present)
        if !first.threat_refs.is_empty() {
            let citations: Vec<String> = first
                .threat_refs
                .iter()
                .map(|r| match r {
                    ThreatRef::OwaspAgentic(cat) => {
                        use crate::types::OwaspCategory::*;
                        let id = match cat {
                            Asi01 => "01",
                            Asi02 => "02",
                            Asi03 => "03",
                            Asi04 => "04",
                            Asi05 => "05",
                            Asi06 => "06",
                            Asi07 => "07",
                            Asi08 => "08",
                            Asi09 => "09",
                            Asi10 => "10",
                        };
                        format!("OWASP ASI{id}")
                    }
                    ThreatRef::OwaspWeb(s) => format!("OWASP {s}"),
                    ThreatRef::OwaspApi(s) => format!("OWASP API{s}"),
                    ThreatRef::Cwe(n) => format!("CWE-{n}"),
                    ThreatRef::MitreAtlas(s) => format!("ATLAS {s}"),
                    ThreatRef::NistAiRmf(s) => format!("NIST AI RMF {s}"),
                })
                .collect();
            writeln!(
                stdout,
                "  \x1b[90m│  Refs: {}\x1b[0m",
                citations.join(" · ")
            )?;
        }

        writeln!(stdout)?;

        Ok(())
    }

    /// JSON output for CI/CD integration
    fn render_json(&self, result: &ScanResult) -> Result<()> {
        let json = serde_json::to_string_pretty(result)?;
        println!("{}", json);
        Ok(())
    }

    /// Render an incremental watch delta event to stdout.
    pub fn render_watch_delta(
        &self,
        timestamp: &str,
        changed_paths: &[PathBuf],
        delta: &[ViolationDelta],
        health_score: u32,
        elapsed_ms: u64,
    ) -> Result<()> {
        let mut stdout = io::stdout();
        let dim = "\x1b[90m";
        let reset = "\x1b[0m";
        let bold = "\x1b[1m";

        // Event header — list changed files
        for path in changed_paths {
            writeln!(
                stdout,
                "  {}[{}]{} {}",
                dim,
                timestamp,
                reset,
                path.display()
            )?;
        }

        if delta.is_empty() {
            writeln!(
                stdout,
                "  {}↳ No change in issues  ({}ms)  Health: {}{}{}/100{}\n",
                dim,
                elapsed_ms,
                bold,
                score_color(health_score),
                health_score,
                reset
            )?;
            return Ok(());
        }

        for entry in delta {
            let v = &entry.violation;
            if entry.is_new {
                writeln!(
                    stdout,
                    "  \x1b[31m↳ NEW   {} {} [{}]{} {}{}  {}:{}{}",
                    v.rule_id.0,
                    v.severity.ansi_color(),
                    format!("{:?}", v.severity).to_uppercase(),
                    reset,
                    bold,
                    v.tool_target,
                    reset,
                    v.file_path.display(),
                    v.line_number.map(|l| format!(":{}", l)).unwrap_or_default()
                )?;
            } else {
                writeln!(
                    stdout,
                    "  \x1b[32m↳ FIXED {} — {}{}{}",
                    v.rule_id.0,
                    dim,
                    v.file_path.display(),
                    reset,
                )?;
            }
        }

        let score_col = score_color(health_score);
        writeln!(
            stdout,
            "  {}↳ Health: {}{}{}/100{}  {}({}ms){}\n",
            dim, bold, score_col, health_score, reset, dim, elapsed_ms, reset
        )?;

        Ok(())
    }

    /// Plain text output
    fn render_plain(&self, result: &ScanResult) -> Result<()> {
        println!("Tuora Security Analysis Report");
        println!("==================================");
        println!("Scan ID: {}", result.scan_id);
        println!("Framework: {}", result.framework.name());
        println!("Files Scanned: {}", result.files_scanned);
        println!("Rules Checked: {}", result.rules_evaluated);
        println!("Duration: {}ms", result.scan_duration_ms);
        println!("Mode: {}", mode_label(result.framework));
        println!("Health Score: {}/100", result.health_score);
        println!();

        if result.violations.is_empty() {
            println!("No issues detected!");
        } else {
            println!("Issues Found: {}", result.violations.len());
            println!();

            for v in &result.violations {
                let line_str = v.line_number.map(|l| format!(":{}", l)).unwrap_or_default();
                println!(
                    "[{:?}] {} - {}:{}",
                    v.severity,
                    v.rule_id.0,
                    v.file_path.display(),
                    line_str
                );
                println!("  Target: {}", v.tool_target);
                println!("  Issue: {}", v.plain_message);
                println!("  Fix: {}", v.plain_remediation);
                println!();
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Framework, OwaspCategory, RuleCategory, RuleId};
    use std::path::PathBuf;

    fn create_test_violation(severity: Severity) -> Violation {
        use crate::types::DetectionConfidence;
        Violation {
            rule_id: RuleId::new("TEST-01"),
            category: RuleCategory::Security,
            owasp_ref: OwaspCategory::Asi02,
            severity,
            file_path: PathBuf::from("test.py"),
            line_number: Some(42),
            tool_target: "test_tool".to_string(),
            message: "Test message".to_string(),
            remediation: "Test fix".to_string(),
            plain_message: "Plain test message".to_string(),
            plain_remediation: "Plain test fix".to_string(),
            confidence: DetectionConfidence::Heuristic,
            threat_refs: vec![],
        }
    }

    fn create_test_result() -> ScanResult {
        ScanResult {
            scan_id: "test-scan-123".to_string(),
            workspace_path: PathBuf::from("/test"),
            framework: Framework::CrewAI,
            files_scanned: 10,
            rules_evaluated: 8,
            violations: vec![
                create_test_violation(Severity::Critical),
                create_test_violation(Severity::High),
            ],
            scan_duration_ms: 150,
            health_score: 60,
        }
    }

    #[test]
    fn test_reporter_creation() {
        let reporter = Reporter::new(OutputFormat::Ansi);
        let result = create_test_result();
        // Just verify it doesn't panic
        let _ = reporter.render(&result);
    }
}
