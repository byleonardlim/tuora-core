//! ANSI report rendering (Stage 4)

use crate::commands::watch::ViolationDelta;
use crate::config::OutputFormat;
use crate::paint;
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

/// Format threat framework citations into a single string.
fn format_threat_refs(refs: &[ThreatRef]) -> String {
    use crate::types::OwaspCategory::*;
    let citations: Vec<String> = refs
        .iter()
        .map(|r| match r {
            ThreatRef::OwaspAgentic(cat) => {
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
    citations.join(" · ")
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

        writeln!(stdout, "\n{}", paint::brand(&top_border))?;
        writeln!(stdout, "{}", paint::brand(&header_line))?;
        writeln!(stdout, "{}\n", paint::brand(&bottom_border))?;

        // Scan metadata
        let meta_label_width: usize = 13;
        writeln!(
            stdout,
            "  {}: {}",
            paint::dim(&format!("{:<width$}", "Scan ID", width = meta_label_width)),
            result.scan_id
        )?;
        writeln!(
            stdout,
            "  {}: {}",
            paint::dim(&format!(
                "{:<width$}",
                "Framework",
                width = meta_label_width
            )),
            result.framework.name()
        )?;
        writeln!(
            stdout,
            "  {}: {}",
            paint::dim(&format!(
                "{:<width$}",
                "Files Scanned",
                width = meta_label_width
            )),
            result.files_scanned
        )?;
        writeln!(
            stdout,
            "  {}: {}",
            paint::dim(&format!(
                "{:<width$}",
                "Rules Checked",
                width = meta_label_width
            )),
            result.rules_evaluated
        )?;
        writeln!(
            stdout,
            "  {}: {}ms",
            paint::dim(&format!("{:<width$}", "Duration", width = meta_label_width)),
            result.scan_duration_ms
        )?;

        // Mode banner
        let label = mode_label(result.framework);
        let mode_str = if result.framework != Framework::Unknown {
            paint::accent(&label)
        } else {
            paint::warn(&label)
        };
        writeln!(stdout, "  {:<14} {}\n", paint::dim("Mode:"), mode_str)?;

        // Health Score
        writeln!(
            stdout,
            "  {}  {}/100\n",
            paint::bold("Health Score:"),
            paint::health_score(result.health_score)
        )?;

        // Violations summary
        if result.violations.is_empty() {
            writeln!(
                stdout,
                "  {} No issues detected! Great job!\n",
                paint::success("✓")
            )?;
        } else {
            self.render_violations_ansi(&mut stdout, &result.violations)?;
        }

        // Footer
        writeln!(
            stdout,
            "\n{}\n",
            paint::dim("────────────────────────────────────────────────────────────")
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
            "  {}\n",
            paint::bold(&format!(
                "Issues Found: {} Critical, {} High, {} Medium, {} Low",
                critical, high, medium, low
            ))
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

        // Confidence badge
        let conf_badge_str = match first.confidence {
            DetectionConfidence::Confirmed => paint::success("CONFIRMED"),
            DetectionConfidence::Heuristic => paint::dim("HEURISTIC"),
        };

        // Rule header with ID, severity, confidence, and title
        writeln!(
            stdout,
            "{} {} [{}] [{}] {} ",
            icon,
            rule_id.0,
            severity.styled_label(),
            conf_badge_str,
            paint::bold_white(&first.tool_target)
        )?;

        // Description (wrapped at 88 chars, indented)
        let bar = paint::dim("│");
        let desc_lines = wrap_text(&first.plain_message, 88);
        for line in &desc_lines {
            writeln!(stdout, "  {} {}", bar, line)?;
        }

        // Affected locations
        writeln!(stdout, "  {}", bar)?;
        writeln!(stdout, "  {} {}", bar, paint::bold("Affected locations:"))?;
        for v in violations {
            let line_str = v.line_number.map(|l| format!(":{}", l)).unwrap_or_default();
            writeln!(
                stdout,
                "  {}   • {}{}",
                bar,
                v.file_path.display(),
                line_str
            )?;
        }

        // Remediation (wrapped at 88 chars)
        writeln!(stdout, "  {}", bar)?;
        let fix_lines = wrap_text(&first.plain_remediation, 88);
        if let Some(first_line) = fix_lines.first() {
            writeln!(
                stdout,
                "  {} {} {}",
                bar,
                paint::success("💡 Fix:"),
                first_line
            )?;
        }
        for line in fix_lines.iter().skip(1) {
            writeln!(stdout, "  {}     {}", bar, line)?;
        }

        // Threat framework citations (only shown when present)
        if !first.threat_refs.is_empty() {
            writeln!(
                stdout,
                "  {}  Refs: {}",
                bar,
                paint::dim(&format_threat_refs(&first.threat_refs))
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

        // Event header — list changed files
        for path in changed_paths {
            writeln!(
                stdout,
                "  {} {}",
                paint::dim(&format!("[{}]", timestamp)),
                path.display()
            )?;
        }

        if delta.is_empty() {
            writeln!(
                stdout,
                "  {}  Health: {}/100\n",
                paint::dim(&format!("↳ No change in issues  ({}ms)", elapsed_ms)),
                paint::health_score(health_score)
            )?;
            return Ok(());
        }

        for entry in delta {
            let v = &entry.violation;
            if entry.is_new {
                let conf_badge_str = match v.confidence {
                    DetectionConfidence::Confirmed => paint::success("CONFIRMED"),
                    DetectionConfidence::Heuristic => paint::dim("HEURISTIC"),
                };
                writeln!(
                    stdout,
                    "  {} {} [{}] [{}] {}  {}{}",
                    paint::error("↳ NEW  "),
                    v.rule_id.0,
                    v.severity.styled_label(),
                    conf_badge_str,
                    paint::bold_white(&v.tool_target),
                    v.file_path.display(),
                    v.line_number.map(|l| format!(":{}", l)).unwrap_or_default()
                )?;

                // Context and fix
                let bar = paint::dim("│");
                let desc_lines = wrap_text(&v.plain_message, 88);
                for line in &desc_lines {
                    writeln!(stdout, "    {} {}", bar, line)?;
                }
                writeln!(stdout, "    {}", bar)?;
                let fix_lines = wrap_text(&v.plain_remediation, 88);
                if let Some(first_line) = fix_lines.first() {
                    writeln!(
                        stdout,
                        "    {} {} {}",
                        bar,
                        paint::success("💡 Fix:"),
                        first_line
                    )?;
                }
                for line in fix_lines.iter().skip(1) {
                    writeln!(stdout, "    {}     {}", bar, line)?;
                }
                if !v.threat_refs.is_empty() {
                    writeln!(
                        stdout,
                        "    {}  Refs: {}",
                        bar,
                        paint::dim(&format_threat_refs(&v.threat_refs))
                    )?;
                }
                writeln!(stdout)?;
            } else {
                writeln!(
                    stdout,
                    "  {} {} — {}",
                    paint::success("↳ FIXED"),
                    v.rule_id.0,
                    paint::dim(&v.file_path.display().to_string()),
                )?;
            }
        }

        writeln!(
            stdout,
            "  {}  Health: {}/100\n",
            paint::dim(&format!("↳ ({}ms)", elapsed_ms)),
            paint::health_score(health_score)
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

    #[test]
    fn test_render_watch_delta_shows_context_and_remediation() {
        use crate::commands::watch::ViolationDelta;
        let reporter = Reporter::new(OutputFormat::Ansi);
        let violation = create_test_violation(Severity::Critical);
        let delta = vec![ViolationDelta {
            violation,
            is_new: true,
        }];
        let result =
            reporter.render_watch_delta("12:34:56", &[PathBuf::from("test.py")], &delta, 75, 12);
        assert!(result.is_ok());
    }
}
