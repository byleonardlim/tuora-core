//! Centralized terminal styling helpers.
//!
//! All ANSI color/style usage in the codebase goes through this module.
//! Respects `NO_COLOR`, `TERM=dumb`, and non-TTY stdout/stderr automatically
//! via the `owo-colors` `supports-colors` feature.

use owo_colors::OwoColorize;
use owo_colors::Stream;

// ── Style primitives ──────────────────────────────────────────────────────────

/// Cyan + bold — primary brand accent (banner, headings, command names).
pub fn brand(s: &str) -> String {
    let styled = s.if_supports_color(Stream::Stdout, |t| t.cyan());
    format!("{}", styled.if_supports_color(Stream::Stdout, |t| t.bold()))
}

/// Cyan — secondary accent (version numbers, paths, links).
pub fn accent(s: &str) -> String {
    format!("{}", s.if_supports_color(Stream::Stdout, |t| t.cyan()))
}

/// Dim white — metadata labels, secondary info, rule borders.
pub fn dim(s: &str) -> String {
    format!("{}", s.if_supports_color(Stream::Stdout, |t| t.dimmed()))
}

/// Bold — section headings, emphasis.
pub fn bold(s: &str) -> String {
    format!("{}", s.if_supports_color(Stream::Stdout, |t| t.bold()))
}

/// Bold bright white — tool target names in violation headers.
pub fn bold_white(s: &str) -> String {
    let styled = s.if_supports_color(Stream::Stdout, |t| t.bright_white());
    format!("{}", styled.if_supports_color(Stream::Stdout, |t| t.bold()))
}

/// Green — success checkmarks, resolved violations.
pub fn success(s: &str) -> String {
    format!("{}", s.if_supports_color(Stream::Stdout, |t| t.green()))
}

/// Yellow — warnings, MEDIUM severity.
pub fn warn(s: &str) -> String {
    format!("{}", s.if_supports_color(Stream::Stdout, |t| t.yellow()))
}

/// Red — errors, HIGH severity.
pub fn error(s: &str) -> String {
    format!("{}", s.if_supports_color(Stream::Stdout, |t| t.red()))
}

/// Bright red — CRITICAL severity.
#[allow(dead_code)]
pub fn critical(s: &str) -> String {
    format!(
        "{}",
        s.if_supports_color(Stream::Stdout, |t| t.bright_red())
    )
}

/// Cyan — LOW severity.
#[allow(dead_code)]
pub fn low(s: &str) -> String {
    format!("{}", s.if_supports_color(Stream::Stdout, |t| t.cyan()))
}

/// Dim on stderr — used by update checker and non-fatal warnings.
pub fn dim_err(s: &str) -> String {
    format!("{}", s.if_supports_color(Stream::Stderr, |t| t.dimmed()))
}

/// Bold on stderr.
pub fn bold_err(s: &str) -> String {
    format!("{}", s.if_supports_color(Stream::Stderr, |t| t.bold()))
}

/// Yellow on stderr — update notice.
pub fn warn_err(s: &str) -> String {
    format!("{}", s.if_supports_color(Stream::Stderr, |t| t.yellow()))
}

/// Cyan on stderr.
pub fn accent_err(s: &str) -> String {
    format!("{}", s.if_supports_color(Stream::Stderr, |t| t.cyan()))
}

// ── Health score coloring ─────────────────────────────────────────────────────

/// Returns a colored string for a health score value: green ≥80, yellow ≥50, red <50.
pub fn health_score(score: u32) -> String {
    let s = score.to_string();
    if score >= 80 {
        format!("{}", s.if_supports_color(Stream::Stdout, |t| t.green()))
    } else if score >= 50 {
        format!("{}", s.if_supports_color(Stream::Stdout, |t| t.yellow()))
    } else {
        format!("{}", s.if_supports_color(Stream::Stdout, |t| t.red()))
    }
}
