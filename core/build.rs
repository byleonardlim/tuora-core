//! Build script for tuora CLI.
//!
//! On debug builds, automatically compiles the `rule-engine` crate to
//! wasm32-unknown-unknown and places the stripped WASM at `dev/def-{version}.wasm`
//! so the CLI can load it without a network fetch.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let profile = std::env::var("PROFILE").unwrap_or_default();
    if profile != "debug" {
        return;
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.join("..");
    let rule_engine_dir = repo_root.join("cloud").join("rules").join("rule-engine");

    let rule_engine_toml = rule_engine_dir.join("Cargo.toml");
    if !rule_engine_toml.exists() {
        println!("cargo::warning=rule-engine crate not found at {}, skipping WASM build", rule_engine_dir.display());
        println!("cargo::rustc-env=RULE_ENGINE_VERSION=0.0.0");
        return;
    }

    // Re-run if rule-engine source changes
    println!("cargo::rerun-if-changed=../cloud/rules/rule-engine/src");
    println!("cargo::rerun-if-changed=../cloud/rules/rule-engine/Cargo.toml");

    let version = read_cargo_version(&rule_engine_toml);
    let bundle_name = format!("def-{}.wasm", version);

    // Expose version to the CLI crate so remote.rs can find the file
    println!("cargo::rustc-env=RULE_ENGINE_VERSION={}", version);

    let dest = manifest_dir.join("dev").join(&bundle_name);

    // Skip if already built (cargo will re-run on source changes via rerun-if-changed)
    if dest.exists() {
        return;
    }

    eprintln!("build.rs: Building rule-engine WASM...");

    let workspace_manifest = repo_root.join("Cargo.toml");
    let status = Command::new("cargo")
        .args([
            "build",
            "--manifest-path",
            &workspace_manifest.to_string_lossy(),
            "--target",
            "wasm32-unknown-unknown",
            "--release",
            "-p",
            "rule-engine",
        ])
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            println!("cargo::warning=rule-engine WASM build failed with {s}");
            return;
        }
        Err(e) => {
            println!("cargo::warning=Failed to run cargo for WASM build: {e}");
            return;
        }
    }

    let source = repo_root
        .join("target")
        .join("wasm32-unknown-unknown")
        .join("release")
        .join("rule_engine.wasm");

    let raw = match std::fs::read(&source) {
        Ok(b) => b,
        Err(e) => {
            println!("cargo::warning=Failed to read built WASM from {}: {e}", source.display());
            return;
        }
    };

    let stripped = strip_wasm_custom_sections(&raw);

    // Ensure dev/ directory exists
    let dev_dir = manifest_dir.join("dev");
    let _ = std::fs::create_dir_all(&dev_dir);

    if let Err(e) = std::fs::write(&dest, &stripped) {
        println!("cargo::warning=Failed to write WASM to {}: {e}", dest.display());
        return;
    }

    eprintln!("build.rs: rule-engine WASM → {}", dest.display());
}

/// Parse the `version` field from a Cargo.toml without pulling in toml crate.
fn read_cargo_version(path: &std::path::Path) -> String {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("version") {
            if let Some(val) = trimmed.split('=').nth(1) {
                return val.trim().trim_matches('"').to_string();
            }
        }
    }
    "0.0.0".to_string()
}

/// Strip all WASM custom sections (id=0) from a binary.
///
/// Newer Rust/LLVM toolchains emit `target_features`, `producers`, and `name`
/// custom sections that some wasmtime versions reject during translation.
fn strip_wasm_custom_sections(data: &[u8]) -> Vec<u8> {
    if data.len() < 8 {
        return data.to_vec();
    }
    let mut out = data[..8].to_vec(); // keep WASM magic + version
    let mut i = 8usize;
    while i < data.len() {
        let sec_id = data[i];
        let (size, n) = read_leb128(data, i + 1);
        let sec_start = i + 1 + n;
        let sec_end = sec_start + size;
        if sec_id != 0 {
            out.push(sec_id);
            out.extend_from_slice(&encode_leb128(size));
            out.extend_from_slice(&data[sec_start..sec_end]);
        }
        i = sec_end;
    }
    out
}

fn read_leb128(data: &[u8], offset: usize) -> (usize, usize) {
    let (mut result, mut shift, mut n) = (0usize, 0usize, 0usize);
    loop {
        let b = data[offset + n] as usize;
        result |= (b & 0x7f) << shift;
        n += 1;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
    }
    (result, n)
}

fn encode_leb128(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}
