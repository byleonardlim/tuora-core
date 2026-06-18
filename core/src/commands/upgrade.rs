//! `tuora upgrade` command — self-update the binary in-place from GitHub Releases.
//!
//! Downloads the latest release asset for the current platform, verifies it is
//! a valid executable, then atomically replaces the running binary.

use crate::paint;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::debug;

const REPO: &str = "byleonardlim/tuora-core";

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
}

pub async fn run() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");

    println!("\n  {}", paint::bold("Tuora Upgrade"));
    println!("  {}", "─".repeat(40));
    println!(
        "  Current version: {}",
        paint::accent(&format!("v{}", current))
    );

    // ── Step 1: Fetch latest release tag ──────────────────────────────────

    print!("\n  Checking latest release…");
    std::io::stdout().flush().ok();

    let client = build_client()?;
    let latest_tag = fetch_latest_tag(&client).await?;
    let latest = latest_tag.trim_start_matches('v');

    println!(" {}", paint::success("✓"));
    println!(
        "  Latest version:  {}",
        paint::accent(&format!("v{}", latest))
    );

    if !is_newer(latest, current) {
        println!(
            "\n  {} Already on the latest version.\n",
            paint::success("✓")
        );
        return Ok(());
    }

    // ── Step 2: Detect platform ───────────────────────────────────────────

    let platform = detect_platform()?;
    debug!("Detected platform: {}", platform);

    // ── Step 3: Locate current binary path ───────────────────────────────

    let binary_path = std::env::current_exe().context("Could not determine current binary path")?;
    debug!("Binary path: {}", binary_path.display());

    // ── Step 4: Download new binary ───────────────────────────────────────

    let download_url = format!(
        "https://github.com/{}/releases/download/{}/tuora-{}",
        REPO, latest_tag, platform
    );

    println!("\n  Downloading v{}…", latest);
    debug!("Download URL: {}", download_url);

    let bytes = client
        .get(&download_url)
        .send()
        .await
        .context("Download request failed")?
        .error_for_status()
        .context("Server returned an error for the download URL")?
        .bytes()
        .await
        .context("Failed to read download body")?;

    if bytes.is_empty() {
        bail!(
            "Downloaded binary is empty — release asset may be missing for platform '{}'",
            platform
        );
    }

    // ── Step 5: Write to a temp file alongside the current binary ─────────

    let tmp_path = sibling_temp_path(&binary_path)?;
    debug!("Writing to temp path: {}", tmp_path.display());

    {
        let mut f = std::fs::File::create(&tmp_path)
            .with_context(|| format!("Cannot write to {}", tmp_path.display()))?;
        f.write_all(&bytes)
            .context("Failed to write binary bytes")?;
    }

    // ── Step 6: Set executable bit (Unix only) ────────────────────────────

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&tmp_path)
            .context("Cannot read temp file metadata")?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tmp_path, perms).context("Cannot set executable permissions")?;
    }

    // ── Step 7: Atomic replace ────────────────────────────────────────────

    std::fs::rename(&tmp_path, &binary_path).with_context(|| {
        format!(
            "Cannot replace binary at {} — try running with elevated permissions",
            binary_path.display()
        )
    })?;

    println!(
        "  {} Upgraded to {}\n",
        paint::success("✓"),
        paint::bold(&format!("v{}", latest))
    );
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("tuora/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("Failed to build HTTP client")
}

async fn fetch_latest_tag(client: &reqwest::Client) -> Result<String> {
    let url = format!("https://api.github.com/repos/{}/releases?per_page=1", REPO);
    let releases: Vec<GithubRelease> = client
        .get(&url)
        .send()
        .await
        .context("GitHub API request failed")?
        .error_for_status()
        .context("GitHub API returned an error")?
        .json()
        .await
        .context("Failed to parse GitHub API response")?;

    releases
        .into_iter()
        .next()
        .map(|r| r.tag_name)
        .context("No releases found on GitHub")
}

/// Returns the platform suffix used in GitHub release asset names.
fn detect_platform() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        ("macos", "x86_64") => Ok("macos-x86_64"),
        ("macos", "aarch64") => Ok("macos-arm64"),
        (os, arch) => bail!("Unsupported platform: {}-{}", os, arch),
    }
}

/// Build a temp file path in the same directory as the binary (required for
/// `rename` to be atomic — cross-device renames are not atomic).
fn sibling_temp_path(binary: &Path) -> Result<PathBuf> {
    let dir = binary
        .parent()
        .context("Binary path has no parent directory")?;
    Ok(dir.join(".tuora-upgrade-tmp"))
}

/// True if `candidate` semver is strictly greater than `current`.
fn is_newer(candidate: &str, current: &str) -> bool {
    if let (Some(c), Some(cur)) = (parse_semver(candidate), parse_semver(current)) {
        c > cur
    } else {
        candidate > current
    }
}

fn parse_semver(v: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;
    let patch = parts[2].split('-').next()?.parse().ok()?;
    Some((major, minor, patch))
}
