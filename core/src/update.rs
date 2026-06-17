//! Non-blocking update checker — queries GitHub Releases for a newer version.
//!
//! Spawned as a background task immediately after startup. The result is awaited
//! after the main command finishes, so it never delays execution.

use serde::Deserialize;
use tracing::debug;

const GITHUB_API_URL: &str =
    "https://api.github.com/repos/byleonardlim/tuora-core/releases?per_page=1";

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
}

/// Spawn a background task that checks for a newer release on GitHub.
/// Returns a `JoinHandle` — await it after your command completes to print
/// any update notice without blocking startup.
pub fn spawn_check() -> tokio::task::JoinHandle<Option<String>> {
    tokio::spawn(async {
        match fetch_latest_tag().await {
            Ok(latest) => {
                let current = env!("CARGO_PKG_VERSION");
                if is_newer(&latest, current) {
                    Some(latest)
                } else {
                    None
                }
            }
            Err(e) => {
                debug!("Update check failed: {}", e);
                None
            }
        }
    })
}

/// Print the update notice if `handle` resolved to a newer version tag.
/// Call this after your command has finished so it appears as a trailing notice.
pub async fn print_if_outdated(handle: tokio::task::JoinHandle<Option<String>>) {
    match tokio::time::timeout(std::time::Duration::from_secs(5), handle).await {
        Ok(Ok(Some(latest))) => {
            let current = env!("CARGO_PKG_VERSION");
            eprintln!(
                "\n  \x1b[33m⬆  Update available:\x1b[0m \x1b[2mv{}\x1b[0m → \x1b[1mv{}\x1b[0m",
                current, latest
            );
            eprintln!("  Run \x1b[36mtuora upgrade\x1b[0m to install the latest version.\n");
        }
        Ok(Ok(None)) => {}
        Ok(Err(e)) => debug!("Update check task panicked: {}", e),
        Err(_) => debug!("Update check timed out"),
    }
}

async fn fetch_latest_tag() -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("tuora/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(4))
        .build()?;

    let releases: Vec<GithubRelease> = client
        .get(GITHUB_API_URL)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let tag = releases
        .into_iter()
        .next()
        .map(|r| r.tag_name.trim_start_matches('v').to_string())
        .ok_or_else(|| anyhow::anyhow!("No releases found"))?;
    Ok(tag)
}

/// Compare two semver strings, returning true if `candidate` is strictly newer than `current`.
/// Falls back to a lexicographic comparison if parsing fails.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer_true() {
        assert!(is_newer("0.4.0", "0.3.5"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(is_newer("0.3.6", "0.3.5"));
    }

    #[test]
    fn test_is_newer_false() {
        assert!(!is_newer("0.3.5", "0.3.5"));
        assert!(!is_newer("0.3.4", "0.3.5"));
        assert!(!is_newer("0.2.9", "0.3.0"));
    }

    #[test]
    fn test_is_newer_prerelease() {
        assert!(is_newer("0.4.0-beta.1", "0.3.5"));
        assert!(!is_newer("0.3.5-beta.1", "0.3.5"));
    }
}
