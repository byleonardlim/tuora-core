//! `tuora watch` command — bootstrap once, re-evaluate on file changes.
//!
//! Phase 1 (bootstrap): auth → fetch rules → full scan → render baseline.
//! Phase 2 (watch loop): debounced fs events → re-ingest changed files →
//!   diff violations per file → render delta.

use crate::auth::AuthClient;
use crate::config::ScanConfig;
use crate::progress::Progress;
use crate::reporter::Reporter;
use crate::rules::{RuleBackend, remote::RuleBundleFetcher};
use crate::scanner::IngestedFile;
use crate::telemetry::TelemetrySink;
use crate::types::{Framework, ScanResult, Violation};
use anyhow::{Context, Result};
use ignore::gitignore::GitignoreBuilder;
use notify::{Event, EventKind, PollWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Debounce window — collapses rapid editor save bursts into one evaluation.
const DEBOUNCE_MS: u64 = 200;

/// Threshold for skipping a directory when no .gitignore exists (too many entries).
const FALLBACK_DIR_SIZE_THRESHOLD: usize = 1000;

/// Directories to always skip when no .gitignore exists (common large directories).
const ALWAYS_SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "__pycache__",
    ".pnpm",
    ".next",
    "dist",
    "build",
    "out",
    "coverage",
    ".turbo",
    ".parcel-cache",
    ".cache",
    ".svelte-kit",
];

/// Holds the mutable state of the workspace between change events.
struct WatchState {
    /// All currently ingested files, keyed by canonical path.
    files: HashMap<PathBuf, IngestedFile>,
    /// Last known violations per file.
    violations_by_file: HashMap<PathBuf, Vec<Violation>>,
    /// Detected framework (stable after bootstrap).
    framework: Framework,
    /// Total rules loaded.
    rule_count: usize,
}

impl WatchState {
    fn all_violations(&self) -> Vec<Violation> {
        self.violations_by_file
            .values()
            .flatten()
            .cloned()
            .collect()
    }

    fn health_score(&self) -> u32 {
        let deduction: u32 = self
            .all_violations()
            .iter()
            .map(|v| v.severity.weight())
            .sum();
        100u32.saturating_sub(deduction)
    }
}

/// Run the watch command.
pub async fn run(cfg: ScanConfig) -> Result<()> {
    // ── Pre-flight: Validate path before any network call ─────────────────

    let watch_path = cfg
        .path
        .canonicalize()
        .with_context(|| format!("Path not found: {}", cfg.path.display()))?;

    if !watch_path.is_dir() {
        anyhow::bail!(
            "'{}' is not a directory. tuora watch requires a project folder.",
            watch_path.display()
        );
    }

    // Quick pre-scan to check for scannable files before spending a wallet unit
    let probe = crate::scanner::Scanner::new(&watch_path)
        .scan()
        .with_context(|| format!("Cannot read directory: {}", watch_path.display()))?;

    if probe.files.is_empty() {
        eprintln!(
            "\n\x1b[31m✗\x1b[0m No scannable files found in \x1b[1m{}\x1b[0m\n",
            watch_path.display()
        );
        eprintln!("  Tuora supports: .py  .ts  .js  .tsx  .yaml  .yml  .json  .rs  .env*");
        eprintln!("  Is this a code project directory?\n");
        std::process::exit(1);
    }

    // Warn but continue when no known framework is detected
    if probe.detected_framework == crate::types::Framework::Unknown {
        eprintln!(
            "  \x1b[33m⚠ No agentic framework detected — running in traditional SAST mode.\x1b[0m\n"
        );
    }

    // ── Phase 1: Bootstrap ────────────────────────────────────────────────

    // Stage 1: Auth
    let (mut auth_client, auth_response) = Progress::run(
        "authenticating",
        || async {
            let mut client =
                AuthClient::new(&cfg.ledger_url).context("Failed to initialize auth client")?;
            match client.verify(&cfg.api_key).await {
                Ok(resp) => {
                    let clone = resp.clone();
                    Ok::<_, anyhow::Error>(Some((client, clone)))
                }
                Err(e) => {
                    eprintln!("\n\x1b[31mAuthentication failed:\x1b[0m {}", e);
                    std::process::exit(1);
                }
            }
        },
        |_| None,
    )
    .await?
    .map(|(c, r)| (Some(c), Some(r)))
    .unwrap_or((None, None));

    // Stage 2: Fetch rule bundle (cache-aware: version check → disk → download)
    let mut rule_backend: RuleBackend = Progress::run(
        "loading rules",
        || async {
            let auth = auth_response.as_ref().unwrap().clone();
            let fetcher = RuleBundleFetcher::new(&cfg.ledger_url, &cfg.api_key);
            match fetcher.fetch(&auth).await {
                Ok(engine) => Ok::<_, anyhow::Error>(engine),
                Err(e) => {
                    eprintln!("\n\x1b[33mRule fetch failed:\x1b[0m {}", e);
                    Err(e)
                }
            }
        },
        |res| {
            res.as_ref()
                .ok()
                .map(|b| format!("({} rules)", b.rule_count()))
        },
    )
    .await?;

    // Stage 3: Use probe result directly — directory already validated and scanned
    let framework_info = if probe.detected_framework != Framework::Unknown {
        format!(
            "({} detected, {} files)",
            probe.detected_framework.name(),
            probe.files.len()
        )
    } else {
        format!("({} files, traditional SAST mode)", probe.files.len())
    };
    Progress::status(&format!("scanning files  {}", framework_info));
    let workspace = probe;

    let framework = workspace.detected_framework;
    let rule_count = rule_backend.rule_count();

    // Stage 4: Baseline evaluation
    let baseline_violations =
        tokio::task::block_in_place(|| rule_backend.evaluate(&workspace.files, framework));

    // Build initial watch state
    let files_map: HashMap<PathBuf, IngestedFile> = workspace
        .files
        .into_iter()
        .map(|f| (f.path.clone(), f))
        .collect();

    let violations_by_file = group_violations_by_file(baseline_violations.clone());

    let mut state = WatchState {
        files: files_map,
        violations_by_file,
        framework,
        rule_count,
    };

    // Stage 5: Render baseline report
    let baseline_result = build_scan_result(&cfg.path, &state, Uuid::new_v4().to_string(), 0);
    let reporter = Reporter::new(cfg.format);
    reporter.render(&baseline_result)?;

    // Consume one auth unit for the bootstrap scan
    if let Some(client) = auth_client.as_mut() {
        client.consume_cached_unit();
    }

    // ── Phase 2: Watch Loop ───────────────────────────────────────────────

    println!("\x1b[90m  Watching for changes…\x1b[0m (Ctrl+C to exit)\n");

    // Build gitignore matcher from .gitignore if it exists
    let gitignore = build_gitignore(&cfg.path);

    // Discover directories to watch (excluding ignored/large ones)
    let watch_dirs = discover_watch_dirs(&cfg.path, &gitignore);
    info!("Watching {} directories", watch_dirs.len());

    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();

    // Use PollWatcher for proper non-recursive support across all platforms
    // FSEvents (RecommendedWatcher on macOS) is always recursive
    // Kqueue doesn't support watching directory contents with NonRecursive mode
    let mut watcher: PollWatcher = {
        let config = notify::Config::default().with_poll_interval(Duration::from_millis(500));
        PollWatcher::new(tx, config).context("Failed to create poll file watcher")?
    };

    // Track watched directories so we can unwatch them if deleted
    let mut watched_dirs: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    // Add non-recursive watches for each allowed directory
    for dir in &watch_dirs {
        if let Err(e) = watcher.watch(dir, RecursiveMode::NonRecursive) {
            warn!("Failed to watch directory {}: {}", dir.display(), e);
        } else {
            debug!("Watching directory: {}", dir.display());
            watched_dirs.insert(dir.clone());
        }
    }

    // Debounce: collect events until DEBOUNCE_MS of silence, then process.
    let mut pending: Vec<PathBuf> = Vec::new();
    let mut last_event = Instant::now();

    loop {
        // Non-blocking drain of the channel
        loop {
            match rx.try_recv() {
                Ok(Ok(event)) => {
                    debug!(
                        "Received event: {:?} for paths: {:?}",
                        event.kind, event.paths
                    );
                    if is_relevant_event(&event, &gitignore) {
                        for path in event.paths {
                            // If this is a new directory, add it to our watch list
                            if event.kind.is_create()
                                && path.is_dir()
                                && !is_path_ignored(&path, &gitignore)
                            {
                                if let Err(e) = watcher.watch(&path, RecursiveMode::NonRecursive) {
                                    warn!(
                                        "Failed to watch new directory {}: {}",
                                        path.display(),
                                        e
                                    );
                                } else {
                                    debug!("Added watch for new directory: {}", path.display());
                                    watched_dirs.insert(path.clone());
                                }
                            }
                            debug!("Processing fs event: {}", path.display());
                            pending.push(path);
                        }
                        last_event = Instant::now();
                    } else {
                        debug!("Event filtered out (ignored or not relevant)");
                    }
                }
                Ok(Err(e)) => {
                    // Check if this is a file-not-found error on a watched directory
                    let err_str = e.to_string();
                    let is_file_not_found = err_str.contains("No such file or directory")
                        || err_str.contains("os error 2");

                    if is_file_not_found {
                        // Extract path from error message and unwatch if it's a deleted directory
                        if let Some(path) = extract_path_from_error(&err_str) {
                            if watched_dirs.contains(&path) {
                                debug!("Watched directory deleted, unwatching: {}", path.display());
                                let _ = watcher.unwatch(&path);
                                watched_dirs.remove(&path);
                                // Also remove any tracked files in this directory
                                let prefix = path.as_path();
                                state.files.retain(|p, _| !p.starts_with(prefix));
                                state.violations_by_file.retain(|p, _| !p.starts_with(prefix));
                                continue;
                            }
                        }
                        debug!("Ignoring file-not-found error from deleted file: {}", e);
                    } else {
                        eprintln!("\x1b[31mWatch error:\x1b[0m {}", e);
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    info!("Watcher channel closed — exiting watch loop");
                    flush_telemetry(&cfg, &state).await;
                    return Ok(());
                }
            }
        }

        // Fire evaluation when debounce window has elapsed and there are events
        if !pending.is_empty() && last_event.elapsed() >= Duration::from_millis(DEBOUNCE_MS) {
            let changed: Vec<PathBuf> = std::mem::take(&mut pending);
            let changed = dedup_paths(changed);

            let eval_start = Instant::now();
            let timestamp = chrono_now();

            // Re-ingest only the changed files
            let mut new_violations: HashMap<PathBuf, Vec<Violation>>;
            let mut re_eval_files: Vec<IngestedFile> = Vec::new();

            for path in &changed {
                if path.exists() {
                    match re_ingest_file(path) {
                        Some(ingested) => {
                            state.files.insert(path.clone(), ingested.clone());
                            re_eval_files.push(ingested);
                        }
                        None => {
                            // Non-scannable file type — remove stale state if present
                            state.files.remove(path);
                            state.violations_by_file.remove(path);
                        }
                    }
                } else {
                    // Deleted file — remove from state
                    state.files.remove(path);
                    state.violations_by_file.remove(path);
                }
            }

            // Skip render entirely if no scannable files were touched
            if re_eval_files.is_empty() {
                continue;
            }

            // Evaluate rules against the re-ingested files
            let file_violations = tokio::task::block_in_place(|| {
                rule_backend.evaluate(&re_eval_files, state.framework)
            });
            new_violations = group_violations_by_file(file_violations);

            // Compute delta before updating state
            let delta = compute_delta(&state.violations_by_file, &new_violations, &changed);

            // Commit updated violations into state
            for path in &changed {
                if let Some(v) = new_violations.remove(path) {
                    state.violations_by_file.insert(path.clone(), v);
                } else if state.files.contains_key(path) {
                    state.violations_by_file.insert(path.clone(), vec![]);
                }
            }

            let elapsed_ms = eval_start.elapsed().as_millis() as u64;

            reporter.render_watch_delta(
                &timestamp,
                &changed,
                &delta,
                state.health_score(),
                elapsed_ms,
            )?;
        }

        // Yield briefly to avoid a busy-spin
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Only react to file create/modify/remove — ignore metadata, access events etc.
/// Also filters out paths ignored by .gitignore or matching fallback heuristics.
fn is_relevant_event(event: &Event, gitignore: &Option<ignore::gitignore::Gitignore>) -> bool {
    if !matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    ) {
        return false;
    }

    // Check if any path in the event is ignored
    for path in &event.paths {
        if is_path_ignored(path, gitignore) {
            return false;
        }
    }

    true
}

/// Check if a path should be ignored based on .gitignore or fallback heuristics.
fn is_path_ignored(path: &Path, gitignore: &Option<ignore::gitignore::Gitignore>) -> bool {
    // First check gitignore if available
    if let Some(gi) = gitignore {
        if gi.matched(path, path.is_dir()).is_ignore() {
            return true;
        }
    } else {
        // Fallback: check against known large directory names
        if let Some(name) = path.file_name() {
            let name = name.to_string_lossy();
            if ALWAYS_SKIP_DIRS.iter().any(|skip| name == *skip) {
                return true;
            }
        }
    }
    false
}

/// Build a gitignore matcher from the root path. Returns None if no .gitignore exists.
fn build_gitignore(root: &Path) -> Option<ignore::gitignore::Gitignore> {
    let gitignore_path = root.join(".gitignore");
    if !gitignore_path.exists() {
        return None;
    }

    let mut builder = GitignoreBuilder::new(root);
    if let Some(e) = builder.add(gitignore_path) {
        warn!("Failed to parse .gitignore: {}", e);
        return None;
    }

    // Also add global ignores for common large directories if not already in .gitignore
    for dir in ALWAYS_SKIP_DIRS {
        let _ = builder.add_line(None, dir);
    }

    match builder.build() {
        Ok(gi) => Some(gi),
        Err(e) => {
            warn!("Failed to build gitignore matcher: {}", e);
            None
        }
    }
}

/// Discover all directories that should be watched, excluding ignored/large ones.
/// Returns a list of directories to watch with NonRecursive mode.
fn discover_watch_dirs(
    root: &Path,
    gitignore: &Option<ignore::gitignore::Gitignore>,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    fn scan_dir(
        dir: &Path,
        dirs: &mut Vec<PathBuf>,
        gitignore: &Option<ignore::gitignore::Gitignore>,
        depth: usize,
    ) {
        if depth > 20 {
            // Limit recursion depth to prevent stack overflow
            return;
        }

        // Check if this directory should be ignored
        if is_path_ignored(dir, gitignore) {
            return;
        }

        // Count entries to detect large directories when no gitignore exists
        if gitignore.is_none() {
            let count = match fs::read_dir(dir) {
                Ok(entries) => entries.count(),
                Err(_) => 0,
            };
            if count > FALLBACK_DIR_SIZE_THRESHOLD {
                warn!(
                    "Skipping directory {} with {} entries (no .gitignore)",
                    dir.display(),
                    count
                );
                return;
            }
        }

        // Add this directory to the watch list
        dirs.push(dir.to_path_buf());

        // Scan subdirectories
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_dir(&path, dirs, gitignore, depth + 1);
            }
        }
    }

    scan_dir(root, &mut dirs, gitignore, 0);
    for dir in &dirs {
        debug!("Discovered watch dir: {}", dir.display());
    }
    dirs
}

/// Re-read a single file from disk using the same rules as the Scanner.
fn re_ingest_file(path: &Path) -> Option<IngestedFile> {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let is_env = extension.is_empty()
        && path
            .file_name()
            .map(|n| n.to_string_lossy().starts_with(".env"))
            .unwrap_or(false);

    let allowed = [
        "py", "ts", "js", "tsx", "yaml", "yml", "json", "mjs", "cjs", "svelte", "rs",
    ];
    if !allowed.contains(&extension.as_str()) && !is_env {
        return None;
    }

    let ext_tag = if is_env { "env".to_string() } else { extension };

    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > 1024 * 1024 {
        return None;
    }

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return None,
        Err(_) => return None,
    };

    Some(IngestedFile {
        path: path.to_path_buf(),
        content,
        extension: ext_tag,
    })
}

/// Group a flat violation list by file path.
fn group_violations_by_file(violations: Vec<Violation>) -> HashMap<PathBuf, Vec<Violation>> {
    let mut map: HashMap<PathBuf, Vec<Violation>> = HashMap::new();
    for v in violations {
        map.entry(v.file_path.clone()).or_default().push(v);
    }
    map
}

/// Delta entry — a violation that appeared or was resolved.
pub struct ViolationDelta {
    pub violation: Violation,
    pub is_new: bool,
}

/// Diff old vs new violation sets for the changed paths only.
fn compute_delta(
    old: &HashMap<PathBuf, Vec<Violation>>,
    new: &HashMap<PathBuf, Vec<Violation>>,
    changed_paths: &[PathBuf],
) -> Vec<ViolationDelta> {
    let mut delta = Vec::new();

    for path in changed_paths {
        let old_v = old.get(path).map(|v| v.as_slice()).unwrap_or(&[]);
        let new_v = new.get(path).map(|v| v.as_slice()).unwrap_or(&[]);

        // Newly appeared violations (in new, not in old)
        for v in new_v {
            if !old_v
                .iter()
                .any(|o| o.rule_id == v.rule_id && o.line_number == v.line_number)
            {
                delta.push(ViolationDelta {
                    violation: v.clone(),
                    is_new: true,
                });
            }
        }

        // Resolved violations (in old, not in new)
        for v in old_v {
            if !new_v
                .iter()
                .any(|n| n.rule_id == v.rule_id && n.line_number == v.line_number)
            {
                delta.push(ViolationDelta {
                    violation: v.clone(),
                    is_new: false,
                });
            }
        }
    }

    delta
}

/// Dedup path list while preserving order.
fn dedup_paths(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    paths.retain(|p| seen.insert(p.clone()));
    paths
}

/// Build a ScanResult snapshot from the current watch state (for baseline render).
fn build_scan_result(
    workspace_path: &Path,
    state: &WatchState,
    scan_id: String,
    duration_ms: u64,
) -> ScanResult {
    let violations = state.all_violations();
    let health_score = state.health_score();
    let mut result = ScanResult {
        scan_id,
        workspace_path: workspace_path.to_path_buf(),
        framework: state.framework,
        files_scanned: state.files.len(),
        rules_evaluated: state.rule_count,
        violations,
        scan_duration_ms: duration_ms,
        health_score,
    };
    result.calculate_score();
    result
}

/// Simple wall-clock timestamp string for watch event headers.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

/// Extract a path from an IO error message.
/// Expected format: "IO error for operation on <path>: ..."
fn extract_path_from_error(err_str: &str) -> Option<PathBuf> {
    // Match pattern: "IO error for operation on <path>:"
    let prefix = "IO error for operation on ";
    if let Some(start) = err_str.find(prefix) {
        let after_prefix = &err_str[start + prefix.len()..];
        if let Some(end) = after_prefix.find(':') {
            let path_str = &after_prefix[..end];
            return Some(PathBuf::from(path_str));
        }
    }
    None
}

/// Non-blocking telemetry flush on clean exit.
async fn flush_telemetry(cfg: &ScanConfig, state: &WatchState) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    cfg.api_key.hash(&mut hasher);
    let workspace_id = format!("{:x}", hasher.finish())[..16].to_string();

    let dummy_result = build_scan_result(&cfg.path, state, Uuid::new_v4().to_string(), 0);

    let sink = TelemetrySink::new(&cfg.ledger_url, workspace_id.clone(), &cfg.api_key);
    let _ = sink.record_scan(&dummy_result, &workspace_id).await;
}
