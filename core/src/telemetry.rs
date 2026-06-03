//! Async telemetry sinking (Stage 5)

use crate::types::{MetaStats, ScanResult, TelemetryEvent, ViolationSummary};
use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Telemetry buffer entry
#[derive(Debug, Clone)]
struct TelemetryEntry {
    event: TelemetryEvent,
    #[allow(dead_code)]
    retries: u32,
}

/// Async telemetry sink with atomic ring buffer
pub struct TelemetrySink {
    sender: mpsc::Sender<TelemetryEntry>,
    #[allow(dead_code)]
    ledger_url: String,
    scan_count: Arc<AtomicU64>,
    #[allow(dead_code)]
    api_key: String,
}

impl TelemetrySink {
    /// Create new telemetry sink and spawn background task
    pub fn new(
        ledger_url: impl Into<String>,
        workspace_id: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(100);
        let ledger_url = ledger_url.into();
        let workspace_id = workspace_id.into();
        let api_key = api_key.into();
        let scan_count = Arc::new(AtomicU64::new(0));

        // Spawn background flushing task
        let url = ledger_url.clone();
        let ws_id = workspace_id.clone();
        let key = api_key.clone();
        let count = scan_count.clone();
        tokio::spawn(Self::flush_loop(receiver, url, ws_id, key, count));

        Self {
            sender,
            ledger_url,
            scan_count,
            api_key,
        }
    }

    /// Queue a scan result for telemetry sinking
    pub async fn record_scan(&self, result: &ScanResult, workspace_id: &str) -> Result<()> {
        let event = TelemetryEvent {
            scan_id: result.scan_id.clone(),
            workspace_id: workspace_id.to_string(),
            framework: result.framework.name().to_string(),
            meta_stats: MetaStats {
                rules_evaluated: result.rules_evaluated,
                anomalies_detected: result.violations.len(),
                code_base_files: result.files_scanned,
                scan_duration_ms: result.scan_duration_ms,
            },
            detected_vulnerabilities: result
                .violations
                .iter()
                .map(|v| ViolationSummary {
                    rule_id: v.rule_id.0.clone(),
                    severity: format!("{:?}", v.severity),
                    tool_target: v.tool_target.clone(),
                    message: v.message.clone(),
                })
                .collect(),
        };

        let entry = TelemetryEntry { event, retries: 0 };

        // Non-blocking send - drops if buffer full
        match self.sender.try_send(entry) {
            Ok(_) => {
                self.scan_count.fetch_add(1, Ordering::Relaxed);
                debug!("Telemetry queued for scan {}", result.scan_id);
            }
            Err(_) => {
                warn!(
                    "Telemetry buffer full, dropping event for scan {}",
                    result.scan_id
                );
            }
        }

        Ok(())
    }

    /// Background flush loop
    async fn flush_loop(
        mut receiver: mpsc::Receiver<TelemetryEntry>,
        ledger_url: String,
        workspace_id: String,
        api_key: String,
        _scan_count: Arc<AtomicU64>,
    ) {
        info!("Telemetry sink started for workspace: {}", workspace_id);

        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create telemetry HTTP client: {}", e);
                return;
            }
        };

        let batch_url = format!("{}/telemetry/batch", ledger_url);
        let mut batch = Vec::with_capacity(100);
        let mut last_flush = tokio::time::Instant::now();
        let flush_interval = std::time::Duration::from_secs(60);
        let max_batch_size = 100;

        loop {
            let sleep_for = flush_interval
                .checked_sub(last_flush.elapsed())
                .unwrap_or_else(|| std::time::Duration::from_secs(0));
            let timeout = tokio::time::sleep(sleep_for);

            tokio::select! {
                // Receive new entry
                Some(entry) = receiver.recv() => {
                    batch.push(entry);

                    // Flush if batch is full
                    if batch.len() >= max_batch_size {
                        Self::flush_batch(&client, &batch_url, &api_key, &batch).await;
                        batch.clear();
                        last_flush = tokio::time::Instant::now();
                    }
                }

                // Periodic flush
                _ = timeout => {
                    if !batch.is_empty() {
                        Self::flush_batch(&client, &batch_url, &api_key, &batch).await;
                        batch.clear();
                    }
                    last_flush = tokio::time::Instant::now();
                }

                // Channel closed
                else => {
                    // Flush remaining
                    if !batch.is_empty() {
                        Self::flush_batch(&client, &batch_url, &api_key, &batch).await;
                    }
                    info!("Telemetry sink shutting down");
                    break;
                }
            }
        }
    }

    /// Flush a batch of telemetry events
    async fn flush_batch(
        client: &reqwest::Client,
        url: &str,
        api_key: &str,
        batch: &[TelemetryEntry],
    ) {
        if batch.is_empty() {
            return;
        }

        debug!("Flushing {} telemetry events to {}", batch.len(), url);

        let events: Vec<_> = batch.iter().map(|e| &e.event).collect();

        match client
            .post(url)
            .bearer_auth(api_key)
            .json(&events)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    debug!("Telemetry batch flushed successfully");
                } else {
                    warn!("Telemetry flush failed: HTTP {}", resp.status());
                }
            }
            Err(e) => {
                warn!("Telemetry flush error: {}", e);
                // Events are lost if network fails - acceptable per spec
                // (in-memory volatile buffering with exponential backoff)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Framework, OwaspCategory, RuleCategory, RuleId, Severity, Violation};
    use std::path::PathBuf;

    fn create_test_result() -> ScanResult {
        ScanResult {
            scan_id: "test-123".to_string(),
            workspace_path: PathBuf::from("/test"),
            framework: Framework::CrewAI,
            files_scanned: 5,
            rules_evaluated: 8,
            violations: vec![],
            scan_duration_ms: 100,
            health_score: 100,
        }
    }

    #[tokio::test]
    async fn test_telemetry_event_creation() {
        let result = create_test_result();
        let event = TelemetryEvent {
            scan_id: result.scan_id.clone(),
            workspace_id: "ws-123".to_string(),
            framework: result.framework.name().to_string(),
            meta_stats: MetaStats {
                rules_evaluated: result.rules_evaluated,
                anomalies_detected: 0,
                code_base_files: result.files_scanned,
                scan_duration_ms: result.scan_duration_ms,
            },
            detected_vulnerabilities: vec![],
        };

        assert_eq!(event.scan_id, "test-123");
        assert_eq!(event.workspace_id, "ws-123");
    }
}
