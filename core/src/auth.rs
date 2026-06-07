//! Cloud authentication and wallet verification (Stage 1)

use crate::types::AuthResponse;
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Serialize;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Auth cache entry for minimizing cloud calls
#[derive(Debug, Clone)]
struct CachedAuth {
    response: AuthResponse,
    cached_at: Instant,
    remaining_units: u32,
}

/// Cloud authentication client
pub struct AuthClient {
    client: Client,
    ledger_url: String,
    cache: Option<CachedAuth>,
    cache_ttl: Duration,
}

/// Auth request payload
#[derive(Debug, Serialize)]
struct AuthRequest {
    token_identity: String,
    client_epoch: u64,
}

impl AuthClient {
    /// Create new auth client
    pub fn new(ledger_url: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("Failed to create HTTP client for auth")?;

        Ok(Self {
            client,
            ledger_url: ledger_url.into(),
            cache: None,
            cache_ttl: Duration::from_secs(300), // 5 minute cache
        })
    }

    /// Verify API key and check wallet balance
    pub async fn verify(&mut self, api_key: &str) -> Result<AuthResponse> {
        // Check cache first
        if let Some(cached) = &self.cache
            && cached.cached_at.elapsed() < self.cache_ttl
            && cached.remaining_units > 0
        {
            debug!(
                "Using cached auth response, remaining_units: {}",
                cached.remaining_units
            );
            return Ok(cached.response.clone());
        }

        // Make cloud verification call
        info!("Initiating cloud wallet verification handshake");
        let response = self.perform_handshake(api_key).await?;

        // Cache successful response
        self.cache = Some(CachedAuth {
            response: response.clone(),
            cached_at: Instant::now(),
            remaining_units: response.cache_allowed_units,
        });

        Ok(response)
    }

    /// Perform HTTPS handshake with ledger service
    async fn perform_handshake(&self, api_key: &str) -> Result<AuthResponse> {
        let url = format!("{}/auth", self.ledger_url);
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let payload = AuthRequest {
            token_identity: api_key.to_string(),
            client_epoch: epoch,
        };

        debug!("POST {}", url);

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to connect to ledger service")?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            // Strip HTML from error messages for cleaner output
            let clean_text = if text.trim().starts_with('<') || text.contains("<!DOCTYPE") {
                format!(
                    "The Tuora cloud service is temporarily unavailable (HTTP {} {}). Please try again in a few moments.",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("Unknown")
                )
            } else if text.len() > 200 {
                format!("{}... [truncated]", &text[..200])
            } else {
                text
            };
            anyhow::bail!("Ledger service returned error: {}", clean_text);
        }

        let auth_response: AuthResponse = response
            .json()
            .await
            .context("Failed to parse auth response")?;

        if !auth_response.valid {
            anyhow::bail!(
                "Exit Code 1: Insufficient Balance. Current wallet balance does not cover execution unit parameters (${:.2} / ${:.2}). Minimum top-up threshold: $2.00.",
                auth_response.wallet_balance,
                auth_response.scan_cost
            );
        }

        info!(
            tier = ?auth_response.tier,
            balance = auth_response.wallet_balance,
            cost = auth_response.scan_cost,
            historic = auth_response.historic_scans,
            "Wallet verification successful"
        );

        Ok(auth_response)
    }

    /// Deduct a unit from cache (called after successful scan)
    pub fn consume_cached_unit(&mut self) {
        if let Some(cached) = &mut self.cache
            && cached.remaining_units > 0
        {
            cached.remaining_units -= 1;
            debug!(
                "Consumed cached auth unit, {} remaining",
                cached.remaining_units
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use tuora_types::PricingTier;

    #[test]
    fn test_pricing_tier_display() {
        let hobby = PricingTier::Hobby;
        let standard = PricingTier::Standard;
        let volume = PricingTier::VolumeDiscount;

        // Just verify they exist and don't panic
        let _ = format!("{:?}", hobby);
        let _ = format!("{:?}", standard);
        let _ = format!("{:?}", volume);
    }
}
