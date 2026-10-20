//! Overload protection.
//!
//! - **Global in-flight cap.** Beyond `max_in_flight` concurrent requests the server
//!   sheds load with `503` and `Retry-After` instead of queueing without bound, so
//!   latency stays bounded and health probes keep answering.
//! - **Per-tenant request rate.** A token bucket per authenticated tenant
//!   (`requests_per_second`, `burst`); excess requests get `429` with `Retry-After`.
//! - **Per-tenant concurrent dispatch.** At most `max_concurrent_dispatch` governed
//!   effects per tenant are in progress at once, so one tenant's slow providers or
//!   retry storm cannot take every worker.
//!
//! Limits apply after authentication, so an unauthenticated caller cannot exhaust a
//! tenant's allowance. Per-tenant overrides raise or lower the defaults.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_in_flight")]
    pub max_in_flight: usize,
    #[serde(default = "default_rate")]
    pub requests_per_second: f64,
    #[serde(default = "default_burst")]
    pub burst: f64,
    #[serde(default = "default_dispatch")]
    pub max_concurrent_dispatch: usize,
    #[serde(default)]
    pub tenants: Vec<TenantLimits>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantLimits {
    pub tenant_id: String,
    pub requests_per_second: Option<f64>,
    pub burst: Option<f64>,
    pub max_concurrent_dispatch: Option<usize>,
}

fn default_in_flight() -> usize {
    4096
}

fn default_rate() -> f64 {
    500.0
}

fn default_burst() -> f64 {
    1000.0
}

fn default_dispatch() -> usize {
    256
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_in_flight: default_in_flight(),
            requests_per_second: default_rate(),
            burst: default_burst(),
            max_concurrent_dispatch: default_dispatch(),
            tenants: Vec::new(),
        }
    }
}

impl LimitsConfig {
    pub(crate) fn check(&self) -> Result<(), String> {
        let rate_ok = |r: f64, b: f64| r.is_finite() && b.is_finite() && r > 0.0 && b >= 1.0;
        if self.max_in_flight == 0
            || self.max_concurrent_dispatch == 0
            || !rate_ok(self.requests_per_second, self.burst)
        {
            return Err("limits must be positive".into());
        }
        for t in &self.tenants {
            let (rate, burst) = (
                t.requests_per_second.unwrap_or(self.requests_per_second),
                t.burst.unwrap_or(self.burst),
            );
            if t.tenant_id.is_empty() || !rate_ok(rate, burst) || t.max_concurrent_dispatch == Some(0) {
                return Err(format!("limits for tenant {:?} must be positive", t.tenant_id));
            }
        }
        Ok(())
    }
}

struct Bucket {
    tokens: f64,
    refilled: Instant,
}

/// Enforces [`LimitsConfig`].
pub struct Limiter {
    config: LimitsConfig,
    overrides: HashMap<String, TenantLimits>,
    in_flight: Arc<Semaphore>,
    buckets: Mutex<HashMap<String, Bucket>>,
    dispatch: Mutex<HashMap<String, Arc<Semaphore>>>,
}

impl std::fmt::Debug for Limiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Limiter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Limiter {
    pub fn new(config: LimitsConfig) -> Self {
        let overrides = config
            .tenants
            .iter()
            .map(|t| (t.tenant_id.clone(), t.clone()))
            .collect();
        Self {
            in_flight: Arc::new(Semaphore::new(config.max_in_flight)),
            config,
            overrides,
            buckets: Mutex::default(),
            dispatch: Mutex::default(),
        }
    }

    /// A slot for one request, or `None` when the server is saturated.
    pub fn admit_request(&self) -> Option<OwnedSemaphorePermit> {
        self.in_flight.clone().try_acquire_owned().ok()
    }

    fn rate(&self, tenant_id: &str) -> (f64, f64) {
        let o = self.overrides.get(tenant_id);
        (
            o.and_then(|o| o.requests_per_second)
                .unwrap_or(self.config.requests_per_second),
            o.and_then(|o| o.burst).unwrap_or(self.config.burst),
        )
    }

    /// Takes one token from the tenant's bucket, or returns how long until one is due.
    pub fn take(&self, tenant_id: &str) -> Result<(), Duration> {
        self.take_at(tenant_id, Instant::now())
    }

    fn take_at(&self, tenant_id: &str, now: Instant) -> Result<(), Duration> {
        let (rate, burst) = self.rate(tenant_id);
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        let bucket = buckets.entry(tenant_id.to_owned()).or_insert(Bucket {
            tokens: burst,
            refilled: now,
        });
        let elapsed = now.saturating_duration_since(bucket.refilled).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
        bucket.refilled = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - bucket.tokens) / rate))
        }
    }

    /// A slot for one governed dispatch by `tenant_id`, or `None` at the tenant's cap.
    pub fn dispatch_permit(&self, tenant_id: &str) -> Option<OwnedSemaphorePermit> {
        let semaphore = {
            let mut slots = self.dispatch.lock().unwrap_or_else(PoisonError::into_inner);
            slots
                .entry(tenant_id.to_owned())
                .or_insert_with(|| {
                    let cap = self
                        .overrides
                        .get(tenant_id)
                        .and_then(|o| o.max_concurrent_dispatch)
                        .unwrap_or(self.config.max_concurrent_dispatch);
                    Arc::new(Semaphore::new(cap))
                })
                .clone()
        };
        semaphore.try_acquire_owned().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> Limiter {
        Limiter::new(LimitsConfig {
            max_in_flight: 2,
            requests_per_second: 10.0,
            burst: 3.0,
            max_concurrent_dispatch: 1,
            tenants: vec![TenantLimits {
                tenant_id: "big".into(),
                requests_per_second: None,
                burst: Some(5.0),
                max_concurrent_dispatch: Some(2),
            }],
        })
    }

    #[test]
    fn buckets_refill_per_tenant() {
        let l = limiter();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(l.take_at("a", t0).is_ok());
        }
        let wait = l.take_at("a", t0).unwrap_err();
        assert!(wait > Duration::ZERO && wait <= Duration::from_millis(100));
        assert!(l.take_at("b", t0).is_ok(), "tenants have separate buckets");
        assert!(l.take_at("a", t0 + Duration::from_millis(100)).is_ok(), "refilled");
        for _ in 0..5 {
            assert!(l.take_at("big", t0).is_ok(), "override burst");
        }
        assert!(l.take_at("big", t0).is_err());
    }

    #[test]
    fn concurrency_caps_release_on_drop() {
        let l = limiter();
        let first = l.dispatch_permit("a").unwrap();
        assert!(l.dispatch_permit("a").is_none());
        assert!(l.dispatch_permit("b").is_some());
        drop(first);
        assert!(l.dispatch_permit("a").is_some());
        let (_x, _y) = (l.dispatch_permit("big").unwrap(), l.dispatch_permit("big").unwrap());
        let (_r1, _r2) = (l.admit_request().unwrap(), l.admit_request().unwrap());
        assert!(l.admit_request().is_none(), "global cap");
    }
}
