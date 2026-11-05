//! A provider reachable at more than one endpoint (replicas, regions), with failover
//! that never risks an effect twice and passive outlier detection.
//!
//! - **When a call moves on.** Any call moves to the next endpoint when its request
//!   never left (connection refused, DNS or TLS failure): nothing was delivered, so no
//!   effect can have happened. A read-only call also moves on when its response was
//!   lost or the endpoint answered 502, 503 or 504. An effectful call whose request may
//!   have been delivered never moves on: its outcome is unknown and goes to
//!   reconciliation, as with one endpoint.
//! - **Outlier detection.** Three consecutive failures eject an endpoint for 30
//!   seconds, doubling with each ejection up to five minutes; a success restores it.
//!   Healthy endpoints are tried first in configured order, then ejected ones, soonest
//!   to return first, so a call is never refused without an attempt.
//!
//! With a single endpoint every call behaves exactly as before: one attempt.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use url::Url;

use crate::transport::{EndpointError, Exchange, TransportPolicy, pinned_endpoint, send};

const EJECT_AFTER: u32 = 3;
const BASE_EJECTION: Duration = Duration::from_secs(30);
const MAX_EJECTION: Duration = Duration::from_secs(300);

#[derive(Debug, Default, Clone)]
struct Health {
    consecutive_failures: u32,
    ejections: u32,
    ejected_until: Option<Instant>,
}

/// The endpoints of one adapter, primary first.
#[derive(Debug)]
pub struct Endpoints {
    urls: Vec<Url>,
    health: Mutex<Vec<Health>>,
}

/// Whether a call may move to another endpoint after a lost response or a 5xx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Retry {
    /// Only when the request never left: the call may have an effect.
    NotSentOnly,
    /// Also after a lost response or 502/503/504: the call reads and changes nothing.
    ReadOnly,
}

impl Endpoints {
    /// Pins each endpoint under `policy` (see [`pinned_endpoint`]).
    pub fn new(primary: &str, fallbacks: &[String], policy: &TransportPolicy) -> Result<Self, EndpointError> {
        let mut urls = vec![pinned_endpoint(primary, policy)?];
        for fallback in fallbacks {
            urls.push(pinned_endpoint(fallback, policy)?);
        }
        let health = Mutex::new(vec![Health::default(); urls.len()]);
        Ok(Self { urls, health })
    }

    /// Applies `f` to every endpoint URL (for example, a trailing slash for joining).
    pub(crate) fn map_urls(mut self, f: impl Fn(&mut Url)) -> Self {
        self.urls.iter_mut().for_each(f);
        self
    }

    pub fn primary(&self) -> &Url {
        &self.urls[0]
    }

    pub fn len(&self) -> usize {
        self.urls.len()
    }

    pub fn is_empty(&self) -> bool {
        self.urls.is_empty()
    }

    /// Indexes in the order to try them.
    fn order(&self, now: Instant) -> Vec<usize> {
        let Ok(health) = self.health.lock() else {
            return (0..self.urls.len()).collect();
        };
        let mut healthy: Vec<usize> = Vec::new();
        let mut ejected: Vec<(Instant, usize)> = Vec::new();
        for (i, h) in health.iter().enumerate() {
            match h.ejected_until {
                Some(until) if until > now => ejected.push((until, i)),
                _ => healthy.push(i),
            }
        }
        ejected.sort();
        healthy.extend(ejected.into_iter().map(|(_, i)| i));
        healthy
    }

    fn record(&self, index: usize, ok: bool, now: Instant) {
        let Ok(mut health) = self.health.lock() else {
            return;
        };
        let Some(h) = health.get_mut(index) else {
            return;
        };
        if ok {
            *h = Health::default();
            return;
        }
        h.consecutive_failures += 1;
        if h.consecutive_failures >= EJECT_AFTER {
            let factor = 1u32 << h.ejections.min(4);
            let duration = (BASE_EJECTION * factor).min(MAX_EJECTION);
            h.ejected_until = Some(now + duration);
            h.ejections += 1;
            h.consecutive_failures = 0;
            tracing::warn!(
                endpoint = %self.urls[index],
                seconds = duration.as_secs(),
                "provider endpoint ejected after consecutive failures"
            );
        }
    }

    /// Sends the request `build` makes for each endpoint in turn, as `retry` allows,
    /// and returns the exchange to classify: the first usable one, or the last.
    pub(crate) async fn send(
        &self,
        build: impl Fn(&Url) -> Option<reqwest::RequestBuilder>,
        timeout: Duration,
        max_bytes: usize,
        retry: Retry,
    ) -> Exchange {
        let mut last = Exchange::NotSent;
        for index in self.order(Instant::now()) {
            let Some(request) = build(&self.urls[index]) else {
                return Exchange::NotSent;
            };
            let exchange = send(request, timeout, max_bytes).await;
            let (healthy, move_on) = match &exchange {
                Exchange::NotSent => (false, true),
                Exchange::Lost => (false, retry == Retry::ReadOnly),
                Exchange::Response { status: 502..=504, .. } => (false, retry == Retry::ReadOnly),
                Exchange::Response { .. } => (true, false),
            };
            self.record(index, healthy, Instant::now());
            if !move_on {
                return exchange;
            }
            last = exchange;
        }
        last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints(n: usize) -> Endpoints {
        let policy = TransportPolicy {
            allow_loopback_http: true,
            ..TransportPolicy::default()
        };
        let fallbacks: Vec<String> = (1..n).map(|i| format!("http://127.0.0.1:{}/mcp", 9000 + i)).collect();
        Endpoints::new("http://127.0.0.1:9000/mcp", &fallbacks, &policy).unwrap()
    }

    #[test]
    fn three_failures_eject_and_a_success_restores() {
        let e = endpoints(3);
        let t0 = Instant::now();
        assert_eq!(e.order(t0), [0, 1, 2]);
        e.record(0, false, t0);
        e.record(0, false, t0);
        assert_eq!(e.order(t0), [0, 1, 2], "two failures do not eject");
        e.record(0, false, t0);
        assert_eq!(e.order(t0), [1, 2, 0], "ejected endpoints are tried last");
        assert_eq!(e.order(t0 + BASE_EJECTION + Duration::from_millis(1)), [0, 1, 2]);
        e.record(0, true, t0);
        assert_eq!(e.order(t0), [0, 1, 2]);
    }

    #[test]
    fn repeated_ejections_back_off_to_a_cap() {
        let e = endpoints(2);
        let t0 = Instant::now();
        let mut longest = Duration::ZERO;
        for _ in 0..8 {
            for _ in 0..EJECT_AFTER {
                e.record(1, false, t0);
            }
            let until = e.health.lock().unwrap()[1].ejected_until.unwrap();
            assert!(until - t0 >= longest, "each ejection lasts at least as long");
            longest = until - t0;
        }
        assert_eq!(longest, MAX_EJECTION);
    }

    #[test]
    fn ejected_endpoints_return_soonest_first() {
        let e = endpoints(3);
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(10);
        for _ in 0..EJECT_AFTER {
            e.record(1, false, t0);
        }
        for _ in 0..EJECT_AFTER {
            e.record(0, false, later);
        }
        assert_eq!(e.order(later), [2, 1, 0]);
    }

    #[test]
    fn every_endpoint_is_pinned() {
        let policy = TransportPolicy::default();
        assert!(Endpoints::new("https://a.example/mcp", &["http://b.example/mcp".into()], &policy).is_err());
        assert_eq!(
            Endpoints::new("https://a.example/mcp", &["https://b.example/mcp".into()], &policy)
                .unwrap()
                .len(),
            2
        );
    }
}
