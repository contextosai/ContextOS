//! Prometheus text exposition for request counts and latency.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::Duration;

const BUCKETS_MS: [f64; 12] = [
    0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0,
];

#[derive(Debug, Default)]
struct Histogram {
    counts: [u64; BUCKETS_MS.len()],
    sum_ms: f64,
    count: u64,
}

#[derive(Debug, Default)]
pub struct Metrics {
    requests: Mutex<BTreeMap<(String, u16), u64>>,
    latency: Mutex<BTreeMap<String, Histogram>>,
    outcomes: Mutex<BTreeMap<String, u64>>,
}

impl Metrics {
    pub fn observe(&self, route: &str, status: u16, elapsed: Duration) {
        if let Ok(mut requests) = self.requests.lock() {
            *requests.entry((route.to_owned(), status)).or_default() += 1;
        }
        let ms = elapsed.as_secs_f64() * 1000.0;
        if let Ok(mut latency) = self.latency.lock() {
            let h = latency.entry(route.to_owned()).or_default();
            for (i, bound) in BUCKETS_MS.iter().enumerate() {
                if ms <= *bound {
                    h.counts[i] += 1;
                }
            }
            h.sum_ms += ms;
            h.count += 1;
        }
    }

    /// Counts governed dispatch outcomes by tool-result status.
    pub fn dispatch_outcome(&self, status: &str) {
        if let Ok(mut outcomes) = self.outcomes.lock() {
            *outcomes.entry(status.to_owned()).or_default() += 1;
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP contextos_http_requests_total HTTP requests by route and status.\n");
        out.push_str("# TYPE contextos_http_requests_total counter\n");
        if let Ok(requests) = self.requests.lock() {
            for ((route, status), n) in requests.iter() {
                let _ = writeln!(
                    out,
                    "contextos_http_requests_total{{route=\"{route}\",status=\"{status}\"}} {n}"
                );
            }
        }
        out.push_str("# HELP contextos_http_request_duration_ms Request latency in milliseconds.\n");
        out.push_str("# TYPE contextos_http_request_duration_ms histogram\n");
        if let Ok(latency) = self.latency.lock() {
            for (route, h) in latency.iter() {
                for (i, bound) in BUCKETS_MS.iter().enumerate() {
                    let _ = writeln!(
                        out,
                        "contextos_http_request_duration_ms_bucket{{route=\"{route}\",le=\"{bound}\"}} {}",
                        h.counts[i]
                    );
                }
                let _ = writeln!(
                    out,
                    "contextos_http_request_duration_ms_bucket{{route=\"{route}\",le=\"+Inf\"}} {}",
                    h.count
                );
                let _ = writeln!(
                    out,
                    "contextos_http_request_duration_ms_sum{{route=\"{route}\"}} {}",
                    h.sum_ms
                );
                let _ = writeln!(
                    out,
                    "contextos_http_request_duration_ms_count{{route=\"{route}\"}} {}",
                    h.count
                );
            }
        }
        out.push_str("# HELP contextos_dispatch_outcomes_total Governed tool dispatch outcomes by status.\n");
        out.push_str("# TYPE contextos_dispatch_outcomes_total counter\n");
        if let Ok(outcomes) = self.outcomes.lock() {
            for (status, n) in outcomes.iter() {
                let _ = writeln!(out, "contextos_dispatch_outcomes_total{{status=\"{status}\"}} {n}");
            }
        }
        out
    }
}
