//! Cluster membership for shared tenant limits.
//!
//! Every replica records a heartbeat in one shared document (`replica id -> last seen`)
//! and counts the replicas seen within the time-to-live; the limiter enforces that
//! share of each tenant's limits. Heartbeats are compare-and-swap writes every
//! `interval`, so the store sees `replicas / interval` writes and no request waits on
//! it. A replica that stops (crash, scale-in) ages out after the time-to-live and the
//! survivors' shares grow back. Wall-clock skew between replicas shorter than the
//! time-to-live is tolerated.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use contextos_store::{DocKey, DocKind, DocumentStore, StoreError};
use serde_json::{Map, Value, json};

use crate::limits::Limiter;

/// Membership is cluster-wide, not per tenant.
const SYSTEM_TENANT: &str = "_cluster";

fn key() -> DocKey {
    DocKey::new(SYSTEM_TENANT, DocKind::Replicas, "replicas")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// A replica id unique to this process start.
pub fn replica_id() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    format!(
        "{}-{}-{nanos:x}",
        std::env::var("HOSTNAME").unwrap_or_default(),
        std::process::id()
    )
}

/// The live membership as one replica sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Members {
    pub count: usize,
    /// This replica has the smallest id among the live ones; it runs cluster-wide
    /// chores (retention) so they are not done twice.
    pub leader: bool,
}

/// Records this replica's heartbeat at `now`, drops replicas not seen within `ttl`,
/// and returns the live membership (including this one).
pub async fn heartbeat<S: DocumentStore>(
    store: &S,
    replica: &str,
    now: u64,
    ttl: Duration,
) -> Result<Members, StoreError> {
    let ttl = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
    for _ in 0..8 {
        let current = store.get(&key()).await?;
        let mut live: Map<String, Value> = current
            .as_ref()
            .and_then(|c| c.body["replicas"].as_object().cloned())
            .unwrap_or_default();
        // Live: seen within the time-to-live, and not dated beyond it into the future (a
        // fast clock that then stopped would otherwise count, and lead, long after).
        live.retain(|_, seen| {
            seen.as_u64()
                .is_some_and(|seen| now.saturating_sub(seen) <= ttl && seen.saturating_sub(now) <= ttl)
        });
        live.insert(replica.to_owned(), json!(now));
        let members = Members {
            count: live.len(),
            leader: live.keys().next().is_some_and(|first| first == replica),
        };
        let state = json!({"replicas": live});
        let written = match &current {
            None => store.create(&key(), &state).await.map(|_| ()),
            Some(c) => store.compare_and_swap(&key(), c.revision, &state).await.map(|_| ()),
        };
        match written {
            Ok(()) => return Ok(members),
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e),
        }
    }
    Err(StoreError::Conflict {
        expected: None,
        actual: None,
    })
}

/// Heartbeats forever, keeping the limiter's replica count current. A failed beat
/// keeps the last count (limits stay as tight as last observed).
pub async fn run<S: DocumentStore + 'static>(
    store: Arc<S>,
    limiter: Arc<Limiter>,
    leader: Arc<std::sync::atomic::AtomicBool>,
    interval: Duration,
) {
    let replica = replica_id();
    let ttl = interval * 3;
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match heartbeat(store.as_ref(), &replica, now_ms(), ttl).await {
            Ok(members) => {
                limiter.set_replicas(members.count);
                leader.store(members.leader, std::sync::atomic::Ordering::Relaxed);
            }
            Err(error) => tracing::warn!(%error, "replica heartbeat failed; keeping the last replica count"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contextos_store::MemoryStore;

    #[tokio::test]
    async fn replicas_join_and_age_out() {
        let store = MemoryStore::new();
        let ttl = Duration::from_secs(15);
        assert_eq!(
            heartbeat(&store, "a", 1_000, ttl).await.unwrap(),
            Members { count: 1, leader: true }
        );
        assert_eq!(
            heartbeat(&store, "b", 2_000, ttl).await.unwrap(),
            Members {
                count: 2,
                leader: false
            }
        );
        assert_eq!(
            heartbeat(&store, "a", 6_000, ttl).await.unwrap().count,
            2,
            "a beat again; b is live"
        );
        // b stops; after the time-to-live only a remains.
        assert_eq!(
            heartbeat(&store, "a", 18_000, ttl).await.unwrap(),
            Members { count: 1, leader: true }
        );
        // A replica with a fast clock writes a heartbeat dated far ahead; an honest
        // replica neither counts it nor lets it lead (its id sorts first).
        assert_eq!(heartbeat(&store, "0-fast", 1_000_000, ttl).await.unwrap().count, 1);
        assert_eq!(
            heartbeat(&store, "a", 18_500, ttl).await.unwrap(),
            Members { count: 1, leader: true }
        );
        // b comes back.
        assert_eq!(
            heartbeat(&store, "b", 19_000, ttl).await.unwrap(),
            Members {
                count: 2,
                leader: false
            }
        );
    }
}
