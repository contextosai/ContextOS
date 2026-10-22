//! Tails every source's audit chain into the fleet model.
//!
//! Each page is verified before it is folded in, with the same checks as
//! `ctx audit-verify` (payload digest, record hash, link to the previous entry,
//! Ed25519 signature against the runtime's published keys), anchored on the last
//! entry Tower verified, from genesis on first contact. A page that fails verification
//! marks the source broken and stops reading it: nothing after an unverifiable entry
//! is shown as fact. Deployment and packs are refreshed periodically, so the authority
//! graph follows pack releases.

use std::sync::Arc;
use std::time::{Duration, Instant};

use contextos_audit::{AuditEntry, KeyRing, verify_chain};
use serde_json::json;
use tokio::sync::RwLock;

use crate::fleet::Fleet;
use crate::source::Source;

const PAGE: usize = 1000;
const REFRESH: Duration = Duration::from_secs(60);

fn now() -> String {
    wall_clock()
}

/// Wall-clock contract timestamp.
pub fn wall_clock() -> String {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX));
    contextos_contract::validation::format_unix_micros(micros)
}

/// One pass over a source: refresh its description if due, then pull and verify every
/// new entry. Returns whether the source is still readable.
pub async fn sync(
    source: &Source,
    fleet: &RwLock<Fleet>,
    keys: &mut Option<KeyRing>,
    anchor: &mut Option<AuditEntry>,
    refreshed: &mut Option<Instant>,
) -> bool {
    let id = source.id().to_owned();
    if refreshed.is_none_or(|t| t.elapsed() >= REFRESH) {
        match (source.deployment().await, source.packs().await) {
            (Ok(deployment), Ok(packs)) => {
                let mut f = fleet.write().await;
                let state = f.source(&id);
                state.deployment = deployment;
                state.packs = packs;
                *refreshed = Some(Instant::now());
            }
            (Err(e), _) | (_, Err(e)) => {
                fleet.write().await.source(&id).last_error = Some(format!("describe: {e}"));
                return true;
            }
        }
    }
    if keys.is_none() {
        match source.keys().await {
            Ok(ring) => *keys = Some(ring),
            Err(e) => {
                fleet.write().await.source(&id).last_error = Some(format!("keys: {e}"));
                return true;
            }
        }
    }
    loop {
        let from = anchor.as_ref().map_or(1, |a| a.sequence + 1);
        let page = match source.entries(from, PAGE).await {
            Ok(p) => p,
            Err(e) => {
                fleet.write().await.source(&id).last_error = Some(format!("entries: {e}"));
                return true;
            }
        };
        if page.entries.is_empty() {
            let mut f = fleet.write().await;
            let state = f.source(&id);
            state.head = page.head.unwrap_or(state.head);
            state.last_sync = Some(now());
            state.last_error = None;
            return true;
        }
        let ring = keys.as_ref().expect("loaded above");
        if let Err(e) = verify_chain(&page.entries, anchor.as_ref(), ring) {
            // An unknown key may be a rotation: reload the keys once before failing.
            let fresh = source.keys().await.ok();
            let retry = fresh.as_ref().map(|k| verify_chain(&page.entries, anchor.as_ref(), k));
            if matches!(retry, Some(Ok(()))) {
                *keys = fresh;
            } else {
                let index = match &e {
                    contextos_audit::ChainError::Invalid { index, .. } => *index,
                    contextos_audit::ChainError::Encoding(_) => 0,
                };
                let sequence = page.entries.get(index).map_or(from, |entry| entry.sequence);
                tracing::error!(source = %id, sequence, error = %e, "audit chain failed verification");
                fleet.write().await.source(&id).broken =
                    Some(json!({"sequence": sequence, "reason": e.to_string(), "at": now()}));
                return false;
            }
        }
        let more = page.next.is_some();
        {
            let mut f = fleet.write().await;
            for entry in &page.entries {
                f.apply(&id, entry);
            }
            let state = f.source(&id);
            state.head = page.head.unwrap_or(state.head);
            state.last_sync = Some(now());
            state.last_error = None;
        }
        *anchor = page.entries.last().cloned();
        if !more {
            return true;
        }
    }
}

/// Runs [`sync`] for one source until its chain breaks.
pub async fn run(source: Arc<Source>, fleet: Arc<RwLock<Fleet>>, every: Duration) {
    let (mut keys, mut anchor, mut refreshed) = (None, None, None);
    loop {
        if !sync(&source, &fleet, &mut keys, &mut anchor, &mut refreshed).await {
            return;
        }
        tokio::time::sleep(every).await;
    }
}
