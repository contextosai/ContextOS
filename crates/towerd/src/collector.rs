//! Tails every source's audit chain into the fleet model.
//!
//! Each page is verified before it is folded in, with the same checks as
//! `ctx audit-verify` (payload digest, record hash, link to the previous entry,
//! Ed25519 signature against the runtime's published keys), anchored on the last
//! entry Tower verified, from genesis on first contact. A page that fails verification
//! marks the source broken and stops reading it: nothing after an unverifiable entry
//! is shown as fact. Deployment and packs are refreshed periodically, so the authority
//! graph follows pack releases. After a restart, the chain read again must pass through
//! the entry Tower last pinned for the source (see [`crate::pins`]).

use std::sync::Arc;
use std::time::{Duration, Instant};

use contextos_audit::{AuditEntry, KeyRing, verify_chain};
use serde_json::json;
use tokio::sync::RwLock;

use crate::fleet::Fleet;
use crate::pins::{Pin, Pins};
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
    sync_pinned(source, fleet, keys, anchor, refreshed, &mut None, None).await
}

async fn broken(fleet: &RwLock<Fleet>, id: &str, sequence: u64, reason: &str) -> bool {
    tracing::error!(source = %id, sequence, reason, "audit chain failed verification");
    fleet.write().await.source(id).broken = Some(json!({"sequence": sequence, "reason": reason, "at": now()}));
    false
}

/// As [`sync`], checking the chain against `pin` (the entry Tower pinned before a
/// restart) until it is passed, and moving the pin in `pins` forward afterwards.
pub async fn sync_pinned(
    source: &Source,
    fleet: &RwLock<Fleet>,
    keys: &mut Option<KeyRing>,
    anchor: &mut Option<AuditEntry>,
    refreshed: &mut Option<Instant>,
    pin: &mut Option<Pin>,
    pins: Option<&dyn Pins>,
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
            // Caught up without reaching the pinned entry: the history now ends before it.
            if let Some(p) = pin.as_ref()
                && anchor.as_ref().is_none_or(|a| a.sequence < p.sequence)
            {
                return broken(fleet, &id, p.sequence, "history_truncated").await;
            }
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
        if let Some(p) = pin.as_ref()
            && let Some(entry) = page.entries.iter().find(|e| e.sequence == p.sequence)
        {
            if entry.record_hash != p.record_hash {
                return broken(fleet, &id, p.sequence, "history_rewritten").await;
            }
            *pin = None;
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
            state.anchor = page.entries.last().cloned();
        }
        *anchor = page.entries.last().cloned();
        if pin.is_none()
            && let (Some(pins), Some(last)) = (pins, anchor.as_ref())
        {
            let next = Pin {
                sequence: last.sequence,
                record_hash: last.record_hash.clone(),
            };
            if let Err(error) = pins.advance(&id, &next).await {
                tracing::warn!(source = %id, %error, "could not pin the verified anchor");
            }
        }
        if !more {
            // The last page, and the pinned entry not among what was read: truncated.
            if let Some(p) = pin.as_ref()
                && anchor.as_ref().is_none_or(|a| a.sequence < p.sequence)
            {
                return broken(fleet, &id, p.sequence, "history_truncated").await;
            }
            return true;
        }
    }
}

/// Runs [`sync_pinned`] for one source until its chain breaks, continuing from the
/// last entry Tower verified from it (so a restarted collector never folds an entry
/// twice), and checking the chain against the source's pin.
pub async fn run(source: Arc<Source>, fleet: Arc<RwLock<Fleet>>, every: Duration, pins: Option<Arc<dyn Pins>>) {
    let mut anchor = fleet
        .read()
        .await
        .sources
        .get(source.id())
        .and_then(|s| s.anchor.clone());
    // The pin, unless this process has already verified past it.
    let mut pin = loop {
        match &pins {
            None => break None,
            Some(p) => match p.get(source.id()).await {
                Ok(pin) => break pin.filter(|p| anchor.as_ref().is_none_or(|a| a.sequence < p.sequence)),
                Err(error) => {
                    tracing::warn!(source = %source.id(), %error, "could not read the pinned anchor; retrying");
                    fleet.write().await.source(source.id()).last_error = Some(format!("pin: {error}"));
                    tokio::time::sleep(every).await;
                }
            },
        }
    };
    let (mut keys, mut refreshed) = (None, None);
    loop {
        let pinned = pins.as_deref();
        if !sync_pinned(
            &source,
            &fleet,
            &mut keys,
            &mut anchor,
            &mut refreshed,
            &mut pin,
            pinned,
        )
        .await
        {
            return;
        }
        tokio::time::sleep(every).await;
    }
}
