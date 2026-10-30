//! Conserved exposure for a business resource shared across unrelated agent runs.
//! This runtime extension is deliberately independent of normative run budgets.
//! Callers must authenticate observations and commit transitions with CAS.
//!
//! A settled receipt (committed or released) is kept as a fence: it refuses a stalled
//! dispatcher that comes back for its attempt. That fence matters only while such a
//! dispatcher could still send, which the caller bounds by time. [`compact_exposure`]
//! stamps each receipt the first time it is seen settled and archives it once the
//! caller's retention has passed since, folding its committed amount into
//! `archived_committed`. Held receipts are never archived, so [`MAX_EXPOSURE_RECEIPTS`]
//! bounds the receipts live at once, not a resource's lifetime.
use std::cmp::Ordering;
use std::collections::BTreeMap;

use contextos_contract::validation::{add_contract_seconds, compare_contract_times, is_contract_timestamp};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::TransitionResult;

pub const MAX_EXPOSURE_RECEIPTS: usize = 1024;
pub const MAX_EXACT_EXPOSURE: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureBinding {
    pub guarantee_id: String,
    pub definition_digest: String,
    pub resource_digest: String,
    pub limit: u64,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureClaim {
    pub reservation_id: String,
    pub action_digest: String,
    pub attempt_id: String,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Held,
    Committed,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    claim: ExposureClaim,
    status: Status,
    dispatch_started: bool,
    dispatch_aborted: bool,
    observation_recorded: bool,
    /// When compaction first saw the receipt settled (never set while held).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settled_seen_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    binding: ExposureBinding,
    /// Everything committed, archived receipts included.
    committed: u64,
    held: u64,
    receipts: BTreeMap<String, Receipt>,
    /// The committed amount of archived receipts, and how many were archived.
    #[serde(default)]
    archived_committed: u64,
    #[serde(default)]
    archived_receipts: u64,
}

fn identifier(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

pub fn exposure_digest(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

fn valid_binding(b: &ExposureBinding) -> bool {
    identifier(&b.guarantee_id)
        && identifier(&b.unit)
        && exposure_digest(&b.definition_digest)
        && exposure_digest(&b.resource_digest)
        && b.limit > 0
        && b.limit <= MAX_EXACT_EXPOSURE
}

fn valid_claim(c: &ExposureClaim) -> bool {
    identifier(&c.reservation_id)
        && identifier(&c.attempt_id)
        && exposure_digest(&c.action_digest)
        && c.amount > 0
        && c.amount <= MAX_EXACT_EXPOSURE
}

fn checked(state: &Value, binding: &ExposureBinding) -> Result<Ledger, &'static str> {
    if !valid_binding(binding) {
        return Err("shared_guarantee_invalid");
    }
    let ledger: Ledger = serde_json::from_value(state.clone()).map_err(|_| "shared_guarantee_invalid")?;
    if &ledger.binding != binding {
        return Err("shared_guarantee_definition_mismatch");
    }
    if ledger.receipts.len() > MAX_EXPOSURE_RECEIPTS {
        return Err("shared_guarantee_invalid");
    }
    let (mut committed, mut held) = (0_u64, 0_u64);
    for (id, receipt) in &ledger.receipts {
        if id != &receipt.claim.reservation_id
            || !valid_claim(&receipt.claim)
            || receipt.dispatch_started && receipt.dispatch_aborted
            || receipt
                .settled_seen_at
                .as_ref()
                .is_some_and(|at| receipt.status == Status::Held || !is_contract_timestamp(at))
        {
            return Err("shared_guarantee_invalid");
        }
        let total = match receipt.status {
            Status::Held => &mut held,
            Status::Committed => &mut committed,
            Status::Released => continue,
        };
        *total = total
            .checked_add(receipt.claim.amount)
            .ok_or("shared_guarantee_invalid")?;
    }
    if committed.checked_add(ledger.archived_committed) != Some(ledger.committed)
        || held != ledger.held
        || committed.checked_add(held).is_none_or(|n| n > binding.limit)
    {
        return Err("shared_guarantee_invalid");
    }
    Ok(ledger)
}

pub fn empty_exposure(binding: &ExposureBinding) -> Value {
    serde_json::json!(Ledger {
        binding: binding.clone(),
        committed: 0,
        held: 0,
        receipts: BTreeMap::new(),
        archived_committed: 0,
        archived_receipts: 0,
    })
}

/// Validated operator view; receipt identities stay in the protected store.
pub fn exposure_summary(state: &Value) -> Option<Value> {
    let binding: ExposureBinding = serde_json::from_value(state.get("binding")?.clone()).ok()?;
    let ledger = checked(state, &binding).ok()?;
    Some(
        serde_json::json!({"guarantee_id":binding.guarantee_id,"definition_digest":binding.definition_digest,
        "resource_digest":binding.resource_digest,"unit":binding.unit,"limit":binding.limit,
        "committed":ledger.committed,"held":ledger.held,"available":binding.limit-ledger.committed-ledger.held,
        "receipt_count":ledger.receipts.len(),"archived_receipts":ledger.archived_receipts}),
    )
}

/// Reserves a single logical effect. An unresolved attempt must be reconciled
/// before another attempt can reserve. Operation claiming precedes this transition.
pub fn reserve_exposure(state: &Value, binding: &ExposureBinding, claim: &ExposureClaim) -> TransitionResult {
    let mut ledger = match checked(state, binding) {
        Ok(v) if valid_claim(claim) => v,
        Ok(_) => return TransitionResult::rejected(state.clone(), "shared_guarantee_invalid"),
        Err(r) => return TransitionResult::rejected(state.clone(), r),
    };
    let additional = claim.amount;
    if let Some(receipt) = ledger.receipts.get(&claim.reservation_id) {
        let old = &receipt.claim;
        if old.action_digest != claim.action_digest || old.amount != claim.amount {
            return TransitionResult::rejected(state.clone(), "shared_guarantee_binding_mismatch");
        }
        match receipt.status {
            Status::Committed => {
                return TransitionResult::rejected(state.clone(), "shared_guarantee_already_committed");
            }
            Status::Held if old.attempt_id == claim.attempt_id => {
                return TransitionResult::accepted(state.clone(), vec![]);
            }
            Status::Held => return TransitionResult::rejected(state.clone(), "shared_guarantee_unresolved"),
            Status::Released if old.attempt_id == claim.attempt_id => {
                return TransitionResult::rejected(state.clone(), "shared_guarantee_attempt_closed");
            }
            Status::Released => {}
        }
    } else if ledger.receipts.len() >= MAX_EXPOSURE_RECEIPTS {
        return TransitionResult::rejected(state.clone(), "shared_guarantee_saturated");
    }
    // checked() establishes both totals are bounded by limit; checked arithmetic
    // still rejects hostile input without wrapping.
    if ledger
        .committed
        .checked_add(ledger.held)
        .and_then(|n| n.checked_add(additional))
        .is_none_or(|n| n > binding.limit)
    {
        return TransitionResult::rejected(state.clone(), "shared_guarantee_exceeded");
    }
    ledger.held += additional;
    ledger.receipts.insert(
        claim.reservation_id.clone(),
        Receipt {
            claim: claim.clone(),
            status: Status::Held,
            dispatch_started: false,
            dispatch_aborted: false,
            observation_recorded: false,
            settled_seen_at: None,
        },
    );
    TransitionResult::accepted(serde_json::json!(ledger), vec![])
}

/// Only authenticated, accepted observations may choose "committed" or "released".
/// Unknown and partial effects choose "held"; there is no clock-based release.
pub fn settle_exposure(
    state: &Value,
    binding: &ExposureBinding,
    claim: &ExposureClaim,
    outcome: &str,
) -> TransitionResult {
    let mut ledger = match checked(state, binding) {
        Ok(v) => v,
        Err(r) => return TransitionResult::rejected(state.clone(), r),
    };
    let Some(receipt) = ledger.receipts.get_mut(&claim.reservation_id) else {
        return TransitionResult::rejected(state.clone(), "shared_guarantee_reservation_missing");
    };
    if &receipt.claim != claim {
        return TransitionResult::rejected(state.clone(), "shared_guarantee_binding_mismatch");
    }
    let next = match outcome {
        "held" => Status::Held,
        "committed" => Status::Committed,
        "released" => Status::Released,
        _ => return TransitionResult::rejected(state.clone(), "shared_guarantee_invalid"),
    };
    if receipt.status == next {
        return TransitionResult::accepted(state.clone(), vec![]);
    }
    if receipt.status != Status::Held {
        return TransitionResult::rejected(state.clone(), "shared_guarantee_settlement_conflict");
    }
    if next == Status::Released && receipt.dispatch_started && !receipt.observation_recorded {
        return TransitionResult::rejected(state.clone(), "shared_guarantee_dispatch_active");
    }
    ledger.held -= claim.amount;
    if next == Status::Committed {
        ledger.committed += claim.amount;
    }
    receipt.status = next;
    TransitionResult::accepted(serde_json::json!(ledger), vec![])
}

/// Dispatch and pre-dispatch recovery contend on the same protected receipt.
/// A missing reservation can be aborted by inserting a closed attempt tombstone.
pub fn transition_exposure_dispatch(
    state: &Value,
    binding: &ExposureBinding,
    claim: &ExposureClaim,
    event: &str,
) -> TransitionResult {
    let mut ledger = match checked(state, binding) {
        Ok(v) if valid_claim(claim) => v,
        Ok(_) => return TransitionResult::rejected(state.clone(), "shared_guarantee_invalid"),
        Err(r) => return TransitionResult::rejected(state.clone(), r),
    };
    if event == "abort" && !ledger.receipts.contains_key(&claim.reservation_id) {
        if ledger.receipts.len() >= MAX_EXPOSURE_RECEIPTS {
            return TransitionResult::rejected(state.clone(), "shared_guarantee_saturated");
        }
        ledger.receipts.insert(
            claim.reservation_id.clone(),
            Receipt {
                claim: claim.clone(),
                status: Status::Released,
                dispatch_started: false,
                dispatch_aborted: true,
                observation_recorded: false,
                settled_seen_at: None,
            },
        );
        return TransitionResult::accepted(serde_json::json!(ledger), vec![]);
    }
    let Some(receipt) = ledger.receipts.get_mut(&claim.reservation_id) else {
        return TransitionResult::rejected(state.clone(), "shared_guarantee_reservation_missing");
    };
    if &receipt.claim != claim {
        return TransitionResult::rejected(state.clone(), "shared_guarantee_binding_mismatch");
    }
    match event {
        "start" if receipt.status == Status::Held && !receipt.dispatch_started && !receipt.dispatch_aborted => {
            receipt.dispatch_started = true;
        }
        "start" => return TransitionResult::rejected(state.clone(), "shared_guarantee_dispatch_closed"),
        "observe" => receipt.observation_recorded = true,
        "abort" if receipt.dispatch_started && !receipt.observation_recorded => {
            return TransitionResult::rejected(state.clone(), "shared_guarantee_dispatch_active");
        }
        "abort" if !receipt.dispatch_started => receipt.dispatch_aborted = true,
        "abort" => {}
        _ => return TransitionResult::rejected(state.clone(), "shared_guarantee_invalid"),
    }
    TransitionResult::accepted(serde_json::json!(ledger), vec![])
}

/// Stamps settled receipts first seen settled at `now`, and archives those stamped at
/// least `retain_seconds` before it. Accepted unchanged when there is nothing to do.
/// `retain_seconds` must outlast every way a settled attempt's dispatcher could still
/// send; the caller owns that bound.
pub fn compact_exposure(state: &Value, binding: &ExposureBinding, now: &str, retain_seconds: u64) -> TransitionResult {
    let mut ledger = match checked(state, binding) {
        Ok(v) if is_contract_timestamp(now) => v,
        Ok(_) => return TransitionResult::rejected(state.clone(), "shared_guarantee_invalid"),
        Err(r) => return TransitionResult::rejected(state.clone(), r),
    };
    let mut changed = false;
    let mut archived = Vec::new();
    for (id, receipt) in &mut ledger.receipts {
        if receipt.status == Status::Held {
            continue;
        }
        match &receipt.settled_seen_at {
            None => {
                receipt.settled_seen_at = Some(now.to_owned());
                changed = true;
            }
            Some(seen) => {
                let due = add_contract_seconds(seen, retain_seconds)
                    .and_then(|due| compare_contract_times(&due, now))
                    .is_some_and(|o| o != Ordering::Greater);
                if due {
                    archived.push(id.clone());
                }
            }
        }
    }
    for id in archived {
        let receipt = ledger.receipts.remove(&id).expect("listed above");
        if receipt.status == Status::Committed {
            ledger.archived_committed += receipt.claim.amount;
        }
        ledger.archived_receipts = ledger.archived_receipts.saturating_add(1);
        changed = true;
    }
    if !changed {
        return TransitionResult::accepted(state.clone(), vec![]);
    }
    TransitionResult::accepted(serde_json::json!(ledger), vec![])
}
