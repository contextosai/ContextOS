//! Budget-ledger compaction: a runtime extension, not part of the spec's reference
//! API (see `docs/adr/0003-budget-ledger-compaction.md`).
//!
//! A budget ledger holds at most 128 mutation receipts, which caps a run at about 64
//! governed effects. The spec leaves longer histories to "an explicit versioned
//! archival/migration design that retains recovery receipts and accounting
//! continuity". Compaction is that design:
//!
//! - fully settled reservations and their receipts move, unchanged, into an archive;
//! - their usage folds into `opening_usage`, so `used`, `reserved` and `ceiling` are
//!   untouched: no capacity is created, released or forgotten;
//! - `opening_usage_ref` is re-addressed (its digest is the spec's
//!   `budget_opening_digest`) and names the archive, and the archive records the
//!   digest of the ledger it was cut from, so the ledgers form a verifiable chain;
//! - open reservations (`reserved`, `usage_unknown`) and their receipts stay, so they
//!   settle exactly as before.
//!
//! The input is fully validated and so is the output; a compaction that would not
//! yield a valid ledger with identical counters is rejected.

use serde_json::{Value, json};

use contextos_contract::canonical::sha256_canonical;
use contextos_contract::shape::is_identifier;

use crate::budget_ledger::{budget_opening_digest, valid_ledger};
use crate::run_state::int;
use crate::support::{MAX_SAFE_INTEGER, s};

pub const ARCHIVE_VERSION: &str = "contextos-rs.budget_archive.v1";
const KEYS: [&str; 4] = ["tokens", "tool_calls", "replans", "cost_units"];

/// A compacted ledger and the archive that must be persisted before it.
#[derive(Debug, Clone, PartialEq)]
pub struct Compaction {
    pub ledger: Value,
    pub archive: Value,
}

fn arr(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

/// Moves settled reservations and their receipts out of `ledger` into an archive
/// named `archive_id`. Requires the caller's expected revision and executor
/// generation, like every other ledger transition.
pub fn compact_budget_ledger(
    ledger: &Value,
    archive_id: &str,
    expected_revision: &Value,
    executor_generation: &Value,
) -> Result<Compaction, &'static str> {
    if contextos_contract::canonical::check_canonical(ledger).is_err() || !valid_ledger(ledger) {
        return Err("budget_accounting_invalid");
    }
    if !is_identifier(&json!(archive_id)) {
        return Err("budget_accounting_invalid");
    }
    if int(expected_revision) != int(&ledger["revision"]) || !expected_revision.is_u64() {
        return Err("revision_conflict");
    }
    if int(executor_generation) != int(&ledger["executor_generation"]) || !executor_generation.is_u64() {
        return Err("executor_stale");
    }
    let (settled, open): (Vec<&Value>, Vec<&Value>) = arr(&ledger["reservations"])
        .iter()
        .partition(|r| r["status"] == "settled");
    if settled.is_empty() {
        return Err("nothing_to_compact");
    }
    let archived_ids: std::collections::HashSet<&str> = settled.iter().map(|r| s(&r["reservation_id"])).collect();
    let (archived_receipts, kept_receipts): (Vec<&Value>, Vec<&Value>) = arr(&ledger["mutations"])
        .iter()
        .partition(|m| archived_ids.contains(s(&m["reservation_id"])));
    let revision = int(&ledger["revision"]) + 1;
    if revision > MAX_SAFE_INTEGER {
        return Err("counter_exhausted");
    }

    let mut opening = ledger["opening_usage"].clone();
    for k in KEYS {
        let folded = int(&opening[k]) + settled.iter().map(|r| int(&r["used"][k])).sum::<i64>();
        if folded > MAX_SAFE_INTEGER {
            return Err("counter_exhausted");
        }
        opening[k] = json!(folded);
    }
    let previous_digest = sha256_canonical(ledger).map_err(|_| "budget_accounting_invalid")?;

    let mut next = ledger.clone();
    next["revision"] = json!(revision);
    next["reservations"] = Value::Array(open.into_iter().cloned().collect());
    next["mutations"] = Value::Array(kept_receipts.into_iter().cloned().collect());
    next["opening_usage"] = opening;
    let opening_digest = budget_opening_digest(&next).ok_or("budget_accounting_invalid")?;
    next["opening_usage_ref"] = json!({
        "artifact_type": "budget_opening", "artifact_id": archive_id, "version": revision.to_string(),
        "sha256": opening_digest,
    });

    // The counters a reader relies on are unchanged, and the result is a valid ledger.
    let unchanged = ["used", "reserved", "ceiling"].iter().all(|k| ledger[*k] == next[*k]);
    if !unchanged || !valid_ledger(&next) {
        return Err("budget_accounting_invalid");
    }
    let archive = json!({
        "archive_version": ARCHIVE_VERSION,
        "archive_id": archive_id,
        "ledger_id": ledger["ledger_id"], "contract_id": ledger["contract_id"],
        "parent_run_id": ledger["parent_run_id"], "tenant_id": ledger["tenant_id"],
        "from_revision": ledger["revision"], "to_revision": revision,
        "previous_ledger_digest": previous_digest,
        "previous_opening_usage": ledger["opening_usage"],
        "previous_opening_usage_ref": ledger["opening_usage_ref"],
        "reservations": settled,
        "mutations": archived_receipts,
    });
    Ok(Compaction { ledger: next, archive })
}

/// Checks that `archive` is exactly the archive of compacting `previous` into
/// `compacted` (for auditors replaying a ledger's history).
pub fn verify_compaction(previous: &Value, compacted: &Value, archive: &Value) -> bool {
    let Some(archive_id) = archive["archive_id"].as_str() else {
        return false;
    };
    compact_budget_ledger(
        previous,
        archive_id,
        &previous["revision"],
        &previous["executor_generation"],
    )
    .is_ok_and(|c| &c.ledger == compacted && &c.archive == archive)
}
