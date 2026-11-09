//! Where a shared guarantee reads the resource it limits, the amount a call reserves
//! and the window the limit applies to.
//!
//! By default a guarantee limits a business resource named in the call's arguments
//! (`resource_pointer`, an order) by an amount in the arguments (`amount_pointer`).
//! Two other sources cover spend caps:
//!
//! - `resource_from = "actor"` or `"tenant"`: the limit is per agent (the run's actor)
//!   or for the whole tenant, so a cap needs no argument naming it.
//! - `amount_table`: the call reserves an estimate looked up by one argument
//!   (`key_pointer`, an instance type or a model) in `prices`, or `default`. Estimates
//!   are recorded as such (`estimated` in the reservation's audit entry); the reserved
//!   estimate is what settles.
//!
//! And `window_seconds` makes the limit apply per window (a day, an hour): each window
//! of a resource is its own ledger, so the next window starts empty. Holds stay in the
//! window they were reserved in.

use std::collections::BTreeMap;

use contextos_contract::validation::elapsed_millis;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::shared_guarantees::SharedGuarantee;

/// Windows are at least a minute and at most 31 days.
pub const MIN_WINDOW_SECONDS: u64 = 60;
pub const MAX_WINDOW_SECONDS: u64 = 31 * 86_400;
/// At most this many prices in a table.
pub const MAX_PRICES: usize = 1024;

/// A limit on something the run is, not something the call names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceFrom {
    /// The run's actor (the agent principal it was admitted for).
    Actor,
    /// The tenant: one limit across every run.
    Tenant,
}

/// Estimated amounts by an argument's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AmountTable {
    /// JSON Pointer to the argument whose value (a string, or a number as text) is
    /// looked up in `prices`.
    pub key_pointer: String,
    pub prices: BTreeMap<String, u64>,
    /// The estimate for a value not in `prices`; without one such a call is refused
    /// (`shared_guarantee_amount_invalid`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<u64>,
}

fn amount_ok(n: u64) -> bool {
    n > 0 && n <= contextos_kernel::shared_exposure::MAX_EXACT_EXPOSURE
}

/// Whether the rule names exactly one resource source and one amount source, each
/// well formed, and a window in range.
pub(crate) fn valid(rule: &SharedGuarantee, pointer: impl Fn(&str) -> bool) -> bool {
    let resource = match (rule.resource_pointer.is_empty(), rule.resource_from) {
        (false, None) => pointer(&rule.resource_pointer),
        (true, Some(_)) => true,
        _ => false,
    };
    let amount = match (rule.amount_pointer.is_empty(), &rule.amount_table) {
        (false, None) => pointer(&rule.amount_pointer) && rule.amount_pointer != rule.resource_pointer,
        (true, Some(table)) => {
            pointer(&table.key_pointer)
                && !table.prices.is_empty()
                && table.prices.len() <= MAX_PRICES
                && table
                    .prices
                    .iter()
                    .all(|(k, v)| !k.is_empty() && k.len() <= 256 && amount_ok(*v))
                && table.default.is_none_or(amount_ok)
        }
        _ => false,
    };
    let window = rule
        .window_seconds
        .is_none_or(|w| (MIN_WINDOW_SECONDS..=MAX_WINDOW_SECONDS).contains(&w));
    resource && amount && window
}

/// The resource identifier the call reserves against, before canonicalization.
pub(crate) fn resource(rule: &SharedGuarantee, admission: &RunAdmission, args: &Value) -> Option<String> {
    match rule.resource_from {
        Some(ResourceFrom::Actor) => admission.actor["principal_id"].as_str().map(str::to_owned),
        Some(ResourceFrom::Tenant) => Some(admission.tenant_id.clone()),
        None => args
            .pointer(&rule.resource_pointer)
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

/// The amount the call reserves, and whether it is an estimate.
pub(crate) fn amount(rule: &SharedGuarantee, args: &Value) -> Option<(u64, bool)> {
    let found = match &rule.amount_table {
        None => args
            .pointer(&rule.amount_pointer)
            .and_then(Value::as_u64)
            .map(|n| (n, false)),
        Some(table) => {
            let key = match args.pointer(&table.key_pointer) {
                Some(Value::String(s)) => Some(s.clone()),
                Some(n @ Value::Number(_)) => Some(n.to_string()),
                _ => None,
            };
            key.and_then(|k| table.prices.get(&k).copied())
                .or(table.default)
                .map(|n| (n, true))
        }
    };
    found.filter(|(n, _)| amount_ok(*n))
}

/// The start of the window `now` falls in, in seconds since the epoch, for a windowed
/// guarantee.
pub(crate) fn window_start(rule: &SharedGuarantee, now: &str) -> Option<u64> {
    let width = rule.window_seconds?;
    let seconds = elapsed_millis("1970-01-01T00:00:00Z", now)? / 1000;
    Some(seconds - seconds % width)
}

/// What the ledger's resource digest covers: the canonical identifier, and the window
/// for a windowed guarantee.
pub(crate) fn digest_input(canonical_id: &str, window_start: Option<u64>) -> Value {
    match window_start {
        None => json!(canonical_id),
        Some(start) => json!({"resource": canonical_id, "window_start": start}),
    }
}
