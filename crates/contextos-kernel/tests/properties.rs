//! Properties of the kernel, checked over generated inputs rather than examples.
//!
//! The reference vectors pin the kernel to the specification case by case; these
//! check the invariants the rest of the runtime relies on, for every input proptest
//! generates (and, for the run lifecycle, for every state). Each property is named by
//! its identifier in `docs/verification/PROPERTIES.md`.

// Generated values are small and non-negative, so the casts below cannot wrap or truncate.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]

use contextos_kernel::authorization::{authority_scope_narrows, compose_policy_outcomes, scope_mismatch};
use contextos_kernel::budget_ledger::{budget_limits_digest, reserve_budget, settle_budget, settlement_intent_digest};
use contextos_kernel::operation_ledger::{claim_operation, record_effect_observation};
use contextos_kernel::run_state::next_status;
use proptest::prelude::*;
use proptest::sample::subsequence;
use serde_json::{Value, json};

mod common;

const IDS: [&str; 3] = ["a", "b", "c"];
const LABELS: [&str; 4] = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"];
const POINTERS: [&str; 2] = ["/x", "/y"];

fn ids() -> impl Strategy<Value = Vec<&'static str>> {
    subsequence(IDS.to_vec(), 0..=IDS.len())
}

/// Argument values, including an integral float and a negative number, which the
/// constraint kinds treat differently.
fn argument() -> impl Strategy<Value = Value> {
    prop_oneof![
        (0_i64..5).prop_map(Value::from),
        Just(json!(2.0)),
        Just(json!(-1)),
        Just(json!("s")),
    ]
}

fn constraint(pointer: &'static str) -> impl Strategy<Value = Value> {
    prop_oneof![
        argument().prop_map(move |v| json!({"pointer": pointer, "kind": "equals", "value": v})),
        prop::collection::vec(argument(), 1..4)
            .prop_map(move |v| json!({"pointer": pointer, "kind": "one_of", "values": v})),
        (0_i64..5).prop_map(move |m| json!({"pointer": pointer, "kind": "max_integer", "maximum": m})),
    ]
}

fn amount() -> impl Strategy<Value = Option<Value>> {
    prop::option::of(
        (0_u64..6, prop::sample::select(vec!["INR", "USD"]))
            .prop_map(|(m, c)| json!({"minor_units": m, "currency": c})),
    )
}

prop_compose! {
    fn scope()(
        purposes in ids(), capabilities in ids(), resources in ids(), destinations in ids(),
        labels in subsequence(LABELS.to_vec(), 0..=LABELS.len()),
        x in prop::option::of(constraint("/x")), y in prop::option::of(constraint("/y")),
        ceiling in amount(),
    ) -> Value {
        let constraints: Vec<Value> = [x, y].into_iter().flatten().collect();
        let mut scope = json!({"root_run_id": "run_root", "purpose_ids": purposes, "capability_ids": capabilities,
            "resource_ids": resources, "destination_ids": destinations, "classification_labels": labels,
            "argument_constraints": constraints});
        if let Some(ceiling) = ceiling {
            scope["amount_ceiling"] = ceiling;
        }
        scope
    }
}

prop_compose! {
    fn binding()(
        purpose in prop::sample::select(IDS.to_vec()), capability in prop::sample::select(IDS.to_vec()),
        resources in ids(), destinations in ids(), label in prop::sample::select(LABELS.to_vec()),
        x in prop::option::of(argument()), y in prop::option::of(argument()), amount in amount(),
    ) -> Value {
        let mut arguments = serde_json::Map::new();
        for (pointer, value) in POINTERS.iter().zip([x, y]) {
            if let Some(value) = value {
                arguments.insert(pointer[1..].to_owned(), value);
            }
        }
        let mut binding = json!({"purpose_id": purpose, "capability_id": capability, "resource_ids": resources,
            "destination_ids": destinations, "action_risk": {"data_scope": label}, "arguments": arguments});
        if let Some(amount) = amount {
            binding["amount"] = amount;
        }
        binding
    }
}

/// A scope derived from `parent` by narrowing each dimension (`seed` picks how).
fn narrowed(parent: &Value, seed: u64) -> Value {
    let mut bits = seed;
    let mut next = |n: u64| {
        let v = bits % n;
        bits = (bits / n) ^ bits.rotate_left(17);
        v
    };
    let mut child = parent.clone();
    for key in [
        "purpose_ids",
        "capability_ids",
        "resource_ids",
        "destination_ids",
        "classification_labels",
    ] {
        let kept: Vec<Value> = parent[key]
            .as_array()
            .unwrap()
            .iter()
            .filter(|_| next(3) != 0)
            .cloned()
            .collect();
        child[key] = json!(kept);
    }
    let constraints: Vec<Value> = parent["argument_constraints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| match c["kind"].as_str().unwrap() {
            "max_integer" => {
                let max = c["maximum"].as_i64().unwrap();
                match next(3) {
                    0 => json!({"pointer": c["pointer"], "kind": "equals", "value": next(max as u64 + 1)}),
                    1 => json!({"pointer": c["pointer"], "kind": "one_of", "values": [0, max]}),
                    _ => json!({"pointer": c["pointer"], "kind": "max_integer", "maximum": next(max as u64 + 1)}),
                }
            }
            "one_of" => {
                let values = c["values"].as_array().unwrap();
                json!({"pointer": c["pointer"], "kind": "equals", "value": values[next(values.len() as u64) as usize]})
            }
            _ => c.clone(),
        })
        .collect();
    child["argument_constraints"] = json!(constraints);
    // A narrower scope may also constrain an argument the parent left open.
    if child["argument_constraints"].as_array().unwrap().is_empty() && next(2) == 0 {
        child["argument_constraints"] = json!([{"pointer": "/x", "kind": "max_integer", "maximum": 1}]);
    }
    if let Some(ceiling) = parent.get("amount_ceiling") {
        let max = ceiling["minor_units"].as_u64().unwrap();
        child["amount_ceiling"] = json!({"minor_units": next(max + 1), "currency": ceiling["currency"]});
    }
    child
}

/// Counts how often a property's premise held (`PROPERTY_STATS=1` prints them), so a
/// property cannot pass by never meeting its premise.
fn stat(name: &'static str) {
    static COUNTS: std::sync::Mutex<Vec<(&str, u64)>> = std::sync::Mutex::new(Vec::new());
    if std::env::var_os("PROPERTY_STATS").is_none() {
        return;
    }
    let mut counts = COUNTS.lock().unwrap();
    match counts.iter_mut().find(|(n, _)| *n == name) {
        Some((_, c)) => *c += 1,
        None => counts.push((name, 1)),
    }
    eprintln!("{counts:?}");
}

/// `binding` moved inside `scope` where it can be (`seed` picks values), so that the
/// premise of a soundness property is met often rather than by chance.
fn fit(binding: &Value, scope: &Value, seed: u64) -> Value {
    let mut fitted = binding.clone();
    let first = |key: &str| {
        scope[key]
            .as_array()
            .and_then(|a| a.get(seed as usize % a.len().max(1)))
            .cloned()
    };
    if let Some(purpose) = first("purpose_ids") {
        fitted["purpose_id"] = purpose;
    }
    if let Some(capability) = first("capability_ids") {
        fitted["capability_id"] = capability;
    }
    if let Some(label) = first("classification_labels") {
        fitted["action_risk"]["data_scope"] = label;
    }
    for key in ["resource_ids", "destination_ids"] {
        let allowed = scope[key].as_array().unwrap();
        let kept: Vec<&Value> = fitted[key]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| allowed.contains(v))
            .collect();
        fitted[key] = json!(kept);
    }
    for c in scope["argument_constraints"].as_array().unwrap() {
        let value = match c["kind"].as_str().unwrap() {
            "equals" => c["value"].clone(),
            "one_of" => c["values"][seed as usize % c["values"].as_array().unwrap().len()].clone(),
            _ => json!(seed % (c["maximum"].as_u64().unwrap() + 1)),
        };
        fitted["arguments"][&c["pointer"].as_str().unwrap()[1..]] = value;
    }
    if let Some(ceiling) = scope.get("amount_ceiling") {
        fitted["amount"] = json!({"minor_units": seed % (ceiling["minor_units"].as_u64().unwrap() + 1),
            "currency": ceiling["currency"]});
    }
    fitted
}

fn covers(scope: &Value, binding: &Value) -> bool {
    scope_mismatch(binding, scope).is_none()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// AUTH-1: a scope that narrows another covers no action the other does not.
    #[test]
    fn narrowing_never_admits_more(parent in scope(), other in scope(), seed in any::<u64>(), action in binding()) {
        for child in [narrowed(&parent, seed), other] {
            let action = if seed % 4 == 0 { action.clone() } else { fit(&action, &child, seed >> 2) };
            if authority_scope_narrows(&child, &parent) && covers(&child, &action) {
                stat("AUTH-1 child covers the action");
                prop_assert!(covers(&parent, &action), "child {child} admits {action} beyond parent {parent}");
            }
        }
    }

    /// AUTH-2: narrowing each dimension is recognised as narrowing, and narrowing is
    /// reflexive and transitive (a delegation chain narrows its root).
    #[test]
    fn narrowing_is_a_preorder(root in scope(), a in any::<u64>(), b in any::<u64>()) {
        prop_assert!(authority_scope_narrows(&root, &root));
        let middle = narrowed(&root, a);
        let leaf = narrowed(&middle, b);
        prop_assert!(authority_scope_narrows(&middle, &root), "{middle} should narrow {root}");
        prop_assert!(authority_scope_narrows(&leaf, &middle));
        prop_assert!(authority_scope_narrows(&leaf, &root));
    }
}

/// SPEC-1, found by AUTH-1: the delegation rule read a missing `amount_ceiling` as
/// unlimited while the grant-scope check reads it as "no amount", so a scope that
/// added a ceiling "narrowed" one it widened. The specification now reads it as "no
/// amount" in both (proposal spec-0004); this pins the corrected rule.
#[test]
fn spec_1_a_ceiling_where_none_was_widens() {
    let parent = json!({"root_run_id": "run_root", "purpose_ids": ["p"], "capability_ids": ["c"], "resource_ids": [],
        "destination_ids": [], "classification_labels": ["PUBLIC"], "argument_constraints": []});
    let mut child = parent.clone();
    child["amount_ceiling"] = json!({"minor_units": 100, "currency": "INR"});
    let refund = json!({"purpose_id": "p", "capability_id": "c", "resource_ids": [], "destination_ids": [],
        "action_risk": {"data_scope": "PUBLIC"}, "arguments": {}, "amount": {"minor_units": 100, "currency": "INR"}});
    assert_eq!(scope_mismatch(&refund, &parent), Some("amount"));
    assert_eq!(scope_mismatch(&refund, &child), None);
    assert!(!authority_scope_narrows(&child, &parent), "adding a ceiling widens");
    assert!(!authority_scope_narrows(&parent, &child), "dropping one is refused too");
    assert!(authority_scope_narrows(&parent, &parent));
}

fn bundle(id: &str) -> Value {
    json!({"artifact_type": "policy_bundle", "artifact_id": id, "version": "1",
        "sha256": format!("sha256:{}", "ab".repeat(32))})
}

prop_compose! {
    fn outcome()(
        guardrail in any::<bool>(), priority in 0_u8..3,
        verdict in prop::sample::select(vec!["allow", "deny", "require_approval", "escalate", "error"]),
        rule in 0_u8..4, pack in 0_u8..2,
        obligations in subsequence(vec!["log", "notify"], 0..=2),
    ) -> Value {
        json!({"category": if guardrail { "guardrail" } else { "business" }, "priority": priority,
            "verdict": verdict, "rule_id": format!("rule_{rule}"), "bundle_ref": bundle(&format!("pack_{pack}")),
            "obligations": obligations})
    }
}

fn strictness(verdict: &str) -> u8 {
    match verdict {
        "allow" => 0,
        "require_approval" => 1,
        "escalate" => 2,
        "deny" => 3,
        _ => 4,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// POLICY-1: composition depends on the set of outcomes, not their order.
    #[test]
    fn composition_ignores_order(outcomes in prop::collection::vec(outcome(), 0..6), seed in any::<u64>()) {
        let mut shuffled = outcomes.clone();
        let len = shuffled.len().max(1) as u64;
        shuffled.rotate_left((seed % len) as usize);
        if seed & 1 == 1 {
            shuffled.reverse();
        }
        let (a, b) = (compose_policy_outcomes(&json!(outcomes)), compose_policy_outcomes(&json!(shuffled)));
        prop_assert_eq!((a.verdict, a.reason_codes, a.obligations, a.policy_refs, a.rule_ids),
            (b.verdict, b.reason_codes, b.obligations, b.policy_refs, b.rule_ids));
    }

    /// POLICY-2: adding a guardrail outcome (such as a task authorization's) never
    /// makes the verdict less strict, and a guardrail deny always refuses.
    #[test]
    fn a_guardrail_only_restricts(
        outcomes in prop::collection::vec(outcome(), 0..6),
        verdict in prop::sample::select(vec!["allow", "deny", "require_approval", "escalate"]),
    ) {
        let before = compose_policy_outcomes(&json!(outcomes));
        let mut more = outcomes.clone();
        more.push(json!({"category": "guardrail", "priority": 0, "verdict": verdict, "rule_id": "task_authorization",
            "bundle_ref": {"artifact_type": "task_authorization", "artifact_id": "run_root", "version": "1",
                "sha256": format!("sha256:{}", "cd".repeat(32))}, "obligations": []}));
        let after = compose_policy_outcomes(&json!(more));
        prop_assert!(strictness(&after.verdict) >= strictness(&before.verdict),
            "{} became {} with a {verdict} guardrail", before.verdict, after.verdict);
        if verdict == "deny" {
            prop_assert!(matches!(after.verdict.as_str(), "deny" | "error"));
        }
    }
}

const STATUSES: [&str; 10] = [
    "created",
    "running",
    "waiting_approval",
    "waiting_external",
    "suspended",
    "cancel_requested",
    "completed",
    "failed",
    "cancelled",
    "expired",
];
const TERMINAL: [&str; 4] = ["completed", "failed", "cancelled", "expired"];
const EVENTS: [&str; 11] = [
    "start",
    "wait_approval",
    "wait_external",
    "suspend",
    "resume",
    "request_cancel",
    "acknowledge_cancel",
    "complete",
    "fail",
    "expire",
    "unknown_event",
];

/// RUN-1: the whole lifecycle, explored exhaustively. Every status is reachable from
/// `created`, terminal statuses admit no event, and every status can still end:
/// `fail` and `expire` reach a terminal status from anywhere that is not terminal.
#[test]
fn the_run_lifecycle_always_ends_and_never_reopens() {
    let mut reachable = vec!["created"];
    let mut frontier = vec!["created"];
    while let Some(status) = frontier.pop() {
        for event in EVENTS {
            if let Some(next) = next_status(status, event) {
                assert!(STATUSES.contains(&next), "{status} --{event}--> unknown {next}");
                if !reachable.contains(&next) {
                    reachable.push(next);
                    frontier.push(next);
                }
            }
        }
    }
    let mut sorted = reachable.clone();
    sorted.sort_unstable();
    let mut all = STATUSES.to_vec();
    all.sort_unstable();
    assert_eq!(sorted, all, "every status is reachable");
    for status in STATUSES {
        let terminal = TERMINAL.contains(&status);
        for event in EVENTS {
            if terminal {
                assert_eq!(next_status(status, event), None, "{status} reopened by {event}");
            }
        }
        if !terminal {
            for event in ["fail", "expire"] {
                assert!(
                    next_status(status, event).is_some_and(|s| TERMINAL.contains(&s)),
                    "{status} cannot {event}"
                );
            }
        }
    }
}

/// A step of a budget ledger's history.
#[derive(Debug, Clone)]
enum Step {
    /// Reserve this many of each counter.
    Reserve([u64; 4]),
    /// Settle the `n`th reservation with `per_mille` of what is left of it, with an
    /// outcome: 0 completed, 1 cancelled, 2 still running, 3 unknown usage.
    Settle { n: usize, per_mille: u64, outcome: u8 },
    /// Send an earlier accepted request again.
    Replay(usize),
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        prop::array::uniform4(0_u64..900).prop_map(Step::Reserve),
        (0_usize..8, 0_u64..=1000, 0_u8..4).prop_map(|(n, per_mille, outcome)| Step::Settle { n, per_mille, outcome }),
        (0_usize..8).prop_map(Step::Replay),
    ]
}

const KEYS: [&str; 4] = ["tokens", "tool_calls", "replans", "cost_units"];

fn templates() -> (Value, Value, Value) {
    static TEMPLATES: std::sync::OnceLock<(Value, Value, Value)> = std::sync::OnceLock::new();
    TEMPLATES.get_or_init(load_templates).clone()
}

fn load_templates() -> (Value, Value, Value) {
    let vectors = common::load("durable.json.gz");
    let case = |name: &str| {
        vectors["budgets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap()["input"]
            .clone()
    };
    let reserve = case("reserve_run");
    let settle = case("settle_unknown_usage");
    let mut ledger = reserve["ledger"].clone();
    // Room for many reservations of every counter; the limits are pinned by digest.
    ledger["original_limits"] = json!({"tokens": 4000, "tool_calls": 4000, "replans": 4000, "cost_cents": 40});
    ledger["ceiling"] = json!({"tokens": 4000, "tool_calls": 4000, "replans": 4000, "cost_units": 4000});
    ledger["original_limits_ref"]["sha256"] = json!(budget_limits_digest(&ledger).unwrap());
    assert_eq!(
        reserve_budget(&ledger, &reserve["request"]).status,
        "accepted",
        "the template ledger is valid"
    );
    (ledger, reserve["request"].clone(), settle["request"].clone())
}

fn int(v: &Value) -> i64 {
    v.as_i64().unwrap()
}

/// BUDGET-1..3, checked after every step.
fn conserved(ledger: &Value) -> Result<(), String> {
    let reservations = ledger["reservations"].as_array().unwrap();
    for k in KEYS {
        let (used, reserved, ceiling) = (
            int(&ledger["used"][k]),
            int(&ledger["reserved"][k]),
            int(&ledger["ceiling"][k]),
        );
        if used < 0 || reserved < 0 || used + reserved > ceiling {
            return Err(format!(
                "{k}: used {used} + reserved {reserved} exceeds ceiling {ceiling}"
            ));
        }
        let open: i64 = reservations
            .iter()
            .filter(|r| r["status"] != "settled")
            .map(|r| int(&r["allocation"][k]) - int(&r["used"][k]))
            .sum();
        if reserved != open {
            return Err(format!("{k}: reserved {reserved} but open reservations hold {open}"));
        }
        let spent: i64 = reservations.iter().map(|r| int(&r["used"][k])).sum();
        if used != int(&ledger["opening_usage"][k]) + spent {
            return Err(format!("{k}: used {used} but reservations used {spent}"));
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// BUDGET-1: used plus reserved never exceeds the ceiling. BUDGET-2: what is
    /// reserved is exactly what open reservations still hold, and what is used is what
    /// reservations used. BUDGET-3: a rejected mutation changes nothing, an accepted
    /// one advances the revision by one, and a replayed one is answered from its
    /// receipt without a second effect.
    #[test]
    fn budgets_are_conserved(steps in prop::collection::vec(step(), 1..24)) {
        let (mut ledger, reserve_template, settle_template) = templates();
        let mut accepted: Vec<(Value, bool)> = Vec::new();
        let mut reservations: Vec<String> = Vec::new();
        for (i, step) in steps.iter().enumerate() {
            let (request, is_reserve) = match step {
                Step::Reserve(counts) => {
                    let mut request = reserve_template.clone();
                    request["mutation_id"] = json!(format!("reserve_{i}"));
                    request["reservation_id"] = json!(format!("reservation_{i}"));
                    for (k, count) in KEYS.iter().zip(counts) {
                        request["allocation"][*k] = json!(count);
                    }
                    (request, true)
                }
                Step::Settle { n, per_mille, outcome } => {
                    let Some(id) = reservations.get(n % reservations.len().max(1)) else { continue };
                    let reservation = ledger["reservations"].as_array().unwrap().iter()
                        .find(|r| r["reservation_id"] == id.as_str()).unwrap().clone();
                    let mut request = settle_template.clone();
                    request["mutation_id"] = json!(format!("settle_{i}"));
                    request["reservation_id"] = json!(id);
                    request["scope"] = reservation["scope"].clone();
                    request["run_id"] = reservation["run_id"].clone();
                    for k in KEYS {
                        let (used, allocation) = (int(&reservation["used"][k]), int(&reservation["allocation"][k]));
                        request["usage"][k] = json!(used + (allocation - used) * *per_mille as i64 / 1000);
                    }
                    let (usage_status, execution_status) =
                        [("known", "completed"), ("known", "cancelled"), ("known", "running"), ("unknown", "unknown")]
                            [*outcome as usize];
                    request["usage_status"] = json!(usage_status);
                    request["execution_status"] = json!(execution_status);
                    (request, false)
                }
                Step::Replay(n) => {
                    let Some((request, is_reserve)) = accepted.get(n % accepted.len().max(1)).cloned() else { continue };
                    stat("BUDGET replay");
                    let replayed = if is_reserve { reserve_budget(&ledger, &request) } else { settle_budget(&ledger, &request) };
                    prop_assert_eq!(replayed.status.as_str(), "accepted");
                    prop_assert_eq!(&replayed.state, &ledger, "a replay changed the ledger");
                    continue;
                }
            };
            let mut request = request;
            request["expected_revision"] = ledger["revision"].clone();
            if !is_reserve {
                let digest = settlement_intent_digest(&request).unwrap();
                request["usage_observation"]["intent_digest"] = json!(digest);
            }
            let result = if is_reserve { reserve_budget(&ledger, &request) } else { settle_budget(&ledger, &request) };
            if result.status == "accepted" {
                stat(if is_reserve { "BUDGET reserve accepted" } else { "BUDGET settle accepted" });
                prop_assert_eq!(int(&result.state["revision"]), int(&ledger["revision"]) + 1);
                if is_reserve {
                    reservations.push(request["reservation_id"].as_str().unwrap().to_owned());
                }
                ledger = result.state;
                accepted.push((request, is_reserve));
            } else {
                stat("BUDGET rejected");
                prop_assert_eq!(&result.state, &ledger, "a rejected mutation changed the ledger");
            }
            if let Err(broken) = conserved(&ledger) {
                return Err(TestCaseError::fail(format!("after step {i} ({step:?}): {broken}")));
            }
        }
    }
}

/// A step of an operation ledger's history, over two operations.
#[derive(Debug, Clone)]
enum OpStep {
    /// Claim a new attempt of operation `op`, or (`again`) the last attempt again.
    Claim { op: usize, again: bool },
    /// Record a fact about attempt `back` places before operation `op`'s last (a late
    /// fact when not 0).
    Observe {
        op: usize,
        back: usize,
        outcome: u8,
        definitive: bool,
    },
}

fn op_step() -> impl Strategy<Value = OpStep> {
    prop_oneof![
        (0_usize..2, any::<bool>()).prop_map(|(op, again)| OpStep::Claim {
            op,
            again: again && op == 0
        }),
        (0_usize..2, 0_usize..3, 0_u8..5, any::<bool>()).prop_map(|(op, back, outcome, definitive)| OpStep::Observe {
            op,
            back,
            outcome,
            definitive
        }),
    ]
}

const OUTCOMES: [&str; 5] = ["confirmed", "partial", "not_applied", "not_dispatched", "unknown"];
const STRATEGIES: [&str; 4] = ["manual_reconcile", "idempotent_retry", "no_retry", "query"];

fn op_templates() -> (Value, Value, Value, Value) {
    static TEMPLATES: std::sync::OnceLock<(Value, Value, Value, Value)> = std::sync::OnceLock::new();
    TEMPLATES
        .get_or_init(|| {
            let vectors = common::load("durable.json.gz");
            let case = |name: &str| {
                vectors["ops"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|c| c["name"] == name)
                    .unwrap()["input"]
                    .clone()
            };
            let fresh = case("fresh_claim");
            let observe = case("timeout");
            let proof = case("idem:retry_with_proof")["intent"]["provider_observation"].clone();
            (
                fresh["ledger"].clone(),
                fresh["intent"].clone(),
                observe["observation"].clone(),
                proof,
            )
        })
        .clone()
}

/// `seconds` after the start of the history, as a contract timestamp.
fn at(seconds: u64) -> String {
    format!("2026-10-16T08:{:02}:{:02}Z", seconds / 60, seconds % 60)
}

fn op_of<'a>(ledger: &'a Value, id: &str) -> Option<&'a Value> {
    ledger["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["intent"]["operation_id"] == id)
}

fn attempts(op: Option<&Value>) -> Vec<Value> {
    op.and_then(|o| o["attempts"].as_array().cloned()).unwrap_or_default()
}

/// Whether any attempt of `op` has a definitive fact that the effect was applied.
fn applied(op: Option<&Value>) -> bool {
    op.is_some_and(|o| {
        o["observations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["finality"] == "definitive" && matches!(f["outcome"].as_str(), Some("confirmed" | "partial")))
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// OP-1: a new attempt is claimed only when no attempt was definitively applied,
    /// the evidence does not conflict, the strategy allows retries, and an unknown
    /// outcome is retried only under a verified idempotency contract. OP-2: at most one
    /// attempt is in flight, and it is the last. OP-3: once applied, an operation is
    /// never again `not_applied` or `not_dispatched`; contradicting evidence makes it
    /// `unknown` with a sticky conflict. OP-4: a rejected transition changes nothing,
    /// an accepted change advances the revision by one, and attempts never exceed
    /// `max_attempts`.
    #[test]
    fn effects_are_never_applied_twice(
        strategies in prop::array::uniform2(prop::sample::select(STRATEGIES.to_vec())),
        steps in prop::collection::vec(op_step(), 1..24),
    ) {
        let (mut ledger, intent_template, fact_template, proof_template) = op_templates();
        let ids = ["op_a", "op_b"];
        let mut next_attempt = 0;
        for (i, step) in steps.iter().enumerate() {
            let now = at(7 * (i as u64 + 1));
            let before = ledger.clone();
            let result = match step {
                OpStep::Claim { op, again } => {
                    let id = ids[*op];
                    let existing = attempts(op_of(&ledger, id));
                    let mut intent = intent_template.clone();
                    intent["operation_id"] = json!(id);
                    intent["recovery_strategy"] = json!(strategies[*op]);
                    intent["max_attempts"] = json!(3);
                    intent["retry_delays_seconds"] = json!([5, 10]);
                    if strategies[*op] == "idempotent_retry" {
                        intent["idempotency_key"] = json!(format!("idem_{id}"));
                        intent["idempotency_scope"] = json!("payments:tenant_acme_prod");
                        intent["provider_idempotency_ref"] = proof_template["provider_contract_ref"].clone();
                        let mut proof = proof_template.clone();
                        proof["key"] = json!(format!("idem_{id}"));
                        proof["operation_id"] = json!(id);
                        intent["provider_observation"] = proof;
                    }
                    let attempt = if let (true, Some(last)) = (again, existing.last()) {
                        last.clone()
                    } else {
                        next_attempt += 1;
                        json!({"attempt_id": format!("attempt_{next_attempt}"), "operation_id": id,
                            "executor_generation": 3, "started_at": now, "dispatch_state": "claimed",
                            "last_observation_ref": null})
                    };
                    intent["evaluation_time"] = attempt["started_at"].clone();
                    intent["attempt"] = attempt;
                    claim_operation(&ledger, &intent, &ledger["revision"], &json!(3))
                }
                OpStep::Observe { op, back, outcome, definitive } => {
                    let id = ids[*op];
                    let existing = attempts(op_of(&ledger, id));
                    let Some(attempt) = existing.iter().rev().nth(*back).or(existing.last()) else { continue };
                    let mut fact = fact_template.clone();
                    fact["observation_id"] = json!(format!("fact_{i}"));
                    fact["operation_id"] = json!(id);
                    fact["attempt_id"] = attempt["attempt_id"].clone();
                    fact["outcome"] = json!(OUTCOMES[*outcome as usize]);
                    fact["finality"] = json!(if *definitive { "definitive" } else { "provisional" });
                    fact["observed_at"] = json!(now);
                    fact["evaluation_time"] = json!(now);
                    fact["valid_until"] = json!(at(7 * (i as u64 + 1) + 300));
                    record_effect_observation(&ledger, &fact, &ledger["revision"])
                }
            };
            if result.status != "accepted" {
                stat("OP rejected");
                prop_assert_eq!(&result.state, &before, "OP-4: a rejected transition changed the ledger");
                continue;
            }
            let after = result.state;
            if after != before {
                prop_assert_eq!(int(&after["revision"]), int(&before["revision"]) + 1, "OP-4");
            }
            for (n, id) in ids.iter().enumerate() {
                let (was, now_op) = (op_of(&before, id), op_of(&after, id));
                let (old, new) = (attempts(was), attempts(now_op));
                if new.len() > old.len() && !old.is_empty() {
                    stat("OP retry claimed");
                    let outcome = was.unwrap()["outcome"].as_str().unwrap();
                    prop_assert!(!applied(was), "OP-1: retried {id} after it was applied");
                    prop_assert!(was.unwrap()["conflict"] != true, "OP-1: retried {id} on conflicting evidence");
                    prop_assert!(strategies[n] != "no_retry", "OP-1: retried a no_retry operation");
                    prop_assert!(outcome != "unknown" || strategies[n] == "idempotent_retry",
                        "OP-1: retried {id} with an unknown outcome under {}", strategies[n]);
                    if outcome == "unknown" {
                        stat("OP unknown retried under idempotency");
                    }
                }
                prop_assert!(new.len() <= 3, "OP-4: attempts exceed max_attempts");
                let in_flight: Vec<usize> = new.iter().enumerate()
                    .filter(|(_, a)| a["dispatch_state"] == "claimed").map(|(k, _)| k).collect();
                prop_assert!(in_flight.len() <= 1 && in_flight.iter().all(|k| *k + 1 == new.len()),
                    "OP-2: attempts in flight {in_flight:?} of {}", new.len());
                if let (Some(was), Some(now_op)) = (was, now_op) {
                    if matches!(was["outcome"].as_str(), Some("confirmed" | "partial")) {
                        stat("OP applied then observed");
                        let outcome = now_op["outcome"].as_str().unwrap();
                        prop_assert!(outcome != "not_applied" && outcome != "not_dispatched",
                            "OP-3: applied {id} became {outcome}");
                        prop_assert!(outcome != "unknown" || now_op["conflict"] == true, "OP-3");
                    }
                    if was["conflict"] == true {
                        prop_assert!(now_op["conflict"] == true, "OP-3: a conflict was forgotten");
                    }
                }
            }
            ledger = after;
        }
    }
}
