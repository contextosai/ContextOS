//! Properties of task authorizations over generated inputs (`docs/verification/PROPERTIES.md`).
//!
//! TASK-1 is the property the amendment endpoint rests on: an amendment the executor
//! may make without the principal (`narrowed`) permits nothing the current task
//! authorization did not, for every action, effect and usage so far.

// Generated values are small and non-negative, so the casts below cannot wrap or truncate.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]

use contextos_contract::types::ActionEffect;
use contextos_gateway::{Amount, OutOfScope, ReadOnly, TaskAuthorization, TaskLimits};
use proptest::prelude::*;
use proptest::sample::subsequence;
use serde_json::{Value, json};

const IDS: [&str; 3] = ["a", "b", "c"];

fn ids() -> impl Strategy<Value = Vec<&'static str>> {
    subsequence(IDS.to_vec(), 0..=IDS.len())
}

fn ceiling() -> impl Strategy<Value = Option<Value>> {
    prop::option::of(
        (0_u64..6, prop::sample::select(vec!["INR", "USD"]))
            .prop_map(|(m, c)| json!({"minor_units": m, "currency": c})),
    )
}

prop_compose! {
    fn scope()(capabilities in ids(), resources in ids(), max in prop::option::of(0_i64..4), ceiling in ceiling())
        -> Value {
        let constraints: Vec<Value> = max.map(|m| json!({"pointer": "/x", "kind": "max_integer", "maximum": m}))
            .into_iter().collect();
        let mut scope = json!({"root_run_id": "run_root", "purpose_ids": ["refund"], "capability_ids": capabilities,
            "resource_ids": resources, "destination_ids": ["cus"], "classification_labels": ["CONFIDENTIAL"],
            "argument_constraints": constraints});
        if let Some(ceiling) = ceiling {
            scope["amount_ceiling"] = ceiling;
        }
        scope
    }
}

prop_compose! {
    fn limits()(max_effects in prop::option::of(0_u64..4), total in prop::option::of(0_u64..8), usd in any::<bool>())
        -> Option<TaskLimits> {
        let limits = TaskLimits {
            max_effects,
            amount_total: total.map(|minor_units| Amount {
                minor_units,
                currency: if usd { "USD" } else { "INR" }.into(),
            }),
        };
        (max_effects.is_some() || limits.amount_total.is_some()).then_some(limits)
    }
}

prop_compose! {
    fn task()(scopes in prop::collection::vec(scope(), 1..3), ask in any::<bool>(), scoped in any::<bool>(),
        limits in limits()) -> TaskAuthorization {
        TaskAuthorization {
            issued_by: json!({"principal_id": "usr", "principal_type": "person", "trust_domain": "t", "tenant_id": "t"}),
            scopes,
            out_of_scope: if ask { OutOfScope::Ask } else { OutOfScope::Deny },
            read_only: if scoped { ReadOnly::Scoped } else { ReadOnly::Allow },
            confirmation_ref: None,
            limits,
        }
    }
}

/// `current` narrowed in each part (`seed` picks how), so that `narrows` holds often.
fn narrowed(current: &TaskAuthorization, seed: u64) -> TaskAuthorization {
    let mut bits = seed;
    let mut next = |n: u64| {
        let v = bits % n;
        bits = (bits / n) ^ bits.rotate_left(23);
        v
    };
    let mut task = current.clone();
    for scope in &mut task.scopes {
        for key in ["capability_ids", "resource_ids"] {
            let kept: Vec<Value> = scope[key]
                .as_array()
                .unwrap()
                .iter()
                .filter(|_| next(3) != 0)
                .cloned()
                .collect();
            scope[key] = json!(kept);
        }
        if let Some(c) = scope["argument_constraints"].as_array_mut().and_then(|a| a.first_mut()) {
            c["maximum"] = json!(next(c["maximum"].as_u64().unwrap() + 1));
        }
        if let Some(ceiling) = scope.get_mut("amount_ceiling") {
            ceiling["minor_units"] = json!(next(ceiling["minor_units"].as_u64().unwrap() + 1));
        }
    }
    if next(2) == 0 {
        task.out_of_scope = OutOfScope::Deny;
    }
    if next(2) == 0 {
        task.read_only = ReadOnly::Scoped;
    }
    if let Some(limits) = &mut task.limits {
        if let Some(max) = &mut limits.max_effects {
            *max = next(*max + 1);
        }
        if let Some(total) = &mut limits.amount_total {
            total.minor_units = next(total.minor_units + 1);
        }
    } else if next(2) == 0 {
        task.limits = Some(TaskLimits {
            max_effects: Some(next(3)),
            amount_total: None,
        });
    }
    task
}

prop_compose! {
    fn action()(capability in prop::sample::select(IDS.to_vec()), resources in ids(), x in prop::option::of(0_i64..5),
        amount in ceiling()) -> Value {
        let arguments = x.map_or_else(|| json!({}), |x| json!({"x": x}));
        let mut binding = json!({"purpose_id": "refund", "capability_id": capability, "resource_ids": resources,
            "destination_ids": ["cus"], "action_risk": {"data_scope": "CONFIDENTIAL"}, "arguments": arguments});
        if let Some(amount) = amount {
            binding["amount"] = amount;
        }
        binding
    }
}

/// `binding` moved inside the first scope of `task` where it can be.
fn fit(binding: &Value, task: &TaskAuthorization, seed: u64) -> Value {
    let scope = &task.scopes[0];
    let mut fitted = binding.clone();
    if let Some(capability) = scope["capability_ids"].as_array().and_then(|a| a.first()) {
        fitted["capability_id"] = capability.clone();
    }
    let allowed = scope["resource_ids"].as_array().unwrap();
    let kept: Vec<&Value> = fitted["resource_ids"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| allowed.contains(r))
        .collect();
    fitted["resource_ids"] = json!(kept);
    if let Some(c) = scope["argument_constraints"].as_array().and_then(|a| a.first()) {
        fitted["arguments"]["x"] = json!(seed % (c["maximum"].as_u64().unwrap() + 1));
    }
    match scope.get("amount_ceiling") {
        Some(c) => {
            fitted["amount"] =
                json!({"minor_units": seed % (c["minor_units"].as_u64().unwrap() + 1), "currency": c["currency"]});
        }
        None => {
            fitted.as_object_mut().unwrap().remove("amount");
        }
    }
    fitted
}

prop_compose! {
    /// What the task's effects used so far, as the exposure document records it.
    fn used()(effects in 0_u64..4, inr in 0_u64..8, usd in 0_u64..8) -> Value {
        json!({"effects": effects, "amounts": {"INR": inr, "USD": usd}, "operations": {}})
    }
}

/// Counts how often a premise held (`PROPERTY_STATS=1` prints them).
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

fn strictness(check: &Value) -> u8 {
    match check["verdict"].as_str().unwrap() {
        "allow" => 0,
        "require_approval" => 1,
        _ => 2,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8192))]

    /// TASK-1: an amendment classified `narrowed` permits nothing the current task
    /// authorization did not: for every action, effect and usage, its verdict is at
    /// least as strict, and its limits are reached no later.
    #[test]
    fn a_narrowed_task_permits_nothing_new(
        current in task(), other in task(), seed in any::<u64>(), action in action(), used in used(),
        effect in prop::sample::select(vec![ActionEffect::None, ActionEffect::ExternalState]),
    ) {
        for amended in [narrowed(&current, seed), other.clone()] {
            if !amended.narrows(&current) {
                continue;
            }
            let action = if seed % 4 == 0 { action.clone() } else { fit(&action, &amended, seed >> 2) };
            let exceeds = |t: &TaskAuthorization| {
                effect != ActionEffect::None
                    && t.limits.as_ref().is_some_and(|l| l.exceeded_by(Some(&used), "op", action.get("amount")))
            };
            let (now, before) = (exceeds(&amended), exceeds(&current));
            prop_assert!(now || !before, "limits {:?} allow what {:?} refused", amended.limits, current.limits);
            let after = amended.check("run_root", &action, effect, now).outcome;
            let was = current.check("run_root", &action, effect, before).outcome;
            stat("TASK-1 narrowed");
            if after["verdict"] == "allow" {
                stat("TASK-1 narrowed and allowed");
            }
            prop_assert!(strictness(&after) >= strictness(&was),
                "{} under the amendment, {} before, for {action}", after["verdict"], was["verdict"]);
        }
    }
}
