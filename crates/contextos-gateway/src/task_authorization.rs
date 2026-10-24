//! What the principal authorized for this run.
//!
//! Broker grants say what an agent *may* do; a task authorization says what its
//! principal asked for in this run ("refund order ord_881 for INR 1200"). It is set
//! at admission, before the agent acts, as `AuthorityGrant` scopes, and changes only
//! through an audited amendment ([`TaskAuthorization::change_from`] classifies it).
//! Every effect must also fall inside one of them: the kernel's own grant-scope check
//! decides, on the actual action binding rather than on what the request stated. It only narrows
//! authority, so whoever supplies it cannot widen what the broker grants.
//!
//! Every decision of the run composes a guardrail policy outcome citing it: `allow`
//! inside, and outside `deny` (refuse) or, with `ask`, `require_approval` (an exact
//! approval of that action before it runs). The action binding's `policy_refs` name
//! it, so decisions and approvals are bound to the authorization they were checked
//! against. Agents that ask only after acting are the failure `ask` prevents.
//!
//! Scopes bound each action; `limits` bound the task as a whole ("refund up to INR
//! 1200 in total"). What the effects of the task used is kept in one document per
//! issuing run, shared by the runs delegated from it, and charged with
//! compare-and-swap after the operation is claimed and before it is dispatched, so
//! effects racing in parallel cannot together exceed a limit. A charge is returned
//! only when the provider definitively did not apply the effect.

use contextos_contract::canonical::sha256_canonical;
use contextos_contract::types::ActionEffect;
use contextos_kernel::authorization::{
    authority_scope_narrows, scope_mismatch, valid_authority_scope, valid_principal,
};
use contextos_store::{DocKey, DocKind, DocumentStore, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Most scopes one task authorization may list.
pub const MAX_SCOPES: usize = 32;

/// Most effects one task's limits track. A task that reaches it makes no further
/// effects (`task_limits_saturated`): the limits fail closed, never stop counting.
pub const MAX_TRACKED_EFFECTS: usize = 4096;

/// Largest amount JSON carries exactly (2^53 - 1).
const MAX_MINOR_UNITS: u64 = 9_007_199_254_740_991;

/// An amount of money in minor units, as in `AuthorityGrant.amount_ceiling`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Amount {
    pub minor_units: u64,
    pub currency: String,
}

/// Bounds on the task as a whole, across all its effects (reads are not counted).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskLimits {
    /// Most effects the task may make.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_effects: Option<u64>,
    /// Most the task's effects may move in total. An effect whose amount is in another
    /// currency exceeds it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_total: Option<Amount>,
}

impl TaskLimits {
    fn valid(&self) -> bool {
        (self.max_effects.is_some() || self.amount_total.is_some())
            && self.max_effects.is_none_or(|n| n <= MAX_TRACKED_EFFECTS as u64)
            && self.amount_total.as_ref().is_none_or(|a| {
                a.minor_units <= MAX_MINOR_UNITS
                    && a.currency.len() == 3
                    && a.currency.bytes().all(|b| b.is_ascii_uppercase())
            })
    }

    /// Whether these permit nothing `current` does not.
    fn narrows(&self, current: &TaskLimits) -> bool {
        current
            .max_effects
            .is_none_or(|c| self.max_effects.is_some_and(|n| n <= c))
            && current.amount_total.as_ref().is_none_or(|c| {
                self.amount_total
                    .as_ref()
                    .is_some_and(|n| n.currency == c.currency && n.minor_units <= c.minor_units)
            })
    }

    /// Whether charging `operation_id` (moving `amount`, the binding's) would exceed
    /// these, given what `used` (the task's exposure document) records. An operation
    /// already charged is not charged again.
    pub fn exceeded_by(&self, used: Option<&Value>, operation_id: &str, amount: Option<&Value>) -> bool {
        if used.is_some_and(|u| u["operations"].get(operation_id).is_some()) {
            return false;
        }
        let effects = used.and_then(|u| u["effects"].as_u64()).unwrap_or(0);
        if self.max_effects.is_some_and(|max| effects >= max) {
            return true;
        }
        let Some(total) = &self.amount_total else {
            return false;
        };
        let Some(amount) = amount else {
            return false;
        };
        if amount["currency"] != total.currency.as_str() {
            return true;
        }
        let spent = used.and_then(|u| u["amounts"][&total.currency].as_u64()).unwrap_or(0);
        amount["minor_units"]
            .as_u64()
            .is_none_or(|m| spent.saturating_add(m) > total.minor_units)
    }
}

/// The document counting what the task authorization issued by `origin_run_id` used.
pub fn exposure_key(tenant_id: &str, origin_run_id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::TaskExposure, origin_run_id)
}

/// The outcome of charging an effect to a task's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// Charged (or already charged to this operation).
    Charged,
    /// It would exceed a limit, and was not charged.
    Exceeded,
    /// The task tracks [`MAX_TRACKED_EFFECTS`] effects already.
    Saturated,
}

/// Charges `operation_id`'s effect to the task's limits, atomically: of effects
/// racing for the last of a limit, exactly one is charged. With `over_limit` (the
/// principal approved this exact action) it is charged even past a limit.
pub async fn charge<S: DocumentStore + ?Sized>(
    store: &S,
    key: &DocKey,
    limits: &TaskLimits,
    operation_id: &str,
    amount: Option<&Value>,
    over_limit: bool,
) -> Result<Charge, StoreError> {
    let outcome = std::sync::Mutex::new(Charge::Charged);
    update(store, key, |used| {
        let result = if used["operations"].get(operation_id).is_some() {
            Charge::Charged
        } else if used["operations"]
            .as_object()
            .is_some_and(|o| o.len() >= MAX_TRACKED_EFFECTS)
        {
            Charge::Saturated
        } else if !over_limit && limits.exceeded_by(Some(used), operation_id, amount) {
            Charge::Exceeded
        } else {
            let charged = amount.filter(|a| a["minor_units"].is_u64() && a["currency"].is_string());
            used["effects"] = json!(used["effects"].as_u64().unwrap_or(0) + 1);
            if let Some(a) = charged {
                let currency = a["currency"].as_str().unwrap_or_default();
                let spent = used["amounts"][currency].as_u64().unwrap_or(0);
                used["amounts"][currency] = json!(spent.saturating_add(a["minor_units"].as_u64().unwrap_or(0)));
            }
            used["operations"][operation_id] = charged.cloned().unwrap_or(Value::Null);
            *outcome.lock().map_err(|_| StoreError::Integrity)? = Charge::Charged;
            return Ok(true);
        };
        *outcome.lock().map_err(|_| StoreError::Integrity)? = result;
        Ok(false)
    })
    .await?;
    outcome.into_inner().map_err(|_| StoreError::Integrity)
}

/// Returns `operation_id`'s charge (the provider definitively did not apply it).
pub async fn release<S: DocumentStore + ?Sized>(store: &S, key: &DocKey, operation_id: &str) -> Result<(), StoreError> {
    update(store, key, |used| {
        let Some(charged) = used["operations"].as_object_mut().and_then(|o| o.remove(operation_id)) else {
            return Ok(false);
        };
        used["effects"] = json!(used["effects"].as_u64().unwrap_or(0).saturating_sub(1));
        if let Some(currency) = charged["currency"].as_str() {
            let spent = used["amounts"][currency].as_u64().unwrap_or(0);
            used["amounts"][currency] = json!(spent.saturating_sub(charged["minor_units"].as_u64().unwrap_or(0)));
        }
        Ok(true)
    })
    .await
}

/// Applies `change` with compare-and-swap; `change` returns whether to write.
async fn update<S: DocumentStore + ?Sized>(
    store: &S,
    key: &DocKey,
    change: impl Fn(&mut Value) -> Result<bool, StoreError>,
) -> Result<(), StoreError> {
    for attempt in 0..32_u32 {
        if attempt > 0 {
            // Parallel effects of one task contend on its document: back off briefly.
            tokio::time::sleep(std::time::Duration::from_micros(50 << attempt.min(8))).await;
        }
        let current = store.get(key).await?;
        let mut used = current.as_ref().map_or_else(
            || json!({"effects": 0, "amounts": {}, "operations": {}}),
            |c| c.body.clone(),
        );
        if !change(&mut used)? {
            return Ok(());
        }
        let written = match &current {
            None => store.create(key, &used).await.map(|_| ()),
            Some(c) => store.compare_and_swap(key, c.revision, &used).await.map(|_| ()),
        };
        match written {
            Ok(()) => return Ok(()),
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e),
        }
    }
    Err(StoreError::Conflict {
        expected: None,
        actual: None,
    })
}

/// What happens to an action the principal did not authorize.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutOfScope {
    /// Refuse it.
    #[default]
    Deny,
    /// Pause it for an exact approval of that action.
    Ask,
}

/// Whether read-only capabilities must be listed too.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOnly {
    /// Read-only capabilities (`effect: none`) need no scope.
    #[default]
    Allow,
    /// Every capability, reads included, must fall inside a scope.
    Scoped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAuthorization {
    /// Who authorized the task (`PrincipalRef`), usually the run's user.
    pub issued_by: Value,
    /// `AuthorityGrant` scopes; an action must fall inside at least one.
    pub scopes: Vec<Value>,
    #[serde(default)]
    pub out_of_scope: OutOfScope,
    #[serde(default)]
    pub read_only: ReadOnly,
    /// Evidence of the principal's confirmation (an `ArtifactRef`), when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_ref: Option<Value>,
    /// Bounds on the task as a whole: how many effects, and how much in total.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<TaskLimits>,
}

/// How an amendment changes a run's task authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// It permits nothing the current one did not: anyone running the task may make it.
    Narrowed,
    /// It permits something new: it needs the principal's confirmation.
    Widened,
}

/// The task authorization's verdict on one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCheck {
    /// The guardrail policy outcome to compose with the run's other outcomes.
    pub outcome: Value,
    /// Outside: `outside_task_authorization` and the first dimension that did not
    /// match. Empty inside.
    pub reason_codes: Vec<String>,
}

impl TaskAuthorization {
    /// Structural review at admission. `root_run_id` is the run's root: every scope
    /// must name it, so a scope cannot be replayed into another task.
    pub fn validate(&self, root_run_id: &str) -> Result<(), &'static str> {
        if !valid_principal(&self.issued_by) {
            return Err("issued_by must be a principal reference");
        }
        if self.scopes.is_empty() || self.scopes.len() > MAX_SCOPES {
            return Err("scopes must list between 1 and 32 grant scopes");
        }
        if !self.scopes.iter().all(valid_authority_scope) {
            return Err("every scope must be a valid AuthorityGrant scope");
        }
        if self.scopes.iter().any(|s| s["root_run_id"] != root_run_id) {
            return Err("every scope must name the run's root_run_id");
        }
        if self
            .confirmation_ref
            .as_ref()
            .is_some_and(|r| !contextos_contract::shape::is_artifact_ref(r))
        {
            return Err("confirmation_ref must be an artifact reference");
        }
        if self.limits.as_ref().is_some_and(|l| !l.valid()) {
            return Err("limits must set max_effects (at most 4096) or a valid amount_total");
        }
        Ok(())
    }

    /// Whether this permits nothing `current` does not: each scope narrows one of
    /// `current`'s, reads are no less scoped, actions outside are no less strictly
    /// handled (`ask` is wider than `deny`), and every limit is kept and no higher.
    pub fn narrows(&self, current: &TaskAuthorization) -> bool {
        self.scopes
            .iter()
            .all(|scope| current.scopes.iter().any(|c| authority_scope_narrows(scope, c)))
            && (self.read_only == ReadOnly::Scoped || current.read_only == ReadOnly::Allow)
            && (self.out_of_scope == OutOfScope::Deny || current.out_of_scope == OutOfScope::Ask)
            && current
                .limits
                .as_ref()
                .is_none_or(|c| self.limits.as_ref().is_some_and(|n| n.narrows(c)))
    }

    /// The change from `current` (the run's own authorization, if any) to this one.
    pub fn change_from(&self, current: Option<&TaskAuthorization>) -> Change {
        match current {
            Some(current) if !self.narrows(current) => Change::Widened,
            _ => Change::Narrowed,
        }
    }

    /// The pinned reference policy outcomes cite.
    pub fn bundle_ref(&self, run_id: &str) -> Value {
        let digest = serde_json::to_value(self)
            .ok()
            .and_then(|v| sha256_canonical(&v).ok())
            .unwrap_or_default();
        json!({"artifact_type": "task_authorization", "artifact_id": run_id, "version": "1", "sha256": digest})
    }

    /// The verdict on `binding`. `exceeds_limits` is whether the effect would exceed
    /// the task's limits as last recorded (see [`TaskLimits::exceeded_by`]); the
    /// charge before dispatch is the authoritative check.
    pub fn check(&self, run_id: &str, binding: &Value, effect: ActionEffect, exceeds_limits: bool) -> TaskCheck {
        let outcome = |verdict: &str, obligations: Value| {
            json!({"category": "guardrail", "priority": 0, "verdict": verdict,
                "rule_id": "task_authorization", "bundle_ref": self.bundle_ref(run_id), "obligations": obligations})
        };
        let inside = TaskCheck {
            outcome: outcome("allow", json!([])),
            reason_codes: vec![],
        };
        if effect == ActionEffect::None && self.read_only == ReadOnly::Allow {
            return inside;
        }
        let mismatches = self
            .scopes
            .iter()
            .map(|s| scope_mismatch(binding, s))
            .collect::<Option<Vec<&'static str>>>();
        let dimension = match mismatches {
            // Inside a scope, but past what the whole task may do.
            None if exceeds_limits && effect != ActionEffect::None => "extent",
            None => return inside,
            // Report the dimension of a scope that names this capability: it says what
            // the principal did authorize for it. Otherwise the capability itself is
            // outside.
            Some(mismatches) => self
                .scopes
                .iter()
                .zip(&mismatches)
                .find(|(scope, _)| {
                    scope["capability_ids"]
                        .as_array()
                        .is_some_and(|ids| ids.contains(&binding["capability_id"]))
                })
                .map_or("capability", |(_, m)| *m),
        };
        let (verdict, obligations) = match self.out_of_scope {
            OutOfScope::Deny => ("deny", json!([])),
            OutOfScope::Ask => ("require_approval", json!(["confirm_with_principal"])),
        };
        TaskCheck {
            outcome: outcome(verdict, obligations),
            reason_codes: vec!["outside_task_authorization".into(), format!("task_scope_{dimension}")],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(capability: &str, resource: &str, ceiling: u64) -> Value {
        json!({"root_run_id": "run_1", "purpose_ids": ["support.refund"], "capability_ids": [capability],
            "resource_ids": [resource], "destination_ids": ["cus_77"], "classification_labels": ["CONFIDENTIAL"],
            "argument_constraints": [], "amount_ceiling": {"minor_units": ceiling, "currency": "INR"}})
    }

    fn task(scopes: Vec<Value>, out_of_scope: OutOfScope, read_only: ReadOnly) -> TaskAuthorization {
        TaskAuthorization {
            issued_by: json!({"principal_id": "usr_771", "principal_type": "person", "trust_domain": "t", "tenant_id": "acme"}),
            scopes,
            out_of_scope,
            read_only,
            confirmation_ref: None,
            limits: None,
        }
    }

    fn binding(capability: &str, resource: &str, amount: u64) -> Value {
        json!({"purpose_id": "support.refund", "capability_id": capability, "resource_ids": [resource],
            "destination_ids": ["cus_77"], "action_risk": {"data_scope": "CONFIDENTIAL"}, "arguments": {},
            "amount": {"minor_units": amount, "currency": "INR"}})
    }

    fn verdict(check: &TaskCheck) -> &str {
        check.outcome["verdict"].as_str().unwrap()
    }

    #[test]
    fn any_scope_covering_the_action_admits_it() {
        let t = task(
            vec![scope("pay.refund", "ord_1", 100), scope("pay.refund", "ord_2", 500)],
            OutOfScope::Deny,
            ReadOnly::Allow,
        );
        let inside = t.check(
            "run_1",
            &binding("pay.refund", "ord_2", 400),
            ActionEffect::ExternalState,
            false,
        );
        assert_eq!((verdict(&inside), inside.reason_codes.len()), ("allow", 0));
        let outside = t.check(
            "run_1",
            &binding("pay.refund", "ord_1", 400),
            ActionEffect::ExternalState,
            false,
        );
        assert_eq!(verdict(&outside), "deny");
        assert_eq!(
            outside.reason_codes,
            ["outside_task_authorization", "task_scope_amount"]
        );
    }

    #[test]
    fn an_unlisted_capability_is_named_as_such() {
        let t = task(
            vec![scope("pay.refund", "ord_1", 100)],
            OutOfScope::Ask,
            ReadOnly::Allow,
        );
        let out = t.check(
            "run_1",
            &binding("mail.send", "ord_1", 1),
            ActionEffect::ExternalState,
            false,
        );
        assert_eq!(out.reason_codes[1], "task_scope_capability");
        assert_eq!(verdict(&out), "require_approval");
        assert_eq!(out.outcome["obligations"], json!(["confirm_with_principal"]));
    }

    #[test]
    fn reads_are_scoped_only_when_asked() {
        let read = binding("orders.lookup", "ord_9", 0);
        let allow = task(
            vec![scope("pay.refund", "ord_1", 100)],
            OutOfScope::Deny,
            ReadOnly::Allow,
        );
        assert_eq!(
            verdict(&allow.check("run_1", &read, ActionEffect::None, false)),
            "allow"
        );
        let scoped = task(
            vec![scope("pay.refund", "ord_1", 100)],
            OutOfScope::Deny,
            ReadOnly::Scoped,
        );
        assert_eq!(
            verdict(&scoped.check("run_1", &read, ActionEffect::None, false)),
            "deny"
        );
    }

    #[test]
    fn amendments_are_classified() {
        let current = task(
            vec![scope("pay.refund", "ord_1", 500)],
            OutOfScope::Deny,
            ReadOnly::Allow,
        );
        let lower = task(
            vec![scope("pay.refund", "ord_1", 100)],
            OutOfScope::Deny,
            ReadOnly::Allow,
        );
        assert_eq!(lower.change_from(Some(&current)), Change::Narrowed);
        assert_eq!(current.change_from(Some(&lower)), Change::Widened, "a higher ceiling");
        let other_order = task(
            vec![scope("pay.refund", "ord_2", 100)],
            OutOfScope::Deny,
            ReadOnly::Allow,
        );
        assert_eq!(
            other_order.change_from(Some(&current)),
            Change::Widened,
            "a revised resource"
        );
        let asks = task(
            vec![scope("pay.refund", "ord_1", 100)],
            OutOfScope::Ask,
            ReadOnly::Allow,
        );
        assert_eq!(
            asks.change_from(Some(&current)),
            Change::Widened,
            "ask permits approved actions"
        );
        let reads = task(
            vec![scope("pay.refund", "ord_1", 500)],
            OutOfScope::Deny,
            ReadOnly::Scoped,
        );
        assert_eq!(reads.change_from(Some(&current)), Change::Narrowed);
        assert_eq!(current.change_from(Some(&reads)), Change::Widened);
        assert_eq!(
            current.change_from(None),
            Change::Narrowed,
            "a first authorization only restricts"
        );
    }

    fn limits(max_effects: Option<u64>, total: Option<u64>) -> TaskLimits {
        TaskLimits {
            max_effects,
            amount_total: total.map(|minor_units| Amount {
                minor_units,
                currency: "INR".into(),
            }),
        }
    }

    #[test]
    fn limits_bound_the_task_as_a_whole() {
        let l = limits(Some(2), Some(1200));
        let inr = |m: u64| json!({"minor_units": m, "currency": "INR"});
        assert!(!l.exceeded_by(None, "op_1", Some(&inr(1200))));
        assert!(l.exceeded_by(None, "op_1", Some(&inr(1201))), "more than the total");
        let used = json!({"effects": 1, "amounts": {"INR": 1100}, "operations": {"op_1": inr(1100)}});
        assert!(
            l.exceeded_by(Some(&used), "op_2", Some(&inr(101))),
            "the total is cumulative"
        );
        assert!(!l.exceeded_by(Some(&used), "op_2", Some(&inr(100))));
        assert!(
            !l.exceeded_by(Some(&used), "op_1", Some(&inr(1100))),
            "a retry is not charged again"
        );
        assert!(
            l.exceeded_by(Some(&used), "op_2", Some(&json!({"minor_units": 1, "currency": "USD"}))),
            "another currency"
        );
        let two = json!({"effects": 2, "amounts": {}, "operations": {"op_1": null, "op_2": null}});
        assert!(l.exceeded_by(Some(&two), "op_3", None), "the effect count");

        let t = TaskAuthorization {
            limits: Some(l.clone()),
            ..task(
                vec![scope("pay.refund", "ord_1", 1200)],
                OutOfScope::Ask,
                ReadOnly::Allow,
            )
        };
        let past = t.check(
            "run_1",
            &binding("pay.refund", "ord_1", 100),
            ActionEffect::ExternalState,
            true,
        );
        assert_eq!(verdict(&past), "require_approval");
        assert_eq!(past.reason_codes, ["outside_task_authorization", "task_scope_extent"]);
        let read = t.check("run_1", &binding("orders.lookup", "ord_1", 0), ActionEffect::None, true);
        assert_eq!(verdict(&read), "allow", "reads are not counted");
    }

    #[test]
    fn limits_are_reviewed_and_classified() {
        let with = |l: Option<TaskLimits>| TaskAuthorization {
            limits: l,
            ..task(
                vec![scope("pay.refund", "ord_1", 1200)],
                OutOfScope::Deny,
                ReadOnly::Allow,
            )
        };
        assert!(with(Some(limits(Some(1), None))).validate("run_1").is_ok());
        assert!(
            with(Some(limits(None, None))).validate("run_1").is_err(),
            "an empty limit"
        );
        assert!(with(Some(limits(Some(5000), None))).validate("run_1").is_err());
        let current = with(Some(limits(Some(2), Some(1200))));
        assert_eq!(
            with(Some(limits(Some(1), Some(1200)))).change_from(Some(&current)),
            Change::Narrowed
        );
        assert_eq!(
            with(Some(limits(Some(3), Some(1200)))).change_from(Some(&current)),
            Change::Widened
        );
        assert_eq!(
            with(Some(limits(Some(2), None))).change_from(Some(&current)),
            Change::Widened,
            "a dropped total"
        );
        assert_eq!(
            with(None).change_from(Some(&current)),
            Change::Widened,
            "dropped limits"
        );
        assert_eq!(current.change_from(Some(&with(None))), Change::Narrowed, "added limits");
        assert_ne!(current.bundle_ref("run_1"), with(None).bundle_ref("run_1"));
    }

    #[tokio::test]
    async fn charges_are_conserved_under_concurrency() {
        let store = std::sync::Arc::new(contextos_store::MemoryStore::new());
        let key = exposure_key("acme", "run_1");
        let l = std::sync::Arc::new(limits(None, Some(1200)));
        let amount = json!({"minor_units": 500, "currency": "INR"});
        let tasks: Vec<_> = (0..8)
            .map(|i| {
                let (store, key, l, amount) = (store.clone(), key.clone(), l.clone(), amount.clone());
                tokio::spawn(
                    async move { charge(store.as_ref(), &key, &l, &format!("op_{i}"), Some(&amount), false).await },
                )
            })
            .collect();
        let mut charged = Vec::new();
        for (i, t) in tasks.into_iter().enumerate() {
            if t.await.unwrap().unwrap() == Charge::Charged {
                charged.push(format!("op_{i}"));
            }
        }
        assert_eq!(charged.len(), 2, "500 + 500 fit in 1200, a third does not");
        release(store.as_ref(), &key, &charged[0]).await.unwrap();
        let used = store.get(&key).await.unwrap().unwrap().body;
        assert_eq!(
            (used["effects"].clone(), used["amounts"]["INR"].clone()),
            (json!(1), json!(500))
        );
        assert_eq!(
            charge(store.as_ref(), &key, &l, "op_x", Some(&amount), false)
                .await
                .unwrap(),
            Charge::Charged,
            "a returned charge frees its share"
        );
        assert_eq!(
            charge(store.as_ref(), &key, &l, "op_y", Some(&amount), true)
                .await
                .unwrap(),
            Charge::Charged,
            "an approved action may exceed it"
        );
    }

    #[test]
    fn authorizations_are_reviewed_and_pinned() {
        let good = task(
            vec![scope("pay.refund", "ord_1", 100)],
            OutOfScope::Deny,
            ReadOnly::Allow,
        );
        assert!(good.validate("run_1").is_ok());
        assert!(good.validate("run_2").is_err(), "a scope for another task");
        assert!(
            task(vec![], OutOfScope::Deny, ReadOnly::Allow)
                .validate("run_1")
                .is_err()
        );
        let mut malformed = scope("pay.refund", "ord_1", 100);
        malformed["amount_ceiling"]["currency"] = json!("inr");
        assert!(
            task(vec![malformed], OutOfScope::Deny, ReadOnly::Allow)
                .validate("run_1")
                .is_err()
        );
        let mut other = good.clone();
        other.scopes[0]["resource_ids"] = json!(["ord_2"]);
        assert_ne!(
            good.bundle_ref("run_1"),
            other.bundle_ref("run_1"),
            "the reference pins the content"
        );
    }
}
