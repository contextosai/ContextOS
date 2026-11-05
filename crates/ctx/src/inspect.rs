//! `ctx inspect`: a reviewer's summary of a Context Pack. It covers the intents and the
//! rules scoped to each, the tools with their approval modes and permissions, the
//! approval gates, the decisions with the evidence they require, and the names a rule
//! or permission uses that the pack does not define (`problems`). The compiler does not
//! refuse such names at load; a typo in an approval gate or decision binding only shows
//! when its rule applies.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use contextos_contract::canonical::sha256_canonical;
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use contextos_contract::types::{ContextPack, PolicyRule};
use serde_json::{Value, json};

use crate::{Failure, read, typed};

fn effect(rule: &PolicyRule) -> &'static str {
    if !rule.then.allow {
        "deny"
    } else if rule.then.approval_gate().is_some_and(|g| !g.is_empty()) {
        "require_approval"
    } else {
        "allow"
    }
}

/// Names used but not defined, and other review findings, one sentence each.
pub fn problems(pack: &ContextPack) -> Vec<String> {
    let gates: BTreeSet<&str> = pack
        .policy_layer
        .approval_gates
        .iter()
        .map(|g| g.gate_id.as_str())
        .collect();
    let specs: BTreeSet<&str> = pack
        .decision_layer
        .decision_specs
        .iter()
        .map(|s| s.decision_key.as_str())
        .collect();
    let capabilities: BTreeSet<String> = pack
        .tooling_layer
        .adapter_registry
        .iter()
        .flat_map(|a| a.capabilities.iter().map(move |c| format!("{}.{c}", a.adapter_id)))
        .collect();
    let mut out = Vec::new();
    let mut rule_ids = BTreeSet::new();
    for bundle in &pack.policy_layer.policy_bundles {
        for rule in &bundle.policy_dsl.rules {
            let at = format!("{}/{}", bundle.bundle_id, rule.rule_id);
            if !rule_ids.insert(rule.rule_id.as_str()) {
                out.push(format!("{at}: rule_id appears more than once"));
            }
            if let Some(gate) = rule.then.approval_gate().filter(|g| !g.is_empty())
                && !gates.contains(gate)
            {
                out.push(format!("{at}: requires_approval_gate {gate} is not an approval gate"));
            }
            if let Some(key) = rule.decision_binding.as_deref().filter(|k| !k.is_empty())
                && !specs.contains(key)
            {
                out.push(format!("{at}: decision_binding {key} has no decision spec"));
            }
            for prohibited in rule.then.prohibits.iter().flatten() {
                if !capabilities.contains(prohibited) {
                    out.push(format!("{at}: prohibits {prohibited}, which no adapter declares"));
                }
            }
            if rule.rationale.as_deref().is_none_or(str::is_empty) {
                out.push(format!("{at}: no rationale"));
            }
        }
    }
    for permission in &pack.tooling_layer.permissions {
        let id = format!("{}.{}", permission.adapter_id, permission.capability);
        if !capabilities.contains(&id) {
            out.push(format!(
                "permission {}: {id} is not a declared capability",
                permission.permission_id
            ));
        }
        if let Some(Some(gate)) = &permission.requires_approval_gate
            && !gate.is_empty()
            && !gates.contains(gate.as_str())
        {
            out.push(format!(
                "permission {}: requires_approval_gate {gate} is not an approval gate",
                permission.permission_id
            ));
        }
    }
    out
}

/// The summary `ctx inspect` prints.
pub fn summary(pack: &ContextPack, sha256: &str) -> Value {
    let mut intents: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for bundle in &pack.policy_layer.policy_bundles {
        for rule in &bundle.policy_dsl.rules {
            let scope = rule
                .applies_to
                .intent
                .clone()
                .filter(|i| !i.is_empty())
                .unwrap_or_else(|| "*".into());
            let mut entry = json!({"rule_id": rule.rule_id, "bundle_id": bundle.bundle_id,
                "priority": bundle.priority, "effect": effect(rule), "if": rule.condition});
            let fields = entry.as_object_mut().expect("object");
            if let Some(otherwise) = &rule.otherwise {
                fields.insert("else".into(), json!(if otherwise.allow { "allow" } else { "deny" }));
            }
            if let Some(gate) = rule.then.approval_gate().filter(|g| !g.is_empty()) {
                fields.insert("approval_gate".into(), json!(gate));
            }
            for (key, value) in [
                ("obligations", rule.then.requires.clone()),
                ("prohibits", rule.then.prohibits.clone()),
            ] {
                if let Some(value) = value.filter(|v| !v.is_empty()) {
                    fields.insert(key.into(), json!(value));
                }
            }
            if let Some(binding) = &rule.decision_binding {
                fields.insert("decision_binding".into(), json!(binding));
            }
            intents.entry(scope).or_default().push(entry);
        }
    }
    let permitted: BTreeMap<String, &contextos_contract::types::ToolPermission> = pack
        .tooling_layer
        .permissions
        .iter()
        .filter(|p| p.allow)
        .map(|p| (format!("{}.{}", p.adapter_id, p.capability), p))
        .collect();
    let tools: Vec<Value> = pack
        .tooling_layer
        .adapter_registry
        .iter()
        .flat_map(|adapter| {
            adapter.capabilities.iter().map(|capability| {
                let id = format!("{}.{capability}", adapter.adapter_id);
                let permission = permitted.get(&id);
                json!({"capability_id": id, "approval_mode": adapter.approval_mode.as_str(),
                    "permitted": permission.is_some(),
                    "arg_constraints": permission.and_then(|p| p.arg_constraints.clone()),
                    "risk": adapter.capability_risks.as_ref().and_then(|r| r.get(capability))})
            })
        })
        .collect();
    let decisions: Vec<Value> = pack
        .decision_layer
        .decision_specs
        .iter()
        .map(|spec| {
            let bound_by: Vec<&str> = pack
                .policy_layer
                .policy_bundles
                .iter()
                .flat_map(|b| &b.policy_dsl.rules)
                .filter(|r| r.decision_binding.as_deref() == Some(spec.decision_key.as_str()))
                .map(|r| r.rule_id.as_str())
                .collect();
            json!({"decision_key": spec.decision_key, "version": spec.version,
                "required_evidence": spec.required_evidence, "allowed_outcomes": spec.allowed_outcomes,
                "bound_by": bound_by})
        })
        .collect();
    let gates: Vec<Value> = pack
        .policy_layer
        .approval_gates
        .iter()
        .map(|g| json!({"gate_id": g.gate_id, "approver_role": g.required_approver_role, "ttl_seconds": g.ttl_seconds}))
        .collect();
    json!({
        "pack_ref": pack.pack_meta.pack_ref(),
        "tenant_id": pack.pack_meta.tenant.tenant_id,
        "sha256": sha256,
        "intents": intents,
        "tools": tools,
        "approval_gates": gates,
        "decisions": decisions,
        "problems": problems(pack),
    })
}

pub fn run(path: &PathBuf) -> Result<Value, Failure> {
    let value = read(path)?;
    if let Err(e) = validate(&SchemaTarget::document(SchemaDoc::ContextPack), &value) {
        return Err(Failure::Rejected(
            json!({"error": "pack does not conform to context-pack.v2", "violations": e.violations}),
        ));
    }
    let sha256 = sha256_canonical(&value).map_err(|e| Failure::Usage(e.to_string()))?;
    let pack: ContextPack = typed(value, "pack")?;
    Ok(summary(&pack, &sha256))
}
