//! `ctx import-policy`: translates a documented, deterministic subset of OPA decision
//! tables or Cerbos `resourcePolicy` documents into a schema-validated, fail-closed
//! ContextOS Context Pack (`context-pack.v2`), plus an optional starter `ctx test` suite.
//!
//! Full Rego and CEL evaluation are explicitly out of scope (see `docs/SCOPE.md`).
//! Unsupported constructs fail closed rather than being silently dropped (threat T74).

use std::collections::BTreeSet;
use std::path::PathBuf;

use contextos_contract::ingress::parse_strict;
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use contextos_contract::types::ContextPack;
use contextos_kernel::ContextPackCompiler;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Failure;
use crate::import_cerbos;

pub(crate) struct Options<'a> {
    pub format: &'a str,
    pub input: &'a PathBuf,
    pub pack_id: &'a str,
    pub pack_version: &'a str,
    pub tenant: &'a str,
    pub out: Option<&'a PathBuf>,
    pub tests_out: Option<&'a PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportedEffect {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone)]
pub(crate) struct ImportedRule {
    pub rule_id: String,
    pub intent: Option<String>,
    pub effect: ImportedEffect,
    pub condition: Value,
    pub roles: Vec<String>,
    pub approver_role: Option<String>,
    pub rationale: String,
}

// ---- OPA JSON decision-table subset ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpaDecisionTable {
    package: String,
    #[serde(default)]
    default_allow: bool,
    rules: Vec<OpaRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpaRule {
    id: String,
    effect: String,
    #[serde(default)]
    intent: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    conditions: Vec<OpaCondition>,
    #[serde(default)]
    approver_role: Option<String>,
    #[serde(default)]
    rationale: Option<String>,
    #[serde(default)]
    priority: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpaCondition {
    field: String,
    op: String,
    value: Value,
}

fn parse_opa(raw: Value) -> Result<(String, Vec<ImportedRule>), String> {
    let table: OpaDecisionTable = serde_json::from_value(raw).map_err(|e| {
        format!(
            "unsupported OPA decision-table schema (expected JSON with package, rules[], and \
             documented fields only): {e}"
        )
    })?;
    if table.package.trim().is_empty() {
        return Err("OPA table `package` must not be empty".into());
    }
    if table.default_allow {
        return Err(
            "OPA table sets `default_allow: true`; ContextOS refuses fail-open defaults (set default_allow: false)"
                .into(),
        );
    }
    if table.rules.is_empty() {
        return Err("OPA table `rules` must contain at least one rule".into());
    }
    let mut imported = Vec::new();
    for rule in table.rules {
        if rule.id.trim().is_empty() {
            return Err("OPA rule `id` must not be empty".into());
        }
        let effect = match rule.effect.as_str() {
            "allow" => ImportedEffect::Allow,
            "deny" => ImportedEffect::Deny,
            "require_approval" => ImportedEffect::RequireApproval,
            other => {
                return Err(format!(
                    "OPA rule `{}`: unsupported effect `{other}` (expected allow, deny, or require_approval)",
                    rule.id
                ));
            }
        };
        let mut clauses = Vec::new();
        if !rule.roles.is_empty() && !rule.roles.iter().any(|r| r == "*") {
            if rule.roles.len() == 1 {
                clauses.push(json!({"==": [{"var": "user.role"}, rule.roles[0]]}));
            } else {
                clauses.push(json!({"in": [{"var": "user.role"}, rule.roles]}));
            }
        }
        for cond in &rule.conditions {
            if !cond.field.starts_with("request.context.") && !cond.field.starts_with("user.") {
                return Err(format!(
                    "OPA rule `{}`: unsupported condition field `{}` (must start with `request.context.` or `user.`)",
                    rule.id, cond.field
                ));
            }
            let jl_op = match cond.op.as_str() {
                "eq" | "==" => "==",
                "ne" | "!=" => "!=",
                "gt" | ">" => ">",
                "gte" | ">=" => ">=",
                "lt" | "<" => "<",
                "lte" | "<=" => "<=",
                "in" => "in",
                other => {
                    return Err(format!(
                        "OPA rule `{}`: unsupported condition op `{other}` (expected eq, ne, gt, gte, lt, lte, in)",
                        rule.id
                    ));
                }
            };
            clauses.push(json!({jl_op: [{"var": cond.field}, cond.value]}));
        }
        let condition = match clauses.len() {
            0 => json!(true),
            1 => clauses.remove(0),
            _ => json!({"and": clauses}),
        };
        if rule.priority.is_some() {
            return Err(format!(
                "OPA rule `{}`: `priority` is not supported; ContextOS always gives deny rules \
                 precedence over require_approval and allow rules, so remove it",
                rule.id
            ));
        }
        imported.push(ImportedRule {
            rule_id: rule.id.clone(),
            intent: rule.intent,
            effect,
            condition,
            roles: rule.roles,
            approver_role: rule.approver_role,
            rationale: rule
                .rationale
                .unwrap_or_else(|| format!("Imported from OPA package `{}` rule `{}`.", table.package, rule.id)),
        });
    }
    Ok((table.package, imported))
}

fn assemble_pack(
    source_name: &str,
    format: &str,
    pack_id: &str,
    pack_version: &str,
    tenant_id: &str,
    rules: &[ImportedRule],
) -> Result<Value, String> {
    let mut seen_ids = BTreeSet::new();
    let mut deny_rules = Vec::new();
    let mut approval_rules = Vec::new();
    let mut allow_rules = Vec::new();
    let mut gates = Vec::new();
    let mut intents = BTreeSet::new();

    for rule in rules {
        if !seen_ids.insert(rule.rule_id.clone()) {
            return Err(format!("duplicate imported rule_id `{}`", rule.rule_id));
        }
        if let Some(intent) = &rule.intent {
            intents.insert(intent.clone());
        }
        let applies_to = match &rule.intent {
            Some(intent) => json!({"intent": intent}),
            None => json!({}),
        };
        match rule.effect {
            ImportedEffect::Deny => {
                deny_rules.push(json!({
                    "rule_id": rule.rule_id,
                    "applies_to": applies_to,
                    "if": rule.condition,
                    "then": {"allow": false, "reason": rule.rationale},
                    "rationale": rule.rationale,
                }));
            }
            ImportedEffect::RequireApproval => {
                let gate_id = format!("GATE_{}", rule.rule_id);
                let approver = rule.approver_role.as_deref().unwrap_or("policy_approver");
                gates.push(json!({
                    "gate_id": gate_id,
                    "when": rule.condition,
                    "required_approver_role": approver,
                    "ttl_seconds": 3600,
                }));
                approval_rules.push(json!({
                    "rule_id": rule.rule_id,
                    "applies_to": applies_to,
                    "if": rule.condition,
                    "then": {
                        "allow": true,
                        "approval_mode": "destructive",
                        "requires_approval_gate": gate_id,
                    },
                    "rationale": rule.rationale,
                }));
            }
            ImportedEffect::Allow => {
                allow_rules.push(json!({
                    "rule_id": rule.rule_id,
                    "applies_to": applies_to,
                    "if": rule.condition,
                    "then": {"allow": true},
                    "rationale": rule.rationale,
                }));
            }
        }
    }

    let mut bundles = Vec::new();
    if !deny_rules.is_empty() {
        bundles.push(json!({
            "bundle_id": "IMPORTED_DENY",
            "priority": 100,
            "policy_dsl": {"language": "jsonlogic", "rules": deny_rules},
        }));
    }
    if !approval_rules.is_empty() {
        bundles.push(json!({
            "bundle_id": "IMPORTED_APPROVAL",
            "priority": 50,
            "policy_dsl": {"language": "jsonlogic", "rules": approval_rules},
        }));
    }
    if !allow_rules.is_empty() {
        bundles.push(json!({
            "bundle_id": "IMPORTED_ALLOW",
            "priority": 10,
            "policy_dsl": {"language": "jsonlogic", "rules": allow_rules},
        }));
    }
    // Fail-closed baseline: any request not explicitly matched is denied.
    bundles.push(json!({
        "bundle_id": "IMPORTED_DEFAULT_DENY",
        "priority": 0,
        "policy_dsl": {
            "language": "jsonlogic",
            "rules": [{
                "rule_id": "R_IMPORTED_DEFAULT_DENY",
                "applies_to": {},
                "if": true,
                "then": {"allow": false, "reason": "Default deny: no imported rule allowed this request."},
                "rationale": "Fail-closed default for imported policies."
            }]
        }
    }));

    let eval_targets: Vec<Value> = if intents.is_empty() {
        vec![json!({
            "intent": source_name,
            "policy": 1,
            "utility": 0.9,
            "latency_p99_ms": 3000,
            "safety": 1,
            "economics_cents_per_decision": 1.0
        })]
    } else {
        intents
            .iter()
            .map(|intent| {
                json!({
                    "intent": intent,
                    "policy": 1,
                    "utility": 0.9,
                    "latency_p99_ms": 3000,
                    "safety": 1,
                    "economics_cents_per_decision": 1.0
                })
            })
            .collect()
    };

    let pack = json!({
        "contract_meta": {
            "contract_name": pack_id,
            "contract_version": "2.0.0",
            "issuer": tenant_id,
            "created_at": "2026-01-01T00:00:00Z",
            "compatibility": {"requires": {"runtime": ">=2.0.0", "ontology": ">=1.0.0"}}
        },
        "pack_meta": {
            "pack_id": pack_id,
            "pack_version": pack_version,
            "tenant": {"tenant_id": tenant_id, "name": format!("Imported from {format}:{source_name}")},
            "environment_defaults": {"language": "en", "timezone": "UTC", "currency": "USD", "region": "global"},
            "ttl_seconds": 86400,
            "data_classification": "INTERNAL"
        },
        "intelligence_refs": {
            "ontology": {"namespace": format!("ont.{pack_id}"), "version": "1.0.0", "entity_types": ["Resource"], "relationship_types": []},
            "knowledge_graph": {"snapshot_pin_rule": "alias:prod"},
            "identity_layer": {"ceid_namespaces": ["resource"]}
        },
        "business_context": {
            "summary": {
                "what_we_do": format!("Imported {format} policy `{source_name}`."),
                "who_we_serve": ["enterprise"],
                "differentiators": ["deterministic_pre_action_governance"]
            },
            "non_negotiables": ["deny_by_default"]
        },
        "policy_layer": {
            "policy_bundles": bundles,
            "guardrails": {"must_refuse": [], "must_escalate": [], "redaction_rules": []},
            "approval_gates": gates,
            "action_risk_policy": {
                "allowed_effects": ["none", "local_state", "external_state"],
                "allowed_authorities": ["agent", "service", "user_delegated", "human_approved"],
                "allowed_reversibility": ["read_only", "reversible", "compensatable", "irreversible"],
                "allowed_interactions": ["api", "browser", "computer", "agent_to_agent", "human_handoff"],
                "data_scope_ceiling": "CONFIDENTIAL"
            }
        },
        "tooling_layer": {"adapter_registry": [], "permissions": []},
        "decision_layer": {"decision_specs": []},
        "memory_layer": {
            "memory_policy": {
                "tier_ttls": {"working": "1h", "episodic": "24h", "semantic": "365d", "durable": "1825d"},
                "write_classes_allowed": ["decision_outcome"],
                "consent_gating": {"pii_write_back_allowed": false}
            },
            "promotion_thresholds": {"auto_promote_confidence": 0.95}
        },
        "evaluation_layer": {"eval_targets": eval_targets},
        "tone_and_comms": {"voice_attributes": ["clear"], "do": ["cite policy"], "dont": ["bypass controls"]}
    });

    validate(&SchemaTarget::document(SchemaDoc::ContextPack), &pack).map_err(|e| {
        format!(
            "generated pack failed context-pack.v2 schema: {} violation(s)",
            e.violations.len()
        )
    })?;
    let typed: ContextPack = serde_json::from_value(pack.clone()).map_err(|e| e.to_string())?;
    let _ = ContextPackCompiler::new(typed).map_err(|e| format!("generated pack failed compiler check: {e}"))?;
    Ok(pack)
}

fn build_starter_tests(source_name: &str, tenant_id: &str, rules: &[ImportedRule]) -> Value {
    let mut tests = Vec::new();
    for rule in rules {
        let intent = rule.intent.as_deref().unwrap_or(source_name);
        let role = rule.roles.iter().find(|r| *r != "*").map_or("operator", String::as_str);
        let verdict = match rule.effect {
            ImportedEffect::Allow => "allow",
            ImportedEffect::Deny => "deny",
            ImportedEffect::RequireApproval => "require_approval",
        };
        tests.push(json!({
            "name": format!("imported rule {}", rule.rule_id),
            "with": {
                "request": {"intent": intent, "input": {"context": {}}},
                "run_context": {"tenant_id": tenant_id, "user": {"role": role}}
            },
            "expect": {"verdict": verdict, "rules": [rule.rule_id]}
        }));
    }
    tests.push(json!({
        "name": "unmatched role falls back to default deny",
        "with": {
            "request": {"intent": source_name, "input": {"context": {}}},
            "run_context": {"tenant_id": tenant_id, "user": {"role": "__unmatched_role__"}}
        },
        "expect": {"verdict": "deny"}
    }));
    json!({
        "suite": format!("imported-{source_name}"),
        "description": "Starter test suite generated by `ctx import-policy`. Fill in request.input.context fields for conditional rules before running `ctx test`.",
        "tests": tests
    })
}

pub(crate) fn run(options: &Options<'_>) -> Result<Value, Failure> {
    let bytes =
        std::fs::read(options.input).map_err(|e| Failure::Usage(format!("{}: {e}", options.input.display())))?;
    let trimmed = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map_or(&[][..], |i| &bytes[i..]);
    if options.format == "opa" && !trimmed.starts_with(b"{") {
        return Err(Failure::Rejected(json!({
            "error": "unsupported_format",
            "message": "Raw Rego files are out of scope; `ctx import-policy --format opa` imports structured JSON decision tables (`{package, default_allow: false, rules: [...]}`)."
        })));
    }
    let raw = parse_strict(&bytes, 16 * 1024 * 1024)
        .map_err(|e| Failure::Usage(format!("{}: {e}", options.input.display())))?;
    let (source_name, rules) = match options.format {
        "opa" => parse_opa(raw).map_err(|e| Failure::Rejected(json!({"error": "import_refused", "message": e})))?,
        "cerbos" => import_cerbos::parse(raw)
            .map_err(|e| Failure::Rejected(json!({"error": "import_refused", "message": e})))?,
        other => {
            return Err(Failure::Usage(format!(
                "unknown policy format `{other}`; expected `opa` or `cerbos`"
            )));
        }
    };
    let pack = assemble_pack(
        &source_name,
        options.format,
        options.pack_id,
        options.pack_version,
        options.tenant,
        &rules,
    )
    .map_err(|e| Failure::Rejected(json!({"error": "pack_invalid", "message": e})))?;

    if let Some(path) = options.out {
        let rendered = serde_json::to_string_pretty(&pack).map_err(|e| Failure::Usage(e.to_string()))?;
        std::fs::write(path, format!("{rendered}\n"))
            .map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))?;
    }
    if let Some(path) = options.tests_out {
        let suite = build_starter_tests(&source_name, options.tenant, &rules);
        let rendered = serde_json::to_string_pretty(&suite).map_err(|e| Failure::Usage(e.to_string()))?;
        std::fs::write(path, format!("{rendered}\n"))
            .map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))?;
    }

    let summary = json!({
        "imported": true,
        "format": options.format,
        "source": source_name,
        "pack_ref": format!("{}@{}", options.pack_id, options.pack_version),
        "rules_imported": rules.len(),
        "default_effect": "deny",
        "pack": if options.out.is_none() { Some(pack) } else { None },
    });
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cerbos_resource_policy_translates_and_compiles_with_deny_precedence() {
        let input = json!({
            "apiVersion": "api.cerbos.dev/v1",
            "resourcePolicy": {
                "resource": "refund",
                "version": "1",
                "rules": [
                    {
                        "name": "support_allow",
                        "actions": ["issue"],
                        "effect": "EFFECT_ALLOW",
                        "roles": ["support_agent"],
                        "condition": {"match": {"expr": "R.attr.amount <= 5000 && P.attr.region == 'eu'"}}
                    },
                    {
                        "name": "sanctioned_deny",
                        "actions": ["issue"],
                        "effect": "EFFECT_DENY",
                        "roles": ["*"],
                        "condition": {"match": {"expr": "R.attr.sanctioned == true"}}
                    }
                ]
            }
        });
        let (src, rules) = import_cerbos::parse(input).unwrap();
        assert_eq!(src, "refund");
        assert_eq!(rules.len(), 2);
        let pack = assemble_pack(&src, "cerbos", "ctxpack.refund", "1.0.0", "tenant_a", &rules).unwrap();
        assert_eq!(pack["policy_layer"]["policy_bundles"][0]["bundle_id"], "IMPORTED_DENY");
        assert_eq!(pack["policy_layer"]["policy_bundles"][1]["bundle_id"], "IMPORTED_ALLOW");
    }

    #[test]
    fn cerbos_refuses_unsupported_cel_functions_and_derived_roles() {
        let with_fn = json!({
            "apiVersion": "api.cerbos.dev/v1",
            "resourcePolicy": {
                "resource": "refund",
                "rules": [{
                    "actions": ["issue"],
                    "effect": "EFFECT_ALLOW",
                    "roles": ["support"],
                    "condition": {"match": {"expr": "R.attr.tags.exists(t, t == 'vip')"}}
                }]
            }
        });
        assert!(import_cerbos::parse(with_fn).is_err());

        let with_derived = json!({
            "apiVersion": "api.cerbos.dev/v1",
            "resourcePolicy": {
                "resource": "refund",
                "importDerivedRoles": ["common_roles"],
                "rules": [{"actions": ["issue"], "effect": "EFFECT_ALLOW", "roles": ["support"]}]
            }
        });
        assert!(import_cerbos::parse(with_derived).is_err());
    }

    #[test]
    fn opa_decision_table_translates_and_refuses_default_allow() {
        let ok = json!({
            "package": "payments.refunds",
            "default_allow": false,
            "rules": [
                {
                    "id": "R_HIGH_APPROVAL",
                    "effect": "require_approval",
                    "intent": "payments.refund",
                    "roles": ["support_agent"],
                    "conditions": [{"field": "request.context.amount", "op": "gt", "value": 3000}],
                    "approver_role": "finance_lead"
                },
                {
                    "id": "R_LOW_ALLOW",
                    "effect": "allow",
                    "intent": "payments.refund",
                    "roles": ["support_agent"],
                    "conditions": [{"field": "request.context.amount", "op": "lte", "value": 3000}]
                }
            ]
        });
        let (pkg, rules) = parse_opa(ok).unwrap();
        let pack = assemble_pack(&pkg, "opa", "ctxpack.payments", "1.0.0", "tenant_a", &rules).unwrap();
        assert_eq!(
            pack["policy_layer"]["approval_gates"][0]["required_approver_role"],
            "finance_lead"
        );

        let fail_open = json!({
            "package": "payments.refunds",
            "default_allow": true,
            "rules": [{"id": "R1", "effect": "allow"}]
        });
        assert!(parse_opa(fail_open).is_err());

        // A rule ordering ContextOS would not honour is refused, not silently dropped.
        let ordered = json!({
            "package": "payments.refunds",
            "default_allow": false,
            "rules": [{"id": "R1", "effect": "allow", "priority": 5}]
        });
        let error = parse_opa(ordered).unwrap_err();
        assert!(error.contains("priority"), "{error}");
    }
}
