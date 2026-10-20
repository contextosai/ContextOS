//! Validation against the published ContextOS JSON Schemas (draft 2020-12).
//!
//! The schemas in `/schemas` are the normative serialization. Ingress paths validate
//! raw JSON here *before* deserializing into Rust types, so closed envelopes,
//! enum sets, bounds and conditional requirements are enforced exactly as published
//! rather than as re-derived by hand.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use jsonschema::{Registry, Validator};
use serde_json::Value;

/// A published schema document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemaDoc {
    AgentDelegation,
    CompiledContext,
    ContextPack,
    DecisionRecord,
    ExecutionContract,
    InvokeAgent,
    ReplayPacket,
    RunContext,
    ToolEnvelope,
}

impl SchemaDoc {
    pub const ALL: [SchemaDoc; 9] = [
        SchemaDoc::AgentDelegation,
        SchemaDoc::CompiledContext,
        SchemaDoc::ContextPack,
        SchemaDoc::DecisionRecord,
        SchemaDoc::ExecutionContract,
        SchemaDoc::InvokeAgent,
        SchemaDoc::ReplayPacket,
        SchemaDoc::RunContext,
        SchemaDoc::ToolEnvelope,
    ];

    pub fn file_name(self) -> &'static str {
        match self {
            SchemaDoc::AgentDelegation => "agent-delegation.v1.schema.json",
            SchemaDoc::CompiledContext => "compiled-context.v1.schema.json",
            SchemaDoc::ContextPack => "context-pack.v2.schema.json",
            SchemaDoc::DecisionRecord => "decision-record.v1.schema.json",
            SchemaDoc::ExecutionContract => "execution-contract.v1.schema.json",
            SchemaDoc::InvokeAgent => "invoke-agent.v1.schema.json",
            SchemaDoc::ReplayPacket => "replay-packet.v1.schema.json",
            SchemaDoc::RunContext => "run-context.v1.schema.json",
            SchemaDoc::ToolEnvelope => "tool-envelope.v1.schema.json",
        }
    }

    pub fn id(self) -> String {
        format!("https://contextosai.com/schemas/{}", self.file_name())
    }

    fn source(self) -> &'static str {
        match self {
            SchemaDoc::AgentDelegation => include_str!("../../../schemas/agent-delegation.v1.schema.json"),
            SchemaDoc::CompiledContext => include_str!("../../../schemas/compiled-context.v1.schema.json"),
            SchemaDoc::ContextPack => include_str!("../../../schemas/context-pack.v2.schema.json"),
            SchemaDoc::DecisionRecord => include_str!("../../../schemas/decision-record.v1.schema.json"),
            SchemaDoc::ExecutionContract => include_str!("../../../schemas/execution-contract.v1.schema.json"),
            SchemaDoc::InvokeAgent => include_str!("../../../schemas/invoke-agent.v1.schema.json"),
            SchemaDoc::ReplayPacket => include_str!("../../../schemas/replay-packet.v1.schema.json"),
            SchemaDoc::RunContext => include_str!("../../../schemas/run-context.v1.schema.json"),
            SchemaDoc::ToolEnvelope => include_str!("../../../schemas/tool-envelope.v1.schema.json"),
        }
    }

    /// The parsed schema document.
    pub fn document(self) -> &'static Value {
        &DOCUMENTS[&self]
    }
}

static DOCUMENTS: LazyLock<HashMap<SchemaDoc, Value>> = LazyLock::new(|| {
    SchemaDoc::ALL
        .iter()
        .map(|&doc| {
            let value: Value = serde_json::from_str(doc.source()).expect("published schema is valid JSON");
            (doc, value)
        })
        .collect()
});

/// One schema violation, with JSON pointers into the instance and the schema.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SchemaViolation {
    pub instance_path: String,
    pub schema_path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("instance does not conform to {target}: {} violation(s)", violations.len())]
pub struct SchemaError {
    pub target: String,
    pub violations: Vec<SchemaViolation>,
}

/// Maximum violations reported per validation, to bound error payloads.
pub const MAX_REPORTED_VIOLATIONS: usize = 32;

/// A validation target: a whole document or one of its `$defs`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SchemaTarget {
    pub doc: SchemaDoc,
    pub def: Option<String>,
}

impl SchemaTarget {
    pub fn document(doc: SchemaDoc) -> Self {
        Self { doc, def: None }
    }

    pub fn def(doc: SchemaDoc, name: &str) -> Self {
        Self {
            doc,
            def: Some(name.to_owned()),
        }
    }

    fn uri(&self) -> String {
        match &self.def {
            None => self.doc.id(),
            Some(name) => format!("{}#/$defs/{name}", self.doc.id()),
        }
    }
}

static VALIDATORS: LazyLock<Mutex<HashMap<SchemaTarget, Arc<Validator>>>> = LazyLock::new(Default::default);

static REGISTRY: LazyLock<Registry<'static>> = LazyLock::new(|| {
    let mut registry = Registry::new();
    for doc in SchemaDoc::ALL {
        registry = registry
            .add(doc.id(), doc.document())
            .expect("published schema registers");
    }
    registry.prepare().expect("published schemas resolve")
});

fn build(target: &SchemaTarget) -> Arc<Validator> {
    let root = serde_json::json!({ "$ref": target.uri() });
    let validator = jsonschema::options()
        .offline()
        .with_registry(&REGISTRY)
        .build(&root)
        .unwrap_or_else(|e| panic!("published schema target {} must compile: {e}", target.uri()));
    Arc::new(validator)
}

fn validator(target: &SchemaTarget) -> Arc<Validator> {
    let mut cache = VALIDATORS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(cache.entry(target.clone()).or_insert_with(|| build(target)))
}

/// Validates `instance` against a published schema target.
pub fn validate(target: &SchemaTarget, instance: &Value) -> Result<(), SchemaError> {
    let validator = validator(target);
    let violations: Vec<SchemaViolation> = validator
        .iter_errors(instance)
        .take(MAX_REPORTED_VIOLATIONS)
        .map(|error| SchemaViolation {
            instance_path: error.instance_path().to_string(),
            schema_path: error.schema_path().to_string(),
            message: error.to_string(),
        })
        .collect();
    if violations.is_empty() {
        Ok(())
    } else {
        Err(SchemaError {
            target: target.uri(),
            violations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_document_and_execution_contract_def_compiles() {
        for doc in SchemaDoc::ALL {
            let _ = validator(&SchemaTarget::document(doc));
            let defs = doc.document().get("$defs").and_then(Value::as_object);
            for name in defs.into_iter().flat_map(|d| d.keys()) {
                let _ = validator(&SchemaTarget::def(doc, name));
            }
        }
    }

    #[test]
    fn cross_document_refs_resolve() {
        // invoke-agent references run-context $defs by absolute URI.
        let error = validate(&SchemaTarget::document(SchemaDoc::InvokeAgent), &json!({})).unwrap_err();
        assert!(!error.violations.is_empty());
    }

    #[test]
    fn closed_def_rejects_unknown_fields() {
        let target = SchemaTarget::def(SchemaDoc::ExecutionContract, "ControlRef");
        assert!(validate(&target, &json!({"control_id": "a", "control_version": "1"})).is_ok());
        assert!(validate(&target, &json!({"control_id": "a", "control_version": "1", "x": 1})).is_err());
    }
}
