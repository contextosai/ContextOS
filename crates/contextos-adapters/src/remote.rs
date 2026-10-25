//! Remote fact providers: the deployment's identity broker, control plane and
//! approval service answer over HTTPS with verified, normalized facts.
//!
//! Requests are JSON `POST`s to a pinned endpoint carrying a service credential.
//! Any transport failure, non-200 status or malformed body is a [`PortError`], which
//! the gateway treats as a missing fact: the effect is blocked, never allowed.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use contextos_contract::ingress::parse_strict;
use contextos_gateway::{
    ApprovalProvider, AuthorityFacts, AuthorityProvider, BoundaryProvider, CapabilityManifest, ConstraintProvider,
    DataFlowProvider, IdempotencyProvider, MemoryPolicyProvider, PortError, RunAdmission,
};
use serde_json::{Value, json};
use url::Url;

use crate::transport::{Credential, EndpointError, Exchange, TransportPolicy, client, pinned_endpoint, send};

/// One remote fact service.
#[derive(Clone)]
pub struct RemoteFacts {
    endpoint: Url,
    client: reqwest::Client,
    credential: Option<Credential>,
    policy: TransportPolicy,
    timeout: Duration,
}

impl std::fmt::Debug for RemoteFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteFacts")
            .field("endpoint", &self.endpoint.as_str())
            .finish_non_exhaustive()
    }
}

impl RemoteFacts {
    pub fn new(
        endpoint: &str,
        credential: Option<Credential>,
        policy: TransportPolicy,
        timeout: Duration,
    ) -> Result<Self, EndpointError> {
        Ok(Self {
            endpoint: pinned_endpoint(endpoint, &policy)?,
            client: client(&policy),
            credential,
            policy,
            timeout,
        })
    }

    async fn call(&self, port: &'static str, body: &Value) -> Result<Value, PortError> {
        let mut request = self.client.post(self.endpoint.clone()).json(body);
        if let Some(value) = self.credential.as_ref().and_then(Credential::header) {
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        match send(request, self.timeout, self.policy.max_response_bytes).await {
            Exchange::Response { status: 200, body, .. } => parse_strict(&body, self.policy.max_response_bytes)
                .map_err(|_| PortError::new(port, "malformed response")),
            Exchange::Response { status, .. } => Err(PortError::new(port, format!("status {status}"))),
            Exchange::NotSent | Exchange::Lost => Err(PortError::new(port, "unreachable")),
        }
    }
}

/// What a fact service learns about the run. For a delegated run it also gets the
/// lineage, so an authority broker can return the narrowing grant chain to the root.
fn run_summary(admission: &RunAdmission) -> Value {
    let mut run = json!({"tenant_id": admission.tenant_id, "run_id": admission.run_id, "contract_id": admission.contract_id,
        "trace_id": admission.trace_id, "actor": admission.actor, "policy_refs": admission.binding_policy_refs(),
        "root_run_id": admission.run_id});
    // An approval service routes `ask` approvals to who authorized the task.
    if !admission.task_authorizations.is_empty() {
        run["task_authorizations"] = json!(admission.task_authorizations);
    }
    if let Some(lineage) = &admission.lineage {
        run["root_run_id"] = json!(lineage.root_run_id);
        run["parent_run_id"] = json!(lineage.parent_run_id);
        run["delegation_id"] = json!(lineage.delegation_id);
        run["ancestry"] = json!(lineage.links);
    }
    run
}

/// Mandate/identity broker.
#[derive(Debug, Clone)]
pub struct RemoteAuthority(pub Arc<RemoteFacts>);

#[async_trait]
impl AuthorityProvider for RemoteAuthority {
    async fn authority(&self, admission: &RunAdmission, binding: &Value) -> Result<AuthorityFacts, PortError> {
        let facts = self
            .0
            .call("authority", &json!({"run": run_summary(admission), "binding": binding}))
            .await?;
        serde_json::from_value(facts).map_err(|_| PortError::new("authority", "malformed facts"))
    }
}

/// Control-plane attestations for independent required controls.
#[derive(Debug, Clone)]
pub struct RemoteConstraints(pub Arc<RemoteFacts>);

#[async_trait]
impl ConstraintProvider for RemoteConstraints {
    async fn observations(
        &self,
        admission: &RunAdmission,
        required: &[Value],
        action_digest: &str,
    ) -> Result<Vec<Value>, PortError> {
        let facts = self
            .0
            .call(
                "constraints",
                &json!({"run": run_summary(admission), "required_controls": required, "action_digest": action_digest}),
            )
            .await?;
        facts["observations"]
            .as_array()
            .cloned()
            .ok_or_else(|| PortError::new("constraints", "malformed facts"))
    }
}

/// Approval service.
#[derive(Debug, Clone)]
pub struct RemoteApprovals(pub Arc<RemoteFacts>);

#[async_trait]
impl ApprovalProvider for RemoteApprovals {
    async fn approval(&self, admission: &RunAdmission, action_digest: &str) -> Result<Option<Value>, PortError> {
        let facts = self
            .0
            .call(
                "approvals",
                &json!({"op": "lookup", "run": run_summary(admission), "action_digest": action_digest}),
            )
            .await?;
        match &facts["approval"] {
            Value::Null => Ok(None),
            Value::Object(_) => Ok(Some(facts["approval"].clone())),
            _ => Err(PortError::new("approvals", "malformed facts")),
        }
    }

    async fn request(
        &self,
        admission: &RunAdmission,
        binding: &Value,
        action_digest: &str,
    ) -> Result<String, PortError> {
        let facts = self
            .0
            .call("approvals", &json!({"op": "request", "run": run_summary(admission), "binding": binding, "action_digest": action_digest}))
            .await?;
        facts["approval_request_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| PortError::new("approvals", "malformed facts"))
    }
}

/// Data-governance service: returns `{"request", "policy"}` for an action, or
/// `{"request": null}` when no data leaves with it.
#[derive(Debug, Clone)]
pub struct RemoteDataFlow(pub Arc<RemoteFacts>);

#[async_trait]
impl DataFlowProvider for RemoteDataFlow {
    async fn data_flow(
        &self,
        admission: &RunAdmission,
        binding: &Value,
        action_digest: &str,
    ) -> Result<Option<(Value, Value)>, PortError> {
        let facts = self
            .0
            .call(
                "data_flow",
                &json!({"run": run_summary(admission), "binding": binding, "action_digest": action_digest}),
            )
            .await?;
        if facts["request"].is_null() {
            return Ok(None);
        }
        if !facts["request"].is_object() || !facts["policy"].is_object() {
            return Err(PortError::new("data_flow", "malformed facts"));
        }
        Ok(Some((facts["request"].clone(), facts["policy"].clone())))
    }
}

/// Execution-boundary controller: returns `{"requirement", "observation"}` for a run.
#[derive(Debug, Clone)]
pub struct RemoteBoundary(pub Arc<RemoteFacts>);

#[async_trait]
impl BoundaryProvider for RemoteBoundary {
    async fn boundary(&self, admission: &RunAdmission) -> Result<(Value, Value), PortError> {
        let facts = self.0.call("boundary", &json!({"run": run_summary(admission)})).await?;
        if !facts["requirement"].is_object() || !facts["observation"].is_object() {
            return Err(PortError::new("boundary", "malformed facts"));
        }
        Ok((facts["requirement"].clone(), facts["observation"].clone()))
    }
}

/// Memory-governance service: returns `{"context"}` for a lifecycle record.
#[derive(Debug, Clone)]
pub struct RemoteMemoryPolicy(pub Arc<RemoteFacts>);

#[async_trait]
impl MemoryPolicyProvider for RemoteMemoryPolicy {
    async fn memory_context(&self, admission: &RunAdmission, record: &Value) -> Result<Value, PortError> {
        let facts = self
            .0
            .call("memory", &json!({"run": run_summary(admission), "record": record}))
            .await?;
        facts
            .get("context")
            .filter(|c| c.is_object())
            .cloned()
            .ok_or_else(|| PortError::new("memory", "malformed facts"))
    }
}

/// Provider idempotency contract verifier.
#[derive(Debug, Clone)]
pub struct RemoteIdempotency(pub Arc<RemoteFacts>);

#[async_trait]
impl IdempotencyProvider for RemoteIdempotency {
    async fn proof(
        &self,
        manifest: &CapabilityManifest,
        operation_id: &str,
        action_digest: &str,
        key: &str,
    ) -> Result<Option<Value>, PortError> {
        let facts = self
            .0
            .call(
                "idempotency",
                &json!({"capability_id": manifest.capability_id, "operation_id": operation_id,
                "action_digest": action_digest, "key": key}),
            )
            .await?;
        Ok(facts.get("proof").filter(|p| p.is_object()).cloned())
    }
}
