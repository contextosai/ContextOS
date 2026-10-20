//! The ContextOS decision kernel.
//!
//! Every function here is pure and deterministic: no I/O, no clock, no randomness.
//! Time and verified observations are explicit inputs. That makes the kernel safe to
//! embed in any process, replayable from recorded inputs, and checkable against the
//! spec's reference vectors. Results never authorize an effect on their own; the
//! runtime must also enforce them at the boundary that performs the effect.

pub mod action_risk;
pub mod authorization;
pub mod budget_compaction;
pub mod budget_ledger;
pub mod compiler;
pub mod conformance;
pub mod execution_boundary;
pub mod negotiation;
pub mod operation_ledger;
pub mod pathspec;
pub mod profiles;
pub mod release_gate;
pub mod run_state;
pub mod scorecard_gate;
mod support;

pub use support::TransitionResult;

pub use action_risk::{evaluate_action_risk, evaluate_action_risk_json, project_action_risk};
pub use compiler::{CompileDeps, CompileError, ContextPackCompiler, ResolvedRule};
pub use negotiation::negotiate_execution_contract;
pub use profiles::STANDARD_PROFILE_REGISTRY;

/// Evaluates JsonLogic for embedders: JSON result, `null` for `undefined` or
/// non-finite numbers, and a message on evaluation failure.
pub fn policy_apply(logic: &serde_json::Value, data: &serde_json::Value) -> Result<serde_json::Value, String> {
    contextos_policy::apply(logic, data)
        .map(|value| value.to_json().unwrap_or(serde_json::Value::Null))
        .map_err(|e| format!("{:?}", e.kind))
}
