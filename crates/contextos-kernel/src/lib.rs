//! The ContextOS decision kernel.
//!
//! Every function here is pure and deterministic: no I/O, no clock, no randomness.
//! Time and verified observations are explicit inputs. That makes the kernel safe to
//! embed in any process, replayable from recorded inputs, and checkable against the
//! spec's reference vectors. Results never authorize an effect on their own; the
//! runtime must also enforce them at the boundary that performs the effect.

pub mod action_risk;
pub mod authorization;
pub mod budget_ledger;
pub mod compiler;
pub mod conformance;
pub mod execution_boundary;
pub mod negotiation;
pub mod operation_ledger;
pub mod pathspec;
pub mod profiles;
pub mod run_state;
mod support;

pub use support::TransitionResult;

pub use action_risk::{evaluate_action_risk, evaluate_action_risk_json, project_action_risk};
pub use compiler::{CompileDeps, CompileError, ContextPackCompiler, ResolvedRule};
pub use negotiation::negotiate_execution_contract;
pub use profiles::STANDARD_PROFILE_REGISTRY;
