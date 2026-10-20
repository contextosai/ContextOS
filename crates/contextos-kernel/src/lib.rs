//! The ContextOS decision kernel.
//!
//! Every function here is pure and deterministic: no I/O, no clock, no randomness.
//! Time and verified observations are explicit inputs. That makes the kernel safe to
//! embed in any process, replayable from recorded inputs, and checkable against the
//! spec's reference vectors. Results never authorize an effect on their own; the
//! runtime must also enforce them at the boundary that performs the effect.

pub mod action_risk;
pub mod compiler;

pub use action_risk::{evaluate_action_risk, evaluate_action_risk_json, project_action_risk};
pub use compiler::{CompileDeps, CompileError, ContextPackCompiler};
