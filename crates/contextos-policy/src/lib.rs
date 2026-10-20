//! Policy evaluation for ContextOS.
//!
//! Policy rules in a Context Pack are JsonLogic expressions evaluated against the run
//! context. Evaluation is pure, deterministic and bounded; any failure is returned as
//! an error so callers can stop compilation visibly instead of treating it as false.

// JavaScript semantics require exact IEEE-754 comparison, never an epsilon.
#![allow(clippy::float_cmp)]
#![allow(clippy::return_self_not_must_use)]

pub mod jsonlogic;
pub mod value;

pub use jsonlogic::{EvalError, EvalErrorKind, Limits, apply, apply_with_limits, predicate};
pub use value::JsVal;
