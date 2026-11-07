//! End-to-end governed dispatch through `contextosd` with remote fact services and an
//! MCP provider, all over real HTTP.

mod agent_binding;
mod api;
mod audit_sinks;
mod budgets;
mod checks;
mod compensation;
mod coordination;
mod decisions;
mod delegation;
mod discovery;
mod effects;
mod erasure;
mod evaluation;
mod evidence;
mod executors;
mod exposure;
mod exposure_import;
mod findings;
mod harness;
mod hold_owners;
mod information_flow;
mod load;
mod mcp_transport;
mod memory;
mod notifications;
mod operations;
mod outcomes;
mod ownership;
mod pack_intents;
mod startup;
mod task_authorization;
mod usage_claims;
mod user_binding;
