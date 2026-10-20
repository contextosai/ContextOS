//! `ctx`: offline ContextOS tooling on the same kernel the runtime uses.
//!
//! Exit codes: 0 success, 1 the input was evaluated and failed (invalid, rejected,
//! not allowed), 2 usage or I/O error.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use contextos_contract::ingress::parse_strict;
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use contextos_contract::types::{ContextPack, InvokeRequest, RunContext};
use contextos_kernel::authorization::digest_action_binding;
use contextos_kernel::{
    CompileDeps, CompileError, ContextPackCompiler, STANDARD_PROFILE_REGISTRY, negotiate_execution_contract,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "ctx", version, about = "ContextOS offline tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a JSON file against a published schema (e.g. `context-pack`, `execution-contract --def ActionBinding`).
    Validate {
        schema: String,
        file: PathBuf,
        #[arg(long)]
        def: Option<String>,
    },
    /// Compile a Context Pack for a request and run context.
    Compile {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        run_context: PathBuf,
        /// JSON object with optional `evidence`, `evidence_conflicts`, `promoted_memory` arrays.
        #[arg(long)]
        deps: Option<PathBuf>,
    },
    /// Print the RFC 8785 digest of an ActionBinding.
    Digest { binding: PathBuf },
    /// Negotiate an execution contract against the standard profile registry.
    Negotiate {
        #[arg(long)]
        contract: PathBuf,
        #[arg(long)]
        support: PathBuf,
        #[arg(long)]
        features: PathBuf,
    },
    /// Review a capability manifest before pinning it.
    Manifest { file: PathBuf },
    /// Print the standard profile registry.
    Profiles,
    /// Hash an API key for the server configuration (reads the key from stdin).
    HashKey,
    /// Verify an exported audit chain offline against published keys: every entry's
    /// payload digest, record hash and signature, and the chain's linkage from genesis.
    AuditVerify {
        /// The entries in order: a JSON array, or `{"entries": [...]}` pages concatenated
        /// into one array.
        #[arg(long)]
        entries: PathBuf,
        /// `{"keys": [{"kid", "alg", "public_key"}]}` as served by `GET /v1/audit/keys`.
        #[arg(long)]
        keys: PathBuf,
        /// The last entry of an export verified earlier: the entries must continue it
        /// exactly (next sequence, linked hash), so only new entries need checking.
        #[arg(long)]
        continues: Option<PathBuf>,
    },
    /// Collect evaluator scorecards from run evidence bundles (`GET /v1/runs/{id}/evidence`)
    /// into `ctx scorecard-gate` input, one case per run.
    Scorecards {
        /// Evidence bundle files.
        #[arg(required = true)]
        evidence: Vec<PathBuf>,
        /// JSON object mapping run ids to case names (replays of one case under
        /// different run ids pair up); runs without an entry use their run id.
        #[arg(long)]
        case_map: Option<PathBuf>,
    },
    /// Trajectory gate: compare what agents did on the same cases under a baseline and
    /// a candidate (evidence bundles of replayed or shadowed runs): capabilities used,
    /// decision outcomes, effects applied and tool calls. Fails on new capabilities,
    /// changed outcomes, more effects, tool calls beyond a ratio of the baseline's, or a
    /// case the candidate did not run, unless acknowledged per case.
    TrajectoryGate {
        /// Baseline evidence bundle files.
        #[arg(long, required = true, num_args = 1..)]
        baseline: Vec<PathBuf>,
        /// Candidate evidence bundle files.
        #[arg(long, required = true, num_args = 1..)]
        candidate: Vec<PathBuf>,
        /// JSON object mapping run ids to case names.
        #[arg(long)]
        case_map: Option<PathBuf>,
        /// Tool calls a candidate case may make, as a multiple of the baseline's most.
        #[arg(long, default_value_t = 1.5)]
        max_tool_call_ratio: f64,
        /// `{"capabilities": {case: [ids]}, "outcomes": [cases], "effects": [cases], "tool_calls": [cases]}`.
        #[arg(long)]
        acknowledge: Option<PathBuf>,
    },
    /// Scorecard release gate: compare candidate scorecards with the baseline's on
    /// paired replay cases; fails on floors, policy/safety regressions, utility,
    /// latency or cost beyond limits, and missing cases or measurements.
    ScorecardGate {
        /// JSON array of `{case, scorecards: [{policy, utility, safety, latency?, cost?}]}`.
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        /// `{policy_floor, safety_floor, max_utility_drop, max_latency_ratio?, max_cost_ratio?, min_cases}`.
        #[arg(long)]
        thresholds: PathBuf,
    },
    /// Release gate: compare a candidate Context Pack with the baseline on replay
    /// cases; fails on unacknowledged widenings of capabilities, policy or evidence
    /// gates, and on cases the candidate cannot compile.
    Gate {
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        /// JSON array of `{name, request, run_context, deps}` (see `GET /v1/runs/{id}/replay-case`).
        #[arg(long)]
        cases: PathBuf,
        /// Operator acknowledgements: `{capabilities, policy_loosening, evidence_gates}`.
        #[arg(long)]
        acknowledge: Option<PathBuf>,
        /// Open feedback (`GET /v1/feedback`): the gate fails unless every open
        /// record's replay obligation is among the cases.
        #[arg(long)]
        feedback: Option<PathBuf>,
    },
}

enum Failure {
    Usage(String),
    Rejected(Value),
}

fn read(path: &PathBuf) -> Result<Value, Failure> {
    let bytes = std::fs::read(path).map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))?;
    parse_strict(&bytes, 64 * 1024 * 1024).map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))
}

fn typed<T: serde::de::DeserializeOwned>(value: Value, what: &str) -> Result<T, Failure> {
    serde_json::from_value(value).map_err(|e| Failure::Rejected(json!({"error": format!("{what}: {e}")})))
}

fn schema_target(name: &str, def: Option<&str>) -> Result<SchemaTarget, Failure> {
    let doc = SchemaDoc::ALL
        .into_iter()
        .find(|d| d.file_name().split(".v").next() == Some(name))
        .ok_or_else(|| {
            Failure::Usage(format!(
                "unknown schema {name}; known: {}",
                SchemaDoc::ALL.map(SchemaDoc::file_name).join(", ")
            ))
        })?;
    match def {
        Some(def) if doc.document()["$defs"].get(def).is_none() => {
            Err(Failure::Usage(format!("{name} has no definition {def}")))
        }
        Some(def) => Ok(SchemaTarget::def(doc, def)),
        None => Ok(SchemaTarget::document(doc)),
    }
}

fn run(command: Command) -> Result<Value, Failure> {
    match command {
        Command::Validate { schema, file, def } => {
            let target = schema_target(&schema, def.as_deref())?;
            let instance = read(&file)?;
            match validate(&target, &instance) {
                Ok(()) => Ok(json!({"valid": true})),
                Err(e) => Err(Failure::Rejected(json!({"valid": false, "violations": e.violations}))),
            }
        }
        Command::Compile {
            pack,
            request,
            run_context,
            deps,
        } => {
            let pack_value = read(&pack)?;
            if let Err(e) = validate(&SchemaTarget::document(SchemaDoc::ContextPack), &pack_value) {
                return Err(Failure::Rejected(
                    json!({"error": "pack does not conform to context-pack.v2", "violations": e.violations}),
                ));
            }
            let pack: ContextPack = typed(pack_value, "pack")?;
            let request: InvokeRequest = typed(read(&request)?, "request")?;
            let run_context: RunContext = typed(read(&run_context)?, "run_context")?;
            let deps_value = deps.map(|d| read(&d)).transpose()?.unwrap_or(Value::Null);
            let list = |key: &str| deps_value[key].as_array().cloned().unwrap_or_default();
            let deps = CompileDeps {
                evidence: list("evidence"),
                evidence_conflicts: list("evidence_conflicts"),
                promoted_memory: list("promoted_memory"),
            };
            let compiler =
                ContextPackCompiler::new(pack).map_err(|e| Failure::Rejected(json!({"error": e.to_string()})))?;
            match compiler.compile(&request, &run_context, &deps) {
                Ok(compiled) => Ok(serde_json::to_value(compiled).unwrap_or(Value::Null)),
                Err(CompileError::PolicyEval(detail)) => {
                    Err(Failure::Rejected(serde_json::to_value(&*detail).unwrap_or(Value::Null)))
                }
                Err(CompileError::Invalid(message)) => Err(Failure::Rejected(json!({"error": message}))),
            }
        }
        Command::Digest { binding } => match digest_action_binding(&read(&binding)?) {
            Ok(digest) => Ok(json!({"action_digest": digest})),
            Err(e) => Err(Failure::Rejected(json!({"error": e.to_string()}))),
        },
        Command::Negotiate {
            contract,
            support,
            features,
        } => {
            let registry = serde_json::to_value(&*STANDARD_PROFILE_REGISTRY).unwrap_or(Value::Null);
            let result =
                negotiate_execution_contract(&read(&contract)?, &read(&support)?, &registry, &read(&features)?);
            let value = serde_json::to_value(&result).unwrap_or(Value::Null);
            if value["status"] == "accepted" {
                Ok(value)
            } else {
                Err(Failure::Rejected(value))
            }
        }
        Command::Manifest { file } => {
            let manifest: contextos_gateway::CapabilityManifest = typed(read(&file)?, "manifest")?;
            manifest
                .validate()
                .map_err(|e| Failure::Rejected(json!({"error": e.to_string()})))?;
            Ok(json!({"valid": true, "capability_id": manifest.capability_id}))
        }
        Command::Gate {
            baseline,
            candidate,
            cases,
            acknowledge,
            feedback,
        } => {
            use contextos_kernel::release_gate::{Acknowledgements, ReplayCase, evaluate_release_gate};
            let baseline: contextos_contract::types::ContextPack = typed(read(&baseline)?, "baseline")?;
            let candidate: contextos_contract::types::ContextPack = typed(read(&candidate)?, "candidate")?;
            let cases: Vec<ReplayCase> = typed(read(&cases)?, "cases")?;
            let acknowledged: Acknowledgements = match acknowledge {
                Some(path) => typed(read(&path)?, "acknowledgements")?,
                None => Acknowledgements::default(),
            };
            // Every open correction's run must be replayed against the candidate.
            let mut missing: Vec<Value> = Vec::new();
            if let Some(path) = &feedback {
                let open = read(path)?;
                let records = open.get("feedback").cloned().unwrap_or(open);
                let records = records
                    .as_array()
                    .ok_or_else(|| Failure::Usage(format!("{}: not a feedback list", path.display())))?;
                let names: std::collections::HashSet<&str> = cases.iter().map(|c| c.name.as_str()).collect();
                for record in records.iter().filter(|r| r["status"] == "open") {
                    let case = record["replay_obligation"]["case"].as_str().ok_or_else(|| {
                        Failure::Usage(format!(
                            "{}: a feedback record has no replay obligation",
                            path.display()
                        ))
                    })?;
                    if !names.contains(case) {
                        missing.push(json!({"feedback_id": record["feedback_id"], "case": case}));
                    }
                }
            }
            let report = evaluate_release_gate(&baseline, &candidate, &cases, &acknowledged)
                .map_err(|e| Failure::Rejected(json!({"error": e})))?;
            let mut value = serde_json::to_value(&report).unwrap_or(Value::Null);
            if feedback.is_some() {
                value["missing_replay_obligations"] = json!(missing);
                if !missing.is_empty() {
                    value["verdict"] = json!("fail");
                }
            }
            if value["verdict"] == "pass" {
                Ok(value)
            } else {
                Err(Failure::Rejected(value))
            }
        }
        Command::AuditVerify {
            entries,
            keys,
            continues,
        } => {
            use base64::Engine as _;
            use contextos_audit::{AuditEntry, KeyRing, verify_chain};
            let loaded = read(&entries)?;
            let list = loaded.get("entries").cloned().unwrap_or(loaded);
            let chain: Vec<AuditEntry> = typed(list, "entries")?;
            let mut ring = KeyRing::new();
            let published = read(&keys)?;
            let list = published["keys"]
                .as_array()
                .filter(|k| !k.is_empty())
                .ok_or_else(|| Failure::Usage(format!("{}: no keys", keys.display())))?;
            let mut seen = std::collections::HashSet::new();
            for key in list {
                // A malformed key entry must never silently become a fully trusted key.
                let kid = key["kid"].as_str().unwrap_or_default();
                let retired_ok = key.get("retired_at").is_none_or(|r| {
                    r.as_str()
                        .is_some_and(contextos_contract::validation::is_contract_timestamp)
                });
                if kid.is_empty() || key["alg"] != "ed25519" || !retired_ok || !seen.insert(kid.to_owned()) {
                    return Err(Failure::Usage(format!(
                        "{}: each key needs a unique kid, alg ed25519 and, if retired, a valid retired_at",
                        keys.display()
                    )));
                }
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(key["public_key"].as_str().unwrap_or_default())
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                    .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
                    .ok_or_else(|| Failure::Usage(format!("{}: invalid public key", keys.display())))?;
                match key["retired_at"].as_str() {
                    Some(retired_at) => ring.insert_retired(kid, bytes, retired_at),
                    None => ring.insert(kid, bytes),
                }
            }
            let anchor: Option<AuditEntry> = match continues {
                Some(path) => Some(typed(read(&path)?, "anchor entry")?),
                None => None,
            };
            if chain.is_empty() {
                return Err(Failure::Rejected(
                    json!({"verified": false, "error": "no entries to verify"}),
                ));
            }
            match verify_chain(&chain, anchor.as_ref(), &ring) {
                // The anchor is assumed, not checked: report it so a reader sees which
                // verified prefix the result rests on.
                Ok(()) => Ok(json!({"verified": true, "entries": chain.len(),
                    "anchor_sequence": anchor.as_ref().map(|a| a.sequence),
                    "anchor_record_hash": anchor.as_ref().map(|a| a.record_hash.clone()),
                    "tenant_id": chain.first().map(|e| e.tenant_id.clone()),
                    "last_sequence": chain.last().map(|e| e.sequence),
                    "last_record_hash": chain.last().map(|e| e.record_hash.clone())})),
                Err(error) => Err(Failure::Rejected(
                    json!({"verified": false, "error": error.to_string()}),
                )),
            }
        }
        Command::TrajectoryGate {
            baseline,
            candidate,
            case_map,
            max_tool_call_ratio,
            acknowledge,
        } => {
            let map = match case_map {
                Some(path) => read(&path)?,
                None => json!({}),
            };
            let ack = match acknowledge {
                Some(path) => read(&path)?,
                None => json!({}),
            };
            let (base, cand) = (trajectories(&baseline, &map)?, trajectories(&candidate, &map)?);
            let acknowledged = |kind: &str, case: &str| {
                ack[kind]
                    .as_array()
                    .is_some_and(|cases| cases.iter().any(|c| c == case))
            };
            let mut reports = Vec::new();
            let mut failing = 0;
            for (case, b) in &base {
                let mut findings = Vec::new();
                let mut finding = |kind: &str, detail: Value, accepted: bool| {
                    failing += usize::from(!accepted);
                    findings.push(json!({"kind": kind, "detail": detail, "acknowledged": accepted}));
                };
                let Some(c) = cand.get(case) else {
                    finding("case_missing", json!("the candidate did not run this case"), false);
                    reports.push(json!({"case": case, "findings": findings}));
                    continue;
                };
                let new: Vec<&String> = c.capabilities.difference(&b.capabilities).collect();
                if !new.is_empty() {
                    let allowed = ack["capabilities"][case.as_str()].as_array();
                    let accepted = new
                        .iter()
                        .all(|n| allowed.is_some_and(|a| a.iter().any(|x| x == n.as_str())));
                    finding("new_capabilities", json!(new), accepted);
                }
                if c.outcomes != b.outcomes {
                    finding(
                        "outcomes_changed",
                        json!({"baseline": b.outcomes, "candidate": c.outcomes}),
                        acknowledged("outcomes", case),
                    );
                }
                if c.max_effects > b.max_effects {
                    finding(
                        "more_effects",
                        json!({"baseline": b.max_effects, "candidate": c.max_effects}),
                        acknowledged("effects", case),
                    );
                }
                #[allow(clippy::cast_precision_loss)]
                let ceiling = (b.max_tool_calls as f64 * max_tool_call_ratio).ceil();
                #[allow(clippy::cast_precision_loss)]
                if c.max_tool_calls as f64 > ceiling {
                    finding(
                        "more_tool_calls",
                        json!({"baseline": b.max_tool_calls, "candidate": c.max_tool_calls}),
                        acknowledged("tool_calls", case),
                    );
                }
                reports.push(json!({"case": case, "findings": findings}));
            }
            let report = json!({"verdict": if failing == 0 { "pass" } else { "fail" },
                "cases": reports, "unacknowledged": failing});
            if failing == 0 {
                Ok(report)
            } else {
                Err(Failure::Rejected(report))
            }
        }
        Command::Scorecards { evidence, case_map } => {
            let map = match case_map {
                Some(path) => read(&path)?,
                None => json!({}),
            };
            let mut cases: Vec<Value> = Vec::new();
            for path in &evidence {
                let bundle = read(path)?;
                let Some(run_id) = bundle["run_id"].as_str() else {
                    return Err(Failure::Rejected(
                        json!({"error": format!("{}: not an evidence bundle", path.display())}),
                    ));
                };
                let case = map[run_id].as_str().unwrap_or(run_id).to_owned();
                let cards: Vec<Value> = bundle["decisions"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .flat_map(|d| d["scores"].as_array().cloned().unwrap_or_default())
                    .map(|s| s["score"]["scorecard"].clone())
                    .collect();
                // Several runs of one case (trials) accumulate under its name.
                match cases.iter_mut().find(|c| c["case"] == case.as_str()) {
                    Some(existing) => existing["scorecards"]
                        .as_array_mut()
                        .into_iter()
                        .for_each(|a| a.extend(cards.clone())),
                    None => cases.push(json!({"case": case, "scorecards": cards})),
                }
            }
            Ok(Value::Array(cases))
        }
        Command::ScorecardGate {
            baseline,
            candidate,
            thresholds,
        } => {
            use contextos_kernel::scorecard_gate::{CaseScores, ScorecardThresholds, evaluate_scorecard_gate};
            let baseline: Vec<CaseScores> = typed(read(&baseline)?, "baseline")?;
            let candidate: Vec<CaseScores> = typed(read(&candidate)?, "candidate")?;
            let thresholds: ScorecardThresholds = typed(read(&thresholds)?, "thresholds")?;
            let report = evaluate_scorecard_gate(&baseline, &candidate, &thresholds)
                .map_err(|e| Failure::Rejected(json!({"error": e})))?;
            let value = serde_json::to_value(&report).unwrap_or(Value::Null);
            if report.verdict == "pass" {
                Ok(value)
            } else {
                Err(Failure::Rejected(value))
            }
        }
        Command::Profiles => Ok(serde_json::to_value(&*STANDARD_PROFILE_REGISTRY).unwrap_or(Value::Null)),
        Command::HashKey => {
            let mut key = String::new();
            std::io::stdin()
                .read_line(&mut key)
                .map_err(|e| Failure::Usage(e.to_string()))?;
            let key = key.trim_end_matches(['\r', '\n']);
            if key.len() < 32 {
                return Err(Failure::Usage("API keys must be at least 32 characters".into()));
            }
            Ok(json!({"key_sha256": format!("sha256:{}", hex::encode(Sha256::digest(key.as_bytes())))}))
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
            ExitCode::SUCCESS
        }
        Err(Failure::Rejected(value)) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
            ExitCode::from(1)
        }
        Err(Failure::Usage(message)) => {
            eprintln!("ctx: {message}");
            ExitCode::from(2)
        }
    }
}

/// What the runs of one case did, across trials.
#[derive(Default)]
struct Trajectory {
    capabilities: std::collections::BTreeSet<String>,
    /// `decision_key=outcome` of every recorded decision, across trials.
    outcomes: std::collections::BTreeSet<String>,
    /// The most effects (applied mutations) and tool calls any one trial made.
    max_effects: usize,
    max_tool_calls: u64,
}

fn trajectories(paths: &[PathBuf], map: &Value) -> Result<std::collections::BTreeMap<String, Trajectory>, Failure> {
    let mut cases: std::collections::BTreeMap<String, Trajectory> = std::collections::BTreeMap::new();
    for path in paths {
        let bundle = read(path)?;
        let Some(run_id) = bundle["run_id"].as_str() else {
            return Err(Failure::Rejected(
                json!({"error": format!("{}: not an evidence bundle", path.display())}),
            ));
        };
        let case = cases
            .entry(map[run_id].as_str().unwrap_or(run_id).to_owned())
            .or_default();
        let mut effects = 0;
        for decision in bundle["decisions"].as_array().into_iter().flatten() {
            let record = &decision["record"];
            case.outcomes.insert(format!(
                "{}={}",
                record["decision_key"].as_str().unwrap_or_default(),
                record["outcome"].as_str().unwrap_or("none")
            ));
            for call in record["tool_lineage"].as_array().into_iter().flatten() {
                if let Some(capability) = call["capability_id"].as_str() {
                    case.capabilities.insert(capability.to_owned());
                }
                effects += call["mutation_refs"].as_array().map_or(0, Vec::len);
            }
        }
        case.max_effects = case.max_effects.max(effects);
        let calls = bundle["budget_ledger"]["used"]["tool_calls"].as_u64().unwrap_or(0);
        case.max_tool_calls = case.max_tool_calls.max(calls);
    }
    Ok(cases)
}
