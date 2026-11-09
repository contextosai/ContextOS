//! Command-line arguments for `ctx`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ctx", version, about = "ContextOS offline tooling")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
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
    /// Draft a capability manifest for one MCP tool from a saved `tools/list` result
    /// (for example `npx @modelcontextprotocol/inspector --cli <server> --method tools/list`).
    /// Copies the tool's schemas and upstream pins; every decision is left as a
    /// `REVIEW:` field that `ctx manifest` and contextosd refuse until a person fills it.
    InitTool {
        /// The `tools/list` result: `{"tools": [...]}`, the JSON-RPC response, or an array.
        #[arg(long)]
        mcp: PathBuf,
        /// The tool's name on the MCP server.
        #[arg(long)]
        tool: String,
        /// The adapter id the server is configured under in contextosd.
        #[arg(long)]
        adapter: String,
        /// The capability's local name (default: the tool name).
        #[arg(long)]
        capability: Option<String>,
    },
    /// Print the standard profile registry.
    Profiles,
    /// Hash an API key for the server configuration (reads the key from stdin).
    HashKey,
    /// Sign claims as an evidence issuer or outcome witness (for building and testing
    /// one): prints `{attestation, jwks}`, the compact EdDSA JWS and the JWK Set to
    /// configure in `[[evidence_issuers]]`.
    Attest {
        /// The claims, a JSON object with `iss`.
        #[arg(long)]
        claims: PathBuf,
        /// Environment variable holding the 32-byte signing seed, hex encoded.
        #[arg(long)]
        seed_env: String,
        #[arg(long, default_value = "k1")]
        kid: String,
    },
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
    /// Build an evidence pack for a security or compliance review: the verified audit
    /// export and keys, a control map for each framework with the events that evidence
    /// each control counted over the period, a coverage statement, and a manifest of
    /// file digests. Refused unless the export verifies.
    EvidencePack {
        /// The audit export, as for `ctx audit-verify`.
        #[arg(long)]
        entries: PathBuf,
        /// The published audit keys (`GET /v1/audit/keys`).
        #[arg(long)]
        keys: PathBuf,
        /// The last entry of an earlier verified export this one continues.
        #[arg(long)]
        continues: Option<PathBuf>,
        /// soc2, iso42001, eu-ai-act or owasp-agentic; repeat for several.
        #[arg(long = "framework", required = true)]
        frameworks: Vec<String>,
        /// Output of `contextosd --check-config` for the deployment, included as supplied.
        #[arg(long)]
        config_report: Option<PathBuf>,
        /// The folder to write; it must not exist or be empty.
        #[arg(long)]
        out: PathBuf,
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
        /// `{"capabilities": {case: [ids]}, "outcomes": [cases], "effects": [cases], "tool_calls": [cases], "unpaired": [cases]}`.
        #[arg(long)]
        acknowledge: Option<PathBuf>,
        /// Audit exports (`GET /v1/audit/entries`, verified with `ctx audit-verify`): when
        /// given, the capabilities a run called and the effects it applied come from the
        /// runtime's signed record instead of what its decisions reported.
        #[arg(long, num_args = 1..)]
        audit: Vec<PathBuf>,
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
    /// Pack tests: check what a Context Pack decides against the author's expectations.
    /// Each suite is `{suite, base: {request, run_context, deps?}, tests: [{name, with?,
    /// expect}]}`; `with` is a JSON merge patch over the base and `expect` names any of
    /// `compile`, `verdict`, `rules`, `obligations`, `capabilities: {include, exclude}`,
    /// `evidence_gates`. The base, or any of its parts, may be a file path relative to
    /// the suite (for example a replay case). Fails (exit 1) on any failed test.
    Test {
        #[arg(long)]
        pack: PathBuf,
        /// Suite files.
        #[arg(required = true)]
        suites: Vec<PathBuf>,
        /// Also write the results as JUnit XML to this file.
        #[arg(long)]
        junit: Option<PathBuf>,
    },
    /// Decision plan: what a Context Pack lets a principal do for an intent before any
    /// request exists. Each rule is reported as applying always, or when / unless a
    /// residual condition over `request.*` holds, with the verdicts those conditions
    /// can reach. `--run` is a run context, or an admission body carrying
    /// `run_context`; the intent defaults to the run context's, then the request's.
    Plan {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        run: PathBuf,
        #[arg(long)]
        intent: Option<String>,
    },
    /// Summarize a Context Pack for review: intents and their rules, tools with approval
    /// modes and permissions, approval gates, decisions and the evidence they require,
    /// and `problems` (names a rule or permission uses that the pack does not define,
    /// duplicate rule ids, rules without a rationale).
    Inspect { pack: PathBuf },
    /// Try a pack interactively: one case (from an admission body or replay case) edited
    /// with `set PATH JSON` / `unset PATH`, checked with `decide` or `plan`. Each answer
    /// is one JSON line, so a script can also be piped in. `help` lists the commands.
    Repl {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        run: PathBuf,
    },
    /// Build a Context Pack from a pack source (`contextos.pack_source.v1`): a `base`
    /// pack or source, a JSON merge `patch`, and `imports` of rule libraries
    /// (`contextos.rule_library.v1`), each optionally limited to some `bundles`, given a
    /// `priority` or scoped to one `intent`. The result is validated as context-pack.v2.
    /// Without `--out` the pack is printed; `--check` compares it with an existing file
    /// instead (exit 1 if they differ).
    Build {
        source: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, conflicts_with = "out")]
        check: Option<PathBuf>,
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
