# 8. Build it step by step

This guide takes you from a running system to extending it. Part A uses the system as
each person would. Part B connects your own runtime. Part C changes the code: a new
finding, a new audit fold, a new analyst tool and a new UI page, each with its test.
Part D covers testing and the gate.

Prerequisites: the Rust toolchain from `rust-toolchain.toml`, Node 24, Python 3. Run
everything from the repository root.

## Part A. Use it as each person

### A1. Start a runtime with governed agents and Tower over it

```sh
./examples/tower/run.sh --serve
```

What the script does, so you can reproduce it by hand:

1. `source examples/dev-env.sh` builds and starts `contextosd` with the quickstart pack
   and development fact services on free ports (`$CONTEXTOS_URL`).
2. Runs `examples/agent-loop/agent.py` three times: a support agent plans, delegates
   research to a read-only child run, issues a governed refund, records a decision and
   completes.
3. Revokes the refund capability with the development operator key, then runs the agent
   once more: the runtime refuses the refund (`revoked_capability`).
4. Starts `towerd` with `examples/tower/towerd.toml`, pointed at the runtime with a
   read-only key (`svc_tower`, `audit:read`) and a control key.
5. Waits until Tower has verified the chain, prints the posture, and keeps serving.

Keep it running in one terminal. In another:

```sh
export TOWER=http://127.0.0.1:8090/api
as() { local k=$1; shift; curl -s -H "authorization: Bearer $k" -H 'content-type: application/json' "$@"; }
CISO=dev-ciso-0123456789abcdef0123456789abcde
MAYA=dev-owner-0123456789abcdef0123456789abcd
RA=dev-risk-a-0123456789abcdef0123456789abc
RB=dev-risk-b-0123456789abcdef0123456789abc
ONCALL=dev-oncall-0123456789abcdef0123456789abc
AGENT=tenant_acme_prod%2Fagt_support
```

### A2. CISO: what is our posture?

Open <http://127.0.0.1:8090/tower/> and sign in with `$CISO`, or:

```sh
as $CISO $TOWER/posture | jq '{agents, findings: .findings.by_severity}'
as $CISO "$TOWER/findings" | jq -r '.findings[] | "\(.severity)\t\(.rule)"'
```

```text
critical  undeclared_agent
high      unreviewed
high      controls_missing
high      profile_understated
medium    model_unpinned
medium    unscored_decisions
```

Open the agent (Agents → `tenant_acme_prod/agt_support`). The **What it can do** tab
shows three capabilities; `adp_payments.issue_refund` is an external, compensatable
action on confidential data. That, plus delegation and checkpoints, is why the agent
needs the `enterprise` and `durable-delegated` profiles: 17 controls, 9 of which the
runtime does not declare.

### A3. Owner: take accountability

Sign in as maya (`$MAYA`) and press **Declare**, or:

```sh
as $MAYA -X PUT "$TOWER/agents/$AGENT/declaration" -d '{
  "owner": "maya", "team": "support-ai", "business_unit": "Customer Operations",
  "purpose": "Refunds damaged deliveries up to the order amount; never without identity verification.",
  "users_served": "customers", "lifecycle": "production",
  "data_categories": ["orders", "payments"], "regulatory_contexts": []}'
```

`undeclared_agent` disappears. Try declaring it for another team: `403`, because
owners declare their own teams' agents.

### A4. Risk reviewer: review the agent

Sign in as risk-a. The **Review** tab shows the current state; with intelligence on,
**Draft** asks Claude for an intake review first. Record the decision:

```sh
as $RA -X POST "$TOWER/agents/$AGENT/review" -d '{
  "decision": "approved",
  "notes": "Refunds are compensatable, human_approved, behind the finance gate above 3000.",
  "conditions": ["request enterprise and durable-delegated profiles", "pin model_profile"],
  "valid_days": 180}'
```

`unreviewed` disappears. Maya cannot do this for her own agent (`403`).

The remaining findings need changes outside Tower, which is the point: Tower tells you
exactly what. `profile_understated` is fixed by the orchestrator asking for
`contextos.enterprise` and `contextos.durable-delegated` in the execution contract;
`controls_missing` by enabling those controls on the runtime (and proving them with
conformance evidence); `model_unpinned` by adding a `model_profile` release reference;
`unscored_decisions` by an evaluator scoring decisions.

### A5. Owner and reviewer: accept a risk for a while

The runtime team needs a sprint to enable the controls. Maya requests a waiver; risk-b
decides it:

```sh
W=$(as $MAYA -X POST $TOWER/waivers -d '{"rule": "controls_missing",
  "agent": "tenant_acme_prod/agt_support",
  "reason": "Runtime team enabling the enterprise controls in CHG-118", "days": 14}' | jq -r .id)
as $RB -X POST "$TOWER/waivers/$W/decide" -d '{"approve": true, "reason": "Tracked in CHG-118"}'
```

The finding stays visible as *waived until …* and returns by itself after 14 days.

### A6. Risk reviewers: set a rule for every agent

```sh
G=$(as $RA -X POST $TOWER/guardrails -d '{
  "title": "Customer-facing agents pin their model", "severity": "high",
  "rule": {"and": [{"==": [{"var": "declaration.users_served"}, "customers"]},
                   {"!": {"var": "agent.models.0"}}]},
  "remediation": "Pin model_profile in the execution contract release_refs."}' | jq -r .id)
as $RA -X POST $TOWER/guardrails/$G/activate   # 403: the author cannot activate it
as $RB -X POST $TOWER/guardrails/$G/activate   # active
```

With intelligence on, Guardrails → **Draft from intent** writes the rule from a
sentence and shows which agents it would flag before anyone can save it.

### A7. Operator: stop something everywhere

```sh
as $ONCALL -X POST $TOWER/fleet/restore -d '{"kind": "capability",
  "target": "adp_payments.issue_refund", "reason": "INC-7 resolved"}'
```

This restores the refund capability the script revoked, on every runtime Tower holds a
control key for. Runtimes shows the result; the runtime's own chain records it, and
Tower's change feed picks it up on the next poll.

### A8. Auditor: verify the record

```sh
as $CISO "$TOWER/journal?from=1&limit=500" | jq .entries > /tmp/journal.json
curl -s $TOWER/journal/keys > /tmp/keys.json
./target/release/ctx audit-verify --entries /tmp/journal.json --keys /tmp/keys.json
```

Every step above is there, signed, in order.

## Part B. Connect your own runtime

1. **Create a read-only key for Tower on the runtime.**

   ```sh
   KEY=$(openssl rand -hex 24)
   echo "$KEY" | ctx hash-key            # → {"key_sha256": "sha256:…"}
   ```

   ```toml
   # contextosd.toml
   [[api_keys]]
   key_sha256 = "sha256:…"
   tenant_id = "your_tenant"
   principal_id = "svc_tower"
   scopes = ["audit:read"]
   ```

   Optionally a second key with `scopes = ["control"]` for the fleet kill switch.

2. **Describe the source in Tower.**

   ```toml
   # towerd.toml
   [server]
   listen = "0.0.0.0:8090"

   [store]
   kind = "postgres"
   url_env = "TOWER_DATABASE_URL"

   [journal]
   signing_seed_env = "TOWER_JOURNAL_SEED"     # 32 bytes hex, from your secret store
   key_id = "tower-2026-10"

   [[sources]]
   id = "eu-support"
   url = "https://contextosd.eu.internal"
   token_env = "TOWER_EU_SUPPORT_AUDIT_KEY"
   control_token_env = "TOWER_EU_SUPPORT_CONTROL_KEY"
   business_unit = "Customer Operations"
   region = "eu-west-1"
   environment = "production"

   [[api_keys]]
   key_sha256 = "sha256:…"      # each person's key, hashed with ctx hash-key
   principal_id = "alice"
   roles = ["risk"]

   [tower]
   dir = "/usr/share/contextos/tower"
   ```

3. **Start it.** `towerd --config towerd.toml`. The log shows `towerd listening`; the
   Runtimes page shows each source verifying from genesis.

4. **Make runs attributable.** Runs are attributed by `run_context.agent.agent_id`, or
   by `agent_urn` when set. Set `agent_urn` (for example
   `agent:acme/support-refund@1.2.0`) so the same agent is one inventory entry across
   tenants and runtimes.

## Part C. Extend Tower

The code map: `fleet.rs` folds evidence, `authority.rs` derives requirements,
`governance.rs` turns views into facts and findings, `api.rs` exposes them,
`intel/jobs.rs` holds the AI jobs, and `tower/src/pages` holds the UI.

### C1. Add a built-in finding

Goal: flag agents that apply effects but have no evaluator pinned
(`evaluator_suite` release reference), so nobody can say how their decisions are judged.

1. **Write the check** in `governance::builtin`, next to `model_unpinned`:

   ```rust
   if !external.is_empty() && a.runs > 0 && a.evaluators.is_empty() {
       out.push(finding(
           "evaluator_unpinned",
           "medium",
           view,
           format!("{name}'s runs do not record which evaluators judge them"),
           "No evaluator_suite release reference was pinned at admission.".into(),
           "Pin evaluator_suite in the execution contract's release_refs.",
           json!({}),
       ));
   }
   ```

   `finding(rule, severity, view, title, detail, remediation, evidence)` builds the id
   `rule:agent`, so the finding is stable across requests.

2. **Test it** in `governance.rs` tests, reusing the fixture builder:

   ```rust
   #[test]
   fn agents_with_effects_name_their_evaluators() {
       let (fleet, view) = agent_with(&[("refund", "external_state", "compensatable")]);
       let rules: Vec<String> = findings(&fleet, std::slice::from_ref(&view), &Value::Null, &Value::Null, "2026-10-21T10:00:00Z")
           .into_iter().map(|f| f.rule).collect();
       assert!(rules.contains(&"evaluator_unpinned".to_owned()));
   }
   ```

3. **Name it in the UI**: add `evaluator_unpinned: "Decisions without a recorded
   evaluator"` to `LABELS` in `tower/src/pages/FindingsPage.tsx`.

4. **Document it** in the finding table in [§4.5](04-governance-model.md#45-built-in-findings).

Run `cargo test -p towerd`. The finding now appears in Posture, Findings, the agent page,
Ask Tower (through `list_findings`) and can be waived like any other.

### C2. Fold a new audit kind into the fleet model

Goal: count how often tools asked a human for input (`input_response` entries), so
reviewers can see agents that depend on people mid-run.

1. **Add the counter** to `AgentActivity` in `fleet.rs`:

   ```rust
   pub human_inputs: u64,
   ```

2. **Fold the entry** in `Fleet::apply`. `input_response` has no `run_id`; find the run
   through the attempt the earlier `operation_claim` recorded:

   ```rust
   "input_response" => {
       let run = s(&p["attempt_id"])
           .and_then(|a| self.attempts.get(&(source.to_owned(), a.to_owned())))
           .map(|open| open.run.clone());
       if let Some(k) = run.and_then(|r| self.agent_of(source, &r))
           && let Some(a) = self.agents.get_mut(&k)
       {
           a.human_inputs += 1;
       }
   }
   ```

3. **Expose it** in `governance::facts` under `activity` (`"human_inputs":
   a.human_inputs`) so guardrails and the analyst can use it, and add it to the facts
   guide in `intel/jobs.rs` (`FACTS_GUIDE`), which is what the model is told the fields
   mean.

4. **Test it** in `fleet.rs` tests with the `entry(sequence, kind, payload)` helper:
   admit a run, claim an operation with an attempt id, apply an `input_response` with
   that attempt id, and assert the counter.

Every change to the facts schema is also a change to what guardrails can say, so add a
cookbook line to [§4.6](04-governance-model.md#46-guardrails) when it is useful.

### C3. Give the analyst a new tool

Goal: let Ask Tower answer "which agents use model X?" directly.

1. **Declare the tool** in `jobs::analyst_tools()`:

   ```rust
   tool(
       "agents_by_model",
       "Agents whose runs pinned a given model_profile, with owner and required profile.",
       json!({"model": {"type": "string", "description": "model id, e.g. claude-opus-5-5"}}),
       &["model"],
   ),
   ```

   Keep tools read-only, strict, with every property required (nullable when optional).

2. **Answer it** in `Host::call` in `api.rs`, from the snapshot:

   ```rust
   "agents_by_model" => {
       let model = s("model").unwrap_or_default();
       json!(self.snap.views.iter()
           .filter(|v| v.activity.models.iter().any(|m| m.starts_with(&model)))
           .map(|v| agent_row(v, &self.snap.findings))
           .collect::<Vec<_>>())
   }
   ```

3. **Test it** with the scripted model in `tests/e2e.rs`: script a `tool_use` of
   `agents_by_model`, then a text answer, and assert the request sent back to the model
   contains the tool result.

### C4. Add a UI page

Goal: a **Models** page listing agents per model.

1. Create `tower/src/pages/Models.tsx`:

   ```tsx
   import { useQuery } from "@tanstack/react-query";
   import { api } from "../lib/api";
   import type { AgentRow } from "../lib/types";
   import { Card, PageHead } from "../components/ui";

   export function Models() {
     const { data } = useQuery({ queryKey: ["agents", ""], queryFn: () => api<{ agents: AgentRow[] }>("/api/agents") });
     const byModel = new Map<string, AgentRow[]>();
     for (const a of data?.agents ?? []) for (const m of a.models.length ? a.models : ["not pinned"]) byModel.set(m, [...(byModel.get(m) ?? []), a]);
     return (
       <div className="stack">
         <PageHead title="Models" sub="Which models make your agents' decisions." />
         {[...byModel].map(([m, agents]) => (
           <Card key={m} title={m}>{agents.map((a) => a.key).join(", ")}</Card>
         ))}
       </div>
     );
   }
   ```

2. Route it in `tower/src/main.tsx` (`{ path: "models", element: <Models /> }`) and add a
   nav item in `components/Shell.tsx` (`{ to: "/models", label: "Models", plane:
   "intelligence" }`).

3. `cd tower && npm run typecheck && npm run build`, restart `towerd` (it loads the build
   at start), and open `/tower/models`.

Pages hold no state of their own: they read through TanStack Query (cache keys like
`["agents", ""]` are shared across pages) and change things only through
`openAction`, which shows who is acting, collects the reason and re-validates queries.

### C5. Add an API route that changes something

Follow the pattern every change route uses (`api::create_guardrail` is a good model):

1. `caller(&t, &headers, "role")` or `caller_any(...)` for the role.
2. `body::<YourBody>(&bytes)` with `#[serde(deny_unknown_fields)]` and explicit checks.
3. Separation of duties against principal ids, inside the record change closure so it
   is checked against the current state.
4. `t.records.change(collection, journal_kind, payload, &now, |items| …)`: the change is
   journalled first, then applied by compare-and-swap; a refused change leaves no
   journal entry.
5. Add the route in `api::router`, a row in the module's route table, and a test in
   `tests/e2e.rs` that covers the refusal as well as the success.

## Part D. Test and ship

| Layer | Where | How |
|---|---|---|
| Fleet folding | `fleet.rs` tests | Build entries with `entry(seq, kind, payload)`; assert counters |
| Requirements | `authority.rs` tests | Capabilities in, profile and controls out |
| Findings and guardrails | `governance.rs` tests | `agent_with(caps)` fixture; `findings(...)` |
| AI jobs | `intel/jobs.rs` tests | `Scripted` model; assert requests and handling |
| HTTP, roles, journal | `tests/e2e.rs` | An in-process `contextosd` with signed entries, a real collector pass, the real router |
| UI serving | `tests/console.rs` | CSP, client routes, traversal |
| UI logic | `tower/src/lib/*.test.ts` | Vitest |
| Everything together | `examples/tower/run.sh` | A live runtime, real agents, `towerd`, posture assertions |

```sh
cargo test -p towerd
(cd tower && npm test && npm run typecheck)
scripts/check.sh        # the full gate: fmt, clippy (pedantic), all tests, UI, clients, examples incl. Tower
```

Commit only after `scripts/check.sh` passes.
