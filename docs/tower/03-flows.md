# 3. Flows

Each flow shows the sequence, then lists the steps with the function that performs each,
so you can follow it in the code.

## 3.1 From an agent's run to a finding

The path every fact in Tower takes: an orchestrator admits a run, the runtime signs it,
the collector verifies it, the fleet model folds it, and the governance engine turns it
into findings when someone asks.

```mermaid
sequenceDiagram
    autonumber
    participant O as Orchestrator
    participant R as contextosd
    participant C as Collector (towerd)
    participant F as Fleet model
    participant G as Governance engine
    participant U as Tower UI

    O->>R: POST /v1/runs (request, run_context, contract)
    R->>R: compile pack, negotiate contract, admit
    R->>R: audit run_admitted (agent, pack, profiles, controls, capabilities)
    R->>R: audit run_lifecycle start
    O->>R: POST /v1/runs/{id}/tool-calls
    R->>R: audit authorization_decision, operation_claim, effect_observation
    loop every poll_ms
        C->>R: GET /v1/audit/entries?from=anchor+1&limit=1000
        R-->>C: entries, next, head
        C->>C: verify_chain(page, anchor, published keys)
        C->>F: apply(entry) for each, in order
    end
    U->>G: GET /api/agents/{key}
    G->>F: read activity, packs, deployment
    G->>G: graph → requirement → facts → builtin + guardrails → waivers
    G-->>U: facts, graph, findings, series, runs
```

| Step | Code |
|---|---|
| Admission is audited before the run starts | `contextosd::app::admit` (`"run_admitted"`) |
| Pull a page from the verified anchor | `towerd::collector::sync` → `Source::entries` |
| Verify the page against the runtime's keys | `contextos_audit::verify_chain` |
| Fold each entry | `towerd::fleet::Fleet::apply` (table in [Governance model](04-governance-model.md#41-from-audit-entries-to-the-fleet-model)) |
| Compute a view on request | `towerd::api::snapshot` → `governance::views` → `governance::findings` |

Nothing is computed ahead of time except the fleet counters. Findings are a pure function
of (fleet model, records) at the moment of the request, so they always reflect the
latest declarations, reviews, guardrails and waivers.

## 3.2 The collector, including failure

```mermaid
sequenceDiagram
    autonumber
    participant C as Collector
    participant R as Runtime
    participant F as Fleet model

    C->>R: GET /v1/deployment, GET /v1/packs (every 60 s)
    C->>F: source.deployment, source.packs
    C->>R: GET /v1/audit/keys (once)
    loop until a page comes back empty
        C->>R: GET /v1/audit/entries?from=n
        alt page verifies
            C->>F: apply entries, advance anchor
        else page fails verification
            C->>R: GET /v1/audit/keys (a rotation may have happened)
            alt verifies with the fresh keys
                C->>F: apply entries, keep the new keys
            else still fails
                C->>F: source.broken = {sequence, reason}
                Note over C: stop reading this source
            end
        end
    end
```

- On first contact the anchor is empty, so verification starts at genesis: the first
  entry must have sequence 1 and no previous hash.
- A network or HTTP error sets `last_error` and the collector tries again on the next
  poll. Only a verification failure stops a source, because only that means the
  history cannot be trusted.
- A broken source produces a `chain_broken` critical finding and a red banner on
  Posture. Tower shows nothing after the failing entry as fact.

## 3.3 Declare, review, drift

```mermaid
sequenceDiagram
    autonumber
    actor Maya as maya (owner)
    actor RA as risk-a (risk)
    participant API as towerd API
    participant J as Journal
    participant S as Store

    Maya->>API: PUT /api/agents/{key}/declaration
    API->>API: role owner, team in maya's teams, Declaration::check
    API->>J: agent_declared
    API->>S: declarations[key] = … (compare-and-swap)
    RA->>API: POST /api/agents/{key}/review {approved}
    API->>API: role risk, reviewer ≠ owner and ≠ declarer, agent declared
    API->>API: snapshot: current graph, digest, required profile
    API->>J: agent_reviewed (capabilities approved, graph digest)
    API->>S: reviews[key] = …
    Note over API: later, a pack release adds a capability
    API->>API: drift = graph capabilities − reviewed capabilities
    API-->>RA: finding authority_drift (high)
```

The review stores the exact list of capabilities it approved and the digest of the
graph. Drift is computed against that list on every request, so a new pack version that
adds a capability shows up the moment the collector refreshes the packs (within 60 s).

## 3.4 A guardrail from intent to enforcement

```mermaid
sequenceDiagram
    autonumber
    actor RA as risk-a
    actor RB as risk-b
    participant API as towerd API
    participant M as Claude
    participant K as Kernel JsonLogic
    participant J as Journal

    RA->>API: POST /api/guardrails/draft {intent}
    API->>API: facts of every agent, example = richest agent
    API->>M: system: rules + facts guide + example, output_config json_schema
    M-->>API: {title, description, severity, rule (JSON string), remediation, rationale}
    API->>API: parse rule, var paths ⊆ facts schema?
    API->>K: evaluate on every agent
    API->>API: checks: parses, reads_known_facts, evaluates_on_every_agent, selective
    API->>J: intelligence_used (job draft_guardrail, digests, usage)
    API-->>RA: draft + checks + agents it would flag
    RA->>API: POST /api/guardrails (save as draft)
    API->>K: evaluate on every agent (must not error)
    API->>J: guardrail_drafted
    RB->>API: POST /api/guardrails/{id}/activate
    API->>API: status draft, activator ≠ author
    API->>J: guardrail_activated
    Note over API: from now on every findings computation evaluates it
```

A guardrail that reads a field the facts do not have, errors on any agent, or (with
`==`) compares arrays by reference is rejected before it can be saved. An active
guardrail that fails at evaluation time produces a high finding ("could not be
evaluated"): it fails visibly, never as a silent pass.

## 3.5 A waiver

```mermaid
stateDiagram-v2
    [*] --> requested: owner POST /api/waivers {rule, agent, reason, days}
    requested --> approved: risk (≠ requester) decide approve
    requested --> rejected: risk decide reject
    approved --> expired: now ≥ expires_at
    approved --> [*]
    rejected --> [*]
    expired --> [*]
```

While approved and unexpired, the matching finding (same rule, same agent) is returned
with its `waiver` attached and excluded from counts; it is never deleted. Expiry is
computed at read time, so no job is needed.

## 3.6 Ask Tower

```mermaid
sequenceDiagram
    autonumber
    actor P as Person (viewer)
    participant API as towerd API
    participant H as Host (read-only tools)
    participant M as Claude
    participant J as Journal

    P->>API: POST /api/ask {question}
    API->>H: snapshot (views, findings, anomalies, runs) for this request
    loop up to max_turns
        API->>M: system rules + facts guide, strict tools, messages
        M-->>API: stop_reason
        alt refusal or max_tokens
            API-->>P: error (never a partial answer)
        else tool_use
            API->>H: call(tool, input) for each tool_use block
            H-->>API: JSON
            API->>API: wrap as <data>…</data> tool_result
        else end_turn
            API->>API: parse [agent:…] [finding:…] [run:…], check each exists
        end
    end
    API->>J: intelligence_used (who, model, digests, usage)
    API-->>P: answer, citations (exists true/false), tool steps, usage
```

The UI links verified citations and marks unverified ones in red with a warning not to
rely on them. Details in [Intelligence](05-intelligence.md).

## 3.7 Anomaly, brief, contain

```mermaid
sequenceDiagram
    autonumber
    actor On as oncall (operator)
    participant API as towerd API
    participant M as Claude
    participant R1 as runtime A
    participant R2 as runtime B
    participant J as Journal

    On->>API: GET /api/anomalies
    API-->>On: agent X: 30 refused in the last hour (usual 1.0)
    On->>API: POST /api/anomalies/brief {agent, metric}
    API->>M: anomaly + facts + recent runs (structured output)
    M-->>API: what happened, causes, blast radius, options [revoke_capability …]
    API->>J: intelligence_used
    On->>API: POST /api/fleet/revoke {kind: capability, target, reason}
    API->>J: fleet_revoked (before touching any runtime)
    par every source with a control key
        API->>R1: POST /v1/revocations
        API->>R2: POST /v1/revocations
    end
    API-->>On: per-source results
    R1->>R1: audit revocation (operator = Tower's control principal, reason names the person)
    Note over API: the collector reads the revocation back from each chain
```

The AI suggests options; the operator chooses and types the target to confirm. The
journal entry is written before any runtime is called, so an interrupted kill switch is
still on record. Each runtime records the change in its own chain too.

## 3.8 Explain a run

```mermaid
sequenceDiagram
    actor P as Person
    participant API as towerd
    participant J as Journal
    participant R as Runtime
    participant M as Claude
    P->>API: POST /api/runs/{source}/{run}/explain
    API->>J: evidence_accessed {source, run, by}
    API->>R: GET /v1/runs/{run}/evidence (Tower's audit:read key)
    API->>M: run summary + evidence bundle
    API->>J: intelligence_used
    API-->>P: plain-language explanation (labelled AI)
```

## 3.9 Verify Tower's journal offline

```mermaid
sequenceDiagram
    actor A as Auditor
    participant T as towerd
    participant X as ctx (offline)
    A->>T: GET /api/journal?from=1&limit=500
    A->>T: GET /api/journal/keys
    A->>X: ctx audit-verify --entries journal.json --keys keys.json
    X-->>A: {"verified": true, "entries": n, "last_record_hash": …}
```

```sh
curl -s -H "authorization: Bearer $KEY" "$TOWER/api/journal?from=1&limit=500" | jq .entries > journal.json
curl -s "$TOWER/api/journal/keys" > keys.json
ctx audit-verify --entries journal.json --keys keys.json
```

Changing any recorded payload (for example a review's decision) makes verification fail
with `payload digest mismatch` at that entry.
