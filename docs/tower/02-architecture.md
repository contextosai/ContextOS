# 2. Architecture

## 2.1 System context

```mermaid
flowchart TB
    subgraph People
        CISO(["Head of AI risk / CISO<br/>viewer"])
        Owner(["Agent owner<br/>owner"])
        Risk(["Risk reviewer<br/>risk"])
        Oncall(["On-call<br/>operator"])
        Auditor(["Auditor<br/>viewer + offline verify"])
    end

    UI["Tower UI<br/>(browser, served by towerd)"]
    Towerd["towerd<br/>governance plane"]
    Claude["Anthropic Messages API<br/>(optional)"]

    subgraph BU1["Business unit A / region EU"]
        RT1["contextosd"]
        ORC1["Agent orchestrators<br/>(LangGraph, ADK, Agents SDK …)"]
        SVC1["Fact services, approval service,<br/>MCP and HTTP tools"]
    end
    subgraph BU2["Business unit B / region US"]
        RT2["contextosd"]
        ORC2["Agent orchestrators"]
    end

    People --> UI --> Towerd
    Towerd -- "audit:read (verify, ingest)" --> RT1
    Towerd -- "audit:read" --> RT2
    Towerd -. "control (fleet kill switch)" .-> RT1
    Towerd -. "advisory jobs only" .-> Claude
    ORC1 -- "admit, dispatch every tool call" --> RT1
    RT1 --> SVC1
    ORC2 --> RT2
    Auditor -. "ctx audit-verify on exported journal" .-> Towerd
```

Agents never talk to Tower. They talk to their runtime, as they do without Tower. Tower
reads what runtimes sign, and acts on them only through the runtime's own scoped API.

## 2.2 Containers

```mermaid
flowchart LR
    subgraph Browser
        SPA["Tower UI<br/>React · TanStack Query · React Router<br/>token in sessionStorage"]
    end
    subgraph towerd["towerd (one process)"]
        API["HTTP API /api/*<br/>roles · separation of duties"]
        COL["Collectors<br/>one task per source"]
        FLEET[("Fleet model<br/>in memory, bounded")]
        GOV["Governance engine<br/>views · facts · findings · anomalies"]
        INTEL["Intelligence<br/>jobs · Model trait"]
        REC["Records + journal"]
        CON["Console<br/>static UI files in memory"]
    end
    STORE[("Document store<br/>memory or PostgreSQL")]
    LOG[("Journal log<br/>memory or PostgreSQL")]
    RT["contextosd<br/>/v1/audit/entries · /v1/audit/keys<br/>/v1/deployment · /v1/packs<br/>/v1/runs/{id}/evidence · /v1/revocations"]
    AN["api.anthropic.com/v1/messages"]

    SPA -- "fetch /api (Bearer)" --> API
    SPA -- "GET /tower/*" --> CON
    API --> GOV --> FLEET
    API --> REC
    API --> INTEL --> AN
    INTEL -. "read-only tools" .-> GOV
    COL --> RT
    COL --> FLEET
    REC --> STORE
    REC --> LOG
    API -- "evidence on request, kill switch" --> RT
```

| Container | Responsibility | State |
|---|---|---|
| Tower UI | Presents posture, agents, findings, activity, guardrails, waivers, Ask Tower, runtimes, journal. Holds no data. | The signed-in person's key, in the tab only |
| `towerd` API | Authenticates people, enforces roles and separation of duties, computes views on request | None of its own |
| Collectors | Read and verify each source's chain, refresh its deployment and packs every 60 s | Per source: key ring, last verified entry (anchor) |
| Fleet model | Per-agent counters and hourly buckets, recent run summaries, per-source state, change feed | Memory, bounded (see [Operations](09-operations.md#sizing)) |
| Governance engine | Pure functions: authority graph, required controls, facts, findings, anomalies | None |
| Intelligence | Advisory jobs against a `Model` (Anthropic or scripted) | None |
| Records + journal | Declarations, reviews, guardrails, waivers (compare-and-swap); the signed journal | Document store and append-only log (PostgreSQL in production) |

## 2.3 Inside `towerd`

```mermaid
flowchart TB
    main["main.rs<br/>config → store → signer → model → Tower::build → spawn collectors → serve"]
    lib["lib.rs<br/>Tower struct · build/assemble"]
    config["config.rs<br/>TOML, published-key refusal"]
    source["source.rs<br/>runtime client · key_ring()"]
    collector["collector.rs<br/>sync() · run()"]
    fleet["fleet.rs<br/>Fleet::apply() · AgentActivity · RunSummary"]
    authority["authority.rs<br/>pack_capabilities() · graph() · requirement()"]
    governance["governance.rs<br/>views() · facts() · builtin() · guardrail() · findings() · anomalies()"]
    records["records.rs<br/>Records::change() · note() · Declaration"]
    intelmod["intel/mod.rs<br/>Model · Anthropic · Scripted · checked()"]
    jobs["intel/jobs.rs<br/>ask() · draft_guardrail() · assess_agent() · brief_anomaly() · explain_run()"]
    api["api.rs<br/>routes · Callers · snapshot() · Host (analyst tools)"]
    console["console.rs<br/>Console::load() · routes()"]

    main --> lib --> config
    lib --> source
    lib --> collector --> source
    collector --> fleet
    api --> governance --> authority --> fleet
    api --> records
    api --> jobs --> intelmod
    api --> console
    jobs -. "Tools trait" .-> api
```

Every box below `api.rs` is a plain module with unit tests; only `collector.rs`,
`source.rs` and `api.rs` do I/O. `governance.rs` and `authority.rs` are pure functions of
the fleet model and the records, which is what makes findings reproducible and easy to
test.

### Kernel reuse

Tower adds no second implementation of anything the runtime already decides:

| Tower needs | It uses |
|---|---|
| Verify an audit page | `contextos_audit::verify_chain` (same as `ctx audit-verify`) |
| Sign its journal | `contextos_audit::AuditWriter` with Tower's own key |
| Control profiles and conditional controls | `contextos_kernel::STANDARD_PROFILE_REGISTRY` |
| Evaluate guardrails | `contextos_policy::jsonlogic::apply` (bounded, `json-logic-js` parity, errors fail visibly) |
| Persist records | `contextos_store::DocumentStore` (memory or PostgreSQL, compare-and-swap) |
| Canonical digests | `contextos_contract::canonical` (RFC 8785) |

## 2.4 What the runtime provides

Tower needed four additions to `contextosd`, all read-only or audit-only:

| Addition | Why Tower needs it |
|---|---|
| `run_admitted` audit entry | Without it nothing in the chain says which agent ran under which pack, contract and controls, so runs could not be attributed to agents |
| `GET /v1/deployment` | The deployment's mode, support declaration (the controls it declares), guards, providers and adapters, by name only; plus the caller's identity |
| `GET /v1/packs` | The tenant's Context Packs, so Tower can build each agent's authority graph from capability risks and approval gates |
| `head` on `GET /v1/audit/entries` | Lets a reader learn the chain length without verifying all of it |

A real `run_admitted` payload (from `examples/tower`):

```json
{
  "run_id": "run_agent_1792599799213",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "contract_id": "contract_run_agent_1792599799213",
  "agent_id": "agt_support", "agent_urn": null, "agent_role": "support_ops",
  "workload_identity": "spiffe://contextos/agents/support",
  "intent": "support.refund",
  "pack_ref": "ctxpack.support@5.2.0", "requested_pack_ref": "ctxpack.support@5.2.0",
  "profiles": ["contextos.core"],
  "required_controls": [{"control_id": "approval.bound", "control_version": "1"}, "…"],
  "release_refs": [{"artifact_type": "release", "artifact_id": "contextosd", "version": "0.1.0", "sha256": "sha256:…"}],
  "surfaced_capabilities": ["adp_orders.lookup", "adp_payments.issue_refund", "adp_policy.eval"],
  "parent_run_id": null,
  "admitted_by": "svc_quickstart",
  "compiled_context_hash": "sha256:68305e1d…"
}
```

It carries identifiers and references only: no user identity, no prompt, no arguments.

## 2.5 Deployment topologies

### Pilot: one runtime, one Tower

```mermaid
flowchart LR
    RT["contextosd<br/>tenant acme"] --- T["towerd + UI<br/>store: memory"]
```

Good for evaluation (`examples/tower`). Records are lost on restart.

### Production: federated business units

```mermaid
flowchart TB
    subgraph EU["EU region"]
        A1["contextosd · tenant support"]
        A2["contextosd · tenant claims"]
    end
    subgraph US["US region"]
        B1["contextosd · tenant finance"]
    end
    subgraph Gov["Governance (org)"]
        T["towerd (2+ replicas behind a load balancer)<br/>store: PostgreSQL"]
        PG[("PostgreSQL<br/>records + journal")]
        T --- PG
    end
    A1 -- "HTTPS, audit:read key per tenant" --> T
    A2 --> T
    B1 --> T
    T -. "control key, only where the kill switch is wanted" .-> A1
```

- Each **source** is one runtime tenant with its own read-only key. A business unit that
  does not want Tower able to act gives no `control` key; its runtime stays read-only to
  Tower.
- Runtimes stay in their regions. Tower receives metadata; run evidence is fetched on
  request and journalled.
- Several `towerd` replicas can share PostgreSQL for records and the journal. Each
  replica runs its own collectors and builds its own fleet model from the verified
  chains (see [Operations](09-operations.md#scaling)).

### Image

The container image ships both binaries and the UI:

```sh
docker run … image                                   # contextosd (default entrypoint)
docker run --entrypoint /usr/local/bin/towerd … image --config /etc/contextos/towerd.toml
# UI at /usr/share/contextos/tower → [tower] dir = "/usr/share/contextos/tower"
```

## 2.6 Trust boundaries

```mermaid
flowchart LR
    subgraph B1["Boundary 1: the person's browser"]
        UI["Tower UI"]
    end
    subgraph B2["Boundary 2: towerd"]
        API["API + roles"]
        GOV["Governance engine"]
        J["Journal (Tower key)"]
    end
    subgraph B3["Boundary 3: each runtime"]
        RT["contextosd + its audit chain (runtime key)"]
    end
    subgraph B4["Boundary 4: model provider"]
        M["Claude"]
    end
    UI -- "Bearer key, CSP same-origin only" --> API
    API --> GOV
    GOV -- "reads only entries that verify under the runtime's published keys" --> RT
    API -- "advisory prompts, outputs are proposals" --> M
    API -- "every decision" --> J
```

| Boundary | What crosses it | What protects it |
|---|---|---|
| Browser → `towerd` | The person's key, requests | Roles checked server-side; CSP; key in tab session storage only |
| `towerd` → runtime | Read requests, kill-switch requests | Tenant-scoped keys; runtime scopes and audit; Tower cannot forge runtime history (it lacks the runtime key) |
| Runtime → `towerd` | Audit entries, deployment, packs | Every entry verified against the runtime's published keys before use; a broken chain stops the source |
| `towerd` → model | Facts, findings, run evidence (explain only) | Advisory use only; outputs never change state without a person; every call journalled |

The full threat model is in [Security](07-security.md).

## 2.7 What data lives where

| Data | Runtime | Tower |
|---|---|---|
| Prompts, compiled context, tool arguments, personal data | Yes | No (evidence fetched on request, journalled, not stored) |
| Audit chain (signed) | Yes, the record | Verified, folded into counters; not stored |
| Run summaries (ids, status, capabilities, refusal reasons) | Derivable | Recent window, memory |
| Per-agent counters and hourly buckets | No | Memory |
| Declarations, reviews, guardrails, waivers | No | Store (PostgreSQL in production) |
| Governance journal | No | Append-only log, signed with Tower's key |
