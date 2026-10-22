# 6. API reference

All `towerd` routes are under `/api`, take and return JSON, and authenticate with
`Authorization: Bearer <key>`. Bodies are parsed strictly (duplicate keys rejected,
unknown fields rejected, 512 KiB at most).

```sh
export TOWER=http://127.0.0.1:8090
export KEY=dev-ciso-0123456789abcdef0123456789abcde
t() { curl -s -H "authorization: Bearer $KEY" -H 'content-type: application/json' "$@"; }
```

## Roles

| Role | Can |
|---|---|
| `viewer` | Read everything; ask; explain runs |
| `owner` | Viewer, plus declare agents of their `teams`, request waivers, draft intake reviews |
| `risk` | Viewer, plus declare any agent, review agents, create, activate and retire guardrails, decide waivers, draft guardrails and reviews, brief anomalies |
| `operator` | Viewer, plus the fleet kill switch and anomaly briefs |
| `admin` | Everything |

Every authenticated caller is a viewer. Separation of duties is enforced regardless of
role: see [Security](07-security.md#73-roles-and-separation-of-duties).

## Errors

```json
{"error": {"code": "forbidden", "message": "A guardrail is activated by someone other than its author."}}
```

| Status | `code` | When |
|---|---|---|
| 401 | `unauthorized` | Missing or unknown key |
| 403 | `forbidden` | Role missing, or separation of duties |
| 404 | `not_found` | No such agent, record, source or anomaly |
| 409 | `conflict` | Already decided, or not in the required state |
| 413 | `too_large` | Body over 512 KiB |
| 422 | `invalid` | Body fails validation, or a rule fails to evaluate |
| 422 | `intelligence` | The model declined, was cut off, or returned unusable output |
| 501 | `intelligence` | Intelligence is off |
| 502 | `runtime`, `intelligence` | A runtime or the model service failed |
| 503 | `unavailable` | Store or journal unavailable |

## Read

### `GET /api/me`

```json
{"principal_id": "maya", "roles": ["owner"], "teams": ["support-ai"], "intelligence": null}
```

`intelligence` is the model name when enabled.

### `GET /api/posture`

```json
{
  "now": "2026-10-21T16:23:40.120000Z",
  "agents": {"total": 1, "declared": 0, "reviewed": 0, "external_effects": 1, "irreversible_external": 0,
             "by_required_profile": {"contextos.durable-delegated+contextos.enterprise": 1},
             "by_lifecycle": {"undeclared": 1}},
  "findings": {"by_severity": {"critical": 1, "high": 3, "medium": 2}, "by_rule": {"undeclared_agent": 1, "…": 1}, "waived": 0},
  "anomalies": 0,
  "riskiest": [{"key": "tenant_acme_prod/agt_support", "…": "agent row"}],
  "top_findings": [{"id": "undeclared_agent:tenant_acme_prod/agt_support", "…": "finding"}],
  "sources": [{"id": "acme-support-eu", "verified_to": 69, "head": 69, "broken": null, "last_error": null, "last_sync": "…", "revoked": 1}],
  "unattributed": 0, "guardrails": 0, "intelligence": null
}
```

### `GET /api/agents?query=&profile=&lifecycle=`

Agent rows: `key`, `agent_id`, `agent_urn`, `owner`, `team`, `business_unit`,
`lifecycle` (`undeclared` when not declared), `purpose`, `reviewed`,
`required_profile`, `capabilities`, `external`, `irreversible`, `models`, `sources`,
`runs`, `last_seen`, `findings` (counts per severity).

### `GET /api/agents/{key}`

`key` is URL-encoded (`tenant_acme_prod%2Fagt_support`). Returns `row`, `facts` (see
[§4.4](04-governance-model.md#44-facts-what-guardrails-and-the-ai-read)),
`requirement` (`profile`, `profiles`, `reasons`, `features`, `controls`), `graph`,
`digest`, `findings` (including waived ones, with `waiver`), `anomalies`, `series`
(168 hourly buckets: `runs`, `effects`, `applied`, `refused`, `unknown`, `approvals`),
`runs` (the 25 most recent summaries) and `can_revoke`.

### `GET /api/findings?severity=&agent=&rule=&include_waived=`

```json
{"findings": [{
  "id": "controls_missing:tenant_acme_prod/agt_support:acme-support-eu",
  "rule": "controls_missing", "severity": "high",
  "agent": "tenant_acme_prod/agt_support", "source": "acme-support-eu",
  "title": "tenant_acme_prod/agt_support runs where required controls are not supported",
  "detail": "Its authority requires contextos.durable-delegated+contextos.enterprise; runtime acme-support-eu does not declare: authority.revocation, …",
  "remediation": "Enable the controls on that runtime (and record conformance evidence), or narrow the agent's capabilities.",
  "evidence": {"source": "acme-support-eu", "missing": ["…"], "required_profile": "…"},
  "waiver": null
}]}
```

### `GET /api/anomalies`

```json
{"anomalies": [{"agent": "…", "metric": "refused", "hour": 494896, "value": 30, "baseline": 1.0,
  "title": "…: 30 refused in the last hour (usual 1.0)"}]}
```

### `GET /api/runs?agent=&status=&capability=&refused=&limit=`

Recent run summaries, newest first (`limit` up to 500): `source`, `run_id`, `agent`,
`trace_id`, `pack_ref`, `intent`, `parent_run_id`, `status`, `admitted_at`, `last_at`,
`effects`, `refused`, `unknown`, `decisions`, `capabilities`, `refusal_reasons`.

### `GET /api/runs/{source}/{run}/evidence`

The run's evidence bundle, fetched from its runtime with Tower's `audit:read` key.
Journalled as `evidence_accessed`.

### `GET /api/changes`, `GET /api/sources`

The fleet change feed (newest 200), and each source with its business unit, region,
environment, `can_revoke`, verification `state`, `mode`, `tenant`, `packs`, `guards`
and declared `controls`.

### `GET /api/journal?from=&limit=`, `GET /api/journal/keys`

Tower's signed journal (newest `limit` when `from` is omitted; at most 500 per page) and
its public key. `/api/journal/keys` needs no authentication, like a JWKS endpoint.

## Change

### `PUT /api/agents/{key}/declaration` (owner of the team, or risk)

```sh
t -X PUT "$TOWER/api/agents/tenant_acme_prod%2Fagt_support/declaration" -d '{
  "owner": "maya", "team": "support-ai", "business_unit": "Customer Operations",
  "purpose": "Refunds damaged deliveries up to the order amount; never without identity verification.",
  "users_served": "customers", "lifecycle": "production",
  "data_categories": ["orders", "payments"], "regulatory_contexts": []
}'
```

`users_served`: `internal`, `customers`, `public`. `lifecycle`: `proposed`, `pilot`,
`production`, `deprecated`, `retired`. An owner can only declare for teams in their
`teams` and cannot move another team's agent. Journal: `agent_declared`.

### `POST /api/agents/{key}/review` (risk; not the owner or declarer)

```sh
t -X POST "$TOWER/api/agents/tenant_acme_prod%2Fagt_support/review" -d '{
  "decision": "approved", "notes": "Refunds are compensatable and behind the finance gate above 3000.",
  "conditions": ["pin model_profile before the next release"], "valid_days": 180
}'
```

`decision`: `approved`, `changes_requested`, `rejected`. Approval needs a declaration.
Records the current capability list, graph digest and required profile. Journal:
`agent_reviewed`.

### Guardrails (risk)

```sh
# preview impact without saving
t -X POST $TOWER/api/guardrails/preview -d '{"rule": {"!": {"var": "reviewed"}}}'
# → {"evaluated": 1, "violating": ["tenant_acme_prod/agt_support"], "errors": []}

# save a draft (must evaluate on every agent without error)
t -X POST $TOWER/api/guardrails -d '{"title": "Agents are reviewed", "severity": "high",
  "rule": {"!": {"var": "reviewed"}}, "remediation": "Run an intake review."}'
# → 201 {"id": "01a15f3b1efe", "status": "draft", "created_by": "risk-a", …}

t -X POST $TOWER/api/guardrails/01a15f3b1efe/activate   # a different risk reviewer
t -X POST $TOWER/api/guardrails/01a15f3b1efe/retire
```

`GET /api/guardrails` lists them with their current `impact`. Journal:
`guardrail_drafted`, `guardrail_activated`, `guardrail_retired`.

### Waivers

```sh
# owner
t -X POST $TOWER/api/waivers -d '{"rule": "unresolved_effects", "agent": "tenant_acme_prod/agt_support",
  "reason": "Provider outage INC-42; reconciling with finance", "days": 7}'
# risk, not the requester
t -X POST $TOWER/api/waivers/<id>/decide -d '{"approve": true, "reason": "Tracked in INC-42"}'
```

Journal: `waiver_requested`, `waiver_decided`.

### `POST /api/fleet/revoke`, `POST /api/fleet/restore` (operator)

```sh
t -X POST $TOWER/api/fleet/revoke -d '{"kind": "agent", "target": "agt_support",
  "reason": "INC-77: refunds misfiring", "sources": null}'
# → {"results": [{"source": "acme-support-eu", "ok": true}]}
```

`kind`: `agent`, `capability`, `pack`, `adapter`, `principal`. Applies to every source
with a control key (or the listed `sources`), each through its own `POST
/v1/revocations`. Journal: `fleet_revoked` / `fleet_restored`, written before any runtime
is called.

## Intelligence

| Route | Body | Returns |
|---|---|---|
| `POST /api/ask` | `{"question": "…"}` (≤ 4000 chars) | `answer`, `citations` (`kind`, `id`, `exists`), `steps` (tool calls), `usage`, `model` |
| `POST /api/guardrails/draft` | `{"intent": "…"}` (10–2000 chars) | `draft`, `valid`, `checks`, `impact`, `usage`, `model` |
| `POST /api/agents/{key}/assess` | | `review` (see [§5.5](05-intelligence.md#55-structured-outputs-of-the-other-jobs)), `usage`, `model` |
| `POST /api/anomalies/brief` | `{"agent": "…", "metric": "refused"}` | `brief`, `usage`, `model` |
| `POST /api/runs/{source}/{run}/explain` | | `explanation`, `usage`, `model` |

Each journals `intelligence_used`.

## Runtime routes Tower uses

These are part of the `contextosd` OpenAPI document (`openapi/contextosd.v1.json`).

| Route | Scope | Used for |
|---|---|---|
| `GET /v1/audit/entries?from=&limit=` | `audit:read` | Ingest; response has `entries`, `next`, `head` |
| `GET /v1/audit/keys` | public | Verification key ring |
| `GET /v1/deployment` | authenticated | Mode, support declaration (`support.supported_controls`), guards, providers, adapters (names only), caller |
| `GET /v1/packs` | `audit:read` | `{"packs": [{"pack_ref", "pack"}]}` for the tenant |
| `GET /v1/runs/{id}/evidence` | `audit:read` | Explain and evidence on request |
| `POST /v1/revocations`, `POST /v1/revocations/restore` | `control` | Fleet kill switch |
| `GET /v1/config`, `POST /v1/config/validate` | `config` | Configuration review in CI (not used by `towerd`) |
