# 9. Operations

## Configuration reference (`towerd.toml`)

Unknown keys are rejected. The file holds no secrets: keys are SHA-256 hashes, and every
credential is named by an environment variable.

### `[server]`

| Key | Default | Meaning |
|---|---|---|
| `listen` | required | Address to bind, e.g. `0.0.0.0:8090` |
| `development` | `false` | Allows `http://` sources and the published example keys. Never in production |

### `[store]`

| Key | Default | Meaning |
|---|---|---|
| `kind` | `memory` | `memory` (records lost on restart) or `postgres` |
| `url_env` | (postgres) | Environment variable holding the PostgreSQL URL |
| `max_connections` | `8` | Pool size |

PostgreSQL holds declarations, reviews, guardrails, waivers and the journal, using the
same tables and migrations as `contextosd` (`contextos_documents`, `contextos_audit_log`
under tenant `tower`). A dedicated database is recommended.

### `[journal]`

| Key | Meaning |
|---|---|
| `signing_seed_env` | Environment variable holding a 32-byte hex Ed25519 seed |
| `key_id` | Key id published at `/api/journal/keys`; change it when you rotate |

### `[[sources]]` (one per runtime tenant)

| Key | Default | Meaning |
|---|---|---|
| `id` | required | Unique name, shown everywhere (`eu-support`) |
| `url` | required | Runtime base URL; `https://` unless development |
| `token_env` | required | Variable holding that tenant's `audit:read` key. Startup fails if unset |
| `control_token_env` | none | Variable holding a `control` key; without it the kill switch skips this source |
| `business_unit`, `region`, `environment` | none | Labels for people and the analyst |

### `[[api_keys]]` (people and services)

| Key | Meaning |
|---|---|
| `key_sha256` | `sha256:<hex>` from `echo -n "$KEY" \| ctx hash-key` (lowercase) |
| `principal_id` | The name the journal records |
| `roles` | Any of `viewer`, `owner`, `risk`, `operator`, `admin` |
| `teams` | Teams whose agents an `owner` may declare |

### `[intelligence]`

| Key | Default | Meaning |
|---|---|---|
| `provider` | `off` | `anthropic` or `off` |
| `api_key_env` | `ANTHROPIC_API_KEY` | Variable holding the API key |
| `model` | `claude-opus-5-5` | Model id |
| `effort` | `high` | `low`, `medium`, `high`, `xhigh`, `max` |
| `base_url` | `https://api.anthropic.com` | Messages API base URL |
| `max_turns` | `8` | Tool-use turns per question |

### `[collector]`

| Key | Default | Meaning |
|---|---|---|
| `poll_ms` | `2000` | How often each source is polled for new entries |
| `recent_runs` | `50000` | Run summaries kept for search and drill-down |
| `hours` | `720` | Hours of per-agent activity kept (30 days) |

Deployment descriptions and packs refresh every 60 seconds; audit pages are read 1 000
entries at a time.

### `[tower]`

| Key | Meaning |
|---|---|
| `dir` | The UI build (`tower/dist`, or `/usr/share/contextos/tower` in the image). Unset: no UI |

## Deploying

```sh
# build
cargo build --release -p towerd
(cd tower && npm ci && npm run build)

# run
export TOWER_JOURNAL_SEED=…  TOWER_DATABASE_URL=…  TOWER_EU_SUPPORT_AUDIT_KEY=…
towerd --config /etc/contextos/towerd.toml
```

With the container image: `--entrypoint /usr/local/bin/towerd` and
`[tower] dir = "/usr/share/contextos/tower"`. Run it as its own Deployment, separate
from runtimes, with network access to each runtime's API and to PostgreSQL. Put TLS in
front of it (an ingress or a sidecar); `towerd` serves plain HTTP.

## Sizing

Memory is bounded by configuration, not by traffic:

| Structure | Bound by | Grows with |
|---|---|---|
| Per-agent counters | number of agents | capabilities and distinct refusal reasons per agent |
| Hourly buckets | agents × `hours` | eight counters per agent-hour |
| Run summaries | `recent_runs` | capability ids and refusal reasons per run |
| Open attempts | 200 000 entries | cleared beyond that |
| Change feed | 2 000 entries | |

None of these grows with total traffic. As an order of magnitude (an estimate, not a
benchmark), the defaults for a thousand agents stay in the low hundreds of megabytes;
measure with your own fleet and lower `hours` or `recent_runs` if needed.

Ingest costs one canonical digest and one Ed25519 signature check per entry, plus the
fold. Findings are computed per request from the in-memory model; their cost grows with
the number of agents and active guardrails, not with traffic.

## Scaling

- **Replicas.** Several `towerd` instances can share PostgreSQL for records and the
  journal. Each runs its own collectors and builds its own fleet model; counts can differ
  briefly between replicas while they catch up. Journal appends are serialised by the
  store (a replica that loses the race retries).
- **Restart.** The fleet model is rebuilt by verifying every source's chain from
  genesis. For long chains this takes time proportional to chain length; persisting
  collector anchors and aggregates is the next increment (see Limits).
- **Many sources.** One task per source; sources are independent, so a slow or broken
  runtime never delays the others.

## Monitoring

- `GET /healthz` returns `ok` while the process serves.
- Logs are JSON (`RUST_LOG` filters). Watch for `audit chain failed verification`
  (error), and `startup failed`.
- The Runtimes page and `GET /api/sources` show each source's `verified_to`, `head`,
  `last_sync`, `last_error` and `broken`. Alert when `head − verified_to` grows or
  `last_sync` is stale.
- `GET /api/posture` is a cheap summary for dashboards (critical findings, anomalies).

## Backup and audit

- Back up the PostgreSQL database. The journal is append-only; verify exports with
  `ctx audit-verify` (use `--continues` to verify only new entries against the last
  verified one).
- The fleet model needs no backup: it is derived from the runtimes' chains.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `towerd: source X: TOWER_… is not set` at start | A source's key variable is missing | Set it; Tower refuses to start rather than silently skip a business unit |
| Source shows *unreachable* with `401` | The key is wrong or lacks `audit:read` for that tenant | Check the runtime's `[[api_keys]]` entry and the hash |
| Source shows *unreachable* with `describe: …` | `/v1/deployment` or `/v1/packs` failed | Runtime too old (needs the governance reads), or network |
| *Chain broken at #n* | An entry failed verification | Treat as an incident; export and run `ctx audit-verify` against the runtime's keys to confirm; after investigation, restart Tower to re-verify |
| An agent appears twice | Runs sometimes set `agent_urn` and sometimes not | Set `agent_urn` consistently in `run_context.agent` |
| Capabilities show *unknown risk* | Runs surfaced a capability no loaded pack pins | Load the pack in the runtime, or check the pack's `adapter_registry` |
| `profile_understated` on every agent | Orchestrators request `contextos.core` in contracts | Request the profiles Tower lists as required |
| AI buttons disabled | Intelligence off, or the person lacks the role | `[intelligence] provider = "anthropic"` with the key set |
| `422 intelligence: the model declined` | A safety classifier declined and the fallback declined too | Rephrase; nothing was changed |
| `published example key` at start | Development keys in a production config | Generate keys with `openssl rand -hex 24` and `ctx hash-key` |

## Limits and roadmap

What Tower does not do yet, in the order we expect to build it:

1. **Persisted collector state.** Anchors and aggregates in PostgreSQL, so a restart
   resumes instead of re-verifying from genesis.
2. **SSO in the UI.** People sign in with keys today; OIDC login with group-to-role
   mapping is next (the runtime already verifies OIDC bearer tokens).
3. **Discovery of ungoverned agents.** Model-gateway traffic without a ContextOS run id
   (the metering proxy sees it) as a source of agents that bypass runtimes.
4. **Evidence packs per framework.** Mappings of controls and findings to EU AI Act
   articles, ISO/IEC 42001 and NIST AI RMF, exported with the verifiable journal
   (informative, as in the spec).
5. **Policy distribution.** Approved guardrails compiled into pack policy and rolled out
   through the runtime's staged rollouts, closing the loop from detection to prevention.
6. **Approval refusals.** Approval services report refusals so oversight metrics are
   complete (today Tower sees requests and redemptions only).
