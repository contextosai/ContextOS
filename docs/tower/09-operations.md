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
| `token_env` or `token_file` | one required | Variable, or absolute path of a mounted secret file, holding that tenant's `audit:read` key. Startup fails if it cannot be read |
| `control_token_env` or `control_token_file` | none | Variable or secret file holding a `control` key; without it the kill switch skips this source and its escalations are read-only in the inbox |

Sources can also be added from the console (Runtimes → Add runtime, `admin`), with the
same fields. Those are kept in Tower's store, not in this file; every replica converges
on them (see Scaling). Keys are always referenced, so a key file can be rotated in place
and picked up with *Reload keys*.
| `business_unit`, `region`, `environment` | none | Labels for people and the analyst |

### `[[api_keys]]` (people and services)

| Key | Meaning |
|---|---|
| `key_sha256` | `sha256:<hex>` from `echo -n "$KEY" \| ctx hash-key` (lowercase) |
| `principal_id` | The name the journal records |
| `roles` | Any of `viewer`, `owner`, `risk`, `operator`, `admin` |
| `teams` | Teams whose agents an `owner` may declare |

### `[sso]` (people sign in with the identity provider)

People sign in with the organization's OpenID Connect provider (Okta, Microsoft Entra
ID, Keycloak, Google) instead of holding keys; keys keep working for services. Tower
accepts the provider's ID token as a bearer token and maps the person's groups to
roles. Someone in no mapped group gets nothing.

```toml
[sso]
issuer = "https://login.example.com/realms/acme"   # exact `iss`; its metadata is read
client_id = "contextos-tower"                       # the ID token's `aud`
redirect_uri = "https://tower.example.com/tower/"   # registered with the client
# client_secret_env = "TOWER_SSO_SECRET"            # confidential clients only
[[sso.groups]]
group = "grc-ai-risk"
roles = ["risk"]
teams = ["grc"]
[[sso.groups]]
group = "ai-platform-oncall"
roles = ["operator"]
```

| Key | Default | Meaning |
|---|---|---|
| `issuer` | required | Exact `iss`; `<issuer>/.well-known/openid-configuration` gives the keys and endpoints, and must name the same issuer |
| `client_id` | required | The OAuth client the UI signs in as; tokens must name it in `aud` |
| `redirect_uri` | required | Tower's UI root, registered as the client's redirect URI |
| `client_secret_env` | none | Variable holding the client secret. Unset: a public client, protected by PKCE |
| `jwks_url` | from metadata | The issuer's keys |
| `principal_claim` | `email` | The person's name in the journal (`sub` when missing) |
| `groups_claim` | `groups` | Dotted path to the person's groups (for example `realm_access.roles`) |
| `algorithms` | `["RS256", "ES256"]` | Asymmetric only |
| `leeway_seconds` | `60` | Clock skew on `exp` and `nbf` |
| `refresh_seconds` | `600` | How often keys are fetched again; an unknown `kid` refreshes sooner (at most every 30 s) |
| `scopes` | `["openid", "profile", "email"]` | What the UI asks for; add the scope that puts groups in the ID token if your provider needs one |
| `[[sso.groups]]` | at least one | `group`, its `roles` and `teams` |

The provider must put the person's groups in the ID token. Okta: a `groups` claim on
the ID token. Entra ID: `groupMembershipClaims` in the app manifest (group object ids,
so map those). Keycloak: a group or realm-role mapper on the client.

### `[intelligence]`

| Key | Default | Meaning |
|---|---|---|
| `provider` | `off` | `anthropic` or `off` |
| `api_key_env` | `ANTHROPIC_API_KEY` | Variable holding the API key |
| `model` | `claude-opus-5-5` | Model id |
| `effort` | `high` | `low`, `medium`, `high`, `xhigh`, `max` |
| `base_url` | `https://api.anthropic.com` | Messages API base URL |
| `max_turns` | `8` | Tool-use turns per question |

### `[governance]`

| Key | Default | Meaning |
|---|---|---|
| `two_person_restore` | `true` | Restoring a revoked target needs a second operator: one requests it (`POST /api/revocations/restore-requests`), another approves it, and only the approval acts on the runtimes. `POST /api/fleet/restore` then answers `409 two_person_required`. Revoking always stays one operator's action |

### `[collector]`

| Key | Default | Meaning |
|---|---|---|
| `poll_ms` | `2000` | How often each source is polled for new entries |
| `recent_runs` | `50000` | Run summaries kept for search and drill-down |
| `hours` | `720` | Hours of per-agent activity kept (30 days) |
| `reconcile_ms` | `10000` | How often each replica converges with the sources, pauses, retries and key reloads made from the console |

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
front of it (an ingress or a sidecar); `towerd` serves plain HTTP. When runtimes or the
model API sit behind your own CA, set `CONTEXTOS_CA_BUNDLE` to a PEM file of its
certificates, as for `contextosd` (GUIDE section 12, *Private CAs*).

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
- **Console-managed sources.** Additions, pauses, retries, key reloads and removals
  are records in the store; each replica applies them when it next converges (at most
  `reconcile_ms`), and immediately on the replica that took the request. A replica that
  cannot read a console source's key file or variable lists it as *keys unavailable*
  and keeps governing the others; mount the secret on every replica.
- **Many sources.** One task per source; sources are independent, so a slow or broken
  runtime never delays the others.

## Monitoring

- `GET /healthz` returns `ok` while the process serves.
- Logs are JSON (`RUST_LOG` filters). Watch for `audit chain failed verification`
  (error), and `startup failed`.
- The Runtimes page and `GET /api/sources/health` show each source's `state`, `lag`
  (`head − verified_to`), `last_sync_age_seconds`, `last_error` and `broken`. Alert on
  `state` other than `current` or `paused`, a growing `lag`, or `reconcile_error`.
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
| *Chain broken at #n* | An entry failed verification | Treat as an incident; export and run `ctx audit-verify` against the runtime's keys to confirm; after investigation, *Retry verification* (admin, with the reason) continues from the last verified entry |
| Source shows *keys unavailable* | This replica cannot read a console source's key variable or file | Mount the secret (or set the variable) on every replica, then *Reload keys* |
| Source shows *stale* | No successful sync for `stale_after_seconds` | Check `last_error`, the runtime's health and network; *Pause* it during planned maintenance |
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
