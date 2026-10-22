# ContextOS Tower

The organisation's governance plane over its AI agents: know which agents exist and
who owns them, what each can do, which controls that requires and where they are
missing, what is going wrong, and prove it. This directory is the web UI; the service
is [`towerd`](../crates/towerd). Developer documentation, from architecture to a
step-by-step guide, is in [docs/tower](../docs/tower/README.md).

**Why "Tower".** ContextOS describes agent work in five planes. A control tower sees
everything in flight, clears or holds it, and can stop it, without flying the aircraft.
Tower does the same for an organisation's agents: every decision about an effect is
still made by the runtime it passes through; Tower governs the fleet.

## Who it is for

| Person | Starts at | What they get |
|---|---|---|
| Head of AI risk, CISO | **Posture** | Agents, ownership and review coverage, critical findings, the most exposed agents, the controls the fleet's authority requires |
| Agent owner | **Agents → their agent** | What the agent can do and the risk of each capability, the controls it needs and where they are missing, findings with fixes, declaration, waiver requests |
| Risk reviewer | **Agents → Review**, **Guardrails**, **Waivers** | Intake review (with an AI draft), organisation guardrails written in plain language and checked against the real inventory, waiver decisions |
| On-call operator | **Activity**, **Runtimes** | Anomalies against each agent's own baseline with AI briefings, the fleet kill switch |
| Auditor | **Journal** | Every governance decision in a signed chain that verifies offline |
| Anyone | **Ask Tower** | Questions in plain language, answered from read-only tools with citations Tower checks |

## How it stays trustworthy

- **Evidence, not assertion.** `towerd` verifies every runtime audit entry before
  using it and records its own decisions in a signed journal (`ctx audit-verify`).
- **Required controls come from what an agent can do** (the ActionRisk of its
  capabilities), never from what its owner declares; risk is never collapsed into one
  score.
- **Separation of duties, enforced by the server.** Owners cannot review their own
  agents; guardrails are activated and waivers decided by someone other than their
  author.
- **AI advises, people decide.** Claude drafts and explains; nothing it returns changes
  anything until a person with the right role acts. Every use is journalled.
- **Browser hardening.** Same-origin scripts, styles and connections only, no inline
  script, no framing; the key lives in the tab's session storage and is sent only as
  an `Authorization` header. Four direct runtime dependencies (React, React DOM, React
  Router, TanStack Query), pinned and audited in CI.

## Run it

```sh
./examples/tower/run.sh --serve     # a runtime with governed agents, and towerd over it
```

Open `http://127.0.0.1:8090/tower/` and sign in with a development key from
`examples/tower/towerd.toml` (viewer, owner, two risk reviewers, operator). Set
`[intelligence] provider = "anthropic"` and `ANTHROPIC_API_KEY` to turn on Ask Tower
and the AI drafts.

### Develop

```sh
npm ci
TOWER_URL=http://127.0.0.1:8090 npm run dev   # hot reload; proxies /api to towerd
npm test && npm run typecheck && npm run build   # build writes dist/ for [tower] dir
```
