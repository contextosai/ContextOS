# Context Pack reference for authors

How the runtime reads a pack (the `contextos-kernel` compiler and policy composition,
used identically by admission, `ctx test`, `ctx plan` and `ctx gate`).

## What a rule can read

Rule conditions are JsonLogic evaluated against:

| Variable | Source |
| --- | --- |
| `intent` | `request.input.intent`; if empty, a heuristic over the message |
| `user.*` | the run context's user (`user.role` is `support_agent` when absent, unless `[guards] require_user_role`) |
| `agent.*` | the run context's agent |
| `tenant_id` | the run context's tenant |
| `request.request_id`, `request.channel`, `request.locale` | the request |
| `request.context.*` | `request.input.context`, supplied by the caller |

Anything else reads as `null`. A condition that fails to evaluate (an unknown
operator, a property of `null` through a computed path) refuses compilation for that
request; it is never treated as false.

## How rules apply

For the run's intent, every rule in every bundle whose `applies_to.intent` is empty or
equal to it is evaluated:

- condition true → the `then` branch applies: `allow: false` is a deny;
  `allow: true` with `requires_approval_gate` is `require_approval`; otherwise
  `allow`. `then.requires` adds obligations; `then.prohibits` withholds capabilities
  (`adapter_id.capability`).
- condition false and an `else` exists → the `else` branch applies (`allow` only).
- condition false and no `else` → the rule does nothing.

## How the verdict is composed

1. No applying rule → **deny** (`business_policy_denied`). An intent no rule covers is
   denied.
2. Only the applying rules of the **highest priority** among them decide. A
   lower-priority deny is overruled by any higher-priority applying rule.
3. Among those: any deny → **deny**; else any approval gate → **require_approval**;
   else **allow**.
4. Obligations are collected from every applying rule, whatever its priority.

So priority is a scope, not an order: give a bundle a higher priority only when its
rules, whenever they apply, should decide alone.

## Tools

A capability is surfaced when its adapter's `approval_mode` is at most the run's
`safety_mode` (`read_only` < `local_write` < `network` < `delegated` < `destructive`),
a `tooling_layer.permissions` entry allows it, no applying rule `prohibits` it, and its
`capability_risks` entry (if any) is allowed by `policy_layer.action_risk_policy`. An
adapter's `approval_mode` must be at least the projection of each capability risk
(the compiler refuses the pack otherwise). `arg_constraints` on a permission bound the
arguments dispatch accepts.

## Decisions and evidence

A rule whose `then` allows and names `decision_binding: "<decision_key>"` opens an
evidence gate for that `decision_layer.decision_specs[]` entry while it applies. The
gate allows commit only when every `required_evidence` item is met: by an evidence
entry that is `verified` and `current`, or (unless `[guards] evidence = "strict"`) by
a truthy `request.context` key of that name. A binding to a decision key with no spec
refuses compilation, but only for requests where the rule applies, so test that case.

## Approvals

`then.requires_approval_gate` names a `policy_layer.approval_gates[].gate_id` with
`required_approver_role` and `ttl_seconds`. The compiler does not check that the gate
exists: check it yourself (see Pitfalls).

## Pitfalls

- **Truthiness.** `{"var": "request.context.flag"}` alone is true for `1`, `"yes"`
  and any array, even an empty one. Compare with `==` against a literal.
- **Missing facts.** `{"==": [{"var": "request.context.identity_verified"}, true]}` is
  false for a missing field, so the rule needs an `else` with `allow: false` if a
  missing fact must deny. Test the field absent and `null`.
- **Thresholds.** `>` vs `>=` at the boundary; numbers sent as strings compare as
  numbers in `>`/`<` but not in `===`. Test exactly the threshold.
- **Priority surprises.** A new high-priority bundle whose rule applies to every
  request (empty condition, `else` branch) silences every lower-priority deny.
  Check with `ctx plan` that the lower rules still decide where they should.
- **Unknown names.** A typo in `decision_binding`, `requires_approval_gate`, a
  `prohibits` entry or a permission's `adapter_id`/`capability` is not always refused
  at load. `ctx inspect` (and so `check_pack.sh`) lists names that do not resolve.
- **Role defaults.** Rules keyed on `user.role` see `support_agent` for runs that send
  no role, unless the deployment requires roles. Plan for a run without a role too.
- **Editing a released version.** Bump `pack_meta.pack_version`; a reference with new
  content is refused by a running server and breaks replay of recorded runs.

## Commands

| Command | What it proves |
| --- | --- |
| `ctx validate context-pack PACK` | the document conforms to context-pack.v2 |
| `ctx inspect PACK` | a review summary: intents and rules, tools, gates, decisions, and `problems` (names that do not resolve) |
| `ctx test --pack PACK SUITE... [--junit OUT]` | the pack decides the stated cases |
| `ctx plan --pack PACK --run RUN [--intent I]` | what one principal may do, and on which request facts it depends |
| `ctx gate --baseline OLD --candidate NEW --cases CASES [--acknowledge ACK]` | the change widens nothing unacknowledged on recorded cases |
| `ctx build SOURCE [--out PACK \| --check PACK]` | a pack built from a base and rule libraries |
| `ctx compile --pack PACK --request REQ --run-context RC` | the full compiled context for one request |
