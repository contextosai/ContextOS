---
name: contextos-pack-authoring
description: Write, change and review ContextOS Context Packs (context-pack.v2): policy rules in JsonLogic, approval gates, decision specs and evidence, tool permissions, rule libraries. Use when someone asks to author a pack, add or change a business rule, scope a rule to an intent or role, explain what a pack lets a principal do, or prepare a pack change for release. Every change is checked with ctx validate, ctx plan, ctx test and ctx gate before it is called done.
---

# Authoring ContextOS Context Packs

A Context Pack is the governed contract for one tenant's agents: which rules decide,
which tools are surfaced, which decisions need which evidence and approvals. A pack
change is a change to what agents may do, so treat it like a policy change: state the
intent, write it, prove it with tests, and gate it against the version it replaces.

Read [reference.md](reference.md) before writing rules: the composition semantics
(default deny, highest priority decides, `else` branches) are where packs go wrong.

## Workflow

1. **Pin down the requirement as cases.** Before editing JSON, write down, in plain
   language, 3–6 concrete cases: who (user role, agent), which intent, which request
   facts (`request.context.*`), and the verdict each must get (`allow`,
   `require_approval`, `deny`). Include the boundary (exactly the threshold) and the
   missing-fact case (field absent or `null`). If the requester cannot answer what a
   case should decide, ask; do not guess policy.

2. **Find where the change goes.**
   - A business rule → `policy_layer.policy_bundles[].policy_dsl.rules[]`.
   - A rule several packs need → a rule library imported with `ctx build`
     (see "Shared rules" below), not a copy.
   - A tool → `tooling_layer.adapter_registry` (capability, `approval_mode`,
     `capability_risks`) plus an allowing `tooling_layer.permissions` entry.
   - A decision that needs evidence → `decision_layer.decision_specs[]`, bound from the
     rule with `decision_binding`.
   - An approval → `policy_layer.approval_gates[]` and the rule's
     `then.requires_approval_gate` naming that `gate_id`.

3. **Write the change.** Follow the patterns in [reference.md](reference.md). Give
   every rule a stable, unique `rule_id` and a `rationale`. Scope rules with
   `applies_to.intent`. Never edit a released version in place: bump
   `pack_meta.pack_version`, since a pack reference names one content forever and the
   server refuses a changed file under a loaded reference.

4. **Encode the cases as a pack test suite** (`ctx test`). One test per case from
   step 1; expect the `verdict`, and the `rules` and `obligations` where they matter.
   Start the base from a real admission body or replay case
   (`GET /v1/runs/{id}/replay-case`) when one exists.

5. **Check it** with the bundled script, which runs schema validation, the tests, and
   a decision plan per role:

   ```sh
   bash skills/contextos-pack-authoring/scripts/check_pack.sh \
     --pack PACK.json --tests PACK_TEST.json --run RUN.json --roles support_agent,supervisor
   ```

   To explore one case by hand, `ctx repl --pack PACK.json --run RUN.json` takes
   `set request.input.context.<field> <json>` and `decide`. Read every plan: for each role, the rules listed as `always`, `when` or `unless`
   and `possible_verdicts` must match the requirement. A role that should never reach
   `allow` must not have it in `possible_verdicts`.

6. **Gate against the released version** when there is one, on recorded cases:

   ```sh
   bash skills/contextos-pack-authoring/scripts/check_pack.sh --pack NEW.json \
     --baseline OLD.json --cases cases.json [--acknowledge ack.json]
   ```

   A widening (a capability newly surfaced, a verdict loosening, an evidence gate
   newly allowing commit) fails the gate. Do not write acknowledgements yourself to
   make it pass: report each widening and let the release owner acknowledge it.

7. **Report** what changed, the cases and their results, each role's plan in one line,
   and any gate findings. Say plainly if something was not checked (no baseline, no
   recorded cases).

## Shared rules

Put a rule several packs need in a rule library and build each pack from a source:

```json
{"pack_source": "contextos.pack_source.v1",
 "base": "pack-5.2.0.json",
 "patch": {"pack_meta": {"pack_version": "5.3.0"}},
 "imports": [{"library": "libraries/chargebacks.json", "intent": "support.refund"}]}
```

`ctx build SOURCE --out PACK` writes a plain pack; commit it beside the source and
run `ctx build SOURCE --check PACK` in CI. An import's `intent` scopes every imported
rule to that intent and refuses a rule that names another one. See
`examples/support-refund/authoring/`.

## Rules of thumb

- Prefer narrowing a broad rule over adding an exception after it; composition has no
  rule order, only priority.
- A rule without `else` does nothing when its condition is false. Use `else` with
  `allow: false` when a missing fact must deny.
- Compare facts with `==` against literals (`{"==": [{"var": "request.context.identity_verified"}, true]}`);
  truthiness tests (`{"var": ...}` alone) also accept `1`, `"yes"` and non-empty
  arrays.
- Put facts an agent could invent (identity checks, fraud signals) in evidence, not in
  `request.context`, for any decision that matters; under `[guards] evidence = "strict"`
  a request naming a required evidence item in its context is refused.
- Read [reference.md](reference.md) "Pitfalls" before calling a change done.
