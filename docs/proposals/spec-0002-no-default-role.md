# Proposal to the ContextOS specification: no default role in policy inputs

Status: draft for the spec maintainers. Not implemented here yet: this runtime matches
the reference compiler byte for byte (the compiler parity vectors), so it changes only
with the reference.

## Problem

When a run's user claims carry no `role`, the reference compiler evaluates policy as
if the user were a `support_agent`:

```ts
// src/lib/contextos/compiler.ts
user: { ...runCtx.user, role: runCtx.user.role ?? "support_agent" },
```

and this runtime mirrors it (`crates/contextos-kernel/src/compiler.rs`,
`build_rule_eval_context`). Policy then runs on an attribute nobody asserted. Whether
that is safe depends on the rule:

- A rule that restricts a role (the reference scenario's
  `R_HIGH_VALUE_REQUIRES_APPROVAL` fires only for `support_agent`) happens to become
  stricter for unclaimed roles.
- A rule that grants to a role (`{"==": [{"var": "user.role"}, "support_agent"]}` →
  `allow`) becomes a widening: any caller that omits its role is treated as holding
  it.

The governance principle the spec states elsewhere ("a conflict or missing claim fails
closed"; untrusted inputs "cannot broaden the principal chain") argues against
inventing identity attributes. A harness audit of this runtime flagged it as a P0
policy-input defect.

## Proposed normative text

> The rule-evaluation context MUST contain only identity attributes the run's verified
> claims assert. A missing attribute MUST be absent from the context, so a predicate
> over it evaluates as over a missing variable (JsonLogic `var` yields `null`), and MUST
> NOT be replaced by a default. A pack that needs a default role MUST declare it
> explicitly (for example `policy_layer.defaults.user_role`), and the compiler MUST
> record in the context ledger that the default was applied.

## Proposed reference change

```ts
user: runCtx.user,   // no invented role
```

with, optionally, a pack-declared default:

```ts
const role = runCtx.user.role ?? pack.policy_layer.defaults?.user_role;
user: role === undefined ? runCtx.user : { ...runCtx.user, role },
// and record `role_default_applied: true` in the context ledger when it was used
```

## Conformance impact

- Compiler vectors whose run context omits `role` change outcome where a rule keys on
  `user.role`. The generator's grid always sets `userRole`, so the existing grid is
  unaffected; add vectors with the role absent:
  - a granting rule keyed on the role does **not** match (fails closed);
  - a restricting rule keyed on the role does not match either, so the pack must say
    what an unclaimed role gets (a default-deny business outcome already does).
- Deployments that relied on the implicit default must either send the role in the
  user claims or declare a pack default.

## Runtime plan once accepted

Regenerate `conformance/vectors/compiler.json` from the updated reference, drop the
default in `build_rule_eval_context`, and support the pack-declared default if the
spec adopts it. Until then, deployments should always send `user.role` in the run
context's verified claims.
