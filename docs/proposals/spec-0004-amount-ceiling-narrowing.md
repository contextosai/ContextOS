# Proposal to the ContextOS specification: one meaning for a missing amount ceiling

Status: draft for the spec maintainers. Found by property AUTH-1
([verified properties](../verification/PROPERTIES.md), SPEC-1).

## Problem

The execution contract gives `AuthorityGrant.scope.amount_ceiling` two meanings.

- **The grant-scope check** (reference `authorization.ts:284`): an action with an
  `amount` is in scope only if the scope has a ceiling in the same currency at least as
  high. A scope *without* a ceiling admits **no** action that carries an amount.
- **The delegation rule** (reference `authorization.ts:272`): a child scope narrows its
  parent if, among other things, the parent has no ceiling, *or* the child's ceiling is
  in the same currency and no higher. A parent *without* a ceiling is treated as
  **unlimited**, so a child may add any ceiling.

So a child scope that adds `amount_ceiling: INR 1,000,000` to a parent without one is
accepted as narrowing, although it admits refunds the parent refuses. The reverse
(dropping a ceiling, which forbids amounts) is refused as widening, although it narrows.

## Impact

- **Grant chains: none.** Authority validation requires *every* grant in the chain to
  cover the action, so the parent's check still refuses the amount. The rule only lets a
  chain be built that can never authorize the amount.
- **Any other use of the delegation rule as "permits nothing more": exploitable.** This
  runtime classified task-authorization amendments with it (proposal spec-0003), so a
  run admitted with a scope that authorized no amount could have its own executor add a
  ceiling as a "narrowing", without the principal. Fixed in the runtime (test
  `an_executor_cannot_allow_itself_amounts`). Other implementations that reuse the rule
  this way are exposed the same way.

## Proposed change

Make the delegation rule follow the grant-scope check: a missing ceiling means no amount.

> A child scope narrows its parent only if: the parent has no `amount_ceiling` and the
> child has none; or both have one, in the same currency, and the child's
> `minor_units` are no greater than the parent's.

In the reference:

```ts
&& (parent.amount_ceiling
  ? !!child.amount_ceiling && child.amount_ceiling.currency === parent.amount_ceiling.currency
    && child.amount_ceiling.minor_units <= parent.amount_ceiling.minor_units
  : !child.amount_ceiling)
```

Dropping a ceiling stays refused. It narrows in effect, but accepting it would need the
rule to reason about amounts the scope can never admit; refusing it is safe.

The alternative, reading a missing ceiling as unlimited in the grant-scope check too,
would widen every existing grant without a ceiling to unlimited amounts. It is not
proposed.

## Conformance vectors

- Parent without a ceiling, child with one: `delegation_scope_expanded`.
- Parent without a ceiling, child without one: narrows (unchanged).
- Parent with INR 5000, child with INR 4500: narrows (unchanged).
- Parent with a ceiling, child without: `delegation_scope_expanded` (unchanged).

## Property

For all scopes `child`, `parent` and action bindings `b`: if `child` narrows `parent`
and `child` covers `b`, then `parent` covers `b`. With this change the property holds
without exception; the runtime checks it on generated inputs (AUTH-1).
