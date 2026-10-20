# ADR-0002: JsonLogic semantics and deliberate divergences

- Status: accepted
- Date: 2026-10-20

## Context

Context Pack policy rules and approval gates are JsonLogic expressions. The spec's
reference evaluates them with `json-logic-js` 2.0.5, so the same rule must produce the same
verdict here, including JavaScript coercion (`"1" == 1`, `parseFloat` in `+`, UTF-16
string order, `NaN` comparisons).

`json-logic-js` also has behavior that is unsafe or not expressible over JSON data:

- `var` reads inherited JavaScript prototype members, so `{"var": "constructor"}` returns a
  host function and makes a rule fire.
- `==`/`===`/`in` between two arrays or objects compare object *identity*, which depends on
  how the evaluator happened to share references rather than on the data.
- There is no bound on work: `map`/`reduce`/`merge`/`cat` over large inputs can exhaust a
  shared process.

## Decision

`contextos-policy` reproduces `json-logic-js` 2.0.5 semantics exactly, with these
fail-visible exceptions, each returning an `EvalError`:

| Reference behavior | This runtime |
|---|---|
| Reads a prototype member (`constructor`, `__proto__`, `toString`, array/string/number methods) | `UnsafeProperty` |
| Compares two arrays/objects by identity | `ReferenceComparison` |
| Unbounded depth, steps, string length, array size | `LimitExceeded` (defaults: depth 128, 100 000 steps, 1 MiB strings, 100 000 elements) |
| `log` writes to the console | returns its argument, no I/O |

The compiler treats every `EvalError` like any other applicable-predicate failure:
compilation stops with a structured `policy_eval_error`. A rule that depended on one of
the divergent behaviors was already incorrect; failing visibly is the spec's required
behavior for such errors.

## Verification

`conformance/vectors/jsonlogic.json` is a seeded corpus of 6 000 random rules evaluated by
`json-logic-js`. The parity test requires every case to match exactly except those
reported as `UnsafeProperty` or `ReferenceComparison` (65 cases in the current corpus).
