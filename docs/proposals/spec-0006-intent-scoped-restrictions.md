# Proposal to the ContextOS specification: intent-scoped restrictions

Status: draft for the spec maintainers. This runtime matches the reference compiler
byte for byte, so the compiler is unchanged; `contextosd` enforces the first part at
admission (`[guards] pack_intents`, GUIDE section 3).

## Problem

The compiler evaluates a rule whose `applies_to.intent` names an intent only when the
request declares that intent, and the request's intent is the caller's to declare
(`request.input.intent`, or a substring heuristic when it is empty). Tool surfacing
starts from the pack's permissions and subtracts only the prohibitions of rules that
fired. So a restrictive rule scoped to one intent (a prohibition, an approval gate,
required evidence, a `false` else branch) does not apply to a run that declares
another intent, while the tools it was written to restrict are still surfaced, and the
policy manifest dispatch authorizes against never contains it.

Every rule in the reference scenario and in the compiler vectors is intent-scoped, so
this is the normal shape of a pack, not an edge case. A pack author reading
"`support.refund` requires identity verification" reasonably believes refunds require
it; a run declaring `general.query` gets the refund tool without it.

## Proposed normative text

> A Context Pack serves the intents its rules name in `applies_to.intent`, if they name
> any. The compiler MUST refuse a request whose resolved intent the pack does not serve
> (`intent_not_served`), and MUST NOT surface a capability under an intent whose rules
> the pack author did not write for it. A pack that serves several intents SHOULD scope
> each intent's restrictive rules to it; a capability that a restrictive rule scoped to
> intent A governs SHOULD be surfaced under another intent B only if B's rules permit it
> explicitly.

## Conformance impact

- New vectors: a pack whose rules all name `support.refund`, a request declaring
  `general.query` → `intent_not_served`; the heuristic fallback resolving to an intent
  the pack does not serve → refused the same way.
- Existing grid vectors all declare an intent their pack serves and are unaffected.

## Runtime plan once accepted

Regenerate the compiler vectors from the updated reference and move the admission
check into the kernel compiler; keep `[guards] pack_intents = "observe"` for
deployments that need to measure before they enforce.
