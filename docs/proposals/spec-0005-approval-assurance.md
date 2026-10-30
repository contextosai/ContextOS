# Proposal to the ContextOS specification: approver assurance

Status: draft for the spec maintainers. Implemented in this runtime as an opt-in
runtime extension (`[guards.approval_step_up]`,
[guide](../GUIDE.md#4-integrate-your-services), threat T34).

## Problem

An approval binds the exact action. The kernel checks that the approver is eligible
and entitled, that a quorum agrees, that the decision falls within the request's
window, and that it is redeemed once. It does not check how the approver
authenticated. A refund of 4,000,000 minor units approved from a session that signed
in with a password nine hours ago passes the same checks as one approved after a
hardware-key prompt a minute ago. For large or irreversible actions, the session is
the weakest link: a stolen session approves anything its owner may.

The approval decision schema has exact keys, so a runtime cannot read an assurance
level from it without diverging from the reference.

## Proposal

> An approval validation input MAY carry `assurance`: an object keyed by
> `approval_id` whose values state how the approver authenticated for that decision:
> `acr` (string), `amr` (array of strings) and `auth_time` (timestamp), as asserted by
> the approver's identity provider (OpenID Connect Core §2).
>
> A deployment MAY require approver assurance for actions whose bound amount is at
> least a threshold, or for named capabilities. When it is required, every approved
> decision MUST have an `assurance` entry with an accepted `acr` or `amr` value and
> an `auth_time` not after `decided_at` and at most a configured age before it.
> Otherwise the approval MUST NOT be redeemed, and the evaluator SHOULD answer
> `require_approval` with the reason `approval_step_up_required`.

## Why not elsewhere

- **In the approval service alone.** The service can already demand step-up, but the
  runtime then cannot tell a deployment that does from one that does not. Evidence and
  enforcement should meet at the decision.
- **In Tower.** An approver console would cover only deployments that use it.

## Compatibility

Additive: `assurance` is optional, and validation is unchanged when no requirement
applies. This runtime strips `assurance` before calling the parity-locked kernel and
enforces the requirement in the gateway, so its golden vectors are unaffected.
