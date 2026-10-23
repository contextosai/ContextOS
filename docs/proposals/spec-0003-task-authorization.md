# Proposal to the ContextOS specification: task authorization

Status: draft for the spec maintainers. Implemented in this runtime as an opt-in
runtime extension ([guide](../GUIDE.md#bind-the-run-to-what-the-principal-asked),
threat T28).

## Problem

The execution contract authorizes an action when the actor's grant chain covers it and
the composed policy allows it. Neither says what the principal asked for in *this*
run. Grants are issued per role or workload and outlive the task. Pack policy is
evaluated on the request, so a rule like "refunds above 3000 need approval" sees the
amount the request *stated*, not the amount the agent sends later.

[AuthorizationBench](https://arxiv.org/abs/2610.27548) (Zhang et al., 2026) measured the
resulting gap without any adversary: across 286 tasks, four model families and three
harnesses (including the OpenAI Agents SDK and the Claude Agent SDK), 19.2% of
trajectories performed an action the principal had not authorized. Task completion
and reasoning effort did not predict it, and 37% of those actions caused no direct
harm, so harm-based checks miss them. Runs that consulted the user overstepped less,
but in 214 of 313 overstepping runs that asked, every question came after the first
unauthorized action.

The paper's authorization contract (instruction, completion criteria,
out-of-authorization actions) is fixed at task start and judged on actions. The
specification has no place for it.

## Proposed normative text

> An admission MAY carry one or more task authorizations. A task authorization names
> the principal who issued it (`PrincipalRef`) and lists one or more `AuthorityGrant`
> scopes whose `root_run_id` is the run's root run; it MAY cite the principal's
> confirmation as an `ArtifactRef`. A delegated run MUST carry every task
> authorization of its parent unchanged and MAY add its own.
>
> A run's own task authorization MAY be replaced during the run (a principal's
> correction). A replacement *narrows* when every scope narrows one of the current
> scopes under the delegation rule, read-only actions are no less restricted and
> out-of-scope actions are no less strictly handled; otherwise it *widens*. A
> widening replacement MUST be made by a principal that does not execute the run,
> MUST cite the issuing principal's confirmation and MUST keep the same issuer.
> Replacements MUST be totally ordered per run and recorded in the audit with the
> previous and new references.
>
> For each task authorization, the authorization evaluator MUST compose a guardrail
> policy outcome with `rule_id` `task_authorization` and a `bundle_ref` whose `sha256`
> is the canonical digest of the task authorization. The verdict is `allow` when at
> least one scope covers the action binding under the grant-scope rules. Otherwise it
> is `deny`, or `require_approval` when the task authorization says out-of-scope
> actions wait for the principal. Read-only actions MAY be exempt when the task
> authorization says so. The action binding's `policy_refs` MUST include the
> `bundle_ref`.
>
> A task authorization only narrows: it MUST NOT be treated as authority, and an
> action it covers still requires a covering grant chain.

Because the outcome is an ordinary guardrail outcome and the reference is an ordinary
policy reference, composition, approvals (bound to the action digest), constraint
attestations and audit need no new rules.

## Proposed reference API

```ts
interface TaskAuthorization {
  issued_by: PrincipalRef;
  scopes: AuthorityGrant["scope"][];          // 1..32, root_run_id = the run's root
  out_of_scope?: "deny" | "ask";               // default "deny"
  read_only?: "allow" | "scoped";              // default "allow"
  confirmation_ref?: ArtifactRef;
}

// The first dimension outside the scope, or null when it covers the binding:
// "purpose" | "capability" | "resource" | "destination" | "classification" |
// "argument" | "amount".
function scopeMismatch(binding: ActionBinding, scope: AuthorityGrant["scope"]): string | null;
```

`scopeMismatch` returns the existing grant-scope check (`inScope`) broken down by
dimension. It lets a runtime tell the agent, and the principal, *what* exceeded the
task. Proposed reason codes are `outside_task_authorization` and `task_scope_<dimension>`.

## Conformance vectors

- An action inside one scope of two is allowed, and its decision cites the reference.
- Each dimension outside every scope: deny, with that dimension.
- `ask`: `require_approval`, and an exact approval of that digest then allows it.
- A scope naming another root run is rejected at admission.
- A delegated run's binding cites the parent's reference.
- A binding whose `policy_refs` omit the reference is `policy_binding_mismatch`.
- A replacement with a lower ceiling narrows; another resource, a higher ceiling or
  `deny` → `ask` widens; an approval of a digest made before a replacement no longer
  matches the action after it.

## Open questions

- **Cumulative limits.** Amount ceilings are per action. A total such as "refund up to
  INR 1200 across the task" needs conserved per-run exposure, which the shared-guarantee
  ledger provides at the resource level.
- **Deriving scopes from the instruction.** The specification can define what a task
  authorization is, but not how a deployment derives it from natural language. A
  confirmation step with the principal, recorded as `confirmation_ref`, is the
  recommended practice.
- **Over-sharing inside an allowed message** (AuthorizationBench's worked example)
  is covered only as far as classification labels and data-flow policy describe the
  data, not free text.
