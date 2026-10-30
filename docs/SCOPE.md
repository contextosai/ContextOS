# What ContextOS does not govern

ContextOS governs **effects**. Before a tool call runs, it decides whether the call is
allowed, approved, within budget and within shared limits. It tracks the call until
its outcome is known and records all of this in a signed audit chain. It does not judge
the *content* that flows through an agent, and it trusts some facts it is given.

This page lists what falls outside that boundary, so you can place the right control
beside it. Each item names the threat-model entry it relates to
([THREAT_MODEL.md](security/THREAT_MODEL.md)) or says that it is not modeled, and
where the deployment plugs in.

| Not governed | What ContextOS does instead | Where you add the control |
|---|---|---|
| **Prompt injection in tool results, retrieved documents or user input.** Nothing screens text for injected instructions. | Tool output and retrieved evidence are labelled `data_only`, only pinned and surfaced capabilities can dispatch, and approvals bind the exact action digest. Injected text can mislead the model, but it cannot grant authority or change an approved action (T1, T2). | Screen inputs and outputs in your agent framework or model gateway. A port for screening tool results inside the gateway is planned ([plan](design/governance-gaps.md), workstream F). |
| **Content of what the agent says or writes.** ContextOS does not judge whether a reply, summary or decision rationale is true, safe or appropriate. | Decisions cite evidence by reference, and the release gate and evaluator scores measure quality before and after release (GUIDE §5, §7). | Content moderation and evaluation in your model pipeline; score decisions with `POST /v1/runs/{run_id}/decisions/{record_id}/scores`. |
| **Semantic data taint.** The runtime cannot follow personal or confidential data through natural-language transformations. | Capabilities that send data, or name recipients, go through the data-governance port, which checks the destination, purpose and classification the provider declares for that action (T23). | A data-governance service behind `DataFlowProvider` that knows your data classes. |
| **Whether the agent is the workload it claims to be, beyond its credential.** With agent binding, the declared agent must be one the credential names (T30), so the binding is as strong as the credential: a stolen key or token acts as its agent. | Runs are bound to the admitting principal (T29) and, with `[guards] agent_binding = "required"`, to the agents its credential is issued for. X.509 SVIDs and build attestation are not checked. | Short-lived workload credentials (SPIFFE JWT-SVIDs, OIDC client credentials) and one credential per agent service. |
| **Meaning changes in upstream tools.** An upstream MCP server can change what a tool does while keeping its name. | Agents only see reviewed manifests with reviewed input and output schemas. New or renamed upstream tools never reach them, and arguments that don't match the reviewed shape are refused (T22). | Review upstream changes before pinning a new capability version. Detecting upstream drift is planned (workstream D3). |
| **Trust between organizations.** Peer coordination and delegation work within one deployment and store. | Delegation narrows authority and budget at every hop (T5, T21). | Not modeled. Treat a call from another organization as any other caller: its own principal, scopes and task authorization. |
| **Poisoned memory content.** The runtime does not detect that a remembered fact is false. | Memory changes are lifecycle records. They are decided by the kernel against context from your memory-governance service, bound to the run and audited; superseded and deleted memories are refused at recall (T25). | Detect poisoning in your memory-governance service. That service already decides reviews and readers. |
| **Honesty of fact providers and of the caller's evidence labels.** | The kernel checks binding, currency and scope of every observation, but cannot detect a provider that lies. Evidence gates trust the labels the admitting caller supplies (residual risks). | Run identity, approval and control-plane services with their own hardening, and have a trusted service build run requests. |
| **Whether a model or evaluator release exists.** | Production requires release refs and records them in every decision, checking their form, not a registry (residual risks). | Verify release pins in your release process. |
| **The provider's side of an effect.** | Effects whose outcome is unknown hold their reservation until reconciled; the runtime never resends to find out (T6, T19). | Providers that honour idempotency keys and, ideally, fence on the forwarded executor generation. |

## What this means for a review

If a reviewer asks "does ContextOS stop prompt injection?", the accurate answer is no:
it stops a successful injection from **acting** beyond what was authorized, approved
and budgeted, and records what happened. Layer content controls in front of it, and
rely on ContextOS for the guarantee that matters when they miss.
