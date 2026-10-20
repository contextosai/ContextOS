# ADR-0004: Partitioned audit chains for very hot tenants

Status: **proposed** (not implemented). Needs a maintainer decision before any code.

## Context

The spec's hash-chained audit is an optional deployment profile: an append-only,
hash-chained log keyed by `trace_id`, whose chain algorithm, canonical serialization,
signer, rotation rules and gap semantics must be versioned and tested (Security,
"Optional hash-chained audit"). This runtime implements it as **one chain per tenant**
(`contextos-rs.audit.v1`): every governed step of every run of a tenant is linked into
one sequence, so an auditor can prove nothing was removed between any two entries.

That chain is a serialization point. Within a process, group commit batches a tenant's
appends; across replicas, writers to the same tenant contend on the chain head. The
multi-replica load test (PERFORMANCE.md) measures it: on one tenant, three replicas
over PostgreSQL reach ~1,530 runs/s against ~1,730 for one. Replicas add throughput
across tenants (chains are independent) and add availability, but a single dominant
tenant is bounded by roughly one writer's group commit, about one database round trip
per batch.

Deployments can route a dominant tenant with affinity today. This ADR records what to
do if one tenant must exceed a single writer.

## Options

1. **Keep one chain per tenant; route hot tenants with affinity** (status quo). Simple,
   strongest completeness statement. Bounded per tenant.
2. **Per-run (per-trace) chains.** Closest to the spec's "keyed by `trace_id`"; no
   contention between runs. But nothing proves a whole run's chain was not deleted:
   completeness per tenant is lost.
3. **Partitioned tenant chain with a root.** A tenant's entries go to one of `K`
   partitions by a stable hash of `trace_id`, each an independent chain with its own
   sequence. Periodically (by count or time) a writer appends a **root entry** to a
   tenant root chain committing every partition's current head (sequence and record
   hash). Verification checks each partition chain and that root entries commit to
   monotonically advancing partition heads, so deleting or rewriting a partition's
   history between two roots is detected, as is dropping a partition.
4. **Single writer per tenant** (leader election per tenant, other replicas forward
   appends). Keeps one chain and removes cross-replica contention, but adds a network
   hop and leader failover to every append path.

## Proposed decision

Option 3, opt-in per tenant (`partitions = 1` keeps today's format exactly), because it
keeps per-tenant completeness while letting replicas append to different partitions
without contending:

- **Format.** A new entry version `contextos-rs.audit.v2` adds `partition` (0..K-1) to
  the hashed spine; `sequence` and `prev_hash` are per partition. Root entries are a
  reserved kind in a root partition, committing `{partition: {sequence, record_hash}}`
  for all K partitions, and are signed like any entry.
- **Routing.** `partition = H(trace_id) mod K`, so one run's entries stay in order in
  one partition and replay per run is unchanged.
- **Roots.** Written by the cluster leader (membership already elects one) every N
  appends or T seconds, and on demand before an export.
- **Verification.** `ctx audit-verify` verifies each partition and every root; an
  export between two roots is complete if each partition's segment runs exactly from
  the earlier root's head to the later root's head.
- **Changing K** is a migration: a root entry closes the old layout and opens the new
  one; partition count is part of the versioned profile.

## Consequences

- Throughput for one tenant scales with K across replicas; partitions still use group
  commit within a process.
- Completeness is proven at root granularity rather than per entry: entries appended
  after the last root are not yet committed by a root, so exports should end at a root.
- More moving parts in the verifier and the writer; the v1 format stays supported for
  tenants that keep one partition.

## Before implementing

- Measure whether affinity routing is insufficient for real deployments.
- Decide whether roots should also be anchored externally (for example to a
  transparency log) for third-party timestamping.
- Bring the profile's versioning and gap semantics to the spec maintainers, since the
  spec asks for them to be versioned and tested.
