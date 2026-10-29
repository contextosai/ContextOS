#!/usr/bin/env python3
"""Failure drill for one shared business limit on PostgreSQL: separate contextosd
processes, real SIGKILLs and restarts, an optional database restart, and the provider's
own ledger as ground truth. Synthetic and loopback only; no model key or payment account.
"""
import concurrent.futures
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cluster  # noqa: E402
import provider  # noqa: E402
from cluster import LIMIT, admit, balance, current_generation, outcome, reconcile, refund  # noqa: E402

URL_ENV = "CONTEXTOS_DRILL_DATABASE_URL"
REPLICAS = int(os.environ.get("CONTEXTOS_DRILL_REPLICAS", "3"))
AGENTS = int(os.environ.get("CONTEXTOS_DRILL_AGENTS", "12"))
ROUNDS = int(os.environ.get("CONTEXTOS_DRILL_ROUNDS", "10"))
# A shell command that restarts the database (for example `docker restart -t 0 NAME`).
PG_RESTART = os.environ.get("CONTEXTOS_DRILL_PG_RESTART", "")
RECEIPT = Path(os.environ.get("CONTEXTOS_RECEIPT_DIR", cluster.ROOT / "receipts/postgres-drill"))
PREFIX = format(int(time.time() * 1000), "x")
GUARANTEE = f"drill-{PREFIX}"
SHARE = 30_000  # three fit under the limit, a fourth does not


def percentiles(samples):
    if not samples:
        return {}
    ordered = sorted(samples)
    pick = lambda q: ordered[min(len(ordered) - 1, max(0, round(q * len(ordered) + 0.5) - 1))]  # noqa: E731
    return {"n": len(ordered), "p50_ms": round(pick(0.50) * 1000, 1),
            "p95_ms": round(pick(0.95) * 1000, 1), "p99_ms": round(pick(0.99) * 1000, 1),
            "max_ms": round(ordered[-1] * 1000, 1)}


class Drill:
    def __init__(self, replicas, payments):
        self.replicas, self.payments = replicas, payments
        self.orders, self.findings, self.phases = set(), [], {}
        self.samples = {}  # phase -> (outcome counts, outcome -> seconds)
        self.serial = 0  # run ids stay unique when a phase races several times
        self.outage = []  # results of the calls sent while the database restarts

    def base(self, i):
        return self.replicas[i % len(self.replicas)].base

    def check(self, condition, message):
        if not condition:
            self.findings.append(message)
            print(f"    VIOLATION: {message}")
        return condition

    def admit_all(self, name, jobs):
        """jobs: (order, amount). Each run is admitted on one replica and sends through the next."""
        runs = []
        for i, (order, amount) in enumerate(jobs):
            self.serial += 1
            run, agent = f"{name}_{PREFIX}_{self.serial}", f"agent_{i % AGENTS}"
            runs.append((run, agent, order, amount, admit(self.base(i), run, agent, amount), self.base(i + 1)))
            self.orders.add(order)
        return runs

    def race(self, name, jobs=None, runs=None):
        """Send every admitted run's refund at once. Results: (run, order, outcome, seconds, job)."""
        runs = runs or self.admit_all(name, jobs)
        start = threading.Barrier(len(runs))

        def send(job):
            run, agent, order, amount, generation, base = job
            start.wait()
            status, payload, seconds = refund(base, run, agent, order, amount, generation)
            return run, order, outcome(status, payload), seconds, job

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(runs)) as pool:
            results = list(pool.map(send, runs))
        counts, latency = self.samples.setdefault(name, ({}, {}))
        for _, _, label, seconds, _ in results:
            counts[label] = counts.get(label, 0) + 1
            latency.setdefault(label.split(":")[0], []).append(seconds)
        self.phases[name] = {"calls": sum(counts.values()), "outcomes": counts,
                             "latency": {k: percentiles(v) for k, v in latency.items()},
                             "all_latency": percentiles([t for v in latency.values() for t in v])}
        return results

    def contention(self):
        print(f"1. Contention: {ROUNDS} orders, {AGENTS} agents each racing INR 300 refunds across "
              f"{len(self.replicas)} processes; three fit under INR 1,000.")
        filled = 0
        for r in range(ROUNDS):
            order = f"ord_hot_{PREFIX}_{r}"
            results = self.race("contention", [(order, SHARE)] * AGENTS)
            done = sum(x[2] == "completed" for x in results)
            paid, view = self.payments.total(order), balance(self.base(r), GUARANTEE, order)
            self.check(paid <= LIMIT, f"{order}: provider paid {paid} over the limit")
            self.check(view["committed"] == paid and view["held"] == 0,
                       f"{order}: ledger {view['committed']}/{view['held']} vs provider {paid}")
            filled += done == 3
        merged = self.phases["contention"]
        merged["orders_filled_to_three"] = f"{filled}/{ROUNDS}"
        print(f"    outcomes {merged['outcomes']}; {filled}/{ROUNDS} orders reached exactly INR 900")

    def spread(self):
        n = AGENTS * ROUNDS // 2
        print(f"2. Spread: {n} refunds on {n} different orders at once (no shared resource).")
        results = self.race("spread", [(f"ord_spread_{PREFIX}_{i}", SHARE) for i in range(n)])
        done = sum(x[2] == "completed" for x in results)
        self.check(done == n, f"spread: {done}/{n} completed: {self.phases['spread']['outcomes']}")
        print(f"    outcomes {self.phases['spread']['outcomes']}")

    def kill_after_send(self):
        order, run = f"ord_kill_{PREFIX}", f"kill_{PREFIX}"
        victim, peer = self.replicas[0], self.replicas[1 % len(self.replicas)]
        print("3. SIGKILL after send: replica 0 sends INR 400; the provider applies it and the")
        print("   process is killed before any answer is recorded. It restarts on the same store.")
        self.orders.add(order)
        self.payments.faults[order] = "hang"
        generation = admit(victim.base, run, "agent_kill", 40_000)
        sender = threading.Thread(target=refund, args=(victim.base, run, "agent_kill", order, 40_000, generation))
        sender.start()
        self.check(self.payments.arrived.wait(20), "the refund never reached the provider")
        victim.kill()
        self.payments.faults.pop(order)
        self.payments.release.set()
        sender.join()
        victim.start()
        held = [h for h in cluster.holds(peer.base, GUARANTEE) if h["run_id"] == run]
        self.check(len(held) == 1, f"kill: expected one hold for {run}, saw {held}")
        hold = held[0] if held else {}
        step = hold.get("next_safe_step", {}).get("action")
        print(f"    after restart: held INR {hold.get('amount', 0) // 100}, state {hold.get('state')}, "
              f"next safe step {step}")
        self.check(hold.get("state") == "dispatch_active" and step == "confirm_or_attest_absence",
                   f"kill: unexpected diagnosis {hold}")
        # A different agent, a fresh run and key: the held INR 400 still counts.
        over = self.single(peer.base, f"kill_over_{PREFIX}", order, 70_000)
        fits = self.single(peer.base, f"kill_fits_{PREFIX}", order, 60_000)
        print(f"    fresh run, INR 700: {over}; fresh run, INR 600: {fits}")
        self.check(over.startswith("blocked:shared_guarantee_exceeded"), f"kill: INR 700 was {over}")
        self.check(fits == "completed", f"kill: INR 600 was {fits}")
        # A new executor takes the run over on the restarted process and resolves it.
        taken = cluster.ok(victim.base, f"/v1/runs/{run}/takeover",
                           {"expected_generation": current_generation(victim.base, run)})
        generation = taken["executor_generation"]
        status, refused = reconcile(victim.base, run, hold.get("operation_id"), "not_applied", [], generation)
        print(f"    asserting not_applied: {status} {self.code(refused)}")
        self.check(status != 200 or refused.get("status") != "resolved",
                   "kill: absence was accepted for a started dispatch")
        status, done = reconcile(victim.base, run, hold.get("operation_id"), "confirmed",
                                 self.payments.entries(order), generation)
        self.check(status == 200 and done.get("status") == "resolved", f"kill: confirm failed {status} {done}")
        view = balance(peer.base, GUARANTEE, order)
        print(f"    confirmed from the provider ledger: committed INR {view['committed'] // 100}, "
              f"held INR {view['held'] // 100}, provider paid INR {self.payments.total(order) // 100}")

    def lost_reply(self):
        order = f"ord_lost_{PREFIX}"
        print("4. Lost reply, process alive: INR 600 applied, answer lost; the same refund is")
        print("   requested again under a fresh run and key.")
        self.orders.add(order)
        self.payments.faults[order] = "lose"
        run = f"lost_{PREFIX}"
        generation = admit(self.base(0), run, "agent_lost", 60_000)
        first = outcome(*refund(self.base(0), run, "agent_lost", order, 60_000, generation)[:2])
        self.payments.faults.pop(order)
        again = self.single(self.base(1), f"lost_again_{PREFIX}", order, 60_000)
        rest = self.single(self.base(2), f"lost_rest_{PREFIX}", order, 40_000)
        print(f"    first: {first}; same refund again: {again}; INR 400: {rest}")
        self.check(again.startswith("blocked:shared_guarantee_exceeded"), f"lost: retry was {again}")
        self.check(rest == "completed", f"lost: INR 400 was {rest}")
        status, done = reconcile(self.base(1), run, f"refund_{run}", "confirmed",
                                 self.payments.entries(order), current_generation(self.base(1), run))
        self.check(status == 200 and done.get("status") == "resolved", f"lost: confirm failed {status} {done}")

    def database_restart(self):
        if not PG_RESTART:
            print("5. Database restart: skipped (set CONTEXTOS_DRILL_PG_RESTART).")
            self.phases["database_restart"] = "skipped"
            return
        n = AGENTS * 2
        print(f"5. Database restart: {n} slow refunds in flight, and {n // 2} more sent while PostgreSQL")
        print(f"   restarts (`{PG_RESTART}`). Then every failed call is retried unchanged.")
        jobs = [(f"ord_db_{PREFIX}_{i}", SHARE) for i in range(n)]
        for order, _ in jobs:
            self.payments.faults[order] = "slow"
        late = self.admit_all("outage", [(f"ord_outage_{PREFIX}_{i}", SHARE) for i in range(n // 2)])

        def restart():
            deadline = time.monotonic() + 30
            while self.payments.slow_seen < n // 3 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.check(self.payments.slow_seen >= n // 3, "refunds never reached the provider before the restart")
            started = time.monotonic()
            command = subprocess.Popen(PG_RESTART, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.2)
            self.outage = self.race("during_outage", runs=late)
            self.check(command.wait() == 0, "the database restart command failed")
            self.phases["database_restart_seconds"] = round(time.monotonic() - started, 2)

        restarter = threading.Thread(target=restart)
        restarter.start()
        in_flight = self.race("database_restart", runs=self.admit_all("database_restart", jobs))
        restarter.join()
        for replica in self.replicas:
            self.check(replica.alive(), f"replica {replica.index} exited during the database restart")
            replica.wait_ready(60)
        print(f"    in flight: {self.phases['database_restart']['outcomes']}")
        print(f"    sent during the outage: {self.phases['during_outage']['outcomes']}")
        # An agent that treats a 503 as retryable resends the identical call: same run,
        # same key. A call the provider already applied must never reach it again; one the
        # outage stopped before it was sent may be sent now, once.
        before = {e["operation_id"] for e in self.payments.entries()}
        failed = [r[4] for r in in_flight if r[2] != "completed"]
        retried = {}
        for run, agent, order, amount, generation, base in failed:
            label = outcome(*refund(base, run, agent, order, amount, generation)[:2])
            retried[label] = retried.get(label, 0) + 1
        self.phases["identical_retry"] = retried
        print(f"    identical retries of the {len(failed)} failed calls: {retried}")
        again = [e["operation_id"] for e in self.payments.entries() if e["operation_id"] in before]
        self.check(len(again) == len(before), f"identical retries re-sent {len(again) - len(before)} applied refunds")
        first = len(self.payments.entries()) - len(again)
        self.phases["identical_retry_first_sends"] = first
        print(f"    of those, sent for the first time (the outage stopped them before dispatch): {first}")
        # Where the outage met each call decides what a resend does: refused before its
        # claim (store_unavailable), it is an ordinary first attempt; claimed first, it
        # stays fenced (operation_in_flight, retry_unsafe) until reconciled.
        resent = {}
        for run, _, label, _, (_, agent, order, amount, generation, base) in self.outage:
            if label == "completed":
                continue
            again = outcome(*refund(base, run, agent, order, amount, generation)[:2])
            key = f"{label} -> {again}"
            resent[key] = resent.get(key, 0) + 1
        self.phases["outage_retry"] = resent
        print(f"    calls that failed during the outage, resent unchanged: {resent or 'none failed'}")

    def resolve_holds(self):
        """Every hold left anywhere under the guarantee, resolved from the provider ledger
        alone: confirmed when the provider has the refund, not applied only when the
        attempt never started. A started attempt the provider has no record of stays held."""
        left = cluster.holds(self.base(0), GUARANTEE)
        print(f"6. Holds left under the guarantee: {len(left)}. Resolving each from the provider ledger.")
        resolved, kept = {}, []
        for hold in left:
            run, op = hold["run_id"], hold["operation_id"]
            if self.payments.has(op):
                result, cited = "confirmed", [e for e in self.payments.entries() if e["operation_id"] == op]
            elif not hold["dispatch_started"]:
                result, cited = "not_applied", []
            else:
                kept.append(hold)
                continue
            status, done = reconcile(self.base(1), run, op, result, cited, current_generation(self.base(1), run))
            ok = status == 200 and done.get("status") == "resolved"
            self.check(ok, f"resolve {op}: {status} {done}")
            key = f"{hold['state']} -> {result}"
            resolved[key] = resolved.get(key, 0) + ok
        self.phases["holds_resolved"] = resolved
        self.phases["holds_kept"] = [{k: h[k] for k in ("run_id", "operation_id", "state")} for h in kept]
        print(f"    resolved {resolved or 'none'}; kept held (no provider record, dispatch started): {len(kept)}")

    def invariants(self):
        print(f"7. Invariants over {len(self.orders)} orders, against the provider's own ledger.")
        kept = {h["operation_id"] for h in self.phases.get("holds_kept", [])}
        for order in sorted(self.orders):
            paid, view = self.payments.total(order), balance(self.base(0), GUARANTEE, order)
            self.check(paid <= LIMIT, f"{order}: provider paid {paid} over the limit")
            self.check(view["committed"] + view["held"] <= LIMIT, f"{order}: ledger over the limit {view}")
            if not kept:
                self.check(view["committed"] == paid and view["held"] == 0,
                           f"{order}: committed {view['committed']} held {view['held']}, provider {paid}")
            else:
                self.check(view["committed"] <= paid <= view["committed"] + view["held"],
                           f"{order}: provider {paid} outside committed..committed+held {view}")
        duplicates = self.payments.duplicates()
        self.check(not duplicates, f"operations applied more than once: {duplicates}")
        total = sum(self.payments.total(o) for o in self.orders)
        print(f"    provider effects {len(self.payments.entries())}, INR {total // 100:,} paid; "
              f"duplicates {len(duplicates)}; violations {len(self.findings)}")

    def audit(self):
        entries, keys = cluster.export_audit(self.base(2))
        RECEIPT.mkdir(parents=True, exist_ok=True)
        (RECEIPT / "entries.json").write_text(json.dumps({"entries": entries}))
        (RECEIPT / "keys.json").write_text(json.dumps(keys))
        verify = subprocess.run([str(cluster.BIN / "ctx"), "audit-verify", "--entries", str(RECEIPT / "entries.json"),
                                 "--keys", str(RECEIPT / "keys.json")], capture_output=True, text=True)
        proof = json.loads(verify.stdout or "{}")
        self.check(proof.get("verified") is True, f"audit did not verify: {verify.stdout}{verify.stderr}")
        print(f"8. Audit chain written by {len(self.replicas)} processes: {proof.get('entries')} entries, "
              f"verified {proof.get('verified')}")
        return proof

    def single(self, base, run, order, amount):
        self.orders.add(order)
        generation = admit(base, run, run, amount)
        return outcome(*refund(base, run, run, order, amount, generation)[:2])

    @staticmethod
    def code(payload):
        if isinstance(payload, dict):
            codes = ",".join(payload.get("reason_codes", []))
            return payload.get("error", {}).get("code") or f"{payload.get('status')} ({codes})"
        return payload


def version():
    run = subprocess.run([str(cluster.BIN / "contextosd"), "--version"], capture_output=True, text=True)
    return run.stdout.strip()


def main():
    if not os.environ.get(URL_ENV):
        sys.exit(f"{URL_ENV} must name a PostgreSQL database the drill may write to.")
    services, payments = provider.start()
    replicas = []
    try:
        with tempfile.TemporaryDirectory(prefix="contextos-drill-") as tmp:
            replicas = [cluster.Replica(i, Path(tmp), services, GUARANTEE, URL_ENV) for i in range(REPLICAS)]
            for replica in replicas:
                replica.start()
            print(f"{REPLICAS} contextosd processes on one PostgreSQL store; guarantee {GUARANTEE}, "
                  f"INR 1,000 per order.")
            drill = Drill(replicas, payments)
            drill.contention()
            drill.spread()
            drill.kill_after_send()
            drill.lost_reply()
            drill.database_restart()
            drill.resolve_holds()
            drill.invariants()
            proof = drill.audit()
            report = {
                "guarantee_id": GUARANTEE, "limit_minor": LIMIT, "replicas": REPLICAS, "agents": AGENTS,
                "rounds": ROUNDS, "contextosd": version(), "platform": platform.platform(),
                "cpus": os.cpu_count(), "python": platform.python_version(),
                "restarts": {r.index: r.restarts for r in replicas},
                "phases": drill.phases, "provider_effects": len(payments.entries()),
                "audit": proof, "violations": drill.findings}
            (RECEIPT / "report.json").write_text(json.dumps(report, indent=2))
            print(f"Report: {RECEIPT / 'report.json'}")
            if drill.findings:
                sys.exit(f"{len(drill.findings)} violation(s)")
            print("No violations: the limit held on every order, every applied refund is accounted, "
                  "no effect was sent twice.")
    finally:
        for replica in replicas:
            replica.stop()
        for service in services:
            service.shutdown()
            service.server_close()


if __name__ == "__main__":
    main()
