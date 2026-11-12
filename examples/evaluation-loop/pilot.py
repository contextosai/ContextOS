#!/usr/bin/env python3
"""An evaluation platform judges a candidate agent, and its verdicts gate the release.

Synthetic and local: no model key, cloud account or evaluation service. Two versions
of a refund agent each run three cases three times (trials). The evaluation platform,
here a stand-in holding only the `evaluate` scope, does what a real one does with the
traces it reads: it judges each refund call's arguments and each decision, and posts
its verdicts to ContextOS. Its judge is calibrated against human labels first
(`ctx calibrate`); ContextOS accepts verdicts only from that calibrated release.

The candidate agent sometimes puts the customer id in the order id field. Policy
cannot see that (the call is well-formed and within limits), but the platform's
argument check can, and `ctx trials` turns each run's signed evidence into pass/fail
trials that `ctx reliability-gate` compares: pass^3 per case, a paired
non-inferiority interval, and the drop the suite could detect.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings/python"))
from contextos.client import Client, ContextOSHTTPError  # noqa: E402

BIN = Path(os.environ.get("CONTEXTOS_BIN", ROOT / "target/debug"))
EXAMPLE = ROOT / "examples/support-refund"
KEY = "dev-key-0123456789abcdef0123456789abcdef"
JUDGE_KEY = "dev-judge-0123456789abcdef0123456789abcd"
JUDGE = "evaluator.refund_arguments@1"
CASES = {"refund_ord_881": "ord_881", "refund_ord_882": "ord_882", "refund_ord_883": "ord_883"}
TRIALS = 3


def serve(handler):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                payload = json.dumps(handler(request)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def ctx(*args, ok_codes=(0,)):
    out = subprocess.run([str(BIN / "ctx"), *map(str, args)], capture_output=True, text=True)
    if out.returncode not in ok_codes:
        raise RuntimeError(out.stdout + out.stderr)
    return out.returncode, json.loads(out.stdout)


def human_labels():
    """What reviewers decided on 120 past refund calls, and what the judge said."""
    labels = []
    for i in range(60):
        labels.append({"id": f"good_{i}", "human": "pass", "judge": "pass"})
        # The judge misses 2 of the 60 bad calls.
        labels.append({"id": f"bad_{i}", "human": "fail", "judge": "pass" if i < 2 else "fail"})
    return labels


def run_body(run_id, order):
    body = json.loads((EXAMPLE / "requests/run.json").read_text())
    body["run_context"]["run_id"] = body["contract"]["run_id"] = run_id
    body["contract"]["contract_id"] = "contract_" + run_id
    body["request"]["request_id"] = "req_" + run_id
    body["request"]["input"]["message"] = f"Refund order {order} for INR 1200."
    body["request"]["input"]["context"]["order_id"] = order
    body["deps"]["evidence"][0].update(evidence_ref=snapshot(order), content=f"order {order} exists in the snapshot")
    return body


def snapshot(order):
    return f"kg:order:{order}#snapshot_kg_2026_05_03_T0930"


def act(client, version, case, order, trial):
    """One trial: the agent refunds the order, records its decision and completes."""
    run = client.admit(run_body(f"{version}_{case}_{trial}", order))
    call = json.loads((EXAMPLE / "requests/tool_call.json").read_text())
    args = dict(call["args"], order_id=order)
    # The candidate sometimes fills the order id with the customer id.
    if version == "candidate" and case == "refund_ord_883" and trial < 2:
        args["order_id"] = args["customer_id"]
    operation = f"refund:{order}"
    run.call_tool(call["capability_id"], args, approval_mode="destructive", idempotency_key=operation,
                  evidence_refs=[snapshot(order)], tool_call_id="tc_refund")
    decision = run.record_decision("support.refund.execute", "DECIDED", outcome="refund_issued",
                                   tool_calls=[{"tool_call_id": "tc_refund", "operation_id": operation}])
    return run, operation, args, decision["record"]["record_id"]


def judge(platform, run, operation, args, record_id, order):
    """The platform's verdicts: the call's arguments, then the decision."""
    right = args["order_id"] == order
    platform.evaluate_operation(run.run_id, operation, JUDGE, "arguments", score=1.0 if right else 0.0,
                                label="pass" if right else "fail",
                                explanation_ref=f"https://evals.example.test/runs/{run.run_id}")
    platform.score(run.run_id, record_id, JUDGE, policy=1.0, utility=0.9 if right else 0.2, safety=1.0)


def main():
    spec = importlib.util.spec_from_file_location("development_facts", EXAMPLE / "dev_services.py")
    facts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facts)
    services = [serve(handler) for handler in [facts.authority, facts.constraints, facts.approvals, facts.payments]]
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="contextos-evaluation-") as tmp:
            tmp = Path(tmp)
            # 1. The judge is checked against human labels before its verdicts count.
            (tmp / "labels.json").write_text(json.dumps(human_labels()))
            (tmp / "floors.json").write_text(json.dumps({"min_tpr": 0.9, "min_tnr": 0.9, "min_per_class": 50}))
            _, record = ctx("calibrate", "--evaluator-ref", JUDGE, "--labels", tmp / "labels.json",
                            "--floors", tmp / "floors.json")
            (tmp / "calibration.json").write_text(json.dumps(record))
            rates = record["rates"]
            print(f"Judge {JUDGE} calibrated on 120 human labels: "
                  f"TPR {rates['tpr']:.2f}, TNR {rates['tnr']:.2f}, kappa {rates['kappa']:.2f} ({record['verdict']}).")

            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            config = (EXAMPLE / "contextosd.toml").read_text()
            config = config.replace("127.0.0.1:8080", f"127.0.0.1:{port}")
            config = config.replace("sha256:REPLACED_BY_RUN_SH", "sha256:" + hashlib.sha256(KEY.encode()).hexdigest())
            for old, service in zip(range(7701, 7705), services):
                config = config.replace(f"127.0.0.1:{old}", f"127.0.0.1:{service.server_port}")
            config += f"""
# Only evaluator releases calibrated against human labels may score or evaluate.
[guards.evaluator_calibration]
records = ["{tmp / 'calibration.json'}"]
min_tpr = 0.9
min_tnr = 0.9
min_per_class = 50
"""
            (tmp / "runtime.toml").write_text(config)
            base = f"http://127.0.0.1:{port}"
            with (tmp / "server.log").open("w") as log:
                process = subprocess.Popen(
                    [str(BIN / "contextosd"), "--config", str(tmp / "runtime.toml")],
                    cwd=ROOT, stdout=log, stderr=log,
                    env={**os.environ, "CONTEXTOS_AUDIT_SEED": "11" * 32, "RUST_LOG": "warn"})
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError((tmp / "server.log").read_text())
                    try:
                        urlopen(base + "/readyz", timeout=1)
                        break
                    except (URLError, OSError):
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Local runtime did not become ready")

                client = Client(base, token=KEY)
                platform = Client(base, token=JUDGE_KEY)
                runs = {"baseline": {}, "candidate": {}}
                refused_once = False
                for version in runs:
                    for case, order in CASES.items():
                        for trial in range(TRIALS):
                            run, operation, args, record_id = act(client, version, case, order, trial)
                            if not refused_once:
                                # A judge release nobody calibrated cannot give verdicts.
                                try:
                                    platform.evaluate_operation(run.run_id, operation, "evaluator.refund_arguments@2",
                                                                "arguments", label="pass")
                                    raise AssertionError("an uncalibrated judge was accepted")
                                except ContextOSHTTPError as refused:
                                    assert refused.code == "evaluator_uncalibrated", refused
                                print("Verdict from uncalibrated evaluator.refund_arguments@2 refused: "
                                      "evaluator_uncalibrated.")
                                refused_once = True
                            judge(platform, run, operation, args, record_id, order)
                            assert run.complete()["status"] == "completed"
                            path = tmp / f"{run.run_id}.json"
                            path.write_text(json.dumps(run.evidence()))
                            runs[version][run.run_id] = (case, path)
                    print(f"{version}: {len(CASES)} cases x {TRIALS} trials run and judged.")

                # 2. Trials from the signed evidence; the gate compares the versions.
                criteria = tmp / "criteria.json"
                criteria.write_text(json.dumps({"failing_labels": ["fail"], "policy_floor": 1.0, "safety_floor": 1.0}))
                trials = {}
                for version, version_runs in runs.items():
                    case_map = tmp / f"{version}-cases.json"
                    case_map.write_text(json.dumps({run_id: case for run_id, (case, _) in version_runs.items()}))
                    _, out = ctx("trials", "--case-map", case_map, "--criteria", criteria,
                                 *[path for _, path in version_runs.values()])
                    (tmp / f"{version}-trials.json").write_text(json.dumps(out))
                    trials[version] = out
                failed = [t for c in trials["candidate"] for t in c["trials"] if not t["passed"]]
                print(f"Candidate trials failed: {len(failed)}, e.g. {failed[0]['reasons'][0]}")

                limits = tmp / "limits.json"
                limits.write_text(json.dumps({"k": 3, "max_pass_k_drop": 0.05, "min_cases": 3,
                                              "must_pass": ["refund_ord_883"]}))
                code, report = ctx("reliability-gate", "--baseline", tmp / "baseline-trials.json",
                                   "--candidate", tmp / "candidate-trials.json", "--thresholds", limits,
                                   ok_codes=(1,))
                assert report["verdict"] == "fail", report
                print(f"pass^3: baseline {report['baseline']['pass_k']:.2f}, "
                      f"candidate {report['candidate']['pass_k']:.2f} "
                      f"(pass@3 {report['candidate']['pass_at_k']:.2f} would have hidden it).")
                for failure in report["failures"]:
                    print(f"Gate failure {failure['kind']}: {failure['detail']}")
                print("evaluation loop complete")
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for service in services:
            service.shutdown()
            service.server_close()


if __name__ == "__main__":
    main()
