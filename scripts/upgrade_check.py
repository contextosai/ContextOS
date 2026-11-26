"""Upgrade check: a store and packs written by the previous release keep working and
keep verifying under this one.

1. The previous release's contextosd migrates an empty PostgreSQL database, starts with
   that release's example configuration and packs, admits a run and dispatches a refund.
   Its audit export is kept.
2. This build checks the same configuration strictly (`--check-config`), migrates the
   same database and starts on it: the chain verifies (`GET /v1/audit/verify`), the old
   run is still there, a new run works, and the full export verifies offline with this
   build's `ctx audit-verify`, as does the old export on its own.

Usage: python3 scripts/upgrade_check.py --previous DIR --current BIN_DIR
       (CONTEXTOS_UPGRADE_DATABASE_URL names an empty database the check may write to)
"""

import argparse
import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEY = "upgrade-check-key-0123456789abcdef0123456789"
SEED = "22" * 32


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def call(base, method, path, body=None, headers=None):
    request = urllib.request.Request(base + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                     headers={"authorization": f"Bearer {KEY}", "content-type": "application/json",
                                              **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def config(previous: Path, port: int, dev_ports: dict) -> str:
    """The previous release's example configuration, on PostgreSQL, with its own packs."""
    text = (previous / "examples/support-refund/contextosd.toml").read_text()
    text = text.replace("127.0.0.1:8080", f"127.0.0.1:{port}")
    for name, default in (("authority", 7701), ("constraints", 7702), ("approvals", 7703), ("payments", 7704)):
        text = text.replace(f"127.0.0.1:{default}", f"127.0.0.1:{dev_ports[name]}")
    text = text.replace('"examples/', f'"{previous}/examples/')
    text = text.replace("sha256:REPLACED_BY_RUN_SH", "sha256:" + hashlib.sha256(KEY.encode()).hexdigest())
    lines, out, in_store = text.splitlines(), [], False
    for line in lines:
        if line.strip().startswith("[") and in_store:
            in_store = False
        if line.strip() == "[store]":
            in_store = True
            out += ["[store]", 'kind = "postgres"', 'url_env = "CONTEXTOS_UPGRADE_DATABASE_URL"']
            continue
        if not in_store:
            out.append(line)
    return "\n".join(out) + "\n"


class Server:
    def __init__(self, binary: Path, cfg: Path, log: Path):
        env = {**os.environ, "CONTEXTOS_AUDIT_SEED": SEED, "RUST_LOG": "warn"}
        migrated = subprocess.run([str(binary), "--migrate", str(cfg)], env=env, capture_output=True, text=True)
        if migrated.returncode != 0:
            raise SystemExit(f"{binary} --migrate failed:\n{migrated.stdout}{migrated.stderr}")
        self.process = subprocess.Popen([str(binary), "--config", str(cfg)], env=env, stdout=log.open("w"),
                                        stderr=subprocess.STDOUT)
        self.log = log

    def wait(self, base):
        for _ in range(150):
            if self.process.poll() is not None:
                raise SystemExit(f"server exited:\n{self.log.read_text()}")
            try:
                urllib.request.urlopen(base + "/readyz", timeout=1)
                return
            except OSError:
                time.sleep(0.2)
        raise SystemExit(f"server not ready:\n{self.log.read_text()}")

    def stop(self):
        self.process.terminate()
        self.process.wait(timeout=30)


def refund(base, previous: Path, run_id: str):
    run = json.loads((previous / "examples/support-refund/requests/run.json").read_text())
    run["run_context"]["run_id"] = run_id
    if "contract" in run:
        run["contract"]["run_id"] = run_id
    status, admitted = call(base, "POST", "/v1/runs", run)
    assert status == 201, (status, admitted)
    tool_call = json.loads((previous / "examples/support-refund/requests/tool_call.json").read_text())
    tool_call.update(run_id=run_id, tool_call_id=f"tc_{run_id}", idempotency_key=f"refund:{run_id}")
    status, out = call(base, "POST", f"/v1/runs/{run_id}/tool-calls", tool_call,
                       {"contextos-executor-generation": str(admitted["executor_generation"])})
    assert status == 200 and out["result"]["status"] == "completed", (status, out)


def export(base, tmp: Path, name: str):
    status, entries = call(base, "GET", "/v1/audit/entries?from=1&limit=10000")
    assert status == 200, entries
    _, keys = call(base, "GET", "/v1/audit/keys")
    (tmp / f"{name}-entries.json").write_text(json.dumps(entries))
    (tmp / f"{name}-keys.json").write_text(json.dumps(keys))
    return len(entries["entries"])


def ctx_verify(ctx: Path, tmp: Path, name: str):
    out = subprocess.run([str(ctx), "audit-verify", "--entries", str(tmp / f"{name}-entries.json"),
                          "--keys", str(tmp / f"{name}-keys.json")], capture_output=True, text=True)
    report = json.loads(out.stdout or "null")
    assert out.returncode == 0 and report["verified"] is True, (out.returncode, out.stdout, out.stderr)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--previous", required=True, type=Path, help="the unpacked previous release archive")
    parser.add_argument("--current", required=True, type=Path, help="directory holding this build's contextosd and ctx")
    args = parser.parse_args()
    if not os.environ.get("CONTEXTOS_UPGRADE_DATABASE_URL"):
        raise SystemExit("set CONTEXTOS_UPGRADE_DATABASE_URL to an empty PostgreSQL database")
    previous = args.previous.resolve()
    spec = importlib.util.spec_from_file_location("dev_services", ROOT / "examples/support-refund/dev_services.py")
    dev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dev)
    dev_ports = {name: free_port() for name in ("authority", "constraints", "approvals", "payments")}
    for name, handler in (("authority", dev.authority), ("constraints", dev.constraints),
                          ("approvals", dev.approvals), ("payments", dev.payments)):
        dev.serve(dev_ports[name], handler)
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="contextos-upgrade-") as tmp:
        tmp = Path(tmp)
        cfg = tmp / "contextosd.toml"
        cfg.write_text(config(previous, port, dev_ports))

        old = Server(previous / "bin/contextosd", cfg, tmp / "previous.log")
        old.wait(base)
        refund(base, previous, "run_upgrade_before")
        before = export(base, tmp, "before")
        old.stop()
        print(f"previous release: {before} audit entries written")

        check = subprocess.run([str(args.current / "contextosd"), "--check-config", str(cfg)],
                               env={**os.environ, "CONTEXTOS_AUDIT_SEED": SEED}, capture_output=True, text=True)
        assert check.returncode == 0, check.stdout + check.stderr
        new = Server(args.current / "contextosd", cfg, tmp / "current.log")
        new.wait(base)
        try:
            status, verified = call(base, "GET", "/v1/audit/verify")
            assert status == 200 and verified["verified"] is True, verified
            status, run = call(base, "GET", "/v1/runs/run_upgrade_before")
            assert status == 200, (status, run)
            refund(base, previous, "run_upgrade_after")
            after = export(base, tmp, "after")
        finally:
            new.stop()
        assert after > before, (before, after)
        ctx = args.current / "ctx"
        ctx_verify(ctx, tmp, "before")
        report = ctx_verify(ctx, tmp, "after")
        print(f"this build: migrated, {after} audit entries, chain verified offline to {report['last_sequence']}")
        print("UPGRADE CHECK PASSED")


if __name__ == "__main__":
    sys.exit(main())
