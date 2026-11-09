#!/usr/bin/env python3
"""Replays a morning of recorded support-agent tool calls through a local gateway.

The recording (traffic.jsonl) is what the agents really did without ContextOS: one
refund sent twice after a client timeout, a second channel refunding the same order,
a refund whose response was lost, and a refund above the approval threshold. Every
call goes to the replay's own tool server, which answers with the recorded outcome."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings/python"))
from contextos.client import Client  # noqa: E402
from contextos.replay import ToolServer, load_traffic, markdown, replay  # noqa: E402

HERE = Path(__file__).resolve().parent
EXAMPLE = ROOT / "examples/support-refund"
BIN = Path(os.environ.get("CONTEXTOS_BIN", ROOT / "target/debug"))
KEY = "dev-key-0123456789abcdef0123456789abcdef"
OUT = Path(os.environ.get("CONTEXTOS_RECEIPT_DIR", ROOT / "receipts/replay"))
GUARANTEE = '''
[[guarantees]]
id = "refunds-per-order"
capability_ids = ["adp_payments.issue_refund"]
resource_pointer = "/order_id"
amount_pointer = "/amount_minor"
limit = 100000
unit = "INR_minor"
'''


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> None:
    spec = importlib.util.spec_from_file_location("dev_services", EXAMPLE / "dev_services.py")
    dev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dev)
    ports = {name: free_port() for name in ("authority", "constraints", "approvals", "server")}
    for name, handler in (("authority", dev.authority), ("constraints", dev.constraints),
                          ("approvals", dev.approvals)):
        dev.serve(ports[name], handler)
    tools = ToolServer()
    config = (EXAMPLE / "contextosd.toml").read_text()
    config = config.replace("127.0.0.1:8080", f"127.0.0.1:{ports['server']}")
    for name, default in (("authority", 7701), ("constraints", 7702), ("approvals", 7703)):
        config = config.replace(f"127.0.0.1:{default}", f"127.0.0.1:{ports[name]}")
    # Every adapter answers from the recording.
    config = config.replace("http://127.0.0.1:7704/mcp", tools.url)
    config = config.replace('"examples/', f'"{ROOT}/examples/')
    config = config.replace("sha256:REPLACED_BY_RUN_SH", "sha256:" + hashlib.sha256(KEY.encode()).hexdigest())
    config += GUARANTEE
    server = None
    with tempfile.TemporaryDirectory(prefix="contextos-replay-") as tmp:
        path = Path(tmp) / "contextosd.toml"
        path.write_text(config)
        with (Path(tmp) / "server.log").open("w") as log:
            server = subprocess.Popen([str(BIN / "contextosd"), "--config", str(path)], cwd=ROOT,
                                      env={**os.environ, "CONTEXTOS_AUDIT_SEED": "11" * 32, "RUST_LOG": "warn"},
                                      stdout=log, stderr=log)
        try:
            base = f"http://127.0.0.1:{ports['server']}"
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError((Path(tmp) / "server.log").read_text())
                try:
                    urllib.request.urlopen(base + "/readyz", timeout=1)
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("the local gateway did not become ready")
            with (HERE / "traffic.jsonl").open() as f:
                records = load_traffic(f)
            template = json.loads((HERE / "admission.json").read_text())
            report = replay(Client(base, KEY), records, template, tools)
        finally:
            server.terminate()
            server.wait()
            tools.close()
    print(markdown(report))
    expected = {"duplicates_refused": 1, "limits_held": 1, "held_unknown": 1, "approvals_required": 1,
                "effects_sent": 2, "recorded_effects": 5, "effects_prevented": 2}
    actual = {k: report[k] for k in expected}
    assert actual == expected, (actual, report["entries"])
    assert not report["false_block_candidates"], report["false_block_candidates"]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "replay-report.json").write_text(json.dumps(report, indent=2))
    (OUT / "replay-report.md").write_text(markdown(report))
    print(f"replay report written: {OUT / 'replay-report.md'}")


if __name__ == "__main__":
    main()
