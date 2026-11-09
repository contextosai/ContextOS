"""A local gateway for replaying recorded traffic: the support-refund example's packs,
manifests and development fact services, with every adapter answered by the replay's
tool server. Shared by the replay examples."""
import contextlib
import hashlib
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request
from typing import Dict, Iterator, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples/support-refund"
BIN = Path(os.environ.get("CONTEXTOS_BIN", ROOT / "target/debug"))
KEY = "dev-key-0123456789abcdef0123456789abcdef"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def local_gateway(tools, extra: str = "", capabilities: Optional[Dict[str, Path]] = None) -> Iterator[Tuple[str, str]]:
    """Runs contextosd with `extra` appended to the configuration and the manifests in
    `capabilities` (support-refund file name to replacement) swapped in; yields its base
    URL and API key."""
    spec = importlib.util.spec_from_file_location("dev_services", EXAMPLE / "dev_services.py")
    dev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dev)
    ports = {name: free_port() for name in ("authority", "constraints", "approvals", "server")}
    for name, handler in (("authority", dev.authority), ("constraints", dev.constraints),
                          ("approvals", dev.approvals)):
        dev.serve(ports[name], handler)
    config = (EXAMPLE / "contextosd.toml").read_text()
    config = config.replace("127.0.0.1:8080", f"127.0.0.1:{ports['server']}")
    for name, default in (("authority", 7701), ("constraints", 7702), ("approvals", 7703)):
        config = config.replace(f"127.0.0.1:{default}", f"127.0.0.1:{ports[name]}")
    # Every adapter answers from the recording.
    config = config.replace("http://127.0.0.1:7704/mcp", tools.url)
    for name, path in (capabilities or {}).items():
        config = config.replace(f'"examples/support-refund/capabilities/{name}"', f'"{path}"')
    config = config.replace('"examples/', f'"{ROOT}/examples/')
    config = config.replace("sha256:REPLACED_BY_RUN_SH", "sha256:" + hashlib.sha256(KEY.encode()).hexdigest())
    config += extra
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
            yield base, KEY
        finally:
            server.terminate()
            server.wait()
