#!/usr/bin/env python3
"""Builds the two installable HTTP clients from the source tree, standard library only.

    python3 scripts/package_clients.py python <out-dir>   # contextos-<v>-py3-none-any.whl
    python3 scripts/package_clients.py node <out-dir>     # a directory for `npm pack`
    python3 scripts/package_clients.py version            # the workspace version

The Python wheel holds only the HTTP client (`contextos.client`, `contextos.aio`) and
the kernel facade, which raises `native_unavailable` without the compiled extension.
It is the fallback beside the platform wheels maturin builds with the extension:
pip prefers a platform wheel and installs this one everywhere else.

The Node directory holds `client.mjs` and its types as the `contextos-client` package.
The in-process Node kernel needs a native addon and is not published.
"""
import base64
import hashlib
import json
import pathlib
import re
import shutil
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PY_SOURCES = ["__init__.py", "client.py", "errors.py", "aio.py"]
NODE_SOURCES = ["client.mjs", "client.d.ts"]
LEGAL = ["LICENSE", "NOTICE"]
REPOSITORY = "https://github.com/contextosai/ContextOS"
# Wheel members get a fixed time so the same source gives the same bytes.
EPOCH = (1980, 1, 1, 0, 0, 0)


def workspace_version(root=ROOT):
    text = (root / "Cargo.toml").read_text()
    section = text.split("[workspace.package]", 1)[1].split("\n[", 1)[0]
    match = re.search(r'^version\s*=\s*"([^"]+)"', section, re.M)
    if not match:
        raise SystemExit("no version in [workspace.package] of Cargo.toml")
    return match.group(1)


def pep440(version):
    """`0.1.0-alpha.11` -> `0.1.0a11`, as maturin names the platform wheels."""
    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-(alpha|beta|rc)\.(\d+))?", version)
    if not match:
        raise SystemExit(f"unsupported version {version!r}")
    core, kind, number = match.groups()
    if kind is None:
        return core
    return core + {"alpha": "a", "beta": "b", "rc": "rc"}[kind] + number


def check_facade_version(version, root=ROOT):
    """The facade's fallback `__version__` is what a client-only install reports, and
    `CLIENT_VERSION` is what the client compares with the server's release."""
    init = (root / "bindings/python/contextos/__init__.py").read_text()
    if f'"__version__", "{version}")' not in init:
        raise SystemExit(f"bindings/python/contextos/__init__.py does not report {version}")
    client = (root / "bindings/python/contextos/client.py").read_text()
    if f'CLIENT_VERSION = "{version}"' not in client:
        raise SystemExit(f"bindings/python/contextos/client.py CLIENT_VERSION is not {version}")


def check_node_client_version(version, root=ROOT):
    """`CLIENT_VERSION` is what the Node client compares with the server's release."""
    client = (root / "bindings/node/client.mjs").read_text()
    if f'export const CLIENT_VERSION = "{version}";' not in client:
        raise SystemExit(f"bindings/node/client.mjs CLIENT_VERSION is not {version}")


def _record_hash(data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + digest.decode()


def _metadata(version, root):
    readme = (root / "bindings/python/README.md").read_text()
    return "\n".join([
        "Metadata-Version: 2.1",
        "Name: contextos",
        f"Version: {version}",
        "Summary: ContextOS kernel: governed context, authorization and durable effects for AI agents",
        "License: Apache-2.0",
        "Requires-Python: >=3.9",
        f"Project-URL: Source, {REPOSITORY}",
        "Classifier: License :: OSI Approved :: Apache Software License",
        "Classifier: Programming Language :: Python :: 3",
        "Description-Content-Type: text/markdown",
        "",
        readme,
    ])


def build_python(out_dir, root=ROOT):
    version = workspace_version(root)
    check_facade_version(version, root)
    py_version = pep440(version)
    dist_info = f"contextos-{py_version}.dist-info"
    members = []
    for name in PY_SOURCES:
        members.append((f"contextos/{name}", (root / "bindings/python/contextos" / name).read_bytes()))
    for name in LEGAL:
        members.append((f"{dist_info}/licenses/{name}", (root / name).read_bytes()))
    members.append((f"{dist_info}/METADATA", _metadata(py_version, root).encode()))
    members.append((f"{dist_info}/WHEEL", (
        "Wheel-Version: 1.0\nGenerator: contextos package_clients.py\n"
        "Root-Is-Purelib: true\nTag: py3-none-any\n").encode()))
    record = "".join(f"{path},{_record_hash(data)},{len(data)}\n" for path, data in members)
    record += f"{dist_info}/RECORD,,\n"
    members.append((f"{dist_info}/RECORD", record.encode()))

    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    wheel = out_dir / f"contextos-{py_version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, data in members:
            info = zipfile.ZipInfo(path, EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    return wheel


def node_manifest(version):
    return {
        "name": "contextos-client",
        "version": version,
        "description": "HTTP client for contextosd: govern an AI agent's tool calls. No dependencies.",
        "license": "Apache-2.0",
        "repository": {"type": "git", "url": f"git+{REPOSITORY}.git", "directory": "bindings/node"},
        "homepage": f"{REPOSITORY}/blob/main/bindings/node/README.md",
        "type": "module",
        "main": "client.mjs",
        "types": "client.d.ts",
        "exports": {".": {"types": "./client.d.ts", "default": "./client.mjs"}},
        "files": NODE_SOURCES + ["README.md"] + LEGAL,
        "engines": {"node": ">=18"},
        "sideEffects": False,
    }


def build_node(out_dir, root=ROOT):
    version = workspace_version(root)
    check_node_client_version(version, root)
    out_dir = pathlib.Path(out_dir) / "contextos-client"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    for name in NODE_SOURCES + ["README.md"]:
        shutil.copyfile(root / "bindings/node" / name, out_dir / name)
    for name in LEGAL:
        shutil.copyfile(root / name, out_dir / name)
    (out_dir / "package.json").write_text(json.dumps(node_manifest(version), indent=2) + "\n")
    return out_dir


def main(argv):
    if argv[1:2] == ["version"]:
        print(workspace_version())
        return 0
    if len(argv) != 3 or argv[1] not in ("python", "node"):
        print(__doc__, file=sys.stderr)
        return 2
    built = build_python(argv[2]) if argv[1] == "python" else build_node(argv[2])
    print(built)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
