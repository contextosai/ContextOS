#!/usr/bin/env python3
"""Verifies a ContextOS audit pack with nothing but Python 3.9+: the manifest's Ed25519
signature against the public key you trust, then every file's SHA-256.

    python3 verify.py --public-key <base64url key you obtained independently>

The key in manifest.sig is never trusted on its own: anyone can re-sign a pack with
their own key. Get the publisher's key out of band (their configuration, a ticket, a
call) and pass it here. To re-verify the audit chain itself (each entry's signature and
linkage), run `ctx audit-verify --entries evidence/entries.json --keys evidence/keys.json`.
Exit status: 0 verified, 1 not verified, 2 usage.
"""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

DOMAIN = b"contextos-audit-pack-v1:"

# Ed25519 verification (RFC 8032, section 5.1.7), affine Edwards arithmetic. Slow but
# small, so it can be read and checked by hand.
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _inv(x):
    return pow(x, P - 2, P)


def _recover_x(y, sign):
    xx = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - xx) % P != 0:
        return None
    if x == 0 and sign:
        return None
    if x % 2 != sign:
        x = P - x
    return x


def _add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = D * x1 * x2 * y1 * y2 % P
    return ((x1 * y2 + x2 * y1) * _inv(1 + t) % P, (y1 * y2 + x1 * x2) * _inv(1 - t) % P)


def _mul(point, n):
    result, addend = (0, 1), point
    while n:
        if n & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        n >>= 1
    return result


def _decode(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= P:
        return None
    x = _recover_x(y, sign)
    return None if x is None else (x, y)


_BY = 4 * _inv(5) % P
BASE = (_recover_x(_BY, 0), _BY)


def ed25519_verify(public_key, message, signature):
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a, r = _decode(public_key), _decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    return _mul(BASE, s) == _add(r, _mul(a, h))


def _b64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--public-key", required=True, help="the publisher's key, base64url, obtained independently")
    parser.add_argument("--pack", default=str(Path(__file__).resolve().parent), help="the pack folder (default: this one)")
    args = parser.parse_args()
    root = Path(args.pack)
    manifest_bytes = (root / "manifest.json").read_bytes()
    sig = json.loads((root / "manifest.sig").read_text())
    digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    failures = []
    try:
        key, signature = _b64url(args.public_key), _b64url(sig["signature"])
    except (ValueError, KeyError):
        print("NOT VERIFIED: the key or manifest.sig is malformed")
        return 1
    if sig.get("alg") != "ed25519" or sig.get("manifest_sha256") != digest:
        failures.append("manifest.sig does not name this manifest")
    elif not ed25519_verify(key, DOMAIN + digest.encode(), signature):
        failures.append("the manifest signature does not verify with this key")
    manifest = json.loads(manifest_bytes)
    for name, expected in sorted(manifest.get("files", {}).items()):
        path = (root / name).resolve()
        if root.resolve() not in path.parents:
            failures.append(f"{name}: outside the pack")
            continue
        if not path.is_file():
            failures.append(f"{name}: missing")
        elif "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            failures.append(f"{name}: changed")
    if failures:
        print("NOT VERIFIED")
        for f in failures:
            print(" -", f)
        return 1
    print(f"VERIFIED: manifest signed by {sig.get('kid')}; {len(manifest.get('files', {}))} files match their digests")
    print("Re-verify the audit chain with: ctx audit-verify --entries evidence/entries.json --keys evidence/keys.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
