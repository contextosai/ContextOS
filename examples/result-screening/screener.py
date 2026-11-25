"""A reference result-screening service for ContextOS (`[providers.result_screening]`).

It judges a confirmed effect's output before the agent sees it, by pattern:

- personal data: e-mail addresses (`pii.email`) and phone numbers (`pii.phone`);
- payment card numbers that pass the Luhn check (`pci.card_number`);
- secrets: cloud access key ids, API tokens, bearer tokens (`secret.token`), and private
  keys (`secret.private_key`).

Values that match are redacted by JSON pointer; an output carrying a private key is
withheld whole. Everything else passes. This is a starting point, not a classifier:
patterns miss data written in other forms and can flag lookalikes, so measure it on
your own outputs before relying on it. ContextOS fails closed when the service fails.

Run: python3 screener.py --port 7710 [--token-env SCREENER_TOKEN]
"""

import argparse
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 2 * 1024 * 1024
MAX_POINTERS = 64

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE = re.compile(r"(?<![\w+])\+?\d[\d\s().-]{8,16}\d(?!\w)")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
TOKEN = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[abpr]-[A-Za-z0-9-]{10,})\b"
    r"|\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"
)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")


def luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def findings(text: str) -> set:
    """Reason codes for what `text` carries."""
    found = set()
    if PRIVATE_KEY.search(text):
        found.add("secret.private_key")
    if TOKEN.search(text):
        found.add("secret.token")
    if EMAIL.search(text):
        found.add("pii.email")
    for match in CARD.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if 13 <= len(digits) <= 19 and luhn(digits):
            found.add("pci.card_number")
    if PHONE.search(EMAIL.sub("", text)) and "pci.card_number" not in found:
        found.add("pii.phone")
    return found


def escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def walk(value, pointer=""):
    """(JSON pointer, string) for every string in `value`."""
    if isinstance(value, str):
        yield pointer, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from walk(item, f"{pointer}/{escape(str(key))}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from walk(item, f"{pointer}/{i}")


def screen(output) -> dict:
    """The port's verdict for one output."""
    pointers, reasons = [], set()
    for pointer, text in walk(output):
        found = findings(text)
        if "secret.private_key" in found:
            return {"verdict": "withhold", "pointers": [], "reason_codes": ["secret.private_key"]}
        if found:
            reasons |= found
            pointers.append(pointer)
    if not pointers:
        return {"verdict": "pass", "pointers": [], "reason_codes": []}
    if len(pointers) > MAX_POINTERS:
        return {"verdict": "withhold", "pointers": [], "reason_codes": sorted(reasons)[:16]}
    return {"verdict": "redact", "pointers": pointers, "reason_codes": sorted(reasons)[:16]}


def handler(token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # never log outputs
            pass

        def reply(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if token and self.headers.get("authorization") != f"Bearer {token}":
                return self.reply(401, {"error": "unauthorized"})
            length = int(self.headers.get("content-length") or 0)
            if length <= 0 or length > MAX_BODY:
                return self.reply(413, {"error": "body too large or empty"})
            try:
                request = json.loads(self.rfile.read(length))
            except ValueError:
                return self.reply(400, {"error": "malformed json"})
            self.reply(200, screen(request.get("output")))

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=7710)
    parser.add_argument("--token-env", help="environment variable holding the bearer token ContextOS sends")
    args = parser.parse_args()
    token = os.environ.get(args.token_env) if args.token_env else None
    ThreadingHTTPServer(("127.0.0.1", args.port), handler(token)).serve_forever()


if __name__ == "__main__":
    main()
