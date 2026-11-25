"""A reference approval relay for ContextOS (`[providers.approvals]`).

It is the deployment's approval service: the gateway asks it for an approval of one
exact action (`op: request`) and looks for a decision (`op: lookup`). The relay
delivers each request to people on Slack, Microsoft Teams or e-mail, takes their
decision back through a signed callback, checks who they are and whether they may
decide, and answers the gateway's lookup with verified decision material the kernel
checks again (approver eligibility, no self-approval, the exact action digest).

- **Signed callbacks.** Slack requests carry `X-Slack-Signature` (HMAC-SHA256 of
  `v0:{timestamp}:{body}`, timestamps within five minutes); Teams outgoing webhooks
  carry `Authorization: HMAC <base64 HMAC-SHA256 of the body>`; e-mail links carry a
  token signed by the relay that names one request, one decision and one approver, and
  expires. Anything unsigned, stale or tampered with is refused (401).
- **Who decides.** A channel identity (`slack:U123`, `teams:<aad id>`,
  `email:a@example.com`) maps to a principal and roles in `directory`; unknown
  identities are refused. The requester never decides their own request.
- **Escalation tiers.** `tiers` lists who is asked and when: tier one at once, each
  later tier `after_seconds` after the request while it is undecided. Every tier reached
  stays eligible.
- **Delegation.** `delegations` lets an approver hand their decisions to another
  person until a time (leave, holidays); the delegate decides `on_behalf_of` them, never
  for a request they made.

- **Trust.** `observer` names the principal the relay signs decisions as, and
  `trusted_observers` (principal id, type, trust domain) must be the same set the
  deployment's authority service vouches with: the kernel accepts approval facts only
  from the observers it trusts for every other fact.

Delivery goes to an outbox: Slack and Teams incoming-webhook URLs and an SMTP server
when configured, otherwise a JSON-lines file for development and tests. Secrets are read
from environment variables named in the configuration, never stored in it.

Run: python3 relay.py --config relay.json --port 7703
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import smtplib
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 1024 * 1024
SLACK_SKEW = 300
LINK_TTL = 24 * 3600
REQUEST_TTL = timedelta(days=7)


def jcs(value):
    # RFC 8785 subset sufficient for ASCII-keyed, integer-only payloads.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return "sha256:" + hashlib.sha256(jcs(value).encode()).hexdigest()


def stamp(at: datetime) -> str:
    return at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def artifact(kind, aid):
    return {"artifact_type": kind, "artifact_id": aid, "version": "1", "sha256": digest({"kind": kind, "id": aid})}


class Refused(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class Relay:
    def __init__(self, config: dict, outbox=None, clock=None):
        self.config = config
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.outbox = outbox or Outbox(config.get("outbox", {}))
        self.trust_domain = config.get("trust_domain", "contextos.relay")
        self.requests = {}  # request id -> state
        self.by_digest = {}  # action digest -> request id
        self.lock = threading.Lock()

    # ---- the gateway's contract ----

    def contract(self, req: dict) -> dict:
        if req.get("op") == "lookup":
            with self.lock:
                rid = self.by_digest.get(req.get("action_digest"))
                state = self.requests.get(rid) if rid else None
                return {"approval": state["material"] if state and state.get("material") else None}
        if req.get("op") == "request":
            action_digest = req["action_digest"]
            with self.lock:
                if action_digest in self.by_digest:
                    return {"approval_request_id": self.by_digest[action_digest]}
                rid = "relay:" + action_digest[7:31]
                self.requests[rid] = {"id": rid, "digest": action_digest, "run": req["run"], "binding": req["binding"],
                                      "opened_at": self.clock(), "tier": -1, "material": None}
                self.by_digest[action_digest] = rid
            self.escalate()
            return {"approval_request_id": rid}
        raise Refused(400, "unknown op")

    # ---- tiers and delivery ----

    def escalate(self) -> None:
        """Asks every tier a waiting request has reached and not yet asked."""
        now = self.clock()
        due = []
        with self.lock:
            for state in self.requests.values():
                if state["material"]:
                    continue
                waited = (now - state["opened_at"]).total_seconds()
                for i, tier in enumerate(self.config["tiers"]):
                    if i > state["tier"] and waited >= tier.get("after_seconds", 0):
                        state["tier"] = i
                        due.append((state, tier))
        for state, tier in due:
            for approver in tier["approvers"]:
                self.notify(state, self.delegate_for(approver, now) or approver)

    def notify(self, state: dict, principal: str) -> None:
        binding = state["binding"]
        text = (f"Approval needed: {binding['capability_id']} for run {binding['run_id']} "
                f"(request {state['id']}). Arguments: {jcs(binding.get('arguments', {}))}")
        for identity, entry in self.config["directory"].items():
            if entry["principal_id"] != principal:
                continue
            channel, address = identity.split(":", 1)
            links = None
            if channel == "email":
                links = {d: self.email_link(state["id"], d, identity) for d in ("approved", "denied")}
            self.outbox.send(channel, address, text, state["id"], links)

    def delegate_for(self, principal: str, now: datetime):
        for d in self.config.get("delegations", []):
            if d["from"] == principal and now < parse(d["until"]):
                return d["to"]
        return None

    # ---- decisions ----

    def eligible(self, state: dict, principal: str, now: datetime):
        """The approver this principal decides as (themselves, or whom they stand in for)."""
        reached = [p for tier in self.config["tiers"][: state["tier"] + 1] for p in tier["approvers"]]
        if principal in reached:
            return principal
        for d in self.config.get("delegations", []):
            if d["to"] == principal and d["from"] in reached and now < parse(d["until"]):
                return d["from"]
        return None

    def decide(self, rid: str, verdict: str, identity: str, channel: str) -> dict:
        if verdict not in ("approved", "denied"):
            raise Refused(400, "decision must be approved or denied")
        entry = self.config["directory"].get(identity)
        if entry is None:
            raise Refused(403, "unknown approver identity")
        principal = entry["principal_id"]
        now = self.clock()
        with self.lock:
            state = self.requests.get(rid)
            if state is None:
                raise Refused(404, "no such request")
            if state["material"]:
                raise Refused(409, "already decided")
            if state["run"]["actor"].get("principal_id") == principal:
                raise Refused(403, "a requester does not decide their own request")
            on_behalf_of = self.eligible(state, principal, now)
            if on_behalf_of is None:
                raise Refused(403, "not an eligible approver for this request (yet)")
            state["material"] = self.material(state, principal, entry, verdict, now, on_behalf_of, channel)
            return {"request": rid, "decision": verdict, "approver": principal,
                    "on_behalf_of": None if on_behalf_of == principal else on_behalf_of}

    def material(self, state, principal, entry, verdict, now, on_behalf_of, channel):
        """Decision material the kernel verifies, for exactly one action."""
        run, binding, rid = state["run"], state["binding"], state["id"]
        tenant = run["tenant_id"]
        person = {"principal_id": principal, "principal_type": "person", "trust_domain": self.trust_domain,
                  "tenant_id": tenant}
        # The observer that vouches for the decision must be one the deployment trusts for
        # every fact (the authority service's set): the kernel requires the same set.
        observers = [{**o, "tenant_id": tenant} for o in self.config["trusted_observers"]]
        observer = next(o for o in observers if o["principal_id"] == self.config["observer"])
        role = entry["roles"][0]
        window = {"observed_at": stamp(state["opened_at"]), "valid_until": stamp(state["opened_at"] + REQUEST_TTL)}
        proposal = {"request_id": rid, "proposal_id": binding["proposal_id"], "run_id": binding["run_id"],
                    "tenant_id": tenant, "operation_id": binding["operation_id"], "action_digest": state["digest"],
                    "policy_refs": binding["policy_refs"], "authority_refs": binding["authority_refs"],
                    "not_before": window["observed_at"], "expires_at": window["valid_until"]}
        request = {**proposal, "approval_request_id": rid, "requester": run["actor"], "eligible_approvers": [person],
                   "eligible_approver_roles": entry["roles"], "required_approvals": 1, "prohibit_self_approval": True,
                   "verification_ref": artifact("approval_request", rid)}
        decision = {**proposal, "approval_id": f"{rid}:1", "approval_request_id": rid, "approver": person,
                    "decision": verdict, "decided_at": stamp(now),
                    "verification_ref": artifact("approval_decision", f"{rid}:1:{channel}:{on_behalf_of}")}
        observation = {"approval_id": decision["approval_id"],
                       "decision_digest": digest({"domain": "contextos.approval_decision.v1", "decision": decision}),
                       "verification_ref": decision["verification_ref"], "verification_status": "verified",
                       "observer": observer, "observed_at": stamp(now), "valid_until": window["valid_until"]}
        entitlement = {"approver": person, "role_id": role, "approval_request_id": rid,
                       "action_digest": state["digest"], "observer": observer, "verification_status": "verified",
                       "verification_ref": artifact("entitlement", role), **window}
        return {"proposal": proposal, "request": request, "decisions": [decision],
                "verification_observations": [observation], "entitlements": [entitlement],
                "trusted_observers": observers}

    # ---- signed callbacks ----

    def secret(self, name: str) -> bytes:
        value = os.environ.get(self.config["secrets"][name], "")
        if not value:
            raise Refused(503, f"{name} is not configured")
        return value.encode()

    def slack(self, headers, body: bytes) -> dict:
        ts = headers.get("x-slack-request-timestamp", "")
        sig = headers.get("x-slack-signature", "")
        if not ts.isdigit() or abs(time.time() - int(ts)) > SLACK_SKEW:
            raise Refused(401, "stale or missing timestamp")
        expected = "v0=" + hmac.new(self.secret("slack_signing_secret"), b"v0:" + ts.encode() + b":" + body,
                                    hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            raise Refused(401, "bad signature")
        payload = json.loads(urllib.parse.parse_qs(body.decode())["payload"][0])
        verdict, rid = payload["actions"][0]["value"].split(":", 1)
        return self.decide(rid, verdict, "slack:" + payload["user"]["id"], "slack")

    def teams(self, headers, body: bytes) -> dict:
        auth = headers.get("authorization", "")
        expected = "HMAC " + base64.b64encode(hmac.new(self.secret("teams_secret"), body, hashlib.sha256).digest()).decode()
        if not hmac.compare_digest(expected, auth):
            raise Refused(401, "bad signature")
        payload = json.loads(body)
        return self.decide(payload["request_id"], payload["decision"], "teams:" + payload["from"]["aadObjectId"], "teams")

    def email_link(self, rid: str, verdict: str, identity: str) -> str:
        claims = base64.urlsafe_b64encode(jcs({"r": rid, "d": verdict, "i": identity,
                                               "e": int(self.clock().timestamp()) + LINK_TTL}).encode()).decode()
        sig = hmac.new(self.secret("email_link_secret"), claims.encode(), hashlib.sha256).hexdigest()
        return f"{self.config.get('public_url', '')}/email/decide?token={claims}.{sig}"

    def email(self, token: str) -> dict:
        claims, _, sig = token.partition(".")
        expected = hmac.new(self.secret("email_link_secret"), claims.encode(), hashlib.sha256).hexdigest()
        if not sig or not hmac.compare_digest(expected, sig):
            raise Refused(401, "bad signature")
        c = json.loads(base64.urlsafe_b64decode(claims.encode()))
        if c["e"] < int(self.clock().timestamp()):
            raise Refused(401, "link expired")
        return self.decide(c["r"], c["d"], c["i"], "email")


def parse(at: str) -> datetime:
    return datetime.fromisoformat(at.replace("Z", "+00:00"))


class Outbox:
    """Slack and Teams incoming webhooks and SMTP when configured; else a JSON-lines file."""

    def __init__(self, config: dict):
        self.config = config
        self.sent = []

    def send(self, channel, address, text, rid, links=None):
        message = {"channel": channel, "to": address, "text": text, "request": rid, "links": links}
        self.sent.append(message)
        url_env = {"slack": "slack_webhook_env", "teams": "teams_webhook_env"}.get(channel)
        url = os.environ.get(self.config.get(url_env, ""), "") if url_env else ""
        if url:
            body = {"text": text, "request_id": rid} if channel == "teams" else {
                "text": text, "blocks": [{"type": "actions", "elements": [
                    {"type": "button", "text": {"type": "plain_text", "text": label}, "value": f"{v}:{rid}"}
                    for label, v in (("Approve", "approved"), ("Deny", "denied"))]}]}
            urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(body).encode(),
                                                          headers={"content-type": "application/json"}), timeout=10)
        elif channel == "email" and self.config.get("smtp_host"):
            mail = EmailMessage()
            mail["From"], mail["To"], mail["Subject"] = self.config["mail_from"], address, f"Approval needed: {rid}"
            mail.set_content(text + "\n\n" + "\n".join(f"{k}: {v}" for k, v in (links or {}).items()))
            with smtplib.SMTP(self.config["smtp_host"], self.config.get("smtp_port", 587)) as smtp:
                smtp.starttls()
                smtp.send_message(mail)
        elif self.config.get("file"):
            with open(self.config["file"], "a") as f:
                f.write(json.dumps(message) + "\n")


def handler(relay: Relay):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # never log request bodies or tokens
            pass

        def reply(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def run(self, fn):
            try:
                self.reply(200, fn())
            except Refused as e:
                self.reply(e.status, {"error": str(e)})
            except (KeyError, ValueError, IndexError):
                self.reply(400, {"error": "malformed request"})

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            if url.path == "/email/decide":
                token = urllib.parse.parse_qs(url.query).get("token", [""])[0]
                return self.run(lambda: relay.email(token))
            self.reply(404, {"error": "not found"})

        def do_POST(self):
            length = int(self.headers.get("content-length") or 0)
            if length <= 0 or length > MAX_BODY:
                return self.reply(413, {"error": "body too large or empty"})
            body = self.rfile.read(length)
            headers = {k.lower(): v for k, v in self.headers.items()}
            path = urllib.parse.urlparse(self.path).path
            if path == "/slack/actions":
                return self.run(lambda: relay.slack(headers, body))
            if path == "/teams/actions":
                return self.run(lambda: relay.teams(headers, body))
            if path in ("/", "/approvals"):
                return self.run(lambda: relay.contract(json.loads(body)))
            self.reply(404, {"error": "not found"})

    return Handler


def main():
    parser = argparse.ArgumentParser(description="ContextOS approval relay")
    parser.add_argument("--config", required=True)
    parser.add_argument("--port", type=int, default=7703)
    args = parser.parse_args()
    with open(args.config) as f:
        relay = Relay(json.load(f))

    def tick():
        while True:
            time.sleep(1)
            relay.escalate()

    threading.Thread(target=tick, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", args.port), handler(relay)).serve_forever()


if __name__ == "__main__":
    main()
