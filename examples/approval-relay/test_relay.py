import base64
import hashlib
import hmac
import json
import os
import time
import unittest
import urllib.parse
from datetime import datetime, timedelta, timezone

import relay

T0 = datetime(2026, 11, 26, 10, 0, tzinfo=timezone.utc)
CONFIG = {
    "trust_domain": "acme.test",
    "observer": "approval_service",
    "trusted_observers": [{"principal_id": "approval_service", "principal_type": "workload", "trust_domain": "acme.test"}],
    "directory": {
        "slack:U_ANA": {"principal_id": "ana", "roles": ["finance_lead"]},
        "teams:aad-ravi": {"principal_id": "ravi", "roles": ["finance_head"]},
        "email:meera@acme.test": {"principal_id": "meera", "roles": ["finance_lead"]},
        "slack:U_BOT": {"principal_id": "svc_agent", "roles": ["finance_lead"]},
    },
    "tiers": [{"after_seconds": 0, "approvers": ["ana"]}, {"after_seconds": 900, "approvers": ["ravi"]}],
    "delegations": [{"from": "ana", "to": "meera", "until": "2026-11-27T00:00:00Z"}],
    "secrets": {"slack_signing_secret": "T_SLACK", "teams_secret": "T_TEAMS", "email_link_secret": "T_MAIL"},
}
BINDING = {"proposal_id": "p1", "run_id": "run_1", "operation_id": "op_1", "capability_id": "adp_payments.issue_refund",
           "policy_refs": [], "authority_refs": [], "arguments": {"order_id": "ord_1", "amount_minor": 420000}}
RUN = {"tenant_id": "acme", "run_id": "run_1", "actor": {"principal_id": "svc_agent"}}


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


class Sent(relay.Outbox):
    def __init__(self):
        super().__init__({})


def make():
    os.environ.update({"T_SLACK": "slack-secret", "T_TEAMS": "dGVhbXMtc2VjcmV0", "T_MAIL": "mail-secret"})
    clock = Clock()
    r = relay.Relay(CONFIG, outbox=Sent(), clock=clock)
    rid = r.contract({"op": "request", "action_digest": "sha256:" + "ab" * 32, "run": RUN, "binding": BINDING})[
        "approval_request_id"]
    return r, clock, rid


def slack_body(verdict, rid, user):
    payload = json.dumps({"actions": [{"value": f"{verdict}:{rid}"}], "user": {"id": user}})
    return urllib.parse.urlencode({"payload": payload}).encode()


def slack_headers(body, secret=b"slack-secret", ts=None):
    ts = str(int(time.time()) if ts is None else ts)
    sig = "v0=" + hmac.new(secret, b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    return {"x-slack-request-timestamp": ts, "x-slack-signature": sig}


class RelayTest(unittest.TestCase):
    def test_tiers_are_asked_in_turn_and_stay_eligible(self):
        r, clock, rid = make()
        self.assertEqual([m["to"] for m in r.outbox.sent], ["meera@acme.test"], "ana is away: her delegate is asked")
        with self.assertRaises(relay.Refused):
            r.decide(rid, "approved", "teams:aad-ravi", "teams")  # tier two not reached yet
        clock.now = T0 + timedelta(seconds=901)
        r.escalate()
        self.assertEqual([(m["channel"], m["to"]) for m in r.outbox.sent[1:]], [("teams", "aad-ravi")])
        out = r.decide(rid, "approved", "teams:aad-ravi", "teams")
        self.assertEqual(out["approver"], "ravi")
        lookup = r.contract({"op": "lookup", "action_digest": "sha256:" + "ab" * 32})["approval"]
        self.assertEqual(lookup["decisions"][0]["approver"]["principal_id"], "ravi")
        self.assertEqual(lookup["request"]["eligible_approvers"][0]["principal_id"], "ravi")
        with self.assertRaises(relay.Refused) as again:
            r.decide(rid, "denied", "slack:U_ANA", "slack")
        self.assertEqual(again.exception.status, 409)

    def test_a_delegate_decides_on_behalf_until_the_delegation_ends(self):
        r, clock, rid = make()
        out = r.decide(rid, "approved", "email:meera@acme.test", "email")
        self.assertEqual(out["on_behalf_of"], "ana")
        r2, clock2, rid2 = make()
        clock2.now = datetime(2026, 11, 27, 1, 0, tzinfo=timezone.utc)
        with self.assertRaises(relay.Refused):
            r2.decide(rid2, "approved", "email:meera@acme.test", "email")

    def test_unknown_people_and_requesters_never_decide(self):
        r, _, rid = make()
        for identity, status in (("slack:U_NOBODY", 403), ("slack:U_BOT", 403)):
            with self.assertRaises(relay.Refused) as e:
                r.decide(rid, "approved", identity, "slack")
            self.assertEqual(e.exception.status, status)

    def test_slack_callbacks_must_be_signed_and_fresh(self):
        r, _, rid = make()
        body = slack_body("denied", rid, "U_ANA")
        for headers in (slack_headers(body, secret=b"wrong"), slack_headers(body, ts=int(time.time()) - 3600), {}):
            with self.assertRaises(relay.Refused) as e:
                r.slack(headers, body)
            self.assertEqual(e.exception.status, 401)
        self.assertEqual(r.slack(slack_headers(body), body)["decision"], "denied")

    def test_teams_callbacks_are_checked_against_the_shared_secret(self):
        r, clock, rid = make()
        clock.now = T0 + timedelta(seconds=901)
        r.escalate()
        body = json.dumps({"request_id": rid, "decision": "approved", "from": {"aadObjectId": "aad-ravi"}}).encode()
        good = "HMAC " + base64.b64encode(hmac.new(b"dGVhbXMtc2VjcmV0", body, hashlib.sha256).digest()).decode()
        with self.assertRaises(relay.Refused):
            r.teams({"authorization": "HMAC bm9wZQ=="}, body)
        self.assertEqual(r.teams({"authorization": good}, body)["approver"], "ravi")

    def test_email_links_are_one_decision_signed_and_expiring(self):
        r, clock, rid = make()
        link = r.outbox.sent[0]["links"]["approved"]
        token = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)["token"][0]
        claims, sig = token.split(".")
        forged = base64.urlsafe_b64encode(base64.urlsafe_b64decode(claims).replace(b"approved", b"denied")).decode()
        with self.assertRaises(relay.Refused):
            r.email(f"{forged}.{sig}")
        clock.now = T0 + timedelta(days=2)
        with self.assertRaises(relay.Refused):
            r.email(token)
        clock.now = T0
        self.assertEqual(r.email(token)["on_behalf_of"], "ana")

    def test_the_same_action_is_one_request(self):
        r, _, rid = make()
        again = r.contract({"op": "request", "action_digest": "sha256:" + "ab" * 32, "run": RUN, "binding": BINDING})
        self.assertEqual(again["approval_request_id"], rid)
        self.assertIsNone(r.contract({"op": "lookup", "action_digest": "sha256:" + "cd" * 32})["approval"])


if __name__ == "__main__":
    unittest.main()
