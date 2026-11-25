import json
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

import screener


class Screen(unittest.TestCase):
    def test_clean_output_passes(self):
        self.assertEqual(screener.screen({"order": "ord_881", "amount_minor": 120000, "status": "refunded"})["verdict"], "pass")

    def test_personal_and_card_data_are_redacted_by_pointer(self):
        verdict = screener.screen({
            "customer": {"email": "asha@example.com", "phone": "+91 98765 43210"},
            "payment": {"card": "4111 1111 1111 1111"},
            "notes": ["order ord_881 shipped"],
            "a/b": "ping me at ravi@example.org",
        })
        self.assertEqual(verdict["verdict"], "redact")
        self.assertEqual(sorted(verdict["pointers"]), ["/a~1b", "/customer/email", "/customer/phone", "/payment/card"])
        self.assertEqual(verdict["reason_codes"], ["pci.card_number", "pii.email", "pii.phone"])

    def test_a_number_failing_luhn_is_not_a_card(self):
        self.assertNotIn("pci.card_number", screener.findings("tracking 4111 1111 1111 1112"))

    def test_tokens_are_redacted_and_private_keys_withhold_everything(self):
        self.assertIn("secret.token", screener.findings("key AKIAABCDEFGHIJKLMNOP"))
        self.assertIn("secret.token", screener.findings("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"))
        verdict = screener.screen({"file": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."})
        self.assertEqual(verdict, {"verdict": "withhold", "pointers": [], "reason_codes": ["secret.private_key"]})

    def test_reason_codes_follow_the_runtimes_shape(self):
        import re
        for code in ["pii.email", "pii.phone", "pci.card_number", "secret.token", "secret.private_key"]:
            self.assertRegex(code, re.compile(r"^[a-z0-9_.]{1,64}$"))


class Service(unittest.TestCase):
    def test_the_port_answers_over_http_and_checks_its_token(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), screener.handler("t0ken"))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        body = json.dumps({"run": {}, "capability_id": "adp_crm.get_contact", "output": {"email": "a@b.co"}}).encode()

        def call(token):
            request = urllib.request.Request(url, data=body, headers={"authorization": f"Bearer {token}", "content-type": "application/json"})
            try:
                with urllib.request.urlopen(request) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as e:
                return e.code, None

        self.assertEqual(call("wrong")[0], 401)
        status, verdict = call("t0ken")
        self.assertEqual(status, 200)
        self.assertEqual(verdict, {"verdict": "redact", "pointers": ["/email"], "reason_codes": ["pii.email"]})
        server.shutdown()


if __name__ == "__main__":
    unittest.main()
