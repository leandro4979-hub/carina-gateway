import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from carina_gateway_server import ReceiverConfigError, process_webhook
from github_carina_gateway import SQLiteIntakeLedger


class WebhookReceiverTests(unittest.TestCase):
    def _request(self, secret="receiver-secret"):
        body = json.dumps(
            {
                "action": "opened",
                "sender": {"login": "builder"},
                "repository": {
                    "full_name": "leandro4979-hub/Leandro4979-hub"
                },
                "issue": {
                    "number": 77,
                    "title": "[Idea]: Receiver test",
                    "body": "bounded evidence",
                    "html_url": "https://github.com/leandro4979-hub/Leandro4979-hub/issues/77",
                    "labels": [],
                },
            }
        ).encode("utf-8")
        signature = "sha256=" + hmac.new(
            secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        headers = {
            "X-GitHub-Event": "issues",
            "X-GitHub-Delivery": "delivery-http-77",
            "X-Hub-Signature-256": signature,
        }
        return headers, body

    def test_receiver_persists_only_read_only_intake(self):
        headers, body = self._request()

        with tempfile.TemporaryDirectory() as directory:
            ledger = SQLiteIntakeLedger(Path(directory) / "intake.sqlite3")
            status, response = process_webhook(
                headers,
                body,
                ledger=ledger,
                webhook_secret="receiver-secret",
            )

            self.assertEqual(status, 202)
            self.assertEqual(response["decision"], "ALLOW")

            rows = ledger.read_all()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["phase"], "INTENT")
            self.assertTrue(rows[0]["read_only"])
            self.assertFalse(rows[0]["authorization"]["granted"])
            self.assertEqual(
                rows[0]["authorization"]["authority"],
                "CARINA_ONLY",
            )

    def test_receiver_refuses_to_start_without_secret(self):
        headers, body = self._request()

        with tempfile.TemporaryDirectory() as directory:
            ledger = SQLiteIntakeLedger(Path(directory) / "intake.sqlite3")
            with self.assertRaises(ReceiverConfigError):
                process_webhook(
                    headers,
                    body,
                    ledger=ledger,
                    webhook_secret="",
                )


if __name__ == "__main__":
    unittest.main()
