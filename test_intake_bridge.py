import unittest

import github_carina_gateway as gateway


def issue_payload(title, action="opened", body="details", number=42, labels=None):
    return {
        "action": action,
        "sender": {"login": "builder"},
        "repository": {"full_name": "leandro4979-hub/Leandro4979-hub"},
        "issue": {
            "number": number,
            "title": title,
            "body": body,
            "html_url": f"https://github.com/leandro4979-hub/Leandro4979-hub/issues/{number}",
            "labels": [{"name": value} for value in (labels or [])],
        },
    }


class IntakeBridgeTests(unittest.TestCase):
    def test_opened_idea_maps_to_read_only_intent(self):
        event = gateway.ParsedEvent(
            delivery_id="delivery-1",
            event_type="issues",
            action="opened",
            actor="builder",
            repo_full_name="leandro4979-hub/Leandro4979-hub",
            payload=issue_payload("[Idea]: Safer agent handoff"),
        )

        record = gateway.map_issue_to_intake_record(event)

        self.assertEqual(record.phase.value, "INTENT")
        self.assertFalse(record.authorization_granted)
        self.assertEqual(record.authorization_authority, "CARINA_ONLY")
        self.assertTrue(record.read_only)

    def test_edited_idea_maps_to_evidence(self):
        event = gateway.ParsedEvent(
            delivery_id="delivery-2",
            event_type="issues",
            action="edited",
            actor="builder",
            repo_full_name="leandro4979-hub/Leandro4979-hub",
            payload=issue_payload("[Idea]: Safer agent handoff", action="edited"),
        )

        record = gateway.map_issue_to_intake_record(event)

        self.assertEqual(record.phase.value, "EVIDENCE")

    def test_opened_collaboration_maps_to_decision(self):
        event = gateway.ParsedEvent(
            delivery_id="delivery-3",
            event_type="issues",
            action="opened",
            actor="builder",
            repo_full_name="leandro4979-hub/Leandro4979-hub",
            payload=issue_payload("[Collaboration]: Bounded pilot"),
        )

        record = gateway.map_issue_to_intake_record(event)

        self.assertEqual(record.phase.value, "DECISION")

    def test_authorized_phase_is_rejected_even_if_record_is_mutated(self):
        record = gateway.IntakeRecord(
            record_id="github:test:1",
            phase="AUTHORIZED",
            repo_full_name="owner/repo",
            issue_number=1,
            issue_title="bad",
            issue_body="",
            issue_url="https://example.test/1",
            actor="attacker",
            delivery_id="delivery-4",
        )

        with self.assertRaises(gateway.IntakeAuthorizationError):
            gateway.validate_intake_record(record)

    def test_non_intake_issue_is_ignored(self):
        event = gateway.ParsedEvent(
            delivery_id="delivery-5",
            event_type="issues",
            action="opened",
            actor="builder",
            repo_full_name="owner/repo",
            payload=issue_payload("Ordinary issue"),
        )

        self.assertIsNone(gateway.map_issue_to_intake_record(event))


if __name__ == "__main__":
    unittest.main()
