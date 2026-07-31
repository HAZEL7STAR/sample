import unittest
from datetime import datetime, timedelta, timezone

from policy_engine.engine import evaluate_policy_decision


class DummyIdentity:
    def __init__(self, fingerprint: str = "abc123") -> None:
        self.fingerprint = fingerprint
        self.vendor_id = "dead"
        self.product_id = "beef"
        self.serial_number = "sn-1"
        self.manufacturer = "Test Vendor"
        self.device_name = "Test Device"


class PolicyEngineTests(unittest.TestCase):
    def test_unknown_device_is_blocked_by_default(self) -> None:
        decision = evaluate_policy_decision([], DummyIdentity("unknown-device"))
        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.status, "blacklisted")
        self.assertIn("No matching policy", decision.reason)

    def test_whitelist_policy_allows_device(self) -> None:
        decision = evaluate_policy_decision(
            [
                {
                    "device_fingerprint": "abc123",
                    "rule_type": "whitelist",
                    "expires_at": None,
                    "reason": "known approved device",
                }
            ],
            DummyIdentity("abc123"),
        )
        self.assertEqual(decision.action, "allow")
        self.assertEqual(decision.status, "whitelisted")
        self.assertEqual(decision.reason, "known approved device")

    def test_expired_policy_does_not_apply(self) -> None:
        decision = evaluate_policy_decision(
            [
                {
                    "device_fingerprint": "abc123",
                    "rule_type": "whitelist",
                    "expires_at": datetime.now(timezone.utc) - timedelta(minutes=5),
                    "reason": "expired policy",
                }
            ],
            DummyIdentity("abc123"),
        )
        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.status, "blacklisted")


if __name__ == "__main__":
    unittest.main()
