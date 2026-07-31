import tempfile
import unittest
from pathlib import Path

from dlp.engine import evaluate_dlp_policy


class DLPTests(unittest.TestCase):
    def test_blocks_large_or_sensitive_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="usbguard-dlp-", dir="/tmp") as tmpdir:
            target = Path(tmpdir) / "customer_data.csv"
            target.write_bytes(b"a" * 120000)

            result = evaluate_dlp_policy(
                {
                    "path": str(target),
                    "size_bytes": target.stat().st_size,
                    "extension": ".csv",
                    "mime_type": "text/csv",
                    "direction": "usb_to_computer",
                    "keywords": ["customer", "ssn"],
                }
            )

            self.assertEqual(result["decision"], "block")
            self.assertTrue(result["sensitive"])
            self.assertGreaterEqual(result["risk_score"], 0.5)


if __name__ == "__main__":
    unittest.main()
