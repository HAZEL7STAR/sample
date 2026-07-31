import tempfile
import unittest
from pathlib import Path

from reporting.engine import build_summary, export_csv


class ReportingTests(unittest.TestCase):
    def test_build_summary_and_export_csv(self) -> None:
        records = [
            {"kind": "device", "name": "USB 1"},
            {"kind": "alert", "message": "blocked"},
            {"kind": "transfer", "path": "/tmp/a"},
        ]
        summary = build_summary(records)
        self.assertEqual(summary["count"], 3)
        self.assertEqual(summary["devices"], 1)

        with tempfile.TemporaryDirectory(prefix="usbguard-report-", dir="/tmp") as tmpdir:
            out_path = export_csv(records, Path(tmpdir) / "report.csv")
            self.assertTrue(Path(out_path).exists())


if __name__ == "__main__":
    unittest.main()
