import sqlite3
import tempfile
import unittest
from pathlib import Path

from logger import configure_logging, log_activity


class LoggingTests(unittest.TestCase):
    def test_log_activity_writes_to_file_and_sqlite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="usbguard-test-", dir="/tmp") as tmpdir:
            tmp_path = Path(tmpdir)
            log_file = tmp_path / "usbguard.log"
            db_path = tmp_path / "events.db"

            configure_logging(log_file=str(log_file))
            log_activity("test message", category="system", db_path=str(db_path))

            self.assertTrue(log_file.exists())
            self.assertTrue(log_file.read_text(encoding="utf-8").find("test message") >= 0)

            conn = sqlite3.connect(str(db_path))
            try:
                row = conn.execute("SELECT message FROM system_logs WHERE message = ?", ("test message",)).fetchone()
            finally:
                conn.close()
            self.assertIsNotNone(row)


if __name__ == "__main__":
    unittest.main()
