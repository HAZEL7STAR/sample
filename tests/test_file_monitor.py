import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from file_monitor.engine import FileMonitorEngine


class FileMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="usbguard-filemonitor-", dir="/tmp")
        self.db_path = Path(self.temp_dir.name) / "events.db"
        self.engine = FileMonitorEngine(db_path=str(self.db_path), watch_roots=[self.temp_dir.name])
        self.engine.start()

    def tearDown(self) -> None:
        self.engine.stop()
        self.temp_dir.cleanup()

    def test_watches_create_and_delete_events(self) -> None:
        target = Path(self.temp_dir.name) / "sample.txt"
        target.write_text("hello usbguard", encoding="utf-8")
        time.sleep(1.0)

        conn = sqlite3.connect(str(self.db_path))
        try:
            rows = conn.execute("SELECT event_type, path FROM file_events ORDER BY id").fetchall()
        finally:
            conn.close()

        self.assertTrue(any(event_type == "created" for event_type, _ in rows))

        target.unlink(missing_ok=True)
        time.sleep(1.0)

        conn = sqlite3.connect(str(self.db_path))
        try:
            rows = conn.execute("SELECT event_type, path FROM file_events ORDER BY id").fetchall()
        finally:
            conn.close()

        self.assertTrue(any(event_type == "deleted" for event_type, _ in rows))


if __name__ == "__main__":
    unittest.main()
