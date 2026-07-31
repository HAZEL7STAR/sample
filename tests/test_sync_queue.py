import os
import sqlite3
import tempfile
import unittest

from offline_sync.engine import OfflineSyncQueue


class SyncQueueTests(unittest.TestCase):
    def test_enqueue_and_flush_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="usbguard-sync-", dir="/tmp") as tmpdir:
            queue = OfflineSyncQueue(db_path=os.path.join(tmpdir, "sync.db"))
            queue.enqueue("usb_events", {"action": "plugged", "device": "demo"})
            queue.enqueue("alerts", {"message": "hello"})

            pending = queue.list_pending()
            self.assertEqual(len(pending), 2)

            flushed = queue.flush()
            self.assertEqual(flushed, 2)

            self.assertEqual(queue.list_pending(), [])


if __name__ == "__main__":
    unittest.main()
