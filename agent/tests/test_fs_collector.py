"""
Unit Tests for ForensiTrace File-System Telemetry Collector
Author: Chetna (USB and File-System Collectors Owner)
Scope: Step 2 (Page 6) - File-system collector with watchdog: create, modify, delete, move; ignore temp-file noise.
Rules: Labeled logging, schema conformance, must-fire and must-not-fire test cases.
"""

from __future__ import annotations

import os
import time
import queue
import shutil
import hashlib
import tempfile
import unittest
from typing import Any, Dict, List
from unittest.mock import patch, MagicMock

from agent.collectors.fs_collector import (
    FileSystemCollector,
    canonicalize_windows_path,
    is_ignored_path,
    build_fs_event,
)
from backend.schema import Event, SourceEnum, ActionEnum, EntityTypeEnum, compute_event_id


class TestFileSystemCollector(unittest.TestCase):
    """
    Test suite for FileSystemCollector meeting all Page 6 Step 2 specifications.
    """

    def setUp(self):
        self.event_queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=100)
        self.test_dir = tempfile.mkdtemp()
        self.collector = FileSystemCollector(
            event_queue=self.event_queue,
            debounce_seconds=0.5,
            modify_suppression_window=0.5,
        )

    def tearDown(self):
        if self.collector.is_alive:
            self.collector.stop()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_canonicalize_windows_path(self):
        """Must ensure uppercase drive letter and standard Windows backslashes."""
        self.assertEqual(canonicalize_windows_path("e:/reports/payload.exe"), r"E:\reports\payload.exe")
        self.assertEqual(canonicalize_windows_path(r"c:\temp\..\Windows\notepad.exe"), r"C:\Windows\notepad.exe")
        self.assertEqual(canonicalize_windows_path(""), "")

    def test_noise_filter_must_not_fire_on_temp_and_system_files(self):
        """Must not fire: Filters out Office lock files, temp extensions, system metadata, and directories."""
        # 1. Directories
        self.assertTrue(is_ignored_path(r"E:\reports", is_directory=True))

        # 2. Microsoft Office temporary lock files
        self.assertTrue(is_ignored_path(r"E:\~$confidential_report.docx", is_directory=False))
        self.assertTrue(is_ignored_path(r"E:\.~lock.presentation.pptx#", is_directory=False))

        # 3. Temporary extensions
        self.assertTrue(is_ignored_path(r"E:\payload.tmp", is_directory=False))
        self.assertTrue(is_ignored_path(r"E:\download.crdownload", is_directory=False))
        self.assertTrue(is_ignored_path(r"E:\archive.part", is_directory=False))
        self.assertTrue(is_ignored_path(r"E:\document.bak", is_directory=False))
        self.assertTrue(is_ignored_path(r"E:\editor.swp", is_directory=False))

        # 4. System volume metadata and recycle bin
        self.assertTrue(is_ignored_path(r"E:\$RECYCLE.BIN\S-1-5-21\payload.exe", is_directory=False))
        self.assertTrue(is_ignored_path(r"E:\scratch.tmp", is_directory=False))

        # 5. System exact filenames
        self.assertTrue(is_ignored_path(r"E:\desktop.ini", is_directory=False))
        self.assertTrue(is_ignored_path(r"E:\thumbs.db", is_directory=False))

    def test_noise_filter_must_fire_on_legitimate_files(self):
        """Must fire: Normal files and payloads must not be ignored."""
        self.assertFalse(is_ignored_path(r"E:\reports\payload.exe", is_directory=False))
        self.assertFalse(is_ignored_path(r"E:\contract.pdf", is_directory=False))
        self.assertFalse(is_ignored_path(r"E:\script.ps1", is_directory=False))
        self.assertFalse(is_ignored_path(r"E:\archive.zip", is_directory=False))

    def test_build_fs_event_schema_conformance(self):
        """Must produce an event conforming strictly to docs/schema.md and backend.schema.Event."""
        file_path = r"E:\reports\payload.exe"
        event_dict = build_fs_event(
            action="FILE_CREATED",
            file_path=file_path,
            host="WIN-FORENSIC-01",
        )

        # 1. Validate fields
        self.assertEqual(event_dict["source"], "fs")
        self.assertEqual(event_dict["action"], "FILE_CREATED")
        self.assertEqual(event_dict["entity_type"], "file")
        self.assertEqual(event_dict["entity"], file_path)
        self.assertIsNone(event_dict["user"])  # user is null for FS per schema contract
        self.assertEqual(event_dict["details"]["drive_letter"], "E:")
        self.assertEqual(event_dict["details"]["file_name"], "payload.exe")
        self.assertEqual(event_dict["details"]["extension"], ".exe")

        # 2. Check deterministic hash recipe
        expected_raw_rec = f"FILE_CREATED|{file_path}"
        self.assertEqual(event_dict["details"]["raw_record_id"], expected_raw_rec)
        expected_hash = hashlib.sha256(
            f"fs|{expected_raw_rec}|{event_dict['ts_utc']}".encode("utf-8")
        ).hexdigest()
        self.assertEqual(event_dict["event_id"], expected_hash)

        # 3. Validate with Purva's Pydantic Event model
        validated_event = Event(**event_dict)
        self.assertEqual(validated_event.source, SourceEnum.fs)
        self.assertEqual(validated_event.action, ActionEnum.FILE_CREATED)
        self.assertEqual(validated_event.entity_type, EntityTypeEnum.file)

    def test_all_fs_actions_cycle(self):
        """Must process FILE_CREATED, FILE_MODIFIED, FILE_DELETED, and FILE_MOVED."""
        # 1. FILE_CREATED
        ev_created = self.collector.simulate_event("FILE_CREATED", r"E:\test.txt")
        self.assertIsNotNone(ev_created)
        self.assertEqual(ev_created["action"], "FILE_CREATED")
        Event(**self.event_queue.get_nowait())

        # Wait past modify suppression window
        time.sleep(0.6)

        # 2. FILE_MODIFIED
        ev_mod = self.collector.simulate_event("FILE_MODIFIED", r"E:\test.txt")
        self.assertIsNotNone(ev_mod)
        self.assertEqual(ev_mod["action"], "FILE_MODIFIED")
        Event(**self.event_queue.get_nowait())

        # 3. FILE_MOVED
        ev_moved = self.collector.simulate_event("FILE_MOVED", r"E:\test.txt", dest_path=r"E:\renamed.txt")
        self.assertIsNotNone(ev_moved)
        self.assertEqual(ev_moved["action"], "FILE_MOVED")
        self.assertEqual(ev_moved["details"]["dest_path"], r"E:\renamed.txt")
        Event(**self.event_queue.get_nowait())

        # 4. FILE_DELETED
        ev_del = self.collector.simulate_event("FILE_DELETED", r"E:\renamed.txt")
        self.assertIsNotNone(ev_del)
        self.assertEqual(ev_del["action"], "FILE_DELETED")
        Event(**self.event_queue.get_nowait())

    def test_debounce_suppresses_duplicate_events(self):
        """Must debounce rapid duplicate events on the same file path within debounce window."""
        ev1 = self.collector.simulate_event("FILE_CREATED", r"E:\payload.exe")
        self.assertIsNotNone(ev1)
        self.assertEqual(self.event_queue.qsize(), 1)

        # Immediate identical event must be suppressed
        ev2 = self.collector.simulate_event("FILE_CREATED", r"E:\payload.exe")
        self.assertIsNone(ev2)
        self.assertEqual(self.event_queue.qsize(), 1)

    def test_modify_after_create_suppressed_on_copy(self):
        """
        Done when test:
        Copying a file to the USB produces FILE_CREATED on the removable drive,
        with no flood of duplicate events (immediate FILE_MODIFIED is suppressed).
        """
        # When a file copy begins, OS emits FILE_CREATED
        ev_create = self.collector.simulate_event("FILE_CREATED", r"E:\payload.exe")
        self.assertIsNotNone(ev_create)
        self.assertEqual(self.event_queue.qsize(), 1)

        # As bytes are written during the copy stream, OS emits rapid FILE_MODIFIED events
        ev_mod1 = self.collector.simulate_event("FILE_MODIFIED", r"E:\payload.exe")
        ev_mod2 = self.collector.simulate_event("FILE_MODIFIED", r"E:\payload.exe")

        # Both write bursts must be suppressed!
        self.assertIsNone(ev_mod1)
        self.assertIsNone(ev_mod2)
        # Queue still contains ONLY the single clean FILE_CREATED event
        self.assertEqual(self.event_queue.qsize(), 1)
        event = self.event_queue.get_nowait()
        self.assertEqual(event["action"], "FILE_CREATED")

    def test_inter_collector_drive_event_hook(self):
        """Must dynamically schedule and unschedule watchdog observers upon USB drive ATTACHED and REMOVED."""
        self.collector.start()
        self.assertTrue(self.collector.is_alive)

        # Mock os.path.isdir so test doesn't depend on physical E:\ drive
        with patch("os.path.isdir", return_value=True), \
             patch.object(self.collector.observer, "schedule") as mock_schedule, \
             patch.object(self.collector.observer, "unschedule") as mock_unschedule:

            mock_watch = MagicMock()
            mock_schedule.return_value = mock_watch

            # 1. Drive Attached Hook
            self.collector.handle_drive_event("E:", "ATTACHED")
            mock_schedule.assert_called_once()
            self.assertIn(r"E:\ ", [f"{p} " for p in self.collector.active_watches.keys()])

            # 2. Drive Removed Hook
            self.collector.handle_drive_event("E:", "REMOVED")
            mock_unschedule.assert_called_once_with(mock_watch)
            self.assertEqual(len(self.collector.active_watches), 0)

    def test_live_watchdog_detection_in_real_directory(self):
        """Integration test: Real watchdog observer captures live file creation in a directory."""
        self.collector.initial_watch_paths = [self.test_dir]
        self.collector.start()
        self.assertTrue(self.collector.is_alive)

        # Create a real file on disk
        real_file = os.path.join(self.test_dir, "real_payload.exe")
        with open(real_file, "w") as f:
            f.write("test content")

        # Wait briefly for OS notification delivery to watchdog thread
        found_event = None
        for _ in range(20):
            if not self.event_queue.empty():
                found_event = self.event_queue.get_nowait()
                break
            time.sleep(0.1)

        self.assertIsNotNone(found_event, "Watchdog failed to capture live file creation!")
        self.assertEqual(found_event["action"], "FILE_CREATED")
        self.assertEqual(found_event["entity"], canonicalize_windows_path(real_file))
        Event(**found_event)


if __name__ == "__main__":
    unittest.main()
