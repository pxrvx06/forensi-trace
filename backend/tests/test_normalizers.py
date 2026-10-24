"""
Unit Tests for Telemetry Normalizers Using Real Sample Recordings
Author: Purva (Backend & Data Layer Owner)
Contract: Step 3 of Execution Plan ("Each normalizer has tests using the sample recordings")
"""

import json
import unittest
from pathlib import Path

from backend.schema import SourceEnum, ActionEnum, EntityTypeEnum, Event
from backend.normalizers import (
    normalize_usb_event,
    normalize_fs_event,
    normalize_eventlog_event,
    normalize_event,
    _canonicalize_path
)


class TestTelemetryNormalizers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Locate sample files handed over by Daksh and Chetna in docs/samples/ and docs/examples/
        repo_root = Path(__file__).resolve().parent.parent.parent
        cls.samples_dir = repo_root / "docs" / "samples"
        cls.examples_dir = repo_root / "docs" / "examples"

        # Load USB sample recordings
        with open(cls.samples_dir / "usb_arrival.json", "r", encoding="utf-8") as f:
            cls.usb_arrival_sample = json.load(f)
        with open(cls.samples_dir / "usb_removal.json", "r", encoding="utf-8") as f:
            cls.usb_removal_sample = json.load(f)

        # Load File System sample recordings
        with open(cls.samples_dir / "fs_created.json", "r", encoding="utf-8") as f:
            cls.fs_created_sample = json.load(f)
        with open(cls.samples_dir / "fs_modified.json", "r", encoding="utf-8") as f:
            cls.fs_modified_sample = json.load(f)
        with open(cls.samples_dir / "fs_deleted.json", "r", encoding="utf-8") as f:
            cls.fs_deleted_sample = json.load(f)
        with open(cls.samples_dir / "fs_moved.json", "r", encoding="utf-8") as f:
            cls.fs_moved_sample = json.load(f)

        # Load Event Log sample recording
        with open(cls.examples_dir / "eventlog_event.json", "r", encoding="utf-8") as f:
            cls.eventlog_sample = json.load(f)

    def test_canonicalize_path(self):
        """Test Windows path canonicalization rules (uppercase drive letters, backslashes)."""
        self.assertEqual(_canonicalize_path("e:/reports/payload.exe"), "E:\\reports\\payload.exe")
        self.assertEqual(_canonicalize_path("c:\\windows\\system32\\cmd.exe"), "C:\\windows\\system32\\cmd.exe")
        self.assertEqual(_canonicalize_path("E:\\reports/nested/tool.exe"), "E:\\reports\\nested\\tool.exe")

    def test_normalize_usb_arrival_sample(self):
        """Test normalizing raw USB arrival recording."""
        raw = self.usb_arrival_sample["raw"]
        event = normalize_usb_event(
            raw,
            host=self.usb_arrival_sample["host"],
            ts_utc=self.usb_arrival_sample["ts_utc"]
        )

        self.assertIsInstance(event, Event)
        self.assertEqual(event.source, SourceEnum.usb)
        self.assertEqual(event.action, ActionEnum.DEVICE_ARRIVED)
        self.assertEqual(event.entity_type, EntityTypeEnum.device)
        self.assertTrue(event.entity.startswith("E:"))
        self.assertEqual(event.details["drive_letter"], "E:")
        self.assertEqual(event.event_id, self.usb_arrival_sample["event_id"])

    def test_normalize_usb_removal_sample(self):
        """Test normalizing raw USB removal recording."""
        raw = self.usb_removal_sample["raw"]
        event = normalize_usb_event(
            raw,
            host=self.usb_removal_sample["host"],
            ts_utc=self.usb_removal_sample["ts_utc"]
        )

        self.assertEqual(event.source, SourceEnum.usb)
        self.assertEqual(event.action, ActionEnum.DEVICE_REMOVED)
        self.assertEqual(event.entity_type, EntityTypeEnum.device)
        self.assertEqual(event.event_id, self.usb_removal_sample["event_id"])

    def test_normalize_fs_created_sample(self):
        """Test normalizing raw filesystem created recording."""
        raw = self.fs_created_sample["raw"]
        event = normalize_fs_event(
            raw,
            host=self.fs_created_sample["host"],
            ts_utc=self.fs_created_sample["ts_utc"]
        )

        self.assertEqual(event.source, SourceEnum.fs)
        self.assertEqual(event.action, ActionEnum.FILE_CREATED)
        self.assertEqual(event.entity_type, EntityTypeEnum.file)
        self.assertEqual(event.entity, "E:\\reports\\payload.exe")
        self.assertEqual(event.details["file_name"], "payload.exe")
        self.assertEqual(event.details["extension"], ".exe")
        self.assertEqual(event.event_id, self.fs_created_sample["event_id"])

    def test_normalize_fs_modified_sample(self):
        """Test normalizing raw filesystem modified recording."""
        raw = self.fs_modified_sample["raw"]
        event = normalize_fs_event(
            raw,
            host=self.fs_modified_sample["host"],
            ts_utc=self.fs_modified_sample["ts_utc"]
        )

        self.assertEqual(event.action, ActionEnum.FILE_MODIFIED)
        self.assertEqual(event.entity, "E:\\reports\\payload.exe")
        self.assertEqual(event.event_id, self.fs_modified_sample["event_id"])

    def test_normalize_fs_deleted_sample(self):
        """Test normalizing raw filesystem deleted recording."""
        raw = self.fs_deleted_sample["raw"]
        event = normalize_fs_event(
            raw,
            host=self.fs_deleted_sample["host"],
            ts_utc=self.fs_deleted_sample["ts_utc"]
        )

        self.assertEqual(event.action, ActionEnum.FILE_DELETED)
        self.assertEqual(event.event_id, self.fs_deleted_sample["event_id"])

    def test_normalize_fs_moved_sample(self):
        """Test normalizing raw filesystem moved/renamed recording."""
        raw = self.fs_moved_sample["raw"]
        event = normalize_fs_event(
            raw,
            host=self.fs_moved_sample["host"],
            ts_utc=self.fs_moved_sample["ts_utc"]
        )

        self.assertEqual(event.action, ActionEnum.FILE_MOVED)
        self.assertEqual(event.entity, self.fs_moved_sample["entity"])
        self.assertEqual(event.details["dest_path"], self.fs_moved_sample["details"]["dest_path"])
        self.assertEqual(event.event_id, self.fs_moved_sample["event_id"])

    def test_normalize_eventlog_sample(self):
        """Test normalizing raw Windows Event Log recording (Security 4688)."""
        raw = self.eventlog_sample["raw"]
        event = normalize_eventlog_event(
            raw,
            host=self.eventlog_sample["host"],
            ts_utc=self.eventlog_sample["ts_utc"]
        )

        self.assertEqual(event.source, SourceEnum.eventlog)
        self.assertEqual(event.action, ActionEnum.PROCESS_STARTED)
        self.assertEqual(event.entity_type, EntityTypeEnum.process)
        self.assertEqual(event.entity, "E:\\reports\\payload.exe")
        self.assertEqual(event.details["channel"], "Security")
        self.assertEqual(event.details["event_code"], 4688)
        self.assertEqual(event.event_id, self.eventlog_sample["event_id"])

    def test_unified_dispatcher(self):
        """Test normalize_event dispatches correctly for all three telemetry sources."""
        e_usb = normalize_event("usb", self.usb_arrival_sample["raw"], ts_utc=self.usb_arrival_sample["ts_utc"])
        e_fs = normalize_event("fs", self.fs_created_sample["raw"], ts_utc=self.fs_created_sample["ts_utc"])
        e_log = normalize_event("eventlog", self.eventlog_sample["raw"], ts_utc=self.eventlog_sample["ts_utc"])

        self.assertEqual(e_usb.source, SourceEnum.usb)
        self.assertEqual(e_fs.source, SourceEnum.fs)
        self.assertEqual(e_log.source, SourceEnum.eventlog)


if __name__ == "__main__":
    unittest.main()
