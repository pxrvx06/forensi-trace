"""
Collector Sample Recordings Validation Test Suite
Author: Chetna (USB and File-System Collectors Owner)
Scope: Step 3 (Page 6) - Verifies that all saved sample event files in docs/samples/
strictly adhere to docs/schema.md and can be ingested cleanly by PURVA and AKASH.
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
import unittest

from backend.schema import Event, EventBatch, SourceEnum, ActionEnum, EntityTypeEnum


class TestCollectorSamples(unittest.TestCase):
    """
    Validates all saved sample telemetry files handed to Purva and Akash.
    """

    def setUp(self):
        self.samples_dir = Path(__file__).resolve().parent.parent.parent / "docs" / "samples"
        self.assertTrue(self.samples_dir.is_dir(), f"Samples dir missing: {self.samples_dir}")

    def _load_json(self, filename: str) -> dict:
        filepath = self.samples_dir / filename
        self.assertTrue(filepath.is_file(), f"Sample file missing: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def _verify_event_id_recipe(self, ev_data: dict):
        source = ev_data["source"]
        raw_rec_id = ev_data["details"]["raw_record_id"]
        ts_utc = ev_data["ts_utc"]
        expected_hash = hashlib.sha256(f"{source}|{raw_rec_id}|{ts_utc}".encode("utf-8")).hexdigest()
        self.assertEqual(
            ev_data["event_id"],
            expected_hash,
            f"Event ID mismatch in {ev_data.get('action')} event!",
        )

    # ------------------------------------------------------------------
    # USB Sample Files Verification
    # ------------------------------------------------------------------

    def test_usb_arrival_sample(self):
        """Validates docs/samples/usb_arrival.json schema conformance."""
        data = self._load_json("usb_arrival.json")
        self.assertEqual(data["source"], "usb")
        self.assertEqual(data["action"], "DEVICE_ARRIVED")
        self.assertEqual(data["entity_type"], "device")
        self.assertTrue(data["entity"].startswith("E:"))
        self._verify_event_id_recipe(data)
        event_model = Event(**data)
        self.assertEqual(event_model.action, ActionEnum.DEVICE_ARRIVED)

    def test_usb_removal_sample(self):
        """Validates docs/samples/usb_removal.json schema conformance."""
        data = self._load_json("usb_removal.json")
        self.assertEqual(data["source"], "usb")
        self.assertEqual(data["action"], "DEVICE_REMOVED")
        self.assertEqual(data["entity_type"], "device")
        self._verify_event_id_recipe(data)
        event_model = Event(**data)
        self.assertEqual(event_model.action, ActionEnum.DEVICE_REMOVED)

    def test_usb_samples_batch(self):
        """Validates docs/samples/usb_samples.json as a valid EventBatch payload."""
        data = self._load_json("usb_samples.json")
        batch = EventBatch(**data)
        self.assertEqual(len(batch.events), 2)
        self.assertEqual(batch.batch_size, 2)

    # ------------------------------------------------------------------
    # File-System Sample Files Verification
    # ------------------------------------------------------------------

    def test_fs_created_sample(self):
        """Validates docs/samples/fs_created.json schema conformance."""
        data = self._load_json("fs_created.json")
        self.assertEqual(data["source"], "fs")
        self.assertEqual(data["action"], "FILE_CREATED")
        self.assertEqual(data["entity_type"], "file")
        self.assertIsNone(data["user"])
        self._verify_event_id_recipe(data)
        event_model = Event(**data)
        self.assertEqual(event_model.action, ActionEnum.FILE_CREATED)

    def test_fs_modified_sample(self):
        """Validates docs/samples/fs_modified.json schema conformance."""
        data = self._load_json("fs_modified.json")
        self.assertEqual(data["source"], "fs")
        self.assertEqual(data["action"], "FILE_MODIFIED")
        self._verify_event_id_recipe(data)
        event_model = Event(**data)
        self.assertEqual(event_model.action, ActionEnum.FILE_MODIFIED)

    def test_fs_moved_sample(self):
        """Validates docs/samples/fs_moved.json schema conformance."""
        data = self._load_json("fs_moved.json")
        self.assertEqual(data["source"], "fs")
        self.assertEqual(data["action"], "FILE_MOVED")
        self.assertIn("dest_path", data["details"])
        self._verify_event_id_recipe(data)
        event_model = Event(**data)
        self.assertEqual(event_model.action, ActionEnum.FILE_MOVED)

    def test_fs_deleted_sample(self):
        """Validates docs/samples/fs_deleted.json schema conformance."""
        data = self._load_json("fs_deleted.json")
        self.assertEqual(data["source"], "fs")
        self.assertEqual(data["action"], "FILE_DELETED")
        self._verify_event_id_recipe(data)
        event_model = Event(**data)
        self.assertEqual(event_model.action, ActionEnum.FILE_DELETED)

    def test_fs_samples_batch(self):
        """Validates docs/samples/fs_samples.json as a valid EventBatch payload."""
        data = self._load_json("fs_samples.json")
        batch = EventBatch(**data)
        self.assertEqual(len(batch.events), 4)
        self.assertEqual(batch.batch_size, 4)


if __name__ == "__main__":
    unittest.main()
