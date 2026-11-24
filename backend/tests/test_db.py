"""
Unit Tests for SQLite Data Access Layer & Deduplication
Author: Purva
Validates: backend/db.py against Step 2 requirements
"""

import json
import tempfile
import unittest
from pathlib import Path

from backend.schema import Event, Activity, ActivityEventLink
from backend.db import (
    init_db,
    reset_db,
    insert_event,
    insert_events_batch,
    get_event_by_id,
    get_events,
    get_events_in_window,
    insert_activity,
    get_activities,
    get_activity_by_id,
    get_timeline
)


class TestDatabaseLayer(unittest.TestCase):
    def setUp(self):
        # Create an isolated temporary SQLite database for each test
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_forensitrace.db"
        init_db(self.db_path)

        # Load the 3 validated example JSON files
        examples_dir = Path(__file__).resolve().parent.parent.parent / "docs" / "examples"
        self.sample_events = []
        for name in ["usb_event.json", "fs_event.json", "eventlog_event.json"]:
            path = examples_dir / name
            with open(path, "r", encoding="utf-8") as f:
                self.sample_events.append(json.load(f))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_single_insert_and_retrieval(self):
        """Test inserting a single event and retrieving it by ID."""
        event_data = self.sample_events[0]
        inserted = insert_event(event_data, db_path=self.db_path)
        self.assertTrue(inserted, "First insert should return True")

        # Duplicate insert must be ignored
        duplicate = insert_event(event_data, db_path=self.db_path)
        self.assertFalse(duplicate, "Duplicate insert should return False and be ignored")

        # Retrieve and verify fields
        retrieved = get_event_by_id(event_data["event_id"], db_path=self.db_path)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["event_id"], event_data["event_id"])
        self.assertEqual(retrieved["source"], "usb")
        self.assertEqual(retrieved["action"], "DEVICE_ARRIVED")
        self.assertEqual(retrieved["details"]["drive_letter"], "E:")

    def test_batch_insert_and_deduplication(self):
        """Test batch insertion and verify that duplicates are ignored."""
        # 1. First batch insertion: all 3 should be inserted
        inserted_count, ignored_count = insert_events_batch(self.sample_events, db_path=self.db_path)
        self.assertEqual(inserted_count, 3, "All 3 sample events should be inserted")
        self.assertEqual(ignored_count, 0, "No duplicates should exist initially")

        # 2. Second batch insertion with same events: 0 inserted, 3 ignored
        inserted_count2, ignored_count2 = insert_events_batch(self.sample_events, db_path=self.db_path)
        self.assertEqual(inserted_count2, 0, "Duplicate batch should insert 0 events")
        self.assertEqual(ignored_count2, 3, "Duplicate batch should ignore all 3 events")

        # 3. Verify total stored events is still 3
        all_events = get_events(limit=50, db_path=self.db_path)
        self.assertEqual(len(all_events), 3)

    def test_time_window_query_for_akash_engine(self):
        """Verify get_events_in_window retrieves events in ascending chronological order."""
        insert_events_batch(self.sample_events, db_path=self.db_path)

        # Window spanning entire scenario
        window_events = get_events_in_window(
            ts_start_utc="2026-10-23T10:00:00.000Z",
            ts_end_utc="2026-10-23T10:05:00.000Z",
            db_path=self.db_path
        )
        self.assertEqual(len(window_events), 3)
        self.assertEqual(window_events[0]["source"], "usb")
        self.assertEqual(window_events[1]["source"], "fs")
        self.assertEqual(window_events[2]["source"], "eventlog")

        # Narrow window containing only the file event
        narrow = get_events_in_window(
            ts_start_utc="2026-10-23T10:01:00.000Z",
            ts_end_utc="2026-10-23T10:01:59.000Z",
            db_path=self.db_path
        )
        self.assertEqual(len(narrow), 1)
        self.assertEqual(narrow[0]["action"], "FILE_CREATED")

    def test_activity_insertion_and_evidence_provenance(self):
        """Test storing an activity with its linked evidence events."""
        insert_events_batch(self.sample_events, db_path=self.db_path)

        activity_data = {
            "activity_id": "act_test_001",
            "rule_id": "R7",
            "rule_name": "USB executable copy and launch",
            "ts_start_utc": "2026-10-23T10:00:00.120Z",
            "ts_end_utc": "2026-10-23T10:02:30.800Z",
            "confidence": 0.95,
            "narrative": "USB drive E: inserted, payload.exe written to E:\\reports, and subsequently executed."
        }

        evidence_links = [
            {
                "activity_id": "act_test_001",
                "event_id": self.sample_events[0]["event_id"],
                "rule_id": "R1",
                "reason": "USB drive arrived at mount point E:"
            },
            {
                "activity_id": "act_test_001",
                "event_id": self.sample_events[1]["event_id"],
                "rule_id": "R1",
                "reason": "Binary payload.exe created on removable volume E:"
            },
            {
                "activity_id": "act_test_001",
                "event_id": self.sample_events[2]["event_id"],
                "rule_id": "R2",
                "reason": "Process executed from matching binary path E:\\reports\\payload.exe"
            }
        ]

        act_id = insert_activity(activity_data, evidence_links, db_path=self.db_path)
        self.assertEqual(act_id, "act_test_001")

        # Retrieve activity with evidence chain
        fetched = get_activity_by_id("act_test_001", include_evidence=True, db_path=self.db_path)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["rule_id"], "R7")
        self.assertEqual(len(fetched["evidence_chain"]), 3)
        self.assertEqual(fetched["evidence_chain"][0]["reason"], "USB drive arrived at mount point E:")
        self.assertEqual(fetched["evidence_chain"][1]["reason"], "Binary payload.exe created on removable volume E:")

    def test_activity_ml_fields_and_threat_level(self):
        """Test storing and retrieving activity with ML anomaly score and threat level."""
        activity_data = {
            "activity_id": "act_ml_001",
            "rule_id": "R7",
            "rule_name": "USB executable copy and launch",
            "ts_start_utc": "2026-10-23T10:00:00.120Z",
            "ts_end_utc": "2026-10-23T10:02:30.800Z",
            "confidence": 0.95,
            "narrative": "Suspicious sequence flagged by LSTM Autoencoder and Rule R7.",
            "ml_anomaly_score": 0.88,
            "threat_level": "CRITICAL"
        }
        act_id = insert_activity(activity_data, [], db_path=self.db_path)
        self.assertEqual(act_id, "act_ml_001")

        fetched = get_activity_by_id("act_ml_001", include_evidence=False, db_path=self.db_path)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["ml_anomaly_score"], 0.88)
        self.assertEqual(fetched["threat_level"], "CRITICAL")

    def test_get_timeline_merging(self):
        """Test get_timeline merges events and activities in chronological order."""
        insert_events_batch(self.sample_events, db_path=self.db_path)

        activity_data = {
            "activity_id": "act_timeline_001",
            "rule_id": "R7",
            "rule_name": "USB sequence",
            "ts_start_utc": "2026-10-23T10:01:45.000Z",
            "ts_end_utc": "2026-10-23T10:02:30.800Z",
            "confidence": 0.90,
            "narrative": "Activity occurring between file creation and process start."
        }
        insert_activity(activity_data, [], db_path=self.db_path)

        # Retrieve merged timeline
        timeline = get_timeline(limit=10, db_path=self.db_path)
        # Expected order:
        # 1. usb event (10:00:00.120Z) - event
        # 2. fs event (10:01:15.450Z) - event
        # 3. activity (10:01:45.000Z) - activity
        # 4. eventlog event (10:02:30.800Z) - event
        self.assertEqual(len(timeline), 4)
        self.assertEqual(timeline[0]["type"], "event")
        self.assertEqual(timeline[0]["ts_utc"], "2026-10-23T10:00:00.120Z")
        self.assertEqual(timeline[1]["type"], "event")
        self.assertEqual(timeline[1]["ts_utc"], "2026-10-23T10:01:15.450Z")
        self.assertEqual(timeline[2]["type"], "activity")
        self.assertEqual(timeline[2]["ts_utc"], "2026-10-23T10:01:45.000Z")
        self.assertEqual(timeline[3]["type"], "event")
        self.assertEqual(timeline[3]["ts_utc"], "2026-10-23T10:02:30.800Z")

    def test_reset_db(self):
        """Verify that reset_db clears all data."""
        insert_events_batch(self.sample_events, db_path=self.db_path)
        self.assertEqual(len(get_events(db_path=self.db_path)), 3)

        reset_db(self.db_path)
        self.assertEqual(len(get_events(db_path=self.db_path)), 0)


if __name__ == "__main__":
    unittest.main()
