"""
Unit Tests for FastAPI Ingestion & Presentation Endpoints
Author: Purva (Backend & Data Layer Owner)
Contract: Step 4 of Execution Plan ("Agent sends a batch and it appears in the database")
"""

import json
import tempfile
import unittest
from pathlib import Path
from starlette.testclient import TestClient

from backend.main import app
from backend.db import init_db, reset_db


class TestFastAPIBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create an isolated temporary database for test suite
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = Path(cls.temp_dir.name) / "test_api_forensitrace.db"

        # Patch environment variable so db connects to temporary file
        import os
        os.environ["FORENSITRACE_DB_PATH"] = str(cls.test_db_path)
        init_db(cls.test_db_path)

        # TestClient from starlette/fastapi
        cls.client = TestClient(app)

        # Load sample fixtures
        examples_dir = Path(__file__).resolve().parent.parent.parent / "docs" / "examples"
        cls.sample_events = []
        for name in ["usb_event.json", "fs_event.json", "eventlog_event.json"]:
            with open(examples_dir / name, "r", encoding="utf-8") as f:
                cls.sample_events.append(json.load(f))

    @classmethod
    def tearDownClass(cls):
        import os
        os.environ.pop("FORENSITRACE_DB_PATH", None)
        cls.temp_dir.cleanup()

    def setUp(self):
        # Reset database before each test
        reset_db(self.test_db_path)

    def test_health_check(self):
        """Verify GET /health endpoint returns 200 OK."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("timestamp_utc", data)

    def test_ingest_batch_and_query_events(self):
        """
        Verify Step 4 Done Condition:
        Agent sends a batch to POST /events and it appears in the database.
        """
        batch_payload = {
            "events": self.sample_events,
            "batch_size": len(self.sample_events)
        }

        # 1. Post batch
        post_resp = self.client.post("/events", json=batch_payload)
        self.assertEqual(post_resp.status_code, 200)
        res_data = post_resp.json()
        self.assertEqual(res_data["status"], "success")
        self.assertEqual(res_data["received"], 3)
        self.assertEqual(res_data["inserted"], 3)
        self.assertEqual(res_data["duplicates_ignored"], 0)

        # 2. Query GET /events to verify all 3 appear in the database
        get_resp = self.client.get("/events")
        self.assertEqual(get_resp.status_code, 200)
        events_data = get_resp.json()
        self.assertEqual(events_data["count"], 3)
        self.assertEqual(len(events_data["events"]), 3)

        # 3. Verify chronological ordering
        sources = [e["source"] for e in events_data["events"]]
        self.assertEqual(sources, ["usb", "fs", "eventlog"])

    def test_ingest_duplicate_batch_deduplication(self):
        """Verify duplicate events are ignored without error."""
        batch_payload = {"events": self.sample_events}

        # First ingestion
        resp1 = self.client.post("/events", json=batch_payload)
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(resp1.json()["inserted"], 3)

        # Second ingestion with exact same events
        resp2 = self.client.post("/events", json=batch_payload)
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp2.json()["inserted"], 0)
        self.assertEqual(resp2.json()["duplicates_ignored"], 3)

        # Total stored events is still 3
        get_resp = self.client.get("/events")
        self.assertEqual(get_resp.json()["count"], 3)

    def test_filter_events_by_source_and_action(self):
        """Verify GET /events filters."""
        self.client.post("/events", json={"events": self.sample_events})

        # Filter by source: usb
        usb_resp = self.client.get("/events?source=usb")
        self.assertEqual(usb_resp.status_code, 200)
        self.assertEqual(usb_resp.json()["count"], 1)
        self.assertEqual(usb_resp.json()["events"][0]["source"], "usb")

        # Filter by action: FILE_CREATED
        fs_resp = self.client.get("/events?action=FILE_CREATED")
        self.assertEqual(fs_resp.status_code, 200)
        self.assertEqual(fs_resp.json()["count"], 1)
        self.assertEqual(fs_resp.json()["events"][0]["action"], "FILE_CREATED")

    def test_query_events_window(self):
        """Verify GET /events/window for correlation engine."""
        self.client.post("/events", json={"events": self.sample_events})

        resp = self.client.get(
            "/events/window?ts_start_utc=2026-10-23T10:00:00.000Z&ts_end_utc=2026-10-23T10:05:00.000Z"
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["count"], 3)

    def test_get_single_event(self):
        """Verify GET /events/{event_id} returns the event or 404."""
        self.client.post("/events", json={"events": self.sample_events})
        sample_id = self.sample_events[0]["event_id"]

        resp = self.client.get(f"/events/{sample_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["event_id"], sample_id)

        # Non-existent event
        resp_404 = self.client.get("/events/nonexistent_id")
        self.assertEqual(resp_404.status_code, 404)

    def test_schema_validation_rejection(self):
        """Verify invalid events are rejected with HTTP 422."""
        invalid_payload = {
            "events": [
                {
                    "event_id": "short_id",  # Invalid (not 64 hex characters)
                    "source": "usb",
                    "ts_utc": "invalid-time",
                    "host": "WIN-01",
                    "action": "INVALID_ACTION",
                    "entity_type": "device",
                    "entity": "E:",
                    "details": {},
                    "raw": {}
                }
            ]
        }
        resp = self.client.post("/events", json=invalid_payload)
        self.assertEqual(resp.status_code, 422)


if __name__ == "__main__":
    unittest.main()
