"""
test_baseline.py - Unit & Schema Verification Tests for Baseline Telemetry Sessions
Author: Daksh (Baseline Data, Scenarios & Experiment Owner)
Contract: docs/schema.md & Phase 3 Plan v2 (Step 1)
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

# Add repo root to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
import sys
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.schema import (
    Event,
    SourceEnum,
    ActionEnum,
    EntityTypeEnum,
    TIMESTAMP_REGEX,
    HEX64_REGEX,
)
from backend.db import init_db, get_events, db_session
from scripts.record_baseline import (
    BASELINE_DIR,
    generate_standard_baseline_sessions,
    save_baseline_sessions,
    load_baseline_sessions_to_db,
)


class TestBaselineTelemetry(unittest.TestCase):
    """Test suite verifying Step 1 baseline dataset compliance and integrity."""

    @classmethod
    def setUpClass(cls):
        cls.baseline_files = sorted(BASELINE_DIR.glob("*.json"))
        if not cls.baseline_files:
            # Generate default baseline sessions if missing
            sessions = generate_standard_baseline_sessions(host="TEST-HOST", user="TEST\\analyst")
            save_baseline_sessions(sessions, output_dir=BASELINE_DIR)
            cls.baseline_files = sorted(BASELINE_DIR.glob("*.json"))

    def test_baseline_sessions_exist(self):
        """Verifies several separate sessions are saved on disk."""
        self.assertGreaterEqual(
            len(self.baseline_files),
            3,
            f"Expected at least 3 distinct baseline sessions, found {len(self.baseline_files)}",
        )

    def test_schema_conformance_all_sessions(self):
        """Verifies every event in every baseline session strictly obeys backend.schema.Event."""
        total_events = 0
        for s_file in self.baseline_files:
            with open(s_file, "r", encoding="utf-8") as f:
                events = json.load(f)
            self.assertIsInstance(events, list, f"File {s_file.name} must contain a JSON list of events")
            self.assertGreater(len(events), 0, f"File {s_file.name} must not be empty")

            for idx, raw_ev in enumerate(events):
                try:
                    event_obj = Event.model_validate(raw_ev)
                except Exception as exc:
                    self.fail(f"Event #{idx} in {s_file.name} failed schema validation: {exc}")

                # Verify deterministic hash format
                self.assertRegex(event_obj.event_id, HEX64_REGEX)
                # Verify UTC timestamp format
                self.assertRegex(event_obj.ts_utc, TIMESTAMP_REGEX)
                total_events += 1

        self.assertGreater(total_events, 20, "Total baseline events across sessions should be at least 20")

    def test_session_and_host_metadata(self):
        """Verifies that every event has host and session_id recorded in details."""
        for s_file in self.baseline_files:
            with open(s_file, "r", encoding="utf-8") as f:
                events = json.load(f)

            file_stem = s_file.stem
            for idx, ev in enumerate(events):
                self.assertIn("host", ev, f"Missing host in event #{idx} of {s_file.name}")
                self.assertTrue(ev["host"], f"Empty host in event #{idx} of {s_file.name}")

                details = ev.get("details", {})
                self.assertIn("session_id", details, f"Missing details.session_id in event #{idx} of {s_file.name}")
                self.assertEqual(
                    details["session_id"],
                    file_stem,
                    f"Session ID mismatch in {s_file.name}: expected {file_stem}, got {details['session_id']}",
                )

    def test_ordinary_usb_use_included(self):
        """Verifies ordinary USB usage is included in the baseline per Plan v2 Page 6."""
        found_usb = False
        usb_sessions = []
        for s_file in self.baseline_files:
            with open(s_file, "r", encoding="utf-8") as f:
                events = json.load(f)
            sources = set(e.get("source") for e in events)
            if "usb" in sources:
                found_usb = True
                usb_sessions.append(s_file.name)

        self.assertTrue(
            found_usb,
            "Baseline must contain ordinary USB events so USB use alone is not flagged as anomalous",
        )
        self.assertGreaterEqual(len(usb_sessions), 1)

    def test_database_ingestion_isolated(self):
        """Verifies baseline sessions can be loaded into an isolated SQLite database."""
        temp_dir = Path(tempfile.mkdtemp())
        try:
            temp_db = temp_dir / "test_baseline.db"
            init_db(temp_db)

            ins, ign = load_baseline_sessions_to_db(baseline_dir=BASELINE_DIR, db_path=temp_db)
            self.assertGreater(ins, 0, "Expected new events to be inserted into test DB")

            # Verify records in DB
            db_events = get_events(limit=500, db_path=temp_db)
            self.assertEqual(len(db_events), ins)

            # Re-running ingestion is idempotent
            ins2, ign2 = load_baseline_sessions_to_db(baseline_dir=BASELINE_DIR, db_path=temp_db)
            self.assertEqual(ins2, 0)
            self.assertEqual(ign2, ins)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
