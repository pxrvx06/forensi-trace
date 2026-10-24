#!/usr/bin/env python3
"""
engine/tests/test_rules.py - Comprehensive Unit Tests for Correlation Engine & Rules R1, R2, R3.

Author: Akash (Correlation Engine & Rules Owner)
Contract: docs/schema.md, docs/rules.yaml, backend/schema.py, backend/db.py
Scope: Task 2 - Correlation Engine and Rules R1, R2, R3
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory

# Add repo root to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.db import (
    get_activities,
    get_activity_by_id,
    init_db,
    insert_events_batch,
    reset_db,
)
from backend.schema import Activity, ActivityEventLink, Event, compute_event_id
from engine.config import RuleDefinition, RulesConfig, load_rules_config
from engine.correlator import (
    CorrelationEngine,
    extract_drive_letter,
    generate_activity_id,
    normalize_windows_path,
)

FIXTURES_DIR = REPO_ROOT / "scenarios" / "fixtures"


def make_test_event(
    source: str,
    ts_utc: str,
    action: str,
    entity: str,
    entity_type: str = "file",
    host: str = "WIN-TEST-01",
    user: str | None = None,
    details: dict | None = None,
    raw: dict | None = None,
    raw_record_id: str | None = None,
) -> dict:
    """Helper to construct valid schema events for testing."""
    d = dict(details or {})
    if raw_record_id is None:
        if source == "fs":
            raw_record_id = f"{action}|{entity}"
        elif source == "usb":
            raw_record_id = d.get("serial_number", f"USB_{entity}")
        else:
            raw_record_id = f"{source}:{action}:{entity}"

    d["raw_record_id"] = raw_record_id
    ev_id = compute_event_id(source, raw_record_id, ts_utc)

    return {
        "event_id": ev_id,
        "source": source,
        "ts_utc": ts_utc,
        "host": host,
        "user": user,
        "action": action,
        "entity_type": entity_type,
        "entity": entity,
        "details": d,
        "raw": raw or {"test": True},
    }


class TestCorrelationRules(unittest.TestCase):
    """Unit tests for Correlation Engine rules R1, R2, R3, windowing, and persistence."""

    def setUp(self):
        self.engine = CorrelationEngine()

    # ==========================================================================
    # RULE R1 TESTS: Device arrival followed by file activity (5 min / 300s)
    # ==========================================================================
    def test_r1_positive_device_arrival_and_file_created(self):
        """R1 fires when file is created on removable drive within 5 minutes."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity="E: (SanDisk USB)",
            details={"drive_letter": "E:", "device_name": "SanDisk"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:02:00.000Z",  # +120s
            action="FILE_CREATED",
            entity_type="file",
            entity="E:\\documents\\invoice.docx",
            details={"drive_letter": "E:"},
        )

        results = self.engine.correlate_events([usb, fs])
        r1_results = [r for r in results if r.activity.rule_id == "R1"]

        self.assertEqual(len(r1_results), 1)
        res = r1_results[0]
        self.assertEqual(res.activity.rule_name, "Device arrival followed by file activity")
        self.assertEqual(res.activity.ts_start_utc, "2026-10-23T10:00:00.000Z")
        self.assertEqual(res.activity.ts_end_utc, "2026-10-23T10:02:00.000Z")
        self.assertEqual(len(res.links), 2)
        link_event_ids = {l.event_id for l in res.links}
        self.assertEqual(link_event_ids, {usb["event_id"], fs["event_id"]})

    def test_r1_positive_device_arrival_and_file_modified(self):
        """R1 fires when file is modified on removable drive within 5 minutes."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity="E: (Kingston DT)",
            details={"drive_letter": "E:"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:04:59.000Z",  # +299s
            action="FILE_MODIFIED",
            entity_type="file",
            entity="E:\\data\\archive.zip",
            details={"drive_letter": "E:"},
        )

        results = self.engine.correlate_events([usb, fs])
        r1_results = [r for r in results if r.activity.rule_id == "R1"]
        self.assertEqual(len(r1_results), 1)

    def test_r1_negative_no_device_arrival(self):
        """R1 must NOT fire if there is no preceding device arrival event."""
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:02:00.000Z",
            action="FILE_CREATED",
            entity="E:\\payload.exe",
            details={"drive_letter": "E:"},
        )
        results = self.engine.correlate_events([fs])
        r1_results = [r for r in results if r.activity.rule_id == "R1"]
        self.assertEqual(len(r1_results), 0)

    def test_r1_negative_file_on_different_drive(self):
        """R1 must NOT fire if file activity is on a different drive than the USB device."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity="E: (Kingston DT)",
            details={"drive_letter": "E:"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:00.000Z",
            action="FILE_CREATED",
            entity="F:\\data\\file.txt",  # Drive F: != E:
            details={"drive_letter": "F:"},
        )
        results = self.engine.correlate_events([usb, fs])
        r1_results = [r for r in results if r.activity.rule_id == "R1"]
        self.assertEqual(len(r1_results), 0)

    def test_r1_negative_file_on_different_host(self):
        """R1 must NOT fire if events originate from different machines."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity="E: (USB)",
            host="HOST-A",
            details={"drive_letter": "E:"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:00.000Z",
            action="FILE_CREATED",
            entity="E:\\data\\file.txt",
            host="HOST-B",
            details={"drive_letter": "E:"},
        )
        results = self.engine.correlate_events([usb, fs])
        r1_results = [r for r in results if r.activity.rule_id == "R1"]
        self.assertEqual(len(r1_results), 0)

    def test_r1_boundaries(self):
        """R1 boundary tests: 0s (fires), 300s (fires), 301s (must not fire)."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity="E: (USB)",
            details={"drive_letter": "E:"},
        )

        # 1. Delta = 0s (exact same second) -> Fires
        fs_0s = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="FILE_CREATED",
            entity="E:\\file0.txt",
            details={"drive_letter": "E:"},
        )
        res_0s = self.engine.correlate_events([usb, fs_0s])
        self.assertEqual(len([r for r in res_0s if r.activity.rule_id == "R1"]), 1)

        # 2. Delta = 300s (exactly 5 minutes) -> Fires
        fs_300s = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:05:00.000Z",
            action="FILE_CREATED",
            entity="E:\\file300.txt",
            details={"drive_letter": "E:"},
        )
        res_300s = self.engine.correlate_events([usb, fs_300s])
        self.assertEqual(len([r for r in res_300s if r.activity.rule_id == "R1"]), 1)

        # 3. Delta = 301s (just outside 5m window) -> Must NOT fire
        fs_301s = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:05:01.000Z",
            action="FILE_CREATED",
            entity="E:\\file301.txt",
            details={"drive_letter": "E:"},
        )
        res_301s = self.engine.correlate_events([usb, fs_301s])
        self.assertEqual(len([r for r in res_301s if r.activity.rule_id == "R1"]), 0)

    # ==========================================================================
    # RULE R2 TESTS: File creation followed by process execution (10 min / 600s)
    # ==========================================================================
    def test_r2_positive_file_creation_and_process_execution(self):
        """R2 fires when process starts from created file path within 10 minutes."""
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:00.000Z",
            action="FILE_CREATED",
            entity_type="file",
            entity="E:\\reports\\payload.exe",
        )
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:02:30.000Z",  # +90s
            action="PROCESS_STARTED",
            entity_type="process",
            entity="E:\\reports\\payload.exe",
        )

        results = self.engine.correlate_events([fs, proc])
        r2_results = [r for r in results if r.activity.rule_id == "R2"]

        self.assertEqual(len(r2_results), 1)
        res = r2_results[0]
        self.assertEqual(res.activity.rule_name, "File creation followed by process execution")
        self.assertEqual(res.activity.ts_start_utc, "2026-10-23T10:01:00.000Z")
        self.assertEqual(res.activity.ts_end_utc, "2026-10-23T10:02:30.000Z")
        self.assertEqual(len(res.links), 2)
        link_event_ids = {l.event_id for l in res.links}
        self.assertEqual(link_event_ids, {fs["event_id"], proc["event_id"]})

    def test_r2_positive_windows_path_case_and_separators(self):
        """R2 matches Windows paths case-insensitively and handles backslashes vs forward slashes."""
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:00.000Z",
            action="FILE_CREATED",
            entity="e:\\Reports\\SubFolder\\Tool.exe",
        )
        # Process start with uppercase drive, different casing, forward slashes
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:03:00.000Z",
            action="PROCESS_STARTED",
            entity="E:/reports/subfolder/tool.exe",
        )

        results = self.engine.correlate_events([fs, proc])
        r2_results = [r for r in results if r.activity.rule_id == "R2"]
        self.assertEqual(len(r2_results), 1, "R2 should match Windows paths case-insensitively")

    def test_r2_negative_mismatched_paths(self):
        """R2 must NOT fire if the process image path differs from the created file path."""
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:00.000Z",
            action="FILE_CREATED",
            entity="E:\\tools\\tool1.exe",
        )
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:02:00.000Z",
            action="PROCESS_STARTED",
            entity="E:\\tools\\tool2.exe",  # Different file!
        )
        results = self.engine.correlate_events([fs, proc])
        r2_results = [r for r in results if r.activity.rule_id == "R2"]
        self.assertEqual(len(r2_results), 0)

    def test_r2_negative_missing_file_creation(self):
        """R2 must NOT fire if there is no preceding file creation event."""
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:02:00.000Z",
            action="PROCESS_STARTED",
            entity="C:\\Windows\\System32\\cmd.exe",
        )
        results = self.engine.correlate_events([proc])
        r2_results = [r for r in results if r.activity.rule_id == "R2"]
        self.assertEqual(len(r2_results), 0)

    def test_r2_boundaries(self):
        """R2 boundary tests: 0s (fires), 600s (fires), 601s (must not fire)."""
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="FILE_CREATED",
            entity="E:\\app.exe",
        )

        # Delta = 600s (exactly 10 min) -> Fires
        proc_600s = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:10:00.000Z",
            action="PROCESS_STARTED",
            entity="E:\\app.exe",
        )
        res_600s = self.engine.correlate_events([fs, proc_600s])
        self.assertEqual(len([r for r in res_600s if r.activity.rule_id == "R2"]), 1)

        # Delta = 601s (just outside 10m window) -> Must NOT fire
        proc_601s = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:10:01.000Z",
            action="PROCESS_STARTED",
            entity="E:\\app.exe",
        )
        res_601s = self.engine.correlate_events([fs, proc_601s])
        self.assertEqual(len([r for r in res_601s if r.activity.rule_id == "R2"]), 0)

    # ==========================================================================
    # RULE R3 TESTS: Process starts from removable drive without preceding write
    # ==========================================================================
    def test_r3_positive_process_from_removable_drive_without_preceding_write(self):
        """R3 fires when process executes from confirmed removable drive with no preceding write."""
        # USB device arrival confirms drive H: is removable
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T11:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity="H: (SanDisk USB)",
            details={"drive_letter": "H:"},
        )
        # Process starts from H: drive 2 minutes later without any file write event
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T11:02:00.000Z",
            action="PROCESS_STARTED",
            entity="H:\\tools\\dump.exe",
        )

        results = self.engine.correlate_events([usb, proc])
        r3_results = [r for r in results if r.activity.rule_id == "R3"]

        self.assertEqual(len(r3_results), 1)
        res = r3_results[0]
        self.assertEqual(res.activity.rule_id, "R3")
        self.assertIn("without preceding", res.activity.rule_name.lower())
        self.assertIn(proc["event_id"], [l.event_id for l in res.links])

    def test_r3_negative_with_matching_preceding_write(self):
        """R3 must NOT fire if a matching write event was observed within the preceding 10 min."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T11:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="H: (SanDisk USB)",
            details={"drive_letter": "H:"},
        )
        fs_write = make_test_event(
            source="fs",
            ts_utc="2026-10-23T11:01:00.000Z",
            action="FILE_CREATED",
            entity="H:\\tools\\dump.exe",
        )
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T11:02:00.000Z",
            action="PROCESS_STARTED",
            entity="H:\\tools\\dump.exe",
        )

        results = self.engine.correlate_events([usb, fs_write, proc])
        r3_results = [r for r in results if r.activity.rule_id == "R3"]
        self.assertEqual(len(r3_results), 0, "R3 must not fire when write was observed")

    def test_r3_negative_non_removable_drive(self):
        """R3 must NOT fire for processes on standard non-removable drives like C:."""
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T11:02:00.000Z",
            action="PROCESS_STARTED",
            entity="C:\\Windows\\System32\\notepad.exe",
        )
        results = self.engine.correlate_events([proc])
        r3_results = [r for r in results if r.activity.rule_id == "R3"]
        self.assertEqual(len(r3_results), 0, "R3 must not fire for C: drive")

    def test_r3_negative_unconfirmed_removability(self):
        """R3 must NOT fire if drive removability cannot be established (do not guess)."""
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T11:02:00.000Z",
            action="PROCESS_STARTED",
            entity="Z:\\tools\\binary.exe",  # No USB arrival for Z: in evidence
        )
        results = self.engine.correlate_events([proc])
        r3_results = [r for r in results if r.activity.rule_id == "R3"]
        self.assertEqual(len(r3_results), 0, "R3 must not guess drive removability without evidence")

    def test_r3_positive_preceding_write_outside_window(self):
        """R3 fires if the write event occurred outside the 10-minute window (e.g. 15 min prior)."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="E: (SanDisk USB)",
            details={"drive_letter": "E:"},
        )
        # Write occurred at 10:05
        fs_old_write = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:05:00.000Z",
            action="FILE_CREATED",
            entity="E:\\tools\\binary.exe",
        )
        # Process starts at 10:20 (15 minutes after write -> > 600s threshold)
        proc_late = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:20:00.000Z",
            action="PROCESS_STARTED",
            entity="E:\\tools\\binary.exe",
        )

        results = self.engine.correlate_events([usb, fs_old_write, proc_late])
        r3_results = [r for r in results if r.activity.rule_id == "R3"]
        self.assertEqual(len(r3_results), 1, "R3 should fire when write is older than the 10-minute window")

    # ==========================================================================
    # CHRONOLOGICAL ORDERING & DEDUPLICATION TESTS
    # ==========================================================================
    def test_out_of_chronological_order_handling(self):
        """Engine must sort events chronologically before evaluation."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="E: (USB)",
            details={"drive_letter": "E:"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:00.000Z",
            action="FILE_CREATED",
            entity="E:\\app.exe",
        )
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:02:00.000Z",
            action="PROCESS_STARTED",
            entity="E:\\app.exe",
        )

        # Supply in reverse order: proc -> fs -> usb
        results = self.engine.correlate_events([proc, fs, usb])
        rule_ids = {r.activity.rule_id for r in results}
        self.assertIn("R1", rule_ids)
        self.assertIn("R2", rule_ids)

    def test_duplicate_events_idempotency(self):
        """Supplying duplicate input events must not create duplicate activities."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="E: (USB)",
            details={"drive_letter": "E:"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:00.000Z",
            action="FILE_CREATED",
            entity="E:\\app.exe",
        )

        # List with duplicates
        events_with_dups = [usb, fs, dict(usb), dict(fs)]
        results = self.engine.correlate_events(events_with_dups)
        r1_results = [r for r in results if r.activity.rule_id == "R1"]
        self.assertEqual(len(r1_results), 1, "Duplicate events should be deduplicated")

    # ==========================================================================
    # YAML CONFIGURATION LOADING TESTS
    # ==========================================================================
    def test_yaml_rules_loading_and_custom_thresholds(self):
        """Verifies loading rules from custom YAML configuration."""
        yaml_content = """
version: "1.0"
rules:
  R1:
    rule_id: "R1"
    name: "Custom R1 Window"
    description: "Custom 60s window"
    enabled: true
    window_seconds: 60
"""
        with NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
            tmp.write(yaml_content)
            tmp_path = Path(tmp.name)

        try:
            cfg = load_rules_config(tmp_path)
            self.assertEqual(cfg.get_window_seconds("R1"), 60)
            custom_engine = CorrelationEngine(rules_config=cfg)

            # Test that 70s delta does not fire with 60s window
            usb = make_test_event(
                source="usb",
                ts_utc="2026-10-23T10:00:00.000Z",
                action="DEVICE_ARRIVED",
                entity="E: (USB)",
                details={"drive_letter": "E:"},
            )
            fs = make_test_event(
                source="fs",
                ts_utc="2026-10-23T10:01:10.000Z",  # +70s
                action="FILE_CREATED",
                entity="E:\\app.exe",
            )
            res = custom_engine.correlate_events([usb, fs])
            self.assertEqual(len([r for r in res if r.activity.rule_id == "R1"]), 0)
        finally:
            if tmp_path.exists():
                os.unlink(tmp_path)

    def test_yaml_missing_file_raises_error(self):
        """Missing rules YAML file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            load_rules_config("non_existent_rules_file.yaml")

    def test_yaml_invalid_content_raises_error(self):
        """Invalid YAML syntax raises ValueError."""
        with NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
            tmp.write("rules: [this is invalid yaml: - :")
            tmp_path = Path(tmp.name)
        try:
            with self.assertRaises(ValueError):
                load_rules_config(tmp_path)
        finally:
            if tmp_path.exists():
                os.unlink(tmp_path)

    # ==========================================================================
    # TASK 1 FIXTURES COMPATIBILITY TESTS
    # ==========================================================================
    def test_task1_usb_copy_run_fixture(self):
        """usb_copy_run.json must fire R1 and R2, but not R3."""
        fixture_path = FIXTURES_DIR / "usb_copy_run.json"
        self.assertTrue(fixture_path.exists(), "Fixture usb_copy_run.json must exist")
        with open(fixture_path, "r", encoding="utf-8") as f:
            events = json.load(f)

        results = self.engine.correlate_events(events)
        rule_ids = [r.activity.rule_id for r in results]
        self.assertIn("R1", rule_ids)
        self.assertIn("R2", rule_ids)
        self.assertNotIn("R3", rule_ids, "R3 should not fire when preceding write exists")

    def test_task1_normal_noise_fixture(self):
        """normal_noise.json must NOT form the complete chain (R2 and R3 must not fire)."""
        fixture_path = FIXTURES_DIR / "normal_noise.json"
        self.assertTrue(fixture_path.exists(), "Fixture normal_noise.json must exist")
        with open(fixture_path, "r", encoding="utf-8") as f:
            events = json.load(f)

        results = self.engine.correlate_events(events)
        rule_ids = [r.activity.rule_id for r in results]
        self.assertNotIn("R2", rule_ids, "R2 must not fire on normal noise")
        self.assertNotIn("R3", rule_ids, "R3 must not fire on normal noise")

    def test_task1_edge_cases_fixture(self):
        """edge_cases.json accurately fires R1, R2, and R3 matching the designed edge conditions."""
        fixture_path = FIXTURES_DIR / "edge_cases.json"
        self.assertTrue(fixture_path.exists(), "Fixture edge_cases.json must exist")
        with open(fixture_path, "r", encoding="utf-8") as f:
            events = json.load(f)

        results = self.engine.correlate_events(events)
        rule_ids = {r.activity.rule_id for r in results}
        self.assertIn("R1", rule_ids)
        self.assertIn("R2", rule_ids)
        self.assertIn("R3", rule_ids)

    # ==========================================================================
    # SQLITE DATABASE PERSISTENCE INTEGRATION (Purva's backend/db.py handoff)
    # ==========================================================================
    def test_database_persistence_integration(self):
        """Correlating events from DB window persists activities and evidence links in SQLite."""
        with TemporaryDirectory() as tmp_dir:
            test_db = Path(tmp_dir) / "test_forensitrace.db"
            init_db(test_db)

            # Insert positive scenario events into SQLite
            fixture_path = FIXTURES_DIR / "usb_copy_run.json"
            with open(fixture_path, "r", encoding="utf-8") as f:
                events = json.load(f)

            inserted, ignored = insert_events_batch(events, db_path=test_db)
            self.assertEqual(inserted, 3)

            # Run engine correlation from DB window
            activity_ids = self.engine.correlate_from_db(
                ts_start_utc="2026-10-23T09:00:00.000Z",
                ts_end_utc="2026-10-23T11:00:00.000Z",
                db_path=test_db,
                persist=True,
            )

            self.assertGreaterEqual(len(activity_ids), 2)

            # Verify persisted activities and evidence chain in SQLite
            db_activities = get_activities(db_path=test_db)
            self.assertEqual(len(db_activities), len(activity_ids))

            for act_id in activity_ids:
                act = get_activity_by_id(act_id, include_evidence=True, db_path=test_db)
                self.assertIsNotNone(act)
                self.assertIn("evidence_chain", act)
                self.assertGreaterEqual(len(act["evidence_chain"]), 2)

            # Test idempotency: re-running on same window does not duplicate DB rows
            activity_ids_2 = self.engine.correlate_from_db(
                ts_start_utc="2026-10-23T09:00:00.000Z",
                ts_end_utc="2026-10-23T11:00:00.000Z",
                db_path=test_db,
                persist=True,
            )
            self.assertEqual(len(get_activities(db_path=test_db)), len(activity_ids))


# ==============================================================================
# RULE R7 TESTS: Composite USB Copy-and-Execution Chain (15 min / 900s)
# ==============================================================================
class TestRuleR7CompositeChain(unittest.TestCase):
    """Unit tests for Rule R7: USB arrival -> file created on USB -> process executed from file."""

    def setUp(self):
        self.engine = CorrelationEngine()

    def test_r7_positive_complete_chain(self):
        """R7 fires when USB arrives, payload is written, and executed within 15 minutes."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity="E: (SanDisk Ultra 4C53000123456789)",
            details={"drive_letter": "E:", "device_name": "SanDisk Ultra", "serial_number": "4C53000123456789"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:15.000Z",  # +75s
            action="FILE_CREATED",
            entity_type="file",
            entity="E:\\reports\\payload.exe",
            details={"drive_letter": "E:", "file_path": "E:\\reports\\payload.exe"},
        )
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:02:30.000Z",  # +150s from USB arrival
            action="PROCESS_STARTED",
            entity_type="process",
            entity="E:\\reports\\payload.exe",
            user="CONTOSO\\analyst",
            details={"process_name": "E:\\reports\\payload.exe"},
        )

        results = self.engine.correlate_events([usb, fs, proc])
        r7_acts = [r for r in results if r.activity.rule_id == "R7"]

        self.assertEqual(len(r7_acts), 1, "Exactly one composite R7 activity must be produced")
        r7 = r7_acts[0]
        self.assertEqual(r7.activity.rule_name, "Composite USB copy and execution chain")
        self.assertEqual(r7.activity.ts_start_utc, "2026-10-23T10:00:00.000Z")
        self.assertEqual(r7.activity.ts_end_utc, "2026-10-23T10:02:30.000Z")
        self.assertGreaterEqual(r7.activity.confidence, 0.95)
        self.assertEqual(len(r7.links), 3, "Must have exactly 3 provenance links (one for each stage)")

        # Verify link reasons and event traceability
        link_map = {l.event_id: l.reason for l in r7.links}
        self.assertIn(usb["event_id"], link_map)
        self.assertIn(fs["event_id"], link_map)
        self.assertIn(proc["event_id"], link_map)
        self.assertIn("Stage 1", link_map[usb["event_id"]])
        self.assertIn("Stage 2", link_map[fs["event_id"]])
        self.assertIn("Stage 3", link_map[proc["event_id"]])

    def test_r7_inclusive_boundary_900s(self):
        """R7 fires when process executes at exactly 900 seconds (inclusive boundary)."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="E: (Flash)",
            details={"drive_letter": "E:"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:05:00.000Z",  # +300s
            action="FILE_CREATED",
            entity="E:\\tool.exe",
            details={"drive_letter": "E:"},
        )
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:15:00.000Z",  # +900s exactly from USB arrival
            action="PROCESS_STARTED",
            entity="E:\\tool.exe",
        )

        results = self.engine.correlate_events([usb, fs, proc])
        r7_acts = [r for r in results if r.activity.rule_id == "R7"]
        self.assertEqual(len(r7_acts), 1, "R7 must fire at exact 900s boundary")

    def test_r7_expired_chain_901s(self):
        """R7 must NOT fire if total chain elapsed time exceeds 900 seconds."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="E: (Flash)",
            details={"drive_letter": "E:"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:05:00.000Z",
            action="FILE_CREATED",
            entity="E:\\tool.exe",
            details={"drive_letter": "E:"},
        )
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:15:01.000Z",  # +901s (> 900s)
            action="PROCESS_STARTED",
            entity="E:\\tool.exe",
        )

        results = self.engine.correlate_events([usb, fs, proc])
        r7_acts = [r for r in results if r.activity.rule_id == "R7"]
        self.assertEqual(len(r7_acts), 0, "R7 must reject chains > 900 seconds")

    def test_r7_incomplete_chains_rejected(self):
        """R7 must NOT fire if any stage of the 3-stage chain is missing."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="E: (USB)",
            details={"drive_letter": "E:"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:00.000Z",
            action="FILE_CREATED",
            entity="E:\\app.exe",
            details={"drive_letter": "E:"},
        )
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:02:00.000Z",
            action="PROCESS_STARTED",
            entity="E:\\app.exe",
        )

        # Missing USB
        res_no_usb = self.engine.correlate_events([fs, proc])
        self.assertEqual(len([r for r in res_no_usb if r.activity.rule_id == "R7"]), 0)

        # Missing FS write
        res_no_fs = self.engine.correlate_events([usb, proc])
        self.assertEqual(len([r for r in res_no_fs if r.activity.rule_id == "R7"]), 0)

        # Missing Process execution
        res_no_proc = self.engine.correlate_events([usb, fs])
        self.assertEqual(len([r for r in res_no_proc if r.activity.rule_id == "R7"]), 0)

    def test_r7_path_mismatch_rejected(self):
        """R7 must NOT fire if executed process path does not match created file path."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="E: (USB)",
            details={"drive_letter": "E:"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:00.000Z",
            action="FILE_CREATED",
            entity="E:\\staged\\malware.exe",
            details={"drive_letter": "E:"},
        )
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:02:00.000Z",
            action="PROCESS_STARTED",
            entity="E:\\staged\\other.exe",  # Path mismatch!
        )

        results = self.engine.correlate_events([usb, fs, proc])
        r7_acts = [r for r in results if r.activity.rule_id == "R7"]
        self.assertEqual(len(r7_acts), 0)

    def test_r7_wrong_host_rejected(self):
        """R7 must NOT fire if events originate from different machines."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            host="HOST-ALPHA",
            action="DEVICE_ARRIVED",
            entity="E: (USB)",
            details={"drive_letter": "E:"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:00.000Z",
            host="HOST-ALPHA",
            action="FILE_CREATED",
            entity="E:\\malware.exe",
            details={"drive_letter": "E:"},
        )
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:02:00.000Z",
            host="HOST-BETA",  # Wrong host!
            action="PROCESS_STARTED",
            entity="E:\\malware.exe",
        )

        results = self.engine.correlate_events([usb, fs, proc])
        r7_acts = [r for r in results if r.activity.rule_id == "R7"]
        self.assertEqual(len(r7_acts), 0)

    def test_r7_out_of_order_and_duplicates_handled(self):
        """R7 handles out-of-order input and avoids duplicate activities."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="E: (USB)",
            details={"drive_letter": "E:"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:00.000Z",
            action="FILE_CREATED",
            entity="E:\\malware.exe",
            details={"drive_letter": "E:"},
        )
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:02:00.000Z",
            action="PROCESS_STARTED",
            entity="E:\\malware.exe",
        )

        # Reverse order with duplicate fs event
        results = self.engine.correlate_events([proc, fs, usb, fs])
        r7_acts = [r for r in results if r.activity.rule_id == "R7"]
        self.assertEqual(len(r7_acts), 1, "Must produce exactly one composite R7 activity")


# ==============================================================================
# RULE R4 TESTS: Bulk File Creation on Removable Drive (60s window)
# ==============================================================================
class TestRuleR4BulkFileCreation(unittest.TestCase):
    """Unit tests for Rule R4: Burst of file creation on removable storage."""

    def setUp(self):
        self.engine = CorrelationEngine()

    def test_r4_positive_burst_detection(self):
        """R4 fires when 5 or more files are created on removable drive within 60s."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T12:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="F: (Kingston Flash)",
            details={"drive_letter": "F:", "device_name": "Kingston"},
        )
        fs_events = [
            make_test_event(
                source="fs",
                ts_utc=f"2026-10-23T12:00:{i * 5:02d}.000Z",  # 0s, 5s, 10s, 15s, 20s (total 20s <= 60s)
                action="FILE_CREATED",
                entity=f"F:\\exfil\\data_{i}.pdf",
                details={"drive_letter": "F:"},
            )
            for i in range(1, 6)
        ]

        results = self.engine.correlate_events([usb] + fs_events)
        r4_acts = [r for r in results if r.activity.rule_id == "R4"]

        self.assertEqual(len(r4_acts), 1)
        r4 = r4_acts[0]
        self.assertEqual(r4.activity.rule_name, "Bulk file creation on removable drive")
        self.assertEqual(r4.activity.ts_start_utc, "2026-10-23T12:00:05.000Z")
        self.assertEqual(r4.activity.ts_end_utc, "2026-10-23T12:00:25.000Z")
        self.assertGreaterEqual(r4.activity.confidence, 0.85)
        # Should link all 5 files + USB arrival evidence
        self.assertGreaterEqual(len(r4.links), 5)

    def test_r4_sub_threshold_rejected(self):
        """R4 must NOT fire if fewer than 5 files (default threshold) are created."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T12:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="F: (Flash)",
            details={"drive_letter": "F:"},
        )
        fs_events = [
            make_test_event(
                source="fs",
                ts_utc=f"2026-10-23T12:00:{i * 5:02d}.000Z",
                action="FILE_CREATED",
                entity=f"F:\\data_{i}.pdf",
                details={"drive_letter": "F:"},
            )
            for i in range(1, 5)  # Only 4 files (< 5)
        ]

        results = self.engine.correlate_events([usb] + fs_events)
        r4_acts = [r for r in results if r.activity.rule_id == "R4"]
        self.assertEqual(len(r4_acts), 0)

    def test_r4_boundary_span_exceeded(self):
        """R4 must NOT group events spanning more than 60 seconds into a single burst."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T12:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="F: (Flash)",
            details={"drive_letter": "F:"},
        )
        # 5 files spread 20 seconds apart: total span 80s (> 60s)
        fs_events = [
            make_test_event(
                source="fs",
                ts_utc=f"2026-10-23T12:{i * 20 // 60:02d}:{i * 20 % 60:02d}.000Z",
                action="FILE_CREATED",
                entity=f"F:\\data_{i}.pdf",
                details={"drive_letter": "F:"},
            )
            for i in range(1, 6)
        ]

        results = self.engine.correlate_events([usb] + fs_events)
        r4_acts = [r for r in results if r.activity.rule_id == "R4"]
        self.assertEqual(len(r4_acts), 0, "Spread of > 60s across 5 files must not trigger 60s burst")

    def test_r4_non_removable_drive_rejected(self):
        """R4 must NOT fire on fixed drives (e.g. C:) without removable evidence."""
        # Files created on C: drive with no USB arrival
        fs_events = [
            make_test_event(
                source="fs",
                ts_utc=f"2026-10-23T12:00:{i * 5:02d}.000Z",
                action="FILE_CREATED",
                entity=f"C:\\temp\\file_{i}.txt",
                details={"drive_letter": "C:"},
            )
            for i in range(1, 6)
        ]
        results = self.engine.correlate_events(fs_events)
        r4_acts = [r for r in results if r.activity.rule_id == "R4"]
        self.assertEqual(len(r4_acts), 0)

    def test_r4_duplicate_events_not_double_counted(self):
        """Duplicate emissions of the same file creation must not inflate burst count."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T12:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="F: (Flash)",
            details={"drive_letter": "F:"},
        )
        # Only 2 distinct files, repeated 3 times each (total 6 events)
        fs_1 = make_test_event(
            source="fs",
            ts_utc="2026-10-23T12:00:05.000Z",
            action="FILE_CREATED",
            entity="F:\\data_1.pdf",
            details={"drive_letter": "F:"},
        )
        fs_2 = make_test_event(
            source="fs",
            ts_utc="2026-10-23T12:00:10.000Z",
            action="FILE_CREATED",
            entity="F:\\data_2.pdf",
            details={"drive_letter": "F:"},
        )
        duplicates = [fs_1, fs_1, fs_1, fs_2, fs_2, fs_2]

        results = self.engine.correlate_events([usb] + duplicates)
        r4_acts = [r for r in results if r.activity.rule_id == "R4"]
        self.assertEqual(len(r4_acts), 0, "Duplicate files must not satisfy min_count threshold")


# ==============================================================================
# RULE R5 TESTS: Log Clearing Near Other Activity (10 min / 600s)
# ==============================================================================
class TestRuleR5LogClearing(unittest.TestCase):
    """Unit tests for Rule R5: LOG_CLEARED within 10 minutes of relevant activity."""

    def setUp(self):
        self.engine = CorrelationEngine()

    def test_r5_positive_log_cleared_after_process(self):
        """R5 fires when Security Log 1102 is cleared within 10 minutes of process start."""
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="PROCESS_STARTED",
            entity="C:\\Windows\\System32\\cmd.exe",
            user="CONTOSO\\attacker",
        )
        clear = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:00:45.000Z",  # +45s
            action="LOG_CLEARED",
            entity="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            user="CONTOSO\\attacker",
            details={"channel": "Security", "event_code": 1102},
        )

        results = self.engine.correlate_events([proc, clear])
        r5_acts = [r for r in results if r.activity.rule_id == "R5"]

        self.assertEqual(len(r5_acts), 1)
        r5 = r5_acts[0]
        self.assertEqual(r5.activity.rule_name, "Log clearing near other activity")
        self.assertEqual(len(r5.links), 2)
        narrative_lower = r5.activity.narrative.lower()
        self.assertTrue(
            "anti-forensics" in narrative_lower or "review" in narrative_lower or "routine maintenance" in narrative_lower,
            f"Narrative should contain cautious review wording: {r5.activity.narrative}"
        )


    def test_r5_positive_log_cleared_before_activity(self):
        """R5 fires when log is cleared within 10 minutes preceding file activity."""
        clear = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="LOG_CLEARED",
            entity="C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
            details={"channel": "System", "event_code": 104},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:05:00.000Z",  # +300s
            action="FILE_CREATED",
            entity="E:\\payload.exe",
            details={"drive_letter": "E:"},
        )

        results = self.engine.correlate_events([clear, fs])
        r5_acts = [r for r in results if r.activity.rule_id == "R5"]
        self.assertEqual(len(r5_acts), 1)

    def test_r5_boundary_600s_inclusive(self):
        """R5 fires at exactly 600s boundary."""
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="PROCESS_STARTED",
            entity="C:\\Windows\\System32\\calc.exe",
        )
        clear = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:10:00.000Z",  # +600s exactly
            action="LOG_CLEARED",
            entity="Security.evtx",
            details={"channel": "Security", "event_code": 1102},
        )
        results = self.engine.correlate_events([proc, clear])
        r5_acts = [r for r in results if r.activity.rule_id == "R5"]
        self.assertEqual(len(r5_acts), 1)

    def test_r5_expired_601s_rejected(self):
        """R5 must NOT fire if log cleared > 600 seconds after activity."""
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="PROCESS_STARTED",
            entity="C:\\Windows\\System32\\calc.exe",
        )
        clear = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:10:01.000Z",  # +601s
            action="LOG_CLEARED",
            entity="Security.evtx",
            details={"channel": "Security", "event_code": 1102},
        )
        results = self.engine.correlate_events([proc, clear])
        r5_acts = [r for r in results if r.activity.rule_id == "R5"]
        self.assertEqual(len(r5_acts), 0)

    def test_r5_different_host_rejected(self):
        """R5 must NOT fire if log clearing and activity occur on different hosts."""
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:00:00.000Z",
            host="HOST-A",
            action="PROCESS_STARTED",
            entity="C:\\app.exe",
        )
        clear = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:00:30.000Z",
            host="HOST-B",  # Different host!
            action="LOG_CLEARED",
            entity="Security.evtx",
            details={"channel": "Security", "event_code": 1102},
        )
        results = self.engine.correlate_events([proc, clear])
        r5_acts = [r for r in results if r.activity.rule_id == "R5"]
        self.assertEqual(len(r5_acts), 0)


# ==============================================================================
# RULE R6 TESTS: Timestamp Disagreement (> 120s threshold)
# ==============================================================================
class TestRuleR6TimestampDiscrepancy(unittest.TestCase):
    """Unit tests for Rule R6: Discrepancy between mtime and collector observation time."""

    def setUp(self):
        self.engine = CorrelationEngine()

    def test_r6_positive_discrepancy_above_threshold(self):
        """R6 fires when reported mtime differs from collector observation time by > 120s."""
        ev = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:00:00.000Z",  # Reported mtime
            action="FILE_MODIFIED",
            entity="E:\\suspicious.dll",
            details={
                "drive_letter": "E:",
                "mtime_utc": "2026-10-23T10:00:00.000Z",
                "ts_observed_utc": "2026-10-23T11:00:00.000Z",  # Observed 3600s later
            },
        )
        results = self.engine.correlate_events([ev])
        r6_acts = [r for r in results if r.activity.rule_id == "R6"]

        self.assertEqual(len(r6_acts), 1)
        r6 = r6_acts[0]
        self.assertEqual(r6.activity.rule_name, "Timestamp disagreement")
        self.assertGreaterEqual(r6.activity.confidence, 0.85)
        self.assertEqual(len(r6.links), 1)
        self.assertIn("3600s", r6.links[0].reason)

    def test_r6_boundary_120s_not_triggered(self):
        """R6 must NOT fire if discrepancy is exactly 120.0s (boundary is strictly > 120s)."""
        ev = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="FILE_CREATED",
            entity="E:\\test.txt",
            details={
                "drive_letter": "E:",
                "mtime_utc": "2026-10-23T10:00:00.000Z",
                "ts_observed_utc": "2026-10-23T10:02:00.000Z",  # Exactly 120s difference
            },
        )
        results = self.engine.correlate_events([ev])
        r6_acts = [r for r in results if r.activity.rule_id == "R6"]
        self.assertEqual(len(r6_acts), 0, "Exact 120.0s difference must not trigger strictly > 120s threshold")

    def test_r6_boundary_121s_triggered(self):
        """R6 fires when discrepancy is 121 seconds (> 120s)."""
        ev = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="FILE_CREATED",
            entity="E:\\test.txt",
            details={
                "drive_letter": "E:",
                "mtime_utc": "2026-10-23T10:00:00.000Z",
                "ts_observed_utc": "2026-10-23T10:02:01.000Z",  # 121s (> 120s)
            },
        )
        results = self.engine.correlate_events([ev])
        r6_acts = [r for r in results if r.activity.rule_id == "R6"]
        self.assertEqual(len(r6_acts), 1)

    def test_r6_normal_timestamps_5s(self):
        """R6 must NOT fire for normal timestamp differences within tolerance (e.g. 5s)."""
        ev = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="FILE_CREATED",
            entity="E:\\normal.txt",
            details={
                "drive_letter": "E:",
                "mtime_utc": "2026-10-23T10:00:00.000Z",
                "ts_observed_utc": "2026-10-23T10:00:05.000Z",  # 5s difference
            },
        )
        results = self.engine.correlate_events([ev])
        r6_acts = [r for r in results if r.activity.rule_id == "R6"]
        self.assertEqual(len(r6_acts), 0)

    def test_r6_missing_observation_timestamp_skipped_safely(self):
        """Events without ts_observed_utc must be skipped safely without throwing exceptions."""
        ev = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="FILE_CREATED",
            entity="E:\\normal.txt",
            details={"drive_letter": "E:"},  # No ts_observed_utc
        )
        results = self.engine.correlate_events([ev])
        r6_acts = [r for r in results if r.activity.rule_id == "R6"]
        self.assertEqual(len(r6_acts), 0)

    def test_r6_malformed_timestamp_handled_safely(self):
        """Malformed timestamp strings in ts_observed_utc must not crash the engine."""
        ev = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="FILE_CREATED",
            entity="E:\\normal.txt",
            details={
                "drive_letter": "E:",
                "ts_observed_utc": "invalid-datetime-string",
            },
        )
        results = self.engine.correlate_events([ev])
        r6_acts = [r for r in results if r.activity.rule_id == "R6"]
        self.assertEqual(len(r6_acts), 0)


# ==============================================================================
# CONFIDENCE SCORING & EVIDENCE PROVENANCE TESTS
# ==============================================================================
class TestConfidenceAndProvenance(unittest.TestCase):
    """Unit tests for confidence scoring determinism, evidence provenance, and plain-English narratives."""

    def setUp(self):
        self.engine = CorrelationEngine()

    def test_confidence_bounded_and_deterministic(self):
        """Verify confidence scores are deterministically between 0.0 and 1.0."""
        from engine.scoring import compute_confidence

        for rule in ["R1", "R2", "R3", "R4", "R5", "R6", "R7"]:
            score_1, factors_1 = compute_confidence(rule, [])
            score_2, factors_2 = compute_confidence(rule, [])
            self.assertEqual(score_1, score_2)
            self.assertGreaterEqual(score_1, 0.0)
            self.assertLessEqual(score_1, 1.0)
            self.assertGreater(len(factors_1), 0)

    def test_narratives_cite_event_ids(self):
        """Verify plain-English narratives cite the actual supporting event IDs."""
        usb = make_test_event(
            source="usb",
            ts_utc="2026-10-23T10:00:00.000Z",
            action="DEVICE_ARRIVED",
            entity="E: (USB)",
            details={"drive_letter": "E:"},
        )
        fs = make_test_event(
            source="fs",
            ts_utc="2026-10-23T10:01:00.000Z",
            action="FILE_CREATED",
            entity="E:\\tool.exe",
            details={"drive_letter": "E:"},
        )
        proc = make_test_event(
            source="eventlog",
            ts_utc="2026-10-23T10:02:00.000Z",
            action="PROCESS_STARTED",
            entity="E:\\tool.exe",
        )

        results = self.engine.correlate_events([usb, fs, proc])
        for r in results:
            self.assertIsNotNone(r.activity.narrative)
            # Narrative or links must cite the short event id
            cited = any(e["event_id"][:8] in r.activity.narrative for e in [usb, fs, proc])
            self.assertTrue(cited, f"Narrative '{r.activity.narrative}' should cite supporting event IDs")


# ==============================================================================
# FALSE POSITIVE EVALUATION & TUNING TESTS
# ==============================================================================
class TestFalsePositiveEvaluation(unittest.TestCase):
    """Evaluates rules against normal background noise and real recorded collector samples."""

    def setUp(self):
        self.engine = CorrelationEngine()

    def test_noise_produces_no_suspicious_detections(self):
        """normal_noise.json contains benign everyday activity and must NOT fire R7, R4, R5, or R6."""
        with open(FIXTURES_DIR / "normal_noise.json", "r", encoding="utf-8") as f:
            noise_events = json.load(f)

        results = self.engine.correlate_events(noise_events)
        rule_ids = {r.activity.rule_id for r in results}

        # Benign noise must not fire composite attack chain R7
        self.assertNotIn("R7", rule_ids, "normal_noise.json must not trigger Rule R7 composite chain")

        # Benign noise must not fire bulk file creation R4
        self.assertNotIn("R4", rule_ids, "normal_noise.json must not trigger Rule R4 bulk creation")

        # Benign noise must not fire log clearing R5
        self.assertNotIn("R5", rule_ids, "normal_noise.json must not trigger Rule R5 log clearing")

        # Benign noise must not fire timestamp disagreement R6
        self.assertNotIn("R6", rule_ids, "normal_noise.json must not trigger Rule R6 timestamp disagreement")

    def test_real_collector_samples_execute_cleanly(self):
        """Real USB and FS collector recordings in docs/samples/ parse and execute through engine without error."""
        samples_dir = REPO_ROOT / "docs" / "samples"
        for sample_file in ["usb_samples.json", "fs_samples.json"]:
            path = samples_dir / sample_file
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                events = data.get("events", data) if isinstance(data, dict) else data
                results = self.engine.correlate_events(events)
                self.assertIsInstance(results, list)


if __name__ == "__main__":
    unittest.main()
