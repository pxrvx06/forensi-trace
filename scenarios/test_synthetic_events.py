#!/usr/bin/env python3
"""
test_synthetic_events.py - Comprehensive Unit & Schema Tests for ForensiTrace Synthetic Events & Fixtures.

Author: Akash (Correlation Engine & Fixtures Owner)
Task 1: Synthetic Event Generator and Fixtures
Team Contract: docs/schema.md, backend/schema.py

Verifies:
1. Generator runs successfully and produces parsable JSON fixtures.
2. Valid fixtures follow the approved schema (backend.schema.Event and docs/schema.md).
3. Required fields, ISO-8601 millisecond UTC timestamps, and 64-hex event_id formats are strictly enforced.
4. Deterministic event_id recipe (SHA256 of source|raw_record_id|ts_utc) matches.
5. Positive scenario (usb_copy_run.json) has matching drive letter, file path, process path, and forward chronology.
6. Background noise (normal_noise.json) does NOT accidentally form the complete USB-copy-run chain.
7. Edge cases (edge_cases.json) correctly exhibit their intended forensic conditions (no-write, run-without-write,
   mismatched paths, duplicates, out-of-order, boundary timings).
8. Repeated generation produces bit-for-bit identical output (determinism).
9. Invalid inputs (invalid_events.json) produce clear validation errors instead of unhandled exceptions or crashes.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

# Add repo root to sys.path so modules can be imported
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.schema import (
    ALLOWED_ACTIONS_BY_SOURCE,
    Event,
    compute_event_id,
)
from scenarios.generate_synthetic_events import (
    generate_all_fixtures,
    generate_edge_cases,
    generate_invalid_events,
    generate_normal_noise,
    generate_usb_copy_run,
)

FIXTURES_DIR = REPO_ROOT / "scenarios" / "fixtures"
TIMESTAMP_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
HEX64_REGEX = re.compile(r"^[0-9a-f]{64}$")


class TestSyntheticEventGenerator(unittest.TestCase):
    """Unit tests for synthetic event generator functionality and contract conformance."""

    @classmethod
    def setUpClass(cls):
        # Ensure fixtures are generated before test execution
        if not (FIXTURES_DIR / "usb_copy_run.json").exists():
            generate_all_fixtures(FIXTURES_DIR)

    # --------------------------------------------------------------------------
    # 1. Generator Execution and JSON Parsing
    # --------------------------------------------------------------------------
    def test_01_generator_runs_and_fixtures_exist(self):
        """Verify generator creates all four fixture files with valid JSON."""
        expected_files = [
            "usb_copy_run.json",
            "normal_noise.json",
            "edge_cases.json",
            "invalid_events.json",
        ]
        for filename in expected_files:
            file_path = FIXTURES_DIR / filename
            self.assertTrue(file_path.exists(), f"Fixture file missing: {filename}")
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIsInstance(data, list, f"Root element of {filename} must be a list")
            self.assertGreater(len(data), 0, f"Fixture {filename} must not be empty")

    # --------------------------------------------------------------------------
    # 2. Strict Schema Conformance for Valid Fixtures
    # --------------------------------------------------------------------------
    def test_02_valid_fixtures_conform_to_pydantic_schema(self):
        """Verify all events in valid fixtures pass backend.schema.Event validation."""
        valid_files = ["usb_copy_run.json", "normal_noise.json", "edge_cases.json"]
        for filename in valid_files:
            file_path = FIXTURES_DIR / filename
            with open(file_path, "r", encoding="utf-8") as f:
                events = json.load(f)

            for idx, ev_dict in enumerate(events):
                try:
                    event_obj = Event(**ev_dict)
                    self.assertIsInstance(event_obj, Event)
                except Exception as err:
                    self.fail(f"Event in {filename}[{idx}] failed Event validation: {err}")

    # --------------------------------------------------------------------------
    # 3. Required Fields, Timestamps, and SHA-256 Recipe
    # --------------------------------------------------------------------------
    def test_03_required_fields_and_event_id_recipe(self):
        """Verify required fields, timestamp formats, and deterministic event_id hashing."""
        required_keys = {
            "event_id",
            "source",
            "ts_utc",
            "host",
            "action",
            "entity_type",
            "entity",
            "details",
            "raw",
        }
        valid_files = ["usb_copy_run.json", "normal_noise.json", "edge_cases.json"]

        for filename in valid_files:
            with open(FIXTURES_DIR / filename, "r", encoding="utf-8") as f:
                events = json.load(f)

            for idx, ev in enumerate(events):
                # Check field presence
                missing = required_keys - set(ev.keys())
                self.assertFalse(missing, f"{filename}[{idx}] is missing required fields: {missing}")

                # Check timestamp format
                self.assertRegex(
                    ev["ts_utc"],
                    TIMESTAMP_REGEX,
                    f"{filename}[{idx}] ts_utc '{ev['ts_utc']}' must be YYYY-MM-DDTHH:MM:SS.mmmZ",
                )

                # Check event_id format
                self.assertRegex(
                    ev["event_id"],
                    HEX64_REGEX,
                    f"{filename}[{idx}] event_id '{ev['event_id']}' must be 64-char lowercase hex",
                )

                # Check raw_record_id in details
                self.assertIn("raw_record_id", ev["details"], f"{filename}[{idx}] missing details.raw_record_id")
                raw_rec = ev["details"]["raw_record_id"]

                # Check deterministic event_id recipe calculation
                expected_hash = compute_event_id(ev["source"], raw_rec, ev["ts_utc"])
                self.assertEqual(
                    ev["event_id"],
                    expected_hash,
                    f"{filename}[{idx}] event_id does not match SHA256({ev['source']}|{raw_rec}|{ev['ts_utc']})",
                )

                # Check allowed action for source
                allowed_actions = {a.value for a in ALLOWED_ACTIONS_BY_SOURCE[ev["source"]]}
                self.assertIn(
                    ev["action"],
                    allowed_actions,
                    f"{filename}[{idx}] action '{ev['action']}' not permitted for source '{ev['source']}'",
                )

                # Check uppercase drive letter if present
                entity = ev["entity"]
                if len(entity) >= 2 and entity[1] == ":":
                    self.assertTrue(entity[0].isupper(), f"Drive letter in '{entity}' must be uppercase")
                self.assertNotIn("/", entity, f"Windows path '{entity}' cannot use forward slashes")

    # --------------------------------------------------------------------------
    # 4. Scenario A: USB Copy-and-Execute Sequence Verification
    # --------------------------------------------------------------------------
    def test_04_positive_scenario_consistency(self):
        """Verify usb_copy_run.json contains 3 correlated events with matching entity paths."""
        with open(FIXTURES_DIR / "usb_copy_run.json", "r", encoding="utf-8") as f:
            events = json.load(f)

        self.assertEqual(len(events), 3, "usb_copy_run.json must contain exactly 3 sequence events")
        usb_ev, fs_ev, proc_ev = events[0], events[1], events[2]

        # 1. Sources & actions
        self.assertEqual(usb_ev["source"], "usb")
        self.assertEqual(usb_ev["action"], "DEVICE_ARRIVED")
        self.assertEqual(fs_ev["source"], "fs")
        self.assertEqual(fs_ev["action"], "FILE_CREATED")
        self.assertEqual(proc_ev["source"], "eventlog")
        self.assertEqual(proc_ev["action"], "PROCESS_STARTED")

        # 2. Path and drive correlation
        drive_letter = usb_ev["details"]["drive_letter"]
        self.assertEqual(drive_letter, "E:")
        self.assertTrue(fs_ev["entity"].startswith(drive_letter))
        self.assertEqual(fs_ev["entity"], proc_ev["entity"], "File-copy path and process path must match exactly")
        self.assertEqual(proc_ev["entity"], "E:\\reports\\payload.exe")

        # 3. Chronological order progression
        self.assertLess(usb_ev["ts_utc"], fs_ev["ts_utc"], "USB arrival must precede file copy")
        self.assertLess(fs_ev["ts_utc"], proc_ev["ts_utc"], "File copy must precede process start")

    # --------------------------------------------------------------------------
    # 5. Scenario B: Normal Noise False-Positive Safeguards
    # --------------------------------------------------------------------------
    def test_05_noise_does_not_reproduce_positive_sequence(self):
        """Verify normal_noise.json contains background events but NO complete USB-copy-run chain."""
        with open(FIXTURES_DIR / "normal_noise.json", "r", encoding="utf-8") as f:
            noise_events = json.load(f)

        self.assertGreater(len(noise_events), 5)

        # Collect USB drives arrived in noise
        usb_drives = {
            e["details"].get("drive_letter")
            for e in noise_events
            if e["source"] == "usb" and e["action"] == "DEVICE_ARRIVED"
        }

        # Collect file created events
        fs_created_paths = {
            e["entity"]
            for e in noise_events
            if e["source"] == "fs" and e["action"] == "FILE_CREATED"
        }

        # Collect processes started
        proc_started_paths = {
            e["entity"]
            for e in noise_events
            if e["source"] == "eventlog" and e["action"] == "PROCESS_STARTED"
        }

        # Ensure no process was started from a file created on a connected USB drive
        for proc in proc_started_paths:
            if proc in fs_created_paths:
                drive = proc[:2] if len(proc) >= 2 and proc[1] == ":" else ""
                self.assertNotIn(
                    drive,
                    usb_drives,
                    f"Noise scenario should not start a process '{proc}' from a created file on USB drive {drive}",
                )

    # --------------------------------------------------------------------------
    # 6. Scenario C: Edge Cases Verification
    # --------------------------------------------------------------------------
    def test_06_edge_cases_contain_intended_conditions(self):
        """Verify edge_cases.json accurately represents each specified forensic condition."""
        with open(FIXTURES_DIR / "edge_cases.json", "r", encoding="utf-8") as f:
            edge_events = json.load(f)

        notes = [e["details"].get("edge_case_note", "") for e in edge_events]
        boundary_conditions = [e["details"].get("boundary_condition", "") for e in edge_events]

        # Case 1: USB connection without write
        self.assertTrue(any("without subsequent file write" in n for n in notes))

        # Case 2: Process started with no preceding file write
        self.assertTrue(any("without preceding file write event" in n for n in notes))

        # Case 3: Mismatched drive letters
        self.assertTrue(any("Mismatched drive letter" in n for n in notes))

        # Case 4: Duplicate events (identical event_ids)
        event_ids = [e["event_id"] for e in edge_events]
        self.assertGreater(
            len(event_ids),
            len(set(event_ids)),
            "edge_cases.json must contain at least one duplicate event_id to test dedup",
        )

        # Case 5: Out of chronological order events
        timestamps = [e["ts_utc"] for e in edge_events]
        # Check that timestamps in edge_cases are not strictly sorted
        is_sorted = timestamps == sorted(timestamps)
        self.assertFalse(is_sorted, "edge_cases.json must contain out-of-order timestamps to test sorting")

        # Case 6: Time-window boundaries
        self.assertIn("just_inside_window_599s", boundary_conditions)
        self.assertIn("exactly_on_window_boundary_600s", boundary_conditions)
        self.assertIn("just_outside_window_601s", boundary_conditions)

    # --------------------------------------------------------------------------
    # 7. Determinism: Repeated Generation Produces Identical Bytes
    # --------------------------------------------------------------------------
    def test_07_deterministic_reproducibility(self):
        """Verify repeated generator runs produce byte-identical JSON outputs."""
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            generate_all_fixtures(tmp_path)

            for filename in ["usb_copy_run.json", "normal_noise.json", "edge_cases.json", "invalid_events.json"]:
                file_a = (FIXTURES_DIR / filename).read_bytes()
                file_b = (tmp_path / filename).read_bytes()
                self.assertEqual(
                    file_a,
                    file_b,
                    f"Generator output for {filename} is not deterministic across runs!",
                )

    # --------------------------------------------------------------------------
    # 8. Negative Testing: Schema Rejection of Invalid Events
    # --------------------------------------------------------------------------
    def test_08_invalid_events_produce_validation_errors(self):
        """Verify invalid_events.json cases trigger clear validation errors rather than unexpected crashes."""
        from scenarios.generate_synthetic_events import validate_event_dict

        with open(FIXTURES_DIR / "invalid_events.json", "r", encoding="utf-8") as f:
            invalid_cases = json.load(f)

        self.assertGreater(len(invalid_cases), 5)

        for case in invalid_cases:
            name = case["case_name"]
            expected_err = case["expected_error"]
            payload = case["payload"]

            with self.subTest(case=name):
                is_valid, errors = validate_event_dict(payload)
                self.assertFalse(
                    is_valid,
                    f"Case '{name}' should have failed validation, but passed!",
                )
                self.assertGreater(
                    len(errors),
                    0,
                    f"Case '{name}' should report at least one validation error message",
                )
                combined_errors = " ".join(errors).lower()
                self.assertTrue(
                    expected_err.lower() in combined_errors or "validation" in combined_errors,
                    f"Case '{name}' error messages '{errors}' did not contain expected hint '{expected_err}'",
                )


if __name__ == "__main__":
    unittest.main()
