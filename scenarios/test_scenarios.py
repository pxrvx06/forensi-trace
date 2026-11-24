#!/usr/bin/env python3
"""
test_scenarios.py - Comprehensive Unit & Correlation Engine Tests for Scenarios A, A', B, C & Normal Noise.

Owner: Daksh (Endpoint Agent & Scenarios Owner)
Reference: Build & Execution Plan v2 (Hybrid ML) - Step 3
Contracts: docs/schema.md, docs/rules.yaml, backend/schema.py, engine/correlator.py
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

# Add repo root to path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.schema import Event
from engine.correlator import CorrelationEngine
from scenarios.scenario_a import generate_scenario_a_events, get_ground_truth as gt_a
from scenarios.scenario_a_prime import generate_scenario_a_prime_events, get_ground_truth as gt_a_prime
from scenarios.scenario_b import generate_scenario_b_events, get_ground_truth as gt_b
from scenarios.scenario_c import generate_scenario_c_events, get_ground_truth as gt_c
from scenarios.normal_noise import generate_normal_noise_events, get_ground_truth as gt_noise

GROUND_TRUTH_DIR = REPO_ROOT / "scenarios" / "ground_truth"


class TestScenarios(unittest.TestCase):
    """Unit tests for ForensiTrace Scenarios and Ground Truth contracts."""

    @classmethod
    def setUpClass(cls):
        cls.engine = CorrelationEngine()

    def test_01_ground_truth_files_exist_and_have_required_metadata(self):
        """Verify all ground truth JSON files exist with proper schema and metadata."""
        expected_files = [
            "scenario_a.json",
            "scenario_a_prime.json",
            "scenario_b.json",
            "scenario_c.json",
            "normal_noise.json",
        ]
        required_fields = {
            "scenario_id",
            "name",
            "label",
            "description",
            "expected_rules",
            "expected_threat_level",
            "event_count",
            "events",
        }

        for filename in expected_files:
            file_path = GROUND_TRUTH_DIR / filename
            self.assertTrue(file_path.exists(), f"Missing ground truth file: {filename}")
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for field in required_fields:
                self.assertIn(field, data, f"{filename} missing field '{field}'")

            self.assertIsInstance(data["events"], list)
            self.assertEqual(len(data["events"]), data["event_count"])
            self.assertGreater(data["event_count"], 0)

    def test_02_ground_truth_labels_match_plan(self):
        """Verify ground truth labels conform to Plan v2 (Step 3 specification)."""
        scenarios_labels = {
            "scenario_a.json": "malicious",
            "scenario_a_prime.json": "malicious",
            "scenario_b.json": "malicious",
            "scenario_c.json": "malicious",
            "normal_noise.json": "normal",
        }

        for filename, expected_label in scenarios_labels.items():
            file_path = GROUND_TRUTH_DIR / filename
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(
                data["label"],
                expected_label,
                f"{filename} label mismatch: expected '{expected_label}', got '{data['label']}'",
            )

    def test_03_all_scenario_events_conform_to_pydantic_schema(self):
        """Verify all scenario events pass backend.schema.Event strict validation."""
        for filename in ["scenario_a.json", "scenario_a_prime.json", "scenario_b.json", "scenario_c.json", "normal_noise.json"]:
            file_path = GROUND_TRUTH_DIR / filename
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for idx, ev_dict in enumerate(data["events"]):
                try:
                    event_obj = Event(**ev_dict)
                    self.assertIsInstance(event_obj, Event)
                except Exception as e:
                    self.fail(f"{filename}[{idx}] failed Event validation: {e}")

    def test_04_scenario_a_detection(self):
        """Verify Scenario A triggers rules R1, R2, and composite R7."""
        events = generate_scenario_a_events()
        results = self.engine.correlate_events(events)
        detected_rules = {r.activity.rule_id for r in results}

        self.assertIn("R1", detected_rules, "Scenario A must trigger R1 (Device arrival followed by file activity)")
        self.assertIn("R2", detected_rules, "Scenario A must trigger R2 (File created followed by execution)")
        self.assertIn("R7", detected_rules, "Scenario A must trigger R7 (Composite USB copy and execution chain)")

    def test_05_scenario_a_prime_detection(self):
        """Verify Scenario A' triggers rule R2, but evades direct removable execution R7."""
        events = generate_scenario_a_prime_events()
        results = self.engine.correlate_events(events)
        detected_rules = {r.activity.rule_id for r in results}

        self.assertIn("R2", detected_rules, "Scenario A' must trigger R2 (File creation followed by execution)")
        self.assertNotIn("R7", detected_rules, "Scenario A' must NOT trigger R7 (execution was hosted on C:, not USB)")

    def test_06_scenario_b_detection(self):
        """Verify Scenario B triggers rules R1, R2, and R7."""
        events = generate_scenario_b_events()
        results = self.engine.correlate_events(events)
        detected_rules = {r.activity.rule_id for r in results}

        self.assertIn("R1", detected_rules, "Scenario B must trigger R1")
        self.assertIn("R2", detected_rules, "Scenario B must trigger R2")
        self.assertIn("R7", detected_rules, "Scenario B must trigger R7")

    def test_07_scenario_c_detection(self):
        """Verify Scenario C triggers rules R4 (burst), R5 (log cleared), and R6 (timestomp)."""
        events = generate_scenario_c_events()
        results = self.engine.correlate_events(events)
        detected_rules = {r.activity.rule_id for r in results}

        self.assertIn("R4", detected_rules, "Scenario C must trigger R4 (Bulk file creation on removable drive)")
        self.assertIn("R5", detected_rules, "Scenario C must trigger R5 (Log clearing near activity)")
        self.assertIn("R6", detected_rules, "Scenario C must trigger R6 (Timestamp disagreement)")

    def test_08_normal_noise_produces_no_malicious_activities(self):
        """Verify Normal Noise produces zero malicious activity detections (negative control)."""
        events = generate_normal_noise_events()
        results = self.engine.correlate_events(events)
        self.assertEqual(
            len(results),
            0,
            f"Normal noise must produce 0 detected activities, but produced: {[r.activity.rule_id for r in results]}",
        )

    def test_09_synthetic_labeling_across_scenarios(self):
        """Verify all scenario events carry is_synthetic: True and dataset_type: 'scenario'."""
        for fn in [generate_scenario_a_events, generate_scenario_a_prime_events, generate_scenario_b_events, generate_scenario_c_events, generate_normal_noise_events]:
            events = fn()
            for ev in events:
                details = ev.get("details", {})
                self.assertTrue(details.get("is_synthetic") is True)
                self.assertEqual(details.get("dataset_type"), "scenario")


if __name__ == "__main__":
    unittest.main()
