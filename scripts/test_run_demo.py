#!/usr/bin/env python3
"""
test_run_demo.py - Unit & Integration Tests for scripts/run_demo.py (Phase 3 Step 4).

Owner: Daksh (Endpoint Agent & Scenarios Owner)
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.db import get_activities, get_timeline
from scripts.run_demo import run_demo


class TestRunDemo(unittest.TestCase):
    """Tests for the one-command ForensiTrace demo runner."""

    def test_01_setup_only_scenario_a_with_ml(self):
        """Verify run_demo(setup_only=True) resets DB, loads ML model, ingests Scenario A, and persists hybrid activities."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "demo_test.db"
            summary = run_demo(
                scenario="scenario_a",
                db_path=db_path,
                open_browser=False,
                start_dashboard=False,
                setup_only=True,
            )

            self.assertEqual(summary["scenario"], "scenario_a")
            self.assertEqual(summary["events_count"], 3)
            self.assertTrue(summary["ml_available"], "Trained ML artifacts should be loaded")
            self.assertGreaterEqual(summary["activities_count"], 3)
            for expected_rule in ("R1", "R2", "R7"):
                self.assertIn(expected_rule, summary["rules_triggered"])

            activities = get_activities(db_path=db_path)
            self.assertEqual(len(activities), summary["activities_count"])
            for act in activities:
                self.assertIsNotNone(act["ml_anomaly_score"])
                self.assertIn(act["threat_level"], ("CRITICAL", "HIGH", "MEDIUM", "LOW"))

            timeline = get_timeline(db_path=db_path)
            self.assertGreaterEqual(len(timeline), 6)

    def test_02_setup_only_normal_noise_produces_zero_activities(self):
        """Verify normal_noise scenario in run_demo produces 0 malicious activities (negative test)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "demo_noise.db"
            summary = run_demo(
                scenario="normal_noise",
                db_path=db_path,
                open_browser=False,
                start_dashboard=False,
                setup_only=True,
            )

            self.assertEqual(summary["scenario"], "normal_noise")
            self.assertEqual(summary["events_count"], 11)
            self.assertEqual(summary["activities_count"], 0)
            self.assertEqual(summary["rules_triggered"], [])

    def test_03_invalid_scenario_raises_value_error(self):
        """Verify unknown scenario name fails cleanly with ValueError."""
        with self.assertRaises(ValueError):
            run_demo(scenario="nonexistent_scenario", setup_only=True)


if __name__ == "__main__":
    unittest.main()
