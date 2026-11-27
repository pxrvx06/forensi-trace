#!/usr/bin/env python3
"""
test_experiment.py - Unit Tests for Human Experiment Analysis Script (Phase 3 Step 6).
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scenarios.experiment.analyze_experiment import (
    format_markdown_summary,
    load_and_analyze_csv,
)


class TestExperimentAnalysis(unittest.TestCase):
    """Tests CSV parsing and descriptive metrics calculation."""

    def test_01_analyze_synthetic_trial_csv(self):
        csv_content = (
            "participant_id,run_order,tool,scenario,time_seconds,q1_usb_device,q2_files_copied,q3_user_account,q4_logs_cleared,q5_event_order,notes\n"
            "P01,1,Event Viewer,scenario_a,240.0,1,1,0,1,0,slow search\n"
            "P01,2,ForensiTrace,scenario_a_prime,60.0,1,1,1,1,1,clear timeline\n"
            "P02,1,ForensiTrace,scenario_a,80.0,1,1,1,1,1,\n"
            "P02,2,Event Viewer,scenario_a_prime,200.0,1,0,1,1,0,\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "sample.csv"
            csv_path.write_text(csv_content, encoding="utf-8")

            summary = load_and_analyze_csv(csv_path)
            self.assertEqual(summary["unique_participants"], 2)
            self.assertEqual(summary["total_runs"], 4)

            ev = summary["tools"]["Event Viewer"]
            self.assertEqual(ev["avg_time_seconds"], 220.0)
            self.assertEqual(ev["avg_correct_out_of_5"], 3.0)
            self.assertEqual(ev["accuracy_pct"], 60.0)

            ft = summary["tools"]["ForensiTrace"]
            self.assertEqual(ft["avg_time_seconds"], 70.0)
            self.assertEqual(ft["avg_correct_out_of_5"], 5.0)
            self.assertEqual(ft["accuracy_pct"], 100.0)

            md = format_markdown_summary(summary)
            self.assertIn("Event Viewer", md)
            self.assertIn("ForensiTrace", md)
            self.assertIn("without claiming statistical significance", md)

    def test_02_missing_csv_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_and_analyze_csv(Path("nonexistent_experiment_results.csv"))


if __name__ == "__main__":
    unittest.main()
