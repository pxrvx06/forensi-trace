"""
Unit Tests for Phase 3 ML Evaluation Script
Author: Purva
Validates: backend/evaluate_ml.py (zero leakage across splits, classification metrics, report output)
"""

import unittest
from pathlib import Path

from backend.evaluate_ml import (
    REPO_ROOT,
    compute_classification_metrics,
    load_held_out_test_sessions,
)


class TestEvaluateML(unittest.TestCase):
    def test_classification_metrics_calculation(self):
        """Verify precision, recall, F1, and FPR arithmetic on a known confusion matrix."""
        # TP=3, FP=1, TN=1, FN=1
        preds = [True, True, True, True, False, False]
        truths = [True, True, True, False, False, True]
        m = compute_classification_metrics(preds, truths)

        self.assertEqual(m["tp"], 3)
        self.assertEqual(m["fp"], 1)
        self.assertEqual(m["tn"], 1)
        self.assertEqual(m["fn"], 1)
        self.assertAlmostEqual(m["precision"], 0.75, places=4)
        self.assertAlmostEqual(m["recall"], 0.75, places=4)
        self.assertAlmostEqual(m["f1"], 0.75, places=4)
        self.assertAlmostEqual(m["fpr"], 0.50, places=4)

    def test_held_out_sessions_exclude_train_and_val(self):
        """
        MUST-NOT-FIRE LEAKAGE TEST:
        Ensures load_held_out_test_sessions never includes any session ID
        listed in train or val splits inside threshold_metadata.json.
        """
        artifacts_dir = REPO_ROOT / "engine" / "ml" / "artifacts"
        baseline_dir = REPO_ROOT / "scenarios" / "baseline"
        ground_truth_dir = REPO_ROOT / "scenarios" / "ground_truth"

        test_sessions, threshold_meta = load_held_out_test_sessions(
            artifacts_dir=artifacts_dir,
            baseline_dir=baseline_dir,
            ground_truth_dir=ground_truth_dir,
        )

        splits = threshold_meta.get("additional_metrics", {}).get("splits", {})
        forbidden = set(splits.get("train", [])) | set(splits.get("val", []))
        loaded_ids = {s["session_id"] for s in test_sessions}

        self.assertTrue(
            loaded_ids.isdisjoint(forbidden),
            f"Leakage detected! Found forbidden sessions in test set: {loaded_ids & forbidden}",
        )
        self.assertIn("scenario_a", loaded_ids)
        self.assertIn("normal_noise", loaded_ids)


if __name__ == "__main__":
    unittest.main()
