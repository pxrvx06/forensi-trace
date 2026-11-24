"""
Unit Tests for Feature Extraction, Windowing & Session Splitting Pipeline
Author: Purva
Validates: backend/ml_features.py against docs/ml.md and Step 2 & 3 of Execution Plan
"""

import json
import math
import tempfile
import unittest
from pathlib import Path

from backend.schema import ActionEnum, Event, SourceEnum
from backend.ml_features import (
    FEATURE_DIM,
    NUM_ACTIONS,
    ACTIONS_ORDER,
    extract_event_features,
    create_feature_windows,
    is_executable_entity,
    is_removable_drive,
    partition_sessions_by_recording,
    export_training_data_splits
)


class TestMLFeaturesPipeline(unittest.TestCase):
    def setUp(self):
        # Load sample events from docs/examples
        examples_dir = Path(__file__).resolve().parent.parent.parent / "docs" / "examples"
        self.sample_events = []
        for name in ["usb_event.json", "fs_event.json", "eventlog_event.json"]:
            path = examples_dir / name
            with open(path, "r", encoding="utf-8") as f:
                self.sample_events.append(json.load(f))

    def test_feature_dimension_matches_schema_actions_plus_three(self):
        """
        CRITICAL CONTRACT:
        Verifies vector dimension is dynamic: len(ActionEnum) + 3. Never hard-coded.
        """
        self.assertEqual(NUM_ACTIONS, len(ActionEnum))
        self.assertEqual(FEATURE_DIM, len(ActionEnum) + 3)
        self.assertEqual(FEATURE_DIM, 12)

    def test_feature_extraction_must_fire(self):
        """
        MUST-FIRE TEST:
        An event on removable drive E: creating payload.exe with 60 seconds delta.
        Must fire:
        - One-hot index for FILE_CREATED must be 1.0
        - is_executable flag must be 1.0
        - is_removable flag must be 1.0
        - dt_log must be log(1 + 60.0)
        """
        prev_event = {
            "event_id": "prev000000000000000000000000000000000000000000000000000000000000",
            "source": "usb",
            "ts_utc": "2026-10-23T10:00:00.000Z",
            "host": "WIN-TEST",
            "user": "SYSTEM",
            "action": "DEVICE_ARRIVED",
            "entity_type": "device",
            "entity": "E:",
            "details": {"drive_letter": "E:"},
            "raw": {}
        }

        curr_event = {
            "event_id": "curr000000000000000000000000000000000000000000000000000000000000",
            "source": "fs",
            "ts_utc": "2026-10-23T10:01:00.000Z",  # Exactly 60.0 seconds later
            "host": "WIN-TEST",
            "user": "analyst",
            "action": "FILE_CREATED",
            "entity_type": "file",
            "entity": "E:\\staging\\mimikatz.exe",
            "details": {"drive_letter": "E:"},
            "raw": {}
        }

        vec = extract_event_features(curr_event, prev_event)
        self.assertEqual(len(vec), FEATURE_DIM)

        # 1. Action one-hot check
        created_idx = ACTIONS_ORDER.index(ActionEnum.FILE_CREATED)
        self.assertEqual(vec[created_idx], 1.0, "FILE_CREATED one-hot must fire")
        for idx in range(NUM_ACTIONS):
            if idx != created_idx:
                self.assertEqual(vec[idx], 0.0, f"Action index {idx} must be 0.0")

        # 2. Time delta check: log(1 + 60.0)
        expected_log_dt = math.log(1.0 + 60.0)
        self.assertAlmostEqual(vec[NUM_ACTIONS + 0], expected_log_dt, places=4)

        # 3. Executable flag must fire
        self.assertEqual(vec[NUM_ACTIONS + 1], 1.0, "is_executable must fire for .exe")

        # 4. Removable drive flag must fire
        self.assertEqual(vec[NUM_ACTIONS + 2], 1.0, "is_removable must fire for E: drive")

    def test_feature_extraction_must_not_fire(self):
        """
        MUST-NOT-FIRE TEST:
        Benign non-executable file on system drive C: (C:\\Users\\alice\\notes.txt)
        with zero elapsed time.
        Must NOT fire:
        - is_executable must be 0.0
        - is_removable must be 0.0
        - dt_log must be 0.0
        """
        event = {
            "event_id": "benign0000000000000000000000000000000000000000000000000000000000",
            "source": "fs",
            "ts_utc": "2026-10-23T10:00:00.000Z",
            "host": "WIN-TEST",
            "user": "alice",
            "action": "FILE_MODIFIED",
            "entity_type": "file",
            "entity": "C:\\Users\\alice\\Documents\\notes.txt",
            "details": {"drive_letter": "C:"},
            "raw": {}
        }

        # Extracted without prev_event (delta t = 0)
        vec = extract_event_features(event, prev_event=None)
        self.assertEqual(len(vec), FEATURE_DIM)

        # Time delta must be log(1 + 0) = 0.0
        self.assertEqual(vec[NUM_ACTIONS + 0], 0.0, "dt_log must be 0.0 when no prev event")

        # Executable flag must NOT fire for .txt
        self.assertEqual(vec[NUM_ACTIONS + 1], 0.0, "is_executable must NOT fire for .txt")

        # Removable drive flag must NOT fire for C: drive
        self.assertEqual(vec[NUM_ACTIONS + 2], 0.0, "is_removable must NOT fire for C: drive")

    def test_sliding_window_formulation(self):
        """Test creating sliding windows of size 10 with stride 1."""
        # Synthesize a sequence of 15 events
        events = []
        for i in range(15):
            ev = {
                "event_id": f"event_{i:04d}" + "0" * 54,
                "source": "fs",
                "ts_utc": f"2026-10-23T10:{i:02d}:00.000Z",
                "host": "WIN-TEST",
                "user": "analyst",
                "action": "FILE_MODIFIED",
                "entity_type": "file",
                "entity": f"C:\\test_{i}.log",
                "details": {"drive_letter": "C:"},
                "raw": {}
            }
            events.append(ev)

        windows = create_feature_windows(events, window_size=10, stride=1)
        # 15 events with window size 10 and stride 1 gives 15 - 10 + 1 = 6 windows
        self.assertEqual(len(windows), 6)
        for w in windows:
            matrix = w["feature_matrix"]
            self.assertEqual(len(matrix), 10, "Window length must be exactly 10")
            for row in matrix:
                self.assertEqual(len(row), FEATURE_DIM, f"Row must have {FEATURE_DIM} features")

    def test_short_sequence_left_padding(self):
        """Test left padding when sequence has fewer events than window size."""
        # 3 events < window_size 10
        events = self.sample_events
        self.assertEqual(len(events), 3)

        windows = create_feature_windows(events, window_size=10)
        self.assertEqual(len(windows), 1, "Should produce exactly 1 padded window")
        matrix = windows[0]["feature_matrix"]
        self.assertEqual(len(matrix), 10)

        # First 7 rows must be zero vectors
        for i in range(7):
            self.assertEqual(matrix[i], [0.0] * FEATURE_DIM, f"Row {i} must be zero padded")

        # Last 3 rows must be non-zero
        for i in range(7, 10):
            self.assertTrue(any(v > 0.0 for v in matrix[i]), f"Row {i} should contain event features")

    def test_session_partitioning_disjointness(self):
        """
        CRITICAL ML INTEGRITY TEST:
        Verifies session-based data splitting guarantees zero cross-partition leakage.
        """
        sessions = {
            f"session_{i:02d}": self.sample_events
            for i in range(10)
        }

        splits = partition_sessions_by_recording(sessions, train_ratio=0.7, val_ratio=0.15)
        train_sessions = set(splits["train"])
        val_sessions = set(splits["val"])
        test_sessions = set(splits["test"])

        # 1. Total sessions preserved
        all_split_sessions = train_sessions.union(val_sessions).union(test_sessions)
        self.assertEqual(all_split_sessions, set(sessions.keys()))

        # 2. Strict pairwise disjointness
        self.assertTrue(train_sessions.isdisjoint(val_sessions), "Train and Val must be disjoint")
        self.assertTrue(train_sessions.isdisjoint(test_sessions), "Train and Test must be disjoint")
        self.assertTrue(val_sessions.isdisjoint(test_sessions), "Val and Test must be disjoint")

    def test_export_training_data_splits_to_disk(self):
        """Test exporting split datasets and metadata JSON files to disk."""
        sessions = {
            f"sess_{k}": self.sample_events
            for k in ["01", "02", "03", "04", "05"]
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            result = export_training_data_splits(sessions, output_dir=tmp_dir, window_size=5)

            # Check that files were written
            expected_files = ["train_windows.json", "val_windows.json", "test_windows.json", "split_metadata.json"]
            for fname in expected_files:
                fpath = Path(tmp_dir) / fname
                self.assertTrue(fpath.exists(), f"File {fname} should exist on disk")

                with open(fpath, "r", encoding="utf-8") as f:
                    content = json.load(f)
                    self.assertIn("feature_dim", content)
                    self.assertEqual(content["feature_dim"], FEATURE_DIM)


if __name__ == "__main__":
    unittest.main()
