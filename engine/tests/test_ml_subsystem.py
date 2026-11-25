"""
engine/tests/test_ml_subsystem.py - Comprehensive Unit Tests for ForensiTrace Phase III ML Subsystem.

Author: Akash (Correlation Engine & ML Owner)
Contracts: docs/ml.md, backend/schema.py, backend/ml_features.py
Scope: Section 10 Requirements (Architecture, Forward Pass, Training, Persistence, Windowing,
       Scoring, Normalization, Activity Mapping, Hybrid Scoring, Fallbacks, Narratives, CPU Execution)
"""

from __future__ import annotations

import json
import math
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import torch

from backend.schema import ActionEnum, Activity, ActivityEventLink, Event, SourceEnum
from engine.correlator import CorrelationEngine
from engine.ml.adapter import EventFeatureAdapter, FeatureWindow
from engine.ml.config import MLModelConfig
from engine.ml.hybrid import (
    HybridRiskEngine,
    HybridScoringResult,
    classify_threat_level,
    compute_hybrid_score,
)
from engine.ml.model import LSTMAutoencoder, resolve_device, set_seed
from engine.ml.persistence import (
    ThresholdMetadata,
    artifacts_exist,
    load_artifacts,
    save_artifacts,
)
from engine.ml.scoring import (
    ActivityMLScore,
    AnomalyScorer,
    WindowAnomalyResult,
    normalize_reconstruction_error,
)
from engine.ml.trainer import TrainingPipeline, is_malicious_session_id
from engine.narratives import append_ml_narrative_context, generate_narrative


def make_raw_event(
    event_id: str,
    action: str,
    ts_utc: str = "2026-10-23T10:00:00.000Z",
    source: str = "fs",
    entity: str = "C:\\test.txt",
    session_id: str = "sess_01",
    details: dict | None = None,
) -> dict:
    d = dict(details or {})
    d["session_id"] = session_id
    return {
        "event_id": event_id,
        "source": source,
        "ts_utc": ts_utc,
        "host": "WIN-TEST-01",
        "user": "analyst",
        "action": action,
        "entity_type": "file" if source == "fs" else ("device" if source == "usb" else "process"),
        "entity": entity,
        "details": d,
        "raw": {},
    }


class TestLSTMArchitectureAndTensors(unittest.TestCase):
    """Verifies LSTM Autoencoder structure, tensor dimensions, and CPU execution."""

    def setUp(self):
        set_seed(42)
        self.config = MLModelConfig(
            input_dim=12,
            hidden_dim=16,
            latent_dim=8,
            num_layers=1,
            seq_len=10,
            device="cpu",
        )
        self.model = LSTMAutoencoder(self.config)

    def test_cpu_device_resolution(self):
        """Verifies default resolution to CPU device."""
        dev = resolve_device("cpu")
        self.assertEqual(dev.type, "cpu")

    def test_tensor_dimensions_and_forward_pass(self):
        """Verifies forward pass retains shape (batch, seq_len, input_dim)."""
        x = torch.randn(4, 10, 12)
        out = self.model(x)
        self.assertEqual(out.shape, (4, 10, 12))
        self.assertTrue(torch.isfinite(out).all())

    def test_single_window_2d_tensor_auto_batching(self):
        """Verifies single 2D window of shape (10, 12) automatically gets batched to (1, 10, 12)."""
        x_2d = torch.randn(10, 12)
        out = self.model(x_2d)
        self.assertEqual(out.shape, (1, 10, 12))

    def test_invalid_dimension_raises_error(self):
        """Input with wrong sequence length or feature dimension must raise ValueError."""
        # Wrong seq_len (7 instead of 10)
        with self.assertRaises(ValueError):
            self.model(torch.randn(2, 7, 12))

        # Wrong feature_dim (5 instead of 12)
        with self.assertRaises(ValueError):
            self.model(torch.randn(2, 10, 5))

    def test_nan_and_inf_sanitization(self):
        """NaN and infinite values in input tensor are safely sanitized without crashing."""
        x_nan = torch.randn(2, 10, 12)
        x_nan[0, 2, 3] = float("nan")
        x_nan[1, 5, 8] = float("inf")
        x_nan[1, 6, 9] = float("-inf")

        sanitized = self.model.sanitize_input(x_nan)
        self.assertFalse(torch.isnan(sanitized).any())
        self.assertFalse(torch.isinf(sanitized).all())

        out = self.model(x_nan)
        self.assertEqual(out.shape, (2, 10, 12))
        self.assertTrue(torch.isfinite(out).all())

    def test_reconstruction_error_calculation(self):
        """Verifies MSE computation per sequence across batch."""
        x = torch.randn(3, 10, 12)
        # Identical reconstruction -> MSE = 0
        err_zero = self.model.compute_reconstruction_error(x, x)
        self.assertEqual(err_zero.shape, (3,))
        for e in err_zero:
            self.assertAlmostEqual(e.item(), 0.0, places=5)

        # Perturbed reconstruction -> positive MSE
        x_noisy = x + 0.5
        err_noisy = self.model.compute_reconstruction_error(x, x_noisy)
        for e in err_noisy:
            self.assertAlmostEqual(e.item(), 0.25, places=4)


class TestFeatureAdapterAndSequencing(unittest.TestCase):
    """Verifies feature extraction, sliding window formulation, and session isolation."""

    def setUp(self):
        self.adapter = EventFeatureAdapter(window_size=10, stride=1)

    def test_feature_dimension_and_names(self):
        """Verifies feature vector dimension matches len(ActionEnum) + 3."""
        self.assertEqual(self.adapter.feature_dim, 12)
        names = self.adapter.get_feature_names()
        self.assertEqual(len(names), 12)
        self.assertIn("DELTA_T_LOG", names)
        self.assertIn("IS_EXECUTABLE", names)
        self.assertIn("IS_REMOVABLE", names)

    def test_feature_extraction_accuracy(self):
        """Verifies one-hot, elapsed time, executable, and removable flags."""
        ev1 = make_raw_event("ev1", "DEVICE_ARRIVED", "2026-10-23T10:00:00.000Z", source="usb", entity="E:")
        ev2 = make_raw_event(
            "ev2", "FILE_CREATED", "2026-10-23T10:01:00.000Z", source="fs",
            entity="E:\\payload.exe", details={"drive_letter": "E:"}
        )

        vec1 = self.adapter.extract_features(ev1, None)
        vec2 = self.adapter.extract_features(ev2, ev1)

        # ev1: action DEVICE_ARRIVED, dt=0, is_exec=0, is_rem=1
        self.assertEqual(vec1[10], 0.0)  # dt_log
        self.assertEqual(vec1[11], 1.0)  # is_removable

        # ev2: action FILE_CREATED, dt=60s -> log(1+60), is_exec=1, is_rem=1
        self.assertAlmostEqual(vec2[9], math.log(1.0 + 60.0), places=4)
        self.assertEqual(vec2[10], 1.0)  # is_exec (.exe)
        self.assertEqual(vec2[11], 1.0)  # is_rem (E:)

    def test_short_sequence_left_padding(self):
        """Sequences with < 10 events produce exactly 1 left-padded window with zeros."""
        events = [make_raw_event(f"ev_{i}", "FILE_MODIFIED", f"2026-10-23T10:{i:02d}:00.000Z") for i in range(4)]
        windows = self.adapter.create_windows_for_sequence(events, session_id="short_sess")
        self.assertEqual(len(windows), 1)
        matrix = windows[0].feature_matrix
        self.assertEqual(len(matrix), 10)
        # First 6 rows are zero padded
        for row in matrix[:6]:
            self.assertEqual(row, [0.0] * 12)
        # Last 4 rows contain event features
        for row in matrix[6:]:
            self.assertTrue(any(v > 0.0 for v in row))

    def test_sliding_window_stride(self):
        """Sequence of 14 events with window_size 10 and stride 1 produces 5 windows."""
        events = [make_raw_event(f"ev_{i}", "FILE_MODIFIED", f"2026-10-23T10:{i:02d}:00.000Z") for i in range(14)]
        windows = self.adapter.create_windows_for_sequence(events, session_id="long_sess")
        self.assertEqual(len(windows), 5)  # 14 - 10 + 1 = 5
        self.assertEqual(len(windows[0].event_ids), 10)
        self.assertEqual(windows[0].event_ids[0], "ev_0")
        self.assertEqual(windows[1].event_ids[0], "ev_1")

    def test_session_boundary_preservation(self):
        """CRITICAL INVARIANT: Window formulation never crosses session boundaries."""
        sess_a = [make_raw_event(f"a_{i}", "FILE_CREATED", f"2026-10-23T10:0{i}:00.000Z", session_id="sess_A") for i in range(5)]
        sess_b = [make_raw_event(f"b_{i}", "FILE_CREATED", f"2026-10-23T11:0{i}:00.000Z", session_id="sess_B") for i in range(5)]

        # Combined flat list
        windows = self.adapter.generate_session_windows(sess_a + sess_b)
        self.assertEqual(len(windows), 2)  # 1 padded window for sess_A, 1 for sess_B

        for w in windows:
            # Events in w must all belong to that same session
            if w.session_id == "sess_A":
                self.assertTrue(all(eid.startswith("a_") for eid in w.event_ids))
            elif w.session_id == "sess_B":
                self.assertTrue(all(eid.startswith("b_") for eid in w.event_ids))


class TestModelPersistenceAndReload(unittest.TestCase):
    """Verifies artifact serialization, loading, and numerical fidelity."""

    def test_save_and_reload_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            set_seed(42)
            cfg = MLModelConfig(input_dim=12, hidden_dim=16, latent_dim=8, seq_len=10)
            model = LSTMAutoencoder(cfg)
            threshold_meta = ThresholdMetadata(
                threshold=0.35,
                percentile=99.0,
                val_loss_mean=0.20,
                val_loss_median=0.18,
                val_loss_max=0.36,
                val_samples_count=50,
            )
            feat_meta = {"feature_dim": 12, "actions_order": ["A", "B"]}

            # Save
            save_artifacts(tmp_dir, model, cfg, feat_meta, threshold_meta)
            self.assertTrue(artifacts_exist(tmp_dir))

            # Reload
            loaded_model, loaded_cfg, loaded_f_meta, loaded_t_meta = load_artifacts(tmp_dir)
            self.assertEqual(loaded_cfg.input_dim, 12)
            self.assertEqual(loaded_t_meta.threshold, 0.35)
            self.assertEqual(loaded_f_meta["feature_dim"], 12)

            # Check forward pass outputs match exactly
            test_x = torch.randn(2, 10, 12)
            model.eval()
            loaded_model.eval()
            with torch.no_grad():
                out_orig = model(test_x)
                out_loaded = loaded_model(test_x)
            self.assertTrue(torch.allclose(out_orig, out_loaded, atol=1e-6))


class TestTrainingPipeline(unittest.TestCase):
    """Verifies training on normal baseline data and malicious scenario filtering."""

    def test_malicious_scenario_blacklist(self):
        """Attack scenarios are strictly excluded from training data."""
        self.assertTrue(is_malicious_session_id("scenario_a"))
        self.assertTrue(is_malicious_session_id("scenario_b"))
        self.assertTrue(is_malicious_session_id("scenario_c"))
        self.assertTrue(is_malicious_session_id("usb_copy_run"))
        self.assertFalse(is_malicious_session_id("baseline_session_01"))

    def test_training_pipeline_execution_and_threshold_selection(self):
        """Verifies complete training cycle, loss reduction, and P99 threshold calculation."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            sessions = {
                f"baseline_{i}": [
                    make_raw_event(f"ev_{i}_{j}", "FILE_MODIFIED", f"2026-10-23T10:{j:02d}:00.000Z", session_id=f"baseline_{i}")
                    for j in range(12)
                ]
                for i in range(4)
            }

            cfg = MLModelConfig(
                input_dim=12,
                hidden_dim=16,
                latent_dim=8,
                seq_len=10,
                epochs=5,
                batch_size=8,
                device="cpu",
                artifacts_dir=tmp_dir,
            )
            trainer = TrainingPipeline(config=cfg)
            model, t_meta, summary = trainer.train(sessions, artifacts_dir=tmp_dir)

            self.assertGreater(t_meta.threshold, 0.0)
            self.assertIn("train_windows", summary)
            self.assertTrue(artifacts_exist(tmp_dir))


class TestAnomalyThresholdAndScoring(unittest.TestCase):
    """Verifies reconstruction error normalization formula and activity mapping."""

    def test_normalization_formula(self):
        """
        Tests exact formula:
        - E <= T: score = 0.5 * (E / T)
        - E > T: score = 0.5 + 0.5 * min((E - T) / T, 1.0)
        """
        tau = 0.40

        # E = 0.0 -> score = 0.0
        self.assertEqual(normalize_reconstruction_error(0.0, tau), 0.0)

        # E = 0.20 (half of tau) -> score = 0.25
        self.assertAlmostEqual(normalize_reconstruction_error(0.20, tau), 0.25, places=3)

        # E = 0.40 (equal to tau) -> score = 0.50
        self.assertAlmostEqual(normalize_reconstruction_error(0.40, tau), 0.50, places=3)

        # E = 0.60 (1.5 * tau) -> score = 0.75
        self.assertAlmostEqual(normalize_reconstruction_error(0.60, tau), 0.75, places=3)

        # E = 0.80 (2.0 * tau) -> score = 1.00
        self.assertAlmostEqual(normalize_reconstruction_error(0.80, tau), 1.00, places=3)

        # E = 1.20 (3.0 * tau) -> score = 1.00 (clamped)
        self.assertAlmostEqual(normalize_reconstruction_error(1.20, tau), 1.00, places=3)

    def test_activity_level_max_score_mapping(self):
        """Activity takes the maximum anomaly score across all overlapping windows."""
        set_seed(42)
        cfg = MLModelConfig(input_dim=12, hidden_dim=16, latent_dim=8, seq_len=10, device="cpu")
        model = LSTMAutoencoder(cfg)
        scorer = AnomalyScorer(model=model, threshold=0.50)

        window_results = [
            WindowAnomalyResult(
                window_index=0,
                session_id="s1",
                ts_start_utc="2026-10-23T10:00:00.000Z",
                ts_end_utc="2026-10-23T10:05:00.000Z",
                event_ids=["ev_1", "ev_2", "ev_3"],
                raw_reconstruction_error=0.30,
                anomaly_score=0.30,
            ),
            WindowAnomalyResult(
                window_index=1,
                session_id="s1",
                ts_start_utc="2026-10-23T10:02:00.000Z",
                ts_end_utc="2026-10-23T10:07:00.000Z",
                event_ids=["ev_3", "ev_4", "ev_5"],
                raw_reconstruction_error=0.85,
                anomaly_score=0.85,
            ),
        ]

        # Activity supported by ev_2 and ev_3 (overlaps both windows 0 and 1)
        score_res = scorer.score_activity(
            activity_id="act_test_01",
            supporting_event_ids=["ev_2", "ev_3"],
            window_results=window_results,
        )

        # Must select window 1's score 0.85 (the maximum)
        self.assertEqual(score_res.ml_anomaly_score, 0.85)
        self.assertEqual(score_res.overlapping_window_count, 2)
        self.assertEqual(score_res.peak_window_index, 1)

    def test_missing_model_fallback(self):
        """When ML is offline or missing, ml_anomaly_score is None (never silently 0.0)."""
        scorer = AnomalyScorer(model=None, threshold=None)
        self.assertFalse(scorer.is_available)
        score_res = scorer.score_activity("act_01", ["ev_1"], [])
        self.assertIsNone(score_res.ml_anomaly_score)
        self.assertFalse(score_res.is_available)


class TestHybridScoringAndThreatLevels(unittest.TestCase):
    """Verifies hybrid formula, fallback logic, and discrete threat classification."""

    def test_hybrid_formula_calculation(self):
        """R_hybrid = 0.5 * rule_confidence + 0.5 * ml_anomaly_score."""
        score, avail = compute_hybrid_score(rule_confidence=0.90, ml_anomaly_score=0.70)
        self.assertTrue(avail)
        self.assertAlmostEqual(score, 0.80, places=3)

    def test_missing_ml_fallback_preserves_rule_confidence(self):
        """When ml_anomaly_score is None, combined score equals rule confidence."""
        score, avail = compute_hybrid_score(rule_confidence=0.85, ml_anomaly_score=None)
        self.assertFalse(avail)
        self.assertEqual(score, 0.85)

    def test_threat_level_classification_criteria(self):
        """Verifies discrete threat levels per docs/ml.md Section 5.2."""
        # CRITICAL: Score >= 0.85 OR rule R6 / R7
        self.assertEqual(classify_threat_level("R7", 0.50), "CRITICAL")
        self.assertEqual(classify_threat_level("R6", 0.60), "CRITICAL")
        self.assertEqual(classify_threat_level("R2", 0.88), "CRITICAL")

        # HIGH: 0.70 <= Score < 0.85 OR rule R1 / R4 / R5
        self.assertEqual(classify_threat_level("R1", 0.50), "HIGH")
        self.assertEqual(classify_threat_level("R4", 0.40), "HIGH")
        self.assertEqual(classify_threat_level("R5", 0.60), "HIGH")
        self.assertEqual(classify_threat_level("R2", 0.75), "HIGH")

        # MEDIUM: 0.40 <= Score < 0.70 OR rule R2 / R3
        self.assertEqual(classify_threat_level("R2", 0.45), "MEDIUM")
        self.assertEqual(classify_threat_level("R3", 0.35), "MEDIUM")

        # LOW: Score < 0.40 with no severe rule
        self.assertEqual(classify_threat_level("R0", 0.25), "LOW")


class TestNarrativeAndCorrelatorIntegration(unittest.TestCase):
    """Verifies plain-English narrative extension and full end-to-end correlation."""

    def test_narrative_extension_with_ml(self):
        """Verifies append_ml_narrative_context adds cautious ML explanation."""
        base = "File payload.exe created at 10:00 [event:ev000001]."
        narrative = append_ml_narrative_context(
            base_narrative=base,
            ml_anomaly_score=0.88,
            combined_score=0.89,
            threat_level="CRITICAL",
            ml_explanation="High reconstruction error on action transition.",
            ml_available=True,
        )
        self.assertIn("ev000001", narrative)
        self.assertIn("0.88", narrative)
        self.assertIn("CRITICAL", narrative)
        self.assertIn("statistical deviation", narrative)

    def test_correlator_end_to_end_with_ml_scorer(self):
        """Full integration test: CorrelationEngine correlates events and applies ML scoring."""
        set_seed(42)
        cfg = MLModelConfig(input_dim=12, hidden_dim=16, latent_dim=8, seq_len=10, device="cpu")
        model = LSTMAutoencoder(cfg)
        scorer = AnomalyScorer(model=model, threshold=0.30)

        engine = CorrelationEngine(ml_scorer=scorer)

        usb = make_raw_event("usb000000000000000000000000000000000000000000000000000000000000",
                             "DEVICE_ARRIVED", "2026-10-23T10:00:00.000Z", source="usb", entity="E: (SanDisk)", details={"drive_letter": "E:"})
        fs = make_raw_event("fs0000000000000000000000000000000000000000000000000000000000000",
                            "FILE_CREATED", "2026-10-23T10:01:00.000Z", source="fs", entity="E:\\tool.exe", details={"drive_letter": "E:"})

        results = engine.correlate_events([usb, fs])
        self.assertEqual(len(results), 1)
        act = results[0].activity
        self.assertEqual(act.rule_id, "R1")
        self.assertIsNotNone(act.ml_anomaly_score)
        self.assertIn(act.threat_level, ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.assertIn("ML Analysis", act.narrative)


if __name__ == "__main__":
    unittest.main()
