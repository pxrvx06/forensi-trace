"""
engine/ml/scoring.py - Anomaly Threshold Normalization and Activity-Level Scoring.

Author: Akash (Correlation Engine & ML Owner)
Contract: docs/ml.md (Section 4, 5)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

import numpy as np
import torch

from engine.ml.adapter import EventFeatureAdapter, FeatureWindow
from engine.ml.config import MLModelConfig
from engine.ml.model import LSTMAutoencoder, resolve_device
from engine.ml.persistence import ThresholdMetadata, artifacts_exist, load_artifacts

logger = logging.getLogger("forensitrace.engine.ml.scoring")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def normalize_reconstruction_error(error: float, threshold: float) -> float:
    """
    CRITICAL HANDOFF FORMULA:
    Normalizes raw MSE reconstruction error E against baseline threshold T into [0.0, 1.0]:
    - If E <= T: score = 0.5 * (E / T)
    - If E > T:  score = 0.5 + 0.5 * min((E - T) / T, 1.0)

    Properties:
    - E = 0.0      -> score = 0.00 (routine baseline)
    - E = T        -> score = 0.50 (baseline decision boundary)
    - E >= 2 * T   -> score = 1.00 (severe anomaly)
    - Safe handling for non-positive or invalid threshold values.
    """
    if error is None or math_isnan(error):
        return 0.0

    # Ensure non-negative error
    e = max(0.0, float(error))

    # Safe threshold handling
    t = float(threshold) if threshold is not None else 0.0
    if t <= 1e-6:
        # Avoid division by zero: if threshold is near zero or zero, any non-zero error is an anomaly
        return 0.5 if e == 0.0 else 1.0

    if e <= t:
        score = 0.5 * (e / t)
    else:
        score = 0.5 + 0.5 * min((e - t) / t, 1.0)

    # Strict clamp to [0.0, 1.0] and round to 4 decimal places
    clamped = max(0.0, min(1.0, score))
    return round(clamped, 4)


def math_isnan(val: Any) -> bool:
    try:
        return np.isnan(val)
    except Exception:
        return False


@dataclass
class WindowAnomalyResult:
    """Detailed anomaly scoring outcome for an individual window."""
    window_index: int
    session_id: str
    ts_start_utc: str
    ts_end_utc: str
    event_ids: List[str]
    raw_reconstruction_error: float
    anomaly_score: float
    top_contributing_features: List[Tuple[str, float]] = field(default_factory=list)


@dataclass
class ActivityMLScore:
    """ML scoring and explainability mapping for an activity."""
    activity_id: str
    ml_anomaly_score: Optional[float]
    max_error: Optional[float]
    supporting_event_count: int
    overlapping_window_count: int
    peak_window_index: Optional[int] = None
    peak_window_event_ids: List[str] = field(default_factory=list)
    top_feature_explanations: List[Tuple[str, float]] = field(default_factory=list)
    is_available: bool = True
    explanation: str = ""


class AnomalyScorer:
    """
    Inference and anomaly evaluation engine for the LSTM Autoencoder.
    Calculates window reconstruction errors, normalizes anomaly scores,
    and maps window scores to correlated activities.
    """

    def __init__(
        self,
        model: Optional[LSTMAutoencoder] = None,
        threshold: Optional[float] = None,
        feature_metadata: Optional[Dict[str, Any]] = None,
        artifacts_dir: Optional[Union[str, Path]] = None,
        adapter: Optional[EventFeatureAdapter] = None,
        device: Optional[Union[str, torch.device]] = None,
    ):
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else None
        self.device = resolve_device(str(device) if device else "cpu")
        self.model: Optional[LSTMAutoencoder] = None
        self.threshold: Optional[float] = None
        self.feature_metadata: Dict[str, Any] = {}
        self.threshold_metadata: Optional[ThresholdMetadata] = None

        if model is not None and threshold is not None:
            self.model = model.to(self.device)
            self.model.eval()
            self.threshold = float(threshold)
            self.feature_metadata = feature_metadata or {}
        elif self.artifacts_dir and artifacts_exist(self.artifacts_dir):
            try:
                m, cfg, f_meta, t_meta = load_artifacts(self.artifacts_dir, device=self.device)
                self.model = m
                self.threshold = t_meta.threshold
                self.feature_metadata = f_meta
                self.threshold_metadata = t_meta
                logger.info(
                    "[AnomalyScorer] Successfully initialized from artifacts at '%s' (threshold=%.4f)",
                    self.artifacts_dir, self.threshold,
                )
            except Exception as exc:
                logger.warning(
                    "[AnomalyScorer] Failed to load ML artifacts from '%s': %s",
                    self.artifacts_dir, exc,
                )
                self.model = None
                self.threshold = None
        else:
            logger.info(
                "[AnomalyScorer] ML model or artifacts not provided; operating in fallback mode"
            )

        self.adapter = adapter or EventFeatureAdapter(
            actions_order=self.feature_metadata.get("actions_order"),
            window_size=self.feature_metadata.get("window_size", 10),
            stride=self.feature_metadata.get("stride", 1),
        )

    @property
    def is_available(self) -> bool:
        """Indicates whether an active model and valid threshold are loaded."""
        return self.model is not None and self.threshold is not None and self.threshold > 0.0

    def score_windows(
        self,
        windows: List[FeatureWindow],
    ) -> List[WindowAnomalyResult]:
        """
        Evaluates a list of FeatureWindows, computes reconstruction error and anomaly scores.
        If ML is unavailable, raises RuntimeError (callers should check `is_available`).
        """
        if not self.is_available:
            raise RuntimeError("Cannot score windows: ML model or threshold is not available.")

        if not windows:
            return []

        matrices = [w.feature_matrix for w in windows]
        arr = np.array(matrices, dtype=np.float32)
        arr = np.nan_to_num(arr, nan=0.0, posinf=1e4, neginf=-1e4)
        tensor_x = torch.from_numpy(arr).to(self.device)

        self.model.eval()  # type: ignore[union-attr]
        with torch.no_grad():
            tensor_x_clean = self.model.sanitize_input(tensor_x)  # type: ignore[union-attr]
            tensor_x_hat = self.model(tensor_x_clean)  # type: ignore[union-attr]
            errors = self.model.compute_reconstruction_error(tensor_x_clean, tensor_x_hat).cpu().numpy()  # type: ignore[union-attr]

            # Feature-level reconstruction errors: shape (batch, seq_len, input_dim)
            diff_sq = ((tensor_x_clean - tensor_x_hat) ** 2).cpu().numpy()
            feature_errors = np.mean(diff_sq, axis=1)  # shape: (batch, input_dim)

        feature_names = self.adapter.get_feature_names()
        results: List[WindowAnomalyResult] = []

        for idx, w in enumerate(windows):
            raw_err = float(errors[idx])
            score = normalize_reconstruction_error(raw_err, self.threshold)  # type: ignore[arg-type]

            # Identify top contributing features
            f_errs = feature_errors[idx]
            top_indices = np.argsort(f_errs)[::-1][:3]
            top_features = [
                (feature_names[i] if i < len(feature_names) else f"feature_{i}", float(f_errs[i]))
                for i in top_indices
                if f_errs[i] > 1e-4
            ]

            results.append(
                WindowAnomalyResult(
                    window_index=w.window_index,
                    session_id=w.session_id,
                    ts_start_utc=w.ts_start_utc,
                    ts_end_utc=w.ts_end_utc,
                    event_ids=w.event_ids,
                    raw_reconstruction_error=raw_err,
                    anomaly_score=score,
                    top_contributing_features=top_features,
                )
            )

        return results

    def score_activity(
        self,
        activity_id: str,
        supporting_event_ids: Sequence[str],
        window_results: List[WindowAnomalyResult],
    ) -> ActivityMLScore:
        """
        Maps window-level reconstruction errors and anomaly scores to an activity.
        Uses the maximum anomaly score across all overlapping windows:
        activity.ml_anomaly_score = max_{W_k cap Events(activity) != empty} score(W_k)
        """
        if not self.is_available:
            return ActivityMLScore(
                activity_id=activity_id,
                ml_anomaly_score=None,
                max_error=None,
                supporting_event_count=len(supporting_event_ids),
                overlapping_window_count=0,
                is_available=False,
                explanation="ML anomaly detector is offline or model artifacts not loaded.",
            )

        supporting_set: Set[str] = set(supporting_event_ids)

        # Find overlapping windows: W_k cap Events(activity) != empty
        overlapping = [
            w for w in window_results
            if any(ev_id in supporting_set for ev_id in w.event_ids)
        ]

        if not overlapping:
            # No overlapping windows generated (e.g. events outside sequenced sessions)
            return ActivityMLScore(
                activity_id=activity_id,
                ml_anomaly_score=None,
                max_error=None,
                supporting_event_count=len(supporting_event_ids),
                overlapping_window_count=0,
                is_available=True,
                explanation="No sliding windows overlapped with this activity's supporting events.",
            )

        # Select window with maximum anomaly score
        peak_window = max(overlapping, key=lambda w: w.anomaly_score)
        max_score = peak_window.anomaly_score
        max_err = peak_window.raw_reconstruction_error

        # Concise explainability
        feat_descs = [f"{name} (error={err:.3f})" for name, err in peak_window.top_contributing_features]
        feat_str = f" Top anomalous factors: {', '.join(feat_descs)}." if feat_descs else ""
        explanation = (
            f"Overlapped with {len(overlapping)} sliding window(s). "
            f"Peak window #{peak_window.window_index} had reconstruction error {max_err:.4f} "
            f"(normalized anomaly score {max_score:.2f} vs baseline threshold {self.threshold:.4f}).{feat_str}"
        )

        return ActivityMLScore(
            activity_id=activity_id,
            ml_anomaly_score=max_score,
            max_error=max_err,
            supporting_event_count=len(supporting_event_ids),
            overlapping_window_count=len(overlapping),
            peak_window_index=peak_window.window_index,
            peak_window_event_ids=peak_window.event_ids,
            top_feature_explanations=peak_window.top_contributing_features,
            is_available=True,
            explanation=explanation,
        )
