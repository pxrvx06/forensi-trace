"""
ForensiTrace ML Subsystem Package.

Author: Akash (Correlation Engine & ML Owner)
Phase III Implementation: LSTM Autoencoder, Sequence Formulation, and Anomaly Detection.
"""

from __future__ import annotations

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
from engine.ml.trainer import TrainingPipeline

__all__ = [
    "MLModelConfig",
    "LSTMAutoencoder",
    "resolve_device",
    "set_seed",
    "EventFeatureAdapter",
    "FeatureWindow",
    "ThresholdMetadata",
    "save_artifacts",
    "load_artifacts",
    "artifacts_exist",
    "TrainingPipeline",
    "AnomalyScorer",
    "WindowAnomalyResult",
    "ActivityMLScore",
    "normalize_reconstruction_error",
    "HybridRiskEngine",
    "HybridScoringResult",
    "compute_hybrid_score",
    "classify_threat_level",
]
