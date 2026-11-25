"""
engine/ml/persistence.py - Model, Configuration, and Metadata Persistence.

Author: Akash (Correlation Engine & ML Owner)
Contract: docs/ml.md (Section 4, 6)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import torch

from engine.ml.config import MLModelConfig
from engine.ml.model import LSTMAutoencoder, resolve_device

logger = logging.getLogger("forensitrace.engine.ml.persistence")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

WEIGHTS_FILENAME = "lstm_autoencoder.pt"
CONFIG_FILENAME = "model_config.json"
FEATURE_META_FILENAME = "feature_metadata.json"
THRESHOLD_META_FILENAME = "threshold_metadata.json"


@dataclass
class ThresholdMetadata:
    """Detailed metadata concerning baseline anomaly threshold selection."""
    threshold: float                        # tau = P99(MSE_val)
    percentile: float = 99.0                # Configured percentile
    val_loss_mean: float = 0.0              # Mean validation reconstruction error
    val_loss_median: float = 0.0            # Median validation error
    val_loss_max: float = 0.0               # Maximum validation error
    val_samples_count: int = 0              # Number of validation windows evaluated
    training_epochs_completed: int = 0      # Epochs trained
    trained_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    is_synthetic: bool = False              # Whether synthetic normal data was supplied
    additional_metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ThresholdMetadata:
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


def save_artifacts(
    artifacts_dir: Union[str, Path],
    model: LSTMAutoencoder,
    config: MLModelConfig,
    feature_metadata: Dict[str, Any],
    threshold_metadata: ThresholdMetadata,
) -> Dict[str, str]:
    """
    Persists all ML artifacts into the designated directory:
    - Weights: lstm_autoencoder.pt
    - Config: model_config.json
    - Feature metadata: feature_metadata.json
    - Threshold metadata: threshold_metadata.json
    """
    out_dir = Path(artifacts_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    weights_path = out_dir / WEIGHTS_FILENAME
    config_path = out_dir / CONFIG_FILENAME
    feature_path = out_dir / FEATURE_META_FILENAME
    threshold_path = out_dir / THRESHOLD_META_FILENAME

    # 1. Weights
    model.save_weights(weights_path)

    # 2. Config
    config.save(config_path)

    # 3. Feature metadata
    with open(feature_path, "w", encoding="utf-8") as f:
        json.dump(feature_metadata, f, indent=2)

    # 4. Threshold metadata
    with open(threshold_path, "w", encoding="utf-8") as f:
        json.dump(threshold_metadata.to_dict(), f, indent=2)

    logger.info("[save_artifacts] Saved all ML artifacts to '%s'", out_dir)
    return {
        "weights": str(weights_path),
        "config": str(config_path),
        "feature_metadata": str(feature_path),
        "threshold_metadata": str(threshold_path),
    }


def artifacts_exist(artifacts_dir: Union[str, Path]) -> bool:
    """Verifies whether all required model and metadata files are present on disk."""
    d = Path(artifacts_dir)
    if not d.is_dir():
        return False
    required = [
        d / WEIGHTS_FILENAME,
        d / CONFIG_FILENAME,
        d / FEATURE_META_FILENAME,
        d / THRESHOLD_META_FILENAME,
    ]
    return all(p.is_file() for p in required)


def load_artifacts(
    artifacts_dir: Union[str, Path],
    device: Optional[Union[str, torch.device]] = None,
) -> Tuple[LSTMAutoencoder, MLModelConfig, Dict[str, Any], ThresholdMetadata]:
    """
    Loads all ML artifacts from the specified directory.
    Returns:
        (model, config, feature_metadata, threshold_metadata)
    Raises:
        FileNotFoundError if artifacts are missing or incomplete.
    """
    d = Path(artifacts_dir)
    if not artifacts_exist(d):
        raise FileNotFoundError(
            f"Missing required ML artifacts in directory: '{d}'. "
            f"Ensure {WEIGHTS_FILENAME}, {CONFIG_FILENAME}, {FEATURE_META_FILENAME}, "
            f"and {THRESHOLD_META_FILENAME} exist."
        )

    # 1. Load config
    config = MLModelConfig.load(d / CONFIG_FILENAME)

    # 2. Instantiate and load model
    model = LSTMAutoencoder(config)
    target_device = resolve_device(str(device) if device else config.device)
    model.load_weights(d / WEIGHTS_FILENAME, device=target_device)
    model.eval()

    # 3. Load feature metadata
    with open(d / FEATURE_META_FILENAME, "r", encoding="utf-8") as f:
        feature_metadata = json.load(f)

    # 4. Load threshold metadata
    with open(d / THRESHOLD_META_FILENAME, "r", encoding="utf-8") as f:
        threshold_data = json.load(f)
    threshold_metadata = ThresholdMetadata.from_dict(threshold_data)

    logger.info(
        "[load_artifacts] Successfully loaded ML subsystem from '%s' (threshold=%.4f)",
        d,
        threshold_metadata.threshold,
    )
    return model, config, feature_metadata, threshold_metadata
