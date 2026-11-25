"""
engine/ml/trainer.py - Session-Aware Training and Validation Pipeline for ForensiTrace.

Author: Akash (Correlation Engine & ML Owner)
Contract: docs/ml.md (Section 4, 5, 6)
"""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from engine.ml.adapter import EventFeatureAdapter, FeatureWindow
from engine.ml.config import MLModelConfig
from engine.ml.model import LSTMAutoencoder, resolve_device, set_seed
from engine.ml.persistence import ThresholdMetadata, save_artifacts

logger = logging.getLogger("forensitrace.engine.ml.trainer")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Blacklist of known attack scenarios to guarantee zero contamination of baseline
MALICIOUS_SCENARIO_IDENTIFIERS = {
    "scenario_a",
    "scenario_a_prime",
    "scenario_b",
    "scenario_c",
    "attack",
    "exfiltration",
    "usb_copy_run",
    "edge_cases",
    "bulk_file_creation",
    "log_cleared",
    "timestamp_discrepancy",
}


def is_malicious_session_id(session_id: str) -> bool:
    """Checks whether a session name indicates an attack scenario or test probe."""
    s_lower = session_id.strip().lower()
    return any(mal in s_lower for mal in MALICIOUS_SCENARIO_IDENTIFIERS)


class TrainingPipeline:
    """
    Session-aware training, validation, and threshold selection pipeline.
    Enforces disjoint session partitions, normal-only training, and reproducible seeds.
    """

    def __init__(
        self,
        config: Optional[MLModelConfig] = None,
        adapter: Optional[EventFeatureAdapter] = None,
        allow_synthetic: bool = False,
    ):
        self.config = config or MLModelConfig()
        self.adapter = adapter or EventFeatureAdapter(
            window_size=self.config.seq_len,
            stride=1,
        )
        self.allow_synthetic = allow_synthetic
        self.device = resolve_device(self.config.device)

        # Set reproducible seeds
        set_seed(self.config.random_seed)

    def filter_and_validate_sessions(
        self,
        sessions: Dict[str, Sequence[Any]],
    ) -> Dict[str, Sequence[Any]]:
        """
        Validates sessions and explicitly filters out any attack scenarios.
        Rejects synthetic sessions unless `allow_synthetic` was explicitly enabled.
        """
        clean_sessions: Dict[str, Sequence[Any]] = {}
        for s_id, events in sessions.items():
            if is_malicious_session_id(s_id):
                logger.warning(
                    "[filter_and_validate_sessions] EXCLUDING malicious scenario '%s' from training data",
                    s_id,
                )
                continue

            if "synthetic" in s_id.lower() and not self.allow_synthetic:
                logger.warning(
                    "[filter_and_validate_sessions] Skipping unpermitted synthetic session '%s'",
                    s_id,
                )
                continue

            if not events:
                logger.debug("[filter_and_validate_sessions] Skipping empty session '%s'", s_id)
                continue

            clean_sessions[s_id] = events

        if not clean_sessions:
            raise ValueError(
                "No valid normal training sessions remained after filtering. "
                "Ensure baseline normal data is supplied (attack scenarios are excluded by policy)."
            )

        return clean_sessions

    def partition_sessions(
        self,
        session_ids: List[str],
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
    ) -> Dict[str, List[str]]:
        """
        Partitions sessions into disjoint train, val, and test splits.
        Guarantees zero cross-session data leakage.
        """
        s_ids = sorted(list(session_ids))
        n = len(s_ids)

        if n == 0:
            return {"train": [], "val": [], "test": []}
        if n == 1:
            # 1 session: used for train and val to allow initial baseline modeling
            return {"train": s_ids, "val": s_ids, "test": []}
        if n == 2:
            return {"train": [s_ids[0]], "val": [s_ids[1]], "test": []}

        n_train = max(1, int(round(n * train_ratio)))
        n_val = max(1, int(round(n * val_ratio)))
        if n_train + n_val >= n:
            n_train = max(1, n - 2)
            n_val = 1

        train_s = s_ids[:n_train]
        val_s = s_ids[n_train:n_train + n_val]
        test_s = s_ids[n_train + n_val:]

        # Assert disjointness when n >= 2
        if n >= 3:
            assert set(train_s).isdisjoint(set(val_s)), "Train and Val splits must be disjoint!"
            assert set(train_s).isdisjoint(set(test_s)), "Train and Test splits must be disjoint!"
            assert set(val_s).isdisjoint(set(test_s)), "Val and Test splits must be disjoint!"

        logger.info(
            "[partition_sessions] Partitioned %d sessions: %d train, %d val, %d test",
            n, len(train_s), len(val_s), len(test_s),
        )
        return {"train": train_s, "val": val_s, "test": test_s}

    def windows_to_tensor(self, windows: List[FeatureWindow]) -> torch.Tensor:
        """Converts list of FeatureWindow objects to PyTorch tensor of shape (N, seq_len, input_dim)."""
        if not windows:
            return torch.empty((0, self.config.seq_len, self.config.input_dim), dtype=torch.float32)

        matrices = [w.feature_matrix for w in windows]
        arr = np.array(matrices, dtype=np.float32)
        # Sanitize NaNs and Infs if any present in raw features
        arr = np.nan_to_num(arr, nan=0.0, posinf=1e4, neginf=-1e4)
        return torch.from_numpy(arr)

    def train(
        self,
        sessions: Dict[str, Sequence[Any]],
        artifacts_dir: Optional[Union[str, Path]] = None,
    ) -> Tuple[LSTMAutoencoder, ThresholdMetadata, Dict[str, Any]]:
        """
        Executes end-to-end training and validation pipeline:
        1. Filters out malicious sessions.
        2. Partitions sessions into disjoint train/val/test splits.
        3. Formulates sliding windows per session.
        4. Trains LSTM Autoencoder on train split using MSE loss.
        5. Computes reconstruction errors on normal validation split.
        6. Derives baseline threshold tau = P99(MSE_val).
        7. Persists artifacts and training metadata.
        """
        out_dir = Path(artifacts_dir or self.config.artifacts_dir)
        valid_sessions = self.filter_and_validate_sessions(sessions)

        # 1. Partition sessions
        splits = self.partition_sessions(list(valid_sessions.keys()))
        train_sessions = {s: valid_sessions[s] for s in splits["train"]}
        val_sessions = {s: valid_sessions[s] for s in splits["val"]}

        # 2. Formulate windows
        train_windows = self.adapter.generate_session_windows(train_sessions)
        val_windows = self.adapter.generate_session_windows(val_sessions)

        if not train_windows:
            raise ValueError("No feature windows could be generated from training sessions.")
        if not val_windows:
            # Fallback to train_windows if val set produced no windows
            val_windows = train_windows

        logger.info(
            "[train] Formulated %d train windows, %d validation windows",
            len(train_windows), len(val_windows),
        )

        # 3. Create Tensors and DataLoaders
        X_train = self.windows_to_tensor(train_windows)
        X_val = self.windows_to_tensor(val_windows)

        train_dataset = TensorDataset(X_train)
        train_loader = DataLoader(
            train_dataset,
            batch_size=min(self.config.batch_size, len(X_train)),
            shuffle=True,
            drop_last=False,
        )

        # 4. Instantiate Model and Optimizer
        model = LSTMAutoencoder(self.config).to(self.device)
        optimizer = torch.optim.Adam(model.parameters(), lr=self.config.learning_rate)
        criterion = nn.MSELoss()

        history_train_loss: List[float] = []

        model.train()
        for epoch in range(1, self.config.epochs + 1):
            epoch_loss = 0.0
            batches = 0
            for (batch_x,) in train_loader:
                batch_x = batch_x.to(self.device)
                optimizer.zero_grad()
                reconstructed = model(batch_x)
                loss = criterion(reconstructed, batch_x)
                loss.backward()
                optimizer.step()

                epoch_loss += loss.item()
                batches += 1

            avg_loss = epoch_loss / max(1, batches)
            history_train_loss.append(avg_loss)

            if epoch % max(1, self.config.epochs // 5) == 0 or epoch == self.config.epochs:
                logger.info(
                    "[train] Epoch %d/%d - Train MSE Loss: %.6f",
                    epoch, self.config.epochs, avg_loss,
                )

        # 5. Evaluate on Validation Set to Derive Baseline Anomaly Threshold
        model.eval()
        with torch.no_grad():
            X_val_dev = X_val.to(self.device)
            val_errors = model.compute_reconstruction_error(X_val_dev).cpu().numpy()

        val_mean = float(np.mean(val_errors))
        val_median = float(np.median(val_errors))
        val_max = float(np.max(val_errors))
        val_p90 = float(np.percentile(val_errors, 90.0))
        val_p95 = float(np.percentile(val_errors, 95.0))
        val_p99 = float(np.percentile(val_errors, self.config.threshold_percentile))

        # Safe non-zero threshold safeguard
        threshold_tau = max(val_p99, 1e-4)
        logger.info(
            "[train] Validation Reconstruction Error stats: mean=%.6f, median=%.6f, max=%.6f, P99 (Threshold tau)=%.6f",
            val_mean, val_median, val_max, threshold_tau,
        )

        # 6. Build Threshold and Feature Metadata
        threshold_metadata = ThresholdMetadata(
            threshold=threshold_tau,
            percentile=self.config.threshold_percentile,
            val_loss_mean=val_mean,
            val_loss_median=val_median,
            val_loss_max=val_max,
            val_samples_count=len(val_errors),
            training_epochs_completed=self.config.epochs,
            is_synthetic=self.allow_synthetic,
            additional_metrics={
                "p90": val_p90,
                "p95": val_p95,
                "p99": val_p99,
                "final_train_loss": history_train_loss[-1],
                "splits": splits,
                "window_counts": {
                    "train": len(train_windows),
                    "val": len(val_windows),
                },
            },
        )

        feature_metadata = self.adapter.get_metadata()

        # 7. Persist Artifacts
        saved_paths = save_artifacts(
            artifacts_dir=out_dir,
            model=model,
            config=self.config,
            feature_metadata=feature_metadata,
            threshold_metadata=threshold_metadata,
        )

        training_summary = {
            "saved_paths": saved_paths,
            "threshold": threshold_tau,
            "train_windows": len(train_windows),
            "val_windows": len(val_windows),
            "epochs": self.config.epochs,
            "final_loss": history_train_loss[-1],
        }

        return model, threshold_metadata, training_summary
