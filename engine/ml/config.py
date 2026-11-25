"""
engine/ml/config.py - Configuration Dataclasses and Serialization for ForensiTrace ML Subsystem.

Author: Akash (Correlation Engine & ML Owner)
Contract: docs/ml.md (Section 2, 3, 4)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Union


@dataclass
class MLModelConfig:
    """
    Configuration parameters for the Lightweight PyTorch LSTM Autoencoder.
    Suitable for CPU-first execution, with optional GPU support.
    """
    input_dim: int = 12                     # Default: len(ActionEnum) + 3 context flags
    hidden_dim: int = 16                    # Hidden layer dimension for encoder/decoder
    latent_dim: int = 8                     # Bottleneck latent representation dimension
    num_layers: int = 1                     # Number of stacked LSTM layers
    seq_len: int = 10                       # Sequence/window length N
    batch_size: int = 16                    # Mini-batch size for training
    learning_rate: float = 0.001            # Adam optimizer learning rate
    epochs: int = 50                        # Number of training epochs
    random_seed: int = 42                   # Reproducibility seed
    device: str = "cpu"                     # 'cpu', 'cuda', or 'auto'
    threshold_percentile: float = 99.0      # Baseline threshold percentile (P99)
    artifacts_dir: str = "engine/ml/artifacts"  # Path to persist model and metadata

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Validates configuration parameters for consistency and safety."""
        if self.input_dim <= 0:
            raise ValueError(f"input_dim must be positive, got {self.input_dim}")
        if self.hidden_dim <= 0:
            raise ValueError(f"hidden_dim must be positive, got {self.hidden_dim}")
        if self.latent_dim <= 0:
            raise ValueError(f"latent_dim must be positive, got {self.latent_dim}")
        if self.latent_dim > self.hidden_dim:
            raise ValueError(
                f"latent_dim ({self.latent_dim}) cannot exceed hidden_dim ({self.hidden_dim})"
            )
        if self.num_layers <= 0:
            raise ValueError(f"num_layers must be positive, got {self.num_layers}")
        if self.seq_len <= 0:
            raise ValueError(f"seq_len must be positive, got {self.seq_len}")
        if self.batch_size <= 0:
            raise ValueError(f"batch_size must be positive, got {self.batch_size}")
        if self.learning_rate <= 0.0:
            raise ValueError(f"learning_rate must be positive, got {self.learning_rate}")
        if self.epochs <= 0:
            raise ValueError(f"epochs must be positive, got {self.epochs}")
        if not (0.0 < self.threshold_percentile <= 100.0):
            raise ValueError(
                f"threshold_percentile must be in (0.0, 100.0], got {self.threshold_percentile}"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes configuration to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MLModelConfig:
        """Instantiates configuration from a dictionary, ignoring unknown keys."""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    def save(self, file_path: Union[str, Path]) -> None:
        """Saves configuration as JSON to file."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, file_path: Union[str, Path]) -> MLModelConfig:
        """Loads configuration from JSON file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)
