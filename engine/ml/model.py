"""
engine/ml/model.py - Lightweight PyTorch LSTM Autoencoder Architecture.

Author: Akash (Correlation Engine & ML Owner)
Contract: docs/ml.md (Section 3, 4)

Architecture:
  Input Window (N x D) -> Encoder LSTM -> Bottleneck Latent -> Decoder LSTM -> Reconstructed Window (N x D)
  Reconstruction Loss: MSE(W, W_hat)
"""

from __future__ import annotations

import logging
import os
import random
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import torch
import torch.nn as nn

from engine.ml.config import MLModelConfig

logger = logging.getLogger("forensitrace.engine.ml.model")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def set_seed(seed: int) -> None:
    """Sets random seeds across Python, NumPy, and PyTorch for deterministic reproducibility."""
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False


def resolve_device(device_setting: str = "cpu") -> torch.device:
    """Resolves torch.device based on user configuration and hardware availability."""
    setting = (device_setting or "cpu").lower()
    if setting in ("cuda", "gpu") and torch.cuda.is_available():
        return torch.device("cuda")
    if setting == "auto":
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")
    return torch.device("cpu")


class Encoder(nn.Module):
    """
    LSTM Encoder: compresses a temporal window of shape (batch, seq_len, input_dim)
    into a fixed-size latent representation of shape (batch, latent_dim).
    """

    def __init__(self, input_dim: int, hidden_dim: int, latent_dim: int, num_layers: int = 1):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
        )
        self.fc = nn.Linear(hidden_dim, latent_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x shape: (batch, seq_len, input_dim)
        lstm_out, (hn, _cn) = self.lstm(x)
        # Use final layer's hidden state hn[-1] of shape (batch, hidden_dim)
        latent = self.fc(hn[-1])
        return latent  # shape: (batch, latent_dim)


class Decoder(nn.Module):
    """
    LSTM Decoder: expands latent representation of shape (batch, latent_dim)
    back to the reconstructed sequence of shape (batch, seq_len, input_dim).
    """

    def __init__(
        self,
        latent_dim: int,
        hidden_dim: int,
        input_dim: int,
        seq_len: int,
        num_layers: int = 1,
    ):
        super().__init__()
        self.seq_len = seq_len
        self.fc_in = nn.Linear(latent_dim, hidden_dim)
        self.lstm = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
        )
        self.fc_out = nn.Linear(hidden_dim, input_dim)

    def forward(self, latent: torch.Tensor) -> torch.Tensor:
        # latent shape: (batch, latent_dim)
        hidden = self.fc_in(latent)  # shape: (batch, hidden_dim)
        # Repeat across time steps: (batch, seq_len, hidden_dim)
        repeated = hidden.unsqueeze(1).repeat(1, self.seq_len, 1)
        lstm_out, _ = self.lstm(repeated)
        # Project each time step back to input_dim: (batch, seq_len, input_dim)
        out = self.fc_out(lstm_out)
        return out


class LSTMAutoencoder(nn.Module):
    """
    Complete Lightweight LSTM Autoencoder for temporal anomaly detection.
    Optimized for CPU-first execution, robust input validation, and reconstruction scoring.
    """

    def __init__(self, config: Optional[MLModelConfig] = None):
        super().__init__()
        self.config = config or MLModelConfig()
        self.input_dim = self.config.input_dim
        self.hidden_dim = self.config.hidden_dim
        self.latent_dim = self.config.latent_dim
        self.num_layers = self.config.num_layers
        self.seq_len = self.config.seq_len

        self.encoder = Encoder(
            input_dim=self.input_dim,
            hidden_dim=self.hidden_dim,
            latent_dim=self.latent_dim,
            num_layers=self.num_layers,
        )
        self.decoder = Decoder(
            latent_dim=self.latent_dim,
            hidden_dim=self.hidden_dim,
            input_dim=self.input_dim,
            seq_len=self.seq_len,
            num_layers=self.num_layers,
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass through encoder-decoder.
        Input x: shape (batch, seq_len, input_dim)
        Output: reconstructed tensor of shape (batch, seq_len, input_dim)
        """
        x_clean = self.sanitize_input(x)
        latent = self.encoder(x_clean)
        x_reconstructed = self.decoder(latent)
        return x_reconstructed

    def sanitize_input(self, x: torch.Tensor) -> torch.Tensor:
        """
        Validates and sanitizes input tensor:
        - Ensures tensor is a 3D float tensor of shape (*, seq_len, input_dim)
        - Replaces NaNs with 0.0
        - Clamps +/- infinity to large finite numbers
        """
        if not isinstance(x, torch.Tensor):
            x = torch.tensor(x, dtype=torch.float32)

        if x.dim() == 2:
            # Single sequence of shape (seq_len, input_dim) -> add batch dimension
            x = x.unsqueeze(0)

        if x.dim() != 3:
            raise ValueError(
                f"Expected 3D tensor of shape (batch, {self.seq_len}, {self.input_dim}), "
                f"got tensor with {x.dim()} dimensions: {tuple(x.shape)}"
            )

        if x.shape[1] != self.seq_len:
            raise ValueError(
                f"Input sequence length {x.shape[1]} does not match model seq_len {self.seq_len}"
            )

        if x.shape[2] != self.input_dim:
            raise ValueError(
                f"Input feature dimension {x.shape[2]} does not match model input_dim {self.input_dim}"
            )

        # Handle NaNs and Infs safely
        if torch.isnan(x).any() or torch.isinf(x).any():
            logger.debug("[sanitize_input] Replacing NaN/Inf values with 0.0")
            x = torch.nan_to_num(x, nan=0.0, posinf=1e4, neginf=-1e4)

        return x.to(dtype=torch.float32)

    def compute_reconstruction_error(
        self,
        x: torch.Tensor,
        x_hat: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Computes Mean Squared Error (MSE) per sequence:
        MSE = 1 / (seq_len * input_dim) * sum((x - x_hat)^2)
        Returns:
            1D tensor of shape (batch,) containing MSE per window.
        """
        x_clean = self.sanitize_input(x)
        if x_hat is None:
            self.eval()
            with torch.no_grad():
                x_hat = self.forward(x_clean)

        # Squared difference
        diff_sq = (x_clean - x_hat) ** 2
        # Average across seq_len (dim 1) and features (dim 2)
        mse_per_sequence = torch.mean(diff_sq, dim=(1, 2))
        return mse_per_sequence

    def save_weights(self, file_path: Union[str, Path]) -> None:
        """Saves PyTorch state_dict to file."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(self.state_dict(), str(path))
        logger.info("[save_weights] Saved model weights to '%s'", path)

    def load_weights(
        self,
        file_path: Union[str, Path],
        device: Optional[Union[str, torch.device]] = None,
    ) -> None:
        """Loads PyTorch state_dict from file onto specified device."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Weights file not found: {path}")

        target_device = (
            device
            if isinstance(device, torch.device)
            else resolve_device(str(device) if device else self.config.device)
        )
        state_dict = torch.load(str(path), map_location=target_device, weights_only=True)
        self.load_state_dict(state_dict)
        self.to(target_device)
        logger.info("[load_weights] Loaded model weights from '%s' to device '%s'", path, target_device)
