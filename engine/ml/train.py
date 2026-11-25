"""
engine/ml/train.py - Standalone Command-Line Training Entrypoint for ForensiTrace ML Subsystem.

Author: Akash (Correlation Engine & ML Owner)
Contract: docs/ml.md (Section 4, 6)

Usage:
    python -m engine.ml.train --data-dir scenarios/baseline --output-dir engine/ml/artifacts
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from engine.ml.config import MLModelConfig
from engine.ml.trainer import TrainingPipeline

logger = logging.getLogger("forensitrace.engine.ml.train")


def load_sessions_from_directory(data_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Loads all session JSON files from the specified directory."""
    if not data_dir.is_dir():
        raise FileNotFoundError(f"Data directory '{data_dir}' does not exist.")

    session_files = sorted(data_dir.glob("*.json"))
    if not session_files:
        raise ValueError(f"No JSON session files found in '{data_dir}'.")

    sessions: Dict[str, List[Dict[str, Any]]] = {}
    for file_path in session_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            session_id = file_path.stem
            if isinstance(data, list):
                sessions[session_id] = data
            elif isinstance(data, dict) and "events" in data:
                sessions[session_id] = data["events"]
            else:
                logger.warning("File '%s' does not contain a list of events; skipping.", file_path)
        except Exception as exc:
            logger.error("Failed to parse '%s': %s", file_path, exc)

    logger.info("Loaded %d session(s) from '%s'", len(sessions), data_dir)
    return sessions


def run_training(
    data_dir: Union[str, Path] = "scenarios/baseline",
    output_dir: Union[str, Path] = "engine/ml/artifacts",
    epochs: int = 50,
    batch_size: int = 16,
    learning_rate: float = 0.001,
    random_seed: int = 42,
    device: str = "cpu",
    allow_synthetic: bool = False,
) -> Dict[str, Any]:
    """Runs end-to-end training pipeline and returns summary metrics."""
    data_path = Path(data_dir)
    out_path = Path(output_dir)

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    )

    logger.info("Initializing ForensiTrace ML Training Pipeline...")
    sessions = load_sessions_from_directory(data_path)

    config = MLModelConfig(
        epochs=epochs,
        batch_size=batch_size,
        learning_rate=learning_rate,
        random_seed=random_seed,
        device=device,
        artifacts_dir=str(out_path),
    )

    trainer = TrainingPipeline(
        config=config,
        allow_synthetic=allow_synthetic,
    )

    model, threshold_metadata, summary = trainer.train(
        sessions=sessions,
        artifacts_dir=out_path,
    )

    logger.info("Training complete! Model artifacts saved to: %s", out_path)
    logger.info("Selected Baseline Anomaly Threshold: %.6f (P99)", threshold_metadata.threshold)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Train ForensiTrace PyTorch LSTM Autoencoder")
    parser.add_argument(
        "--data-dir",
        type=str,
        default="scenarios/baseline",
        help="Directory containing normal baseline session JSON files",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="engine/ml/artifacts",
        help="Directory to persist trained model and metadata artifacts",
    )
    parser.add_argument("--epochs", type=int, default=50, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=16, help="Training batch size")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--seed", type=int, default=42, help="Random reproducibility seed")
    parser.add_argument("--device", type=str, default="cpu", help="Execution device: cpu or cuda")
    parser.add_argument(
        "--allow-synthetic",
        action="store_true",
        help="Explicitly allow synthetic normal sessions in training",
    )

    args = parser.parse_args()
    try:
        run_training(
            data_dir=args.data_dir,
            output_dir=args.output_dir,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.lr,
            random_seed=args.seed,
            device=args.device,
            allow_synthetic=args.allow_synthetic,
        )
    except Exception as exc:
        logger.error("Training execution failed: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
