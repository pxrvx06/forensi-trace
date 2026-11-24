"""
ForensiTrace Feature Extraction & ML Dataset Preparation Pipeline
Author: Purva (Backend, Data Layer & ML Interface Owner)
Contract: docs/ml.md & Execution Plan Step 2 & 3

Provides:
- Dynamic feature vector extraction strictly based on ActionEnum plus 3 context flags (never hard-coded)
- Consecutive event sliding window formulation (N=10, stride=1)
- Session-based dataset partitioning (train/val/test) guaranteeing zero cross-session leakage
- Export helpers for Akash's PyTorch LSTM Autoencoder in engine/ml/
"""

from __future__ import annotations

import os
import json
import math
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from backend.schema import ActionEnum, Event, SourceEnum

logger = logging.getLogger("forensitrace.ml_features")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Dynamic action order from schema (never hard-code length)
ACTIONS_ORDER: List[ActionEnum] = list(ActionEnum)
ACTION_TO_INDEX: Dict[ActionEnum, int] = {action: idx for idx, action in enumerate(ACTIONS_ORDER)}
NUM_ACTIONS: int = len(ACTIONS_ORDER)

# Total feature vector dimension: actions + 3 metadata flags
FEATURE_DIM: int = NUM_ACTIONS + 3

# File extensions classified as executable/script payloads
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".sys",
    ".scr", ".msi", ".vbe", ".wsf", ".com", ".cpl"
}


def parse_timestamp_utc(ts: str) -> datetime:
    """Parses UTC ISO 8601 timestamp string into timezone-aware datetime."""
    clean_ts = ts.replace("Z", "+00:00")
    return datetime.fromisoformat(clean_ts)


def is_executable_entity(entity: str) -> bool:
    """
    Checks if an entity path or process name ends with an executable/script extension.
    Case-insensitive check.
    """
    if not entity:
        return False
    lower = entity.strip().lower()
    return any(lower.endswith(ext) for ext in EXECUTABLE_EXTENSIONS)


def is_removable_drive(event: Union[Event, dict[str, Any]]) -> bool:
    """
    Checks if the event targets a removable/non-system volume (i.e. drive != 'C:').
    Inspects source, entity path, and details dictionary.
    """
    src = event.source.value if isinstance(event, Event) else event.get("source")
    if src == SourceEnum.usb.value or src == "usb":
        return True

    details = event.details if isinstance(event, Event) else event.get("details", {})
    drive_letter = details.get("drive_letter")
    if drive_letter and isinstance(drive_letter, str):
        if drive_letter.upper().startswith("C:"):
            return False
        return True

    entity = event.entity if isinstance(event, Event) else event.get("entity", "")
    if len(entity) >= 2 and entity[1] == ":":
        return not entity[0].upper().startswith("C")

    # If USB instance ID or device ID is referenced
    if "USBSTOR" in entity.upper():
        return True

    return False


def extract_event_features(
    event: Union[Event, dict[str, Any]],
    prev_event: Optional[Union[Event, dict[str, Any]]] = None
) -> List[float]:
    """
    CRITICAL HANDOFF CONTRACT FOR AKASH'S ML MODEL (docs/ml.md):
    Extracts a feature vector of exact length FEATURE_DIM = len(ActionEnum) + 3:
    - [0 .. NUM_ACTIONS-1]: One-hot encoded action flag
    - [NUM_ACTIONS + 0]: log(1 + max(0.0, seconds_elapsed))
    - [NUM_ACTIONS + 1]: is_executable (1.0 or 0.0)
    - [NUM_ACTIONS + 2]: is_removable (1.0 or 0.0)
    """
    logger.debug("[extract_event_features] [RECEIVED] event_id='%s'", getattr(event, "event_id", event.get("event_id") if isinstance(event, dict) else "unknown"))

    ev_dict = event.model_dump() if isinstance(event, Event) else event
    action_raw = ev_dict.get("action")
    action_val = action_raw.value if hasattr(action_raw, "value") else str(action_raw)

    # 1. Initialize vector with zeros of length FEATURE_DIM
    features = [0.0] * FEATURE_DIM

    # 2. Action one-hot encoding
    for idx, act in enumerate(ACTIONS_ORDER):
        if act.value == action_val:
            features[idx] = 1.0
            break

    # 3. Elapsed time delta: log(1 + dt)
    curr_ts_str = ev_dict.get("ts_utc")
    dt_sec = 0.0
    if prev_event and curr_ts_str:
        prev_dict = prev_event.model_dump() if isinstance(prev_event, Event) else prev_event
        prev_ts_str = prev_dict.get("ts_utc")
        if prev_ts_str:
            try:
                curr_dt = parse_timestamp_utc(curr_ts_str)
                prev_dt = parse_timestamp_utc(prev_ts_str)
                elapsed = (curr_dt - prev_dt).total_seconds()
                dt_sec = max(0.0, elapsed)
            except Exception as e:
                logger.warning("[extract_event_features] Failed to parse timestamps: %s", e)
                dt_sec = 0.0

    features[NUM_ACTIONS + 0] = float(math.log(1.0 + dt_sec))

    # 4. Executable flag
    entity = ev_dict.get("entity", "")
    features[NUM_ACTIONS + 1] = 1.0 if is_executable_entity(entity) else 0.0

    # 5. Removable drive flag
    features[NUM_ACTIONS + 2] = 1.0 if is_removable_drive(ev_dict) else 0.0

    logger.debug("[extract_event_features] [PRODUCED] Extracted %d-dim vector: %s", len(features), features)
    return features


def create_feature_windows(
    events: List[Union[Event, dict[str, Any]]],
    window_size: int = 10,
    stride: int = 1
) -> List[Dict[str, Any]]:
    """
    Transforms a chronologically ordered sequence of events into sliding windows.
    Returns a list of window dicts containing:
    - window_index: int
    - ts_start_utc: str
    - ts_end_utc: str
    - event_ids: List[str]
    - feature_matrix: List[List[float]] of shape (window_size, FEATURE_DIM)
    """
    logger.debug("[create_feature_windows] [RECEIVED] %d events, window_size=%d", len(events), window_size)
    if not events:
        return []

    # Sort events chronologically to guarantee sequential integrity
    sorted_events = sorted(
        events,
        key=lambda e: getattr(e, "ts_utc", e.get("ts_utc") if isinstance(e, dict) else "")
    )

    # Precompute individual feature vectors
    vectors: List[List[float]] = []
    event_ids: List[str] = []
    timestamps: List[str] = []

    for i, ev in enumerate(sorted_events):
        prev = sorted_events[i - 1] if i > 0 else None
        vec = extract_event_features(ev, prev)
        vectors.append(vec)
        ev_id = getattr(ev, "event_id", ev.get("event_id") if isinstance(ev, dict) else "")
        ts = getattr(ev, "ts_utc", ev.get("ts_utc") if isinstance(ev, dict) else "")
        event_ids.append(ev_id)
        timestamps.append(ts)

    windows: List[Dict[str, Any]] = []

    # If sequence is shorter than window_size, create a single left-padded window
    if len(sorted_events) < window_size:
        pad_count = window_size - len(sorted_events)
        zero_vec = [0.0] * FEATURE_DIM
        padded_matrix = [zero_vec for _ in range(pad_count)] + vectors
        windows.append({
            "window_index": 0,
            "ts_start_utc": timestamps[0],
            "ts_end_utc": timestamps[-1],
            "event_ids": event_ids,
            "feature_matrix": padded_matrix
        })
        logger.debug("[create_feature_windows] [PRODUCED] 1 left-padded window generated")
        return windows

    # Standard sliding window over the vectors
    window_idx = 0
    for start in range(0, len(sorted_events) - window_size + 1, stride):
        end = start + window_size
        matrix = vectors[start:end]
        windows.append({
            "window_index": window_idx,
            "ts_start_utc": timestamps[start],
            "ts_end_utc": timestamps[end - 1],
            "event_ids": event_ids[start:end],
            "feature_matrix": matrix
        })
        window_idx += 1

    logger.debug("[create_feature_windows] [PRODUCED] Generated %d sliding window(s)", len(windows))
    return windows


def partition_sessions_by_recording(
    sessions: Dict[str, List[Union[Event, dict[str, Any]]]],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15
) -> Dict[str, List[str]]:
    """
    CRITICAL FORENSIC REQUIREMENT (docs/ml.md Section 6):
    Partitions datasets strictly by session IDs.
    Guarantees no session appears in multiple splits.
    """
    session_ids = sorted(list(sessions.keys()))
    num_sessions = len(session_ids)
    logger.info("[partition_sessions_by_recording] [RECEIVED] Partitioning %d session(s)", num_sessions)

    if num_sessions == 0:
        return {"train": [], "val": [], "test": []}

    if num_sessions == 1:
        # Single session cannot be split without leakage; default to test
        return {"train": [], "val": [], "test": session_ids}

    if num_sessions == 2:
        return {"train": [session_ids[0]], "val": [], "test": [session_ids[1]]}

    n_train = max(1, int(round(num_sessions * train_ratio)))
    n_val = max(1, int(round(num_sessions * val_ratio)))
    if n_train + n_val >= num_sessions:
        n_train = max(1, num_sessions - 2)
        n_val = 1

    train_sessions = session_ids[:n_train]
    val_sessions = session_ids[n_train:n_train + n_val]
    test_sessions = session_ids[n_train + n_val:]

    # Assert mutual exclusivity (no data leakage)
    train_set = set(train_sessions)
    val_set = set(val_sessions)
    test_set = set(test_sessions)

    assert train_set.isdisjoint(val_set), "Data leakage between train and val splits!"
    assert train_set.isdisjoint(test_set), "Data leakage between train and test splits!"
    assert val_set.isdisjoint(test_set), "Data leakage between val and test splits!"

    logger.info(
        "[partition_sessions_by_recording] [PRODUCED] Split: %d train, %d val, %d test",
        len(train_sessions), len(val_sessions), len(test_sessions)
    )
    return {
        "train": train_sessions,
        "val": val_sessions,
        "test": test_sessions
    }


def export_training_data_splits(
    sessions: Dict[str, List[Union[Event, dict[str, Any]]]],
    output_dir: Union[str, Path],
    window_size: int = 10,
    stride: int = 1
) -> Dict[str, Any]:
    """
    Exports partitioned sliding window datasets as JSON files for Akash's PyTorch model.
    Files created in output_dir:
    - train_windows.json
    - val_windows.json
    - test_windows.json
    - split_metadata.json
    """
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    logger.info("[export_training_data_splits] [RECEIVED] Exporting splits to '%s'", target_dir)

    splits = partition_sessions_by_recording(sessions)
    counts: Dict[str, int] = {}

    for split_name, session_keys in splits.items():
        all_windows: List[Dict[str, Any]] = []
        for s_id in session_keys:
            evs = sessions[s_id]
            windows = create_feature_windows(evs, window_size=window_size, stride=stride)
            for w in windows:
                w["session_id"] = s_id
                all_windows.append(w)

        out_file = target_dir / f"{split_name}_windows.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump({
                "split": split_name,
                "sessions": session_keys,
                "feature_dim": FEATURE_DIM,
                "window_size": window_size,
                "total_windows": len(all_windows),
                "windows": all_windows
            }, f, indent=2)

        counts[split_name] = len(all_windows)
        logger.info("[export_training_data_splits] [PRODUCED] %s: %d windows across %d sessions", split_name, len(all_windows), len(session_keys))

    metadata_file = target_dir / "split_metadata.json"
    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump({
            "exported_at_utc": datetime.now(timezone.utc).isoformat(),
            "feature_dim": FEATURE_DIM,
            "actions_order": [a.value for a in ACTIONS_ORDER],
            "window_size": window_size,
            "splits": splits,
            "window_counts": counts
        }, f, indent=2)

    return {
        "output_dir": str(target_dir),
        "feature_dim": FEATURE_DIM,
        "window_size": window_size,
        "splits": splits,
        "window_counts": counts
    }
