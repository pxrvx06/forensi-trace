"""
engine/ml/adapter.py - Configurable Event-to-Feature Adapter and Sequence Formulation.

Author: Akash (Correlation Engine & ML Owner)
Contract: docs/ml.md (Section 2, 3), backend/ml_features.py, backend/schema.py
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

try:
    from backend.schema import ActionEnum, Event, SourceEnum
    from backend.ml_features import (
        ACTIONS_ORDER as BACKEND_ACTIONS_ORDER,
        FEATURE_DIM as BACKEND_FEATURE_DIM,
        extract_event_features as backend_extract_features,
        create_feature_windows as backend_create_windows,
        is_executable_entity,
        is_removable_drive,
    )
    HAS_BACKEND_ML_FEATURES = True
except ImportError:
    HAS_BACKEND_ML_FEATURES = False
    ActionEnum = None  # type: ignore
    Event = None  # type: ignore
    SourceEnum = None  # type: ignore

logger = logging.getLogger("forensitrace.engine.ml.adapter")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Default fallback action order if backend schema is decoupled
DEFAULT_ACTIONS_ORDER = [
    "DEVICE_ARRIVED",
    "DEVICE_REMOVED",
    "FILE_CREATED",
    "FILE_MODIFIED",
    "FILE_DELETED",
    "FILE_MOVED",
    "PROCESS_STARTED",
    "LOG_CLEARED",
    "LOGON",
]

DEFAULT_NUMERICAL_FEATURE_NAMES = [
    "DELTA_T_LOG",
    "IS_EXECUTABLE",
    "IS_REMOVABLE",
]


@dataclass
class FeatureWindow:
    """Represents a formulated temporal sliding window of consecutive events."""
    window_index: int
    session_id: str
    ts_start_utc: str
    ts_end_utc: str
    event_ids: List[str]
    feature_matrix: List[List[float]]  # Shape: (window_size, feature_dim)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_index": self.window_index,
            "session_id": self.session_id,
            "ts_start_utc": self.ts_start_utc,
            "ts_end_utc": self.ts_end_utc,
            "event_ids": self.event_ids,
            "feature_matrix": self.feature_matrix,
        }


def parse_timestamp_iso(ts: str) -> Optional[datetime]:
    """Safely parses ISO-8601 UTC timestamp string into timezone-aware datetime."""
    if not ts or not isinstance(ts, str):
        return None
    try:
        clean_ts = ts.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception as exc:
        logger.debug("[parse_timestamp_iso] Failed to parse '%s': %s", ts, exc)
        return None


class EventFeatureAdapter:
    """
    Configurable adapter transforming raw/normalized events into feature vectors
    and session-isolated sliding windows for the LSTM Autoencoder.
    """

    def __init__(
        self,
        actions_order: Optional[List[str]] = None,
        window_size: int = 10,
        stride: int = 1,
        feature_extractor: Optional[Callable[[Any, Optional[Any]], List[float]]] = None,
    ):
        if actions_order is not None:
            self.actions_order = list(actions_order)
        elif HAS_BACKEND_ML_FEATURES:
            self.actions_order = [a.value if hasattr(a, "value") else str(a) for a in BACKEND_ACTIONS_ORDER]
        else:
            self.actions_order = list(DEFAULT_ACTIONS_ORDER)

        self.action_to_idx = {act: idx for idx, act in enumerate(self.actions_order)}
        self.num_actions = len(self.actions_order)
        self.numerical_feature_names = list(DEFAULT_NUMERICAL_FEATURE_NAMES)
        self.feature_dim = self.num_actions + len(self.numerical_feature_names)

        self.window_size = window_size
        self.stride = stride
        self._custom_extractor = feature_extractor

        logger.info(
            "[EventFeatureAdapter] Initialized with %d actions, total feature_dim=%d, window_size=%d, stride=%d",
            self.num_actions,
            self.feature_dim,
            self.window_size,
            self.stride,
        )

    def get_feature_names(self) -> List[str]:
        """Returns the ordered list of feature names matching the vector indices."""
        action_names = [f"ACTION_{a}" for a in self.actions_order]
        return action_names + self.numerical_feature_names

    def get_metadata(self) -> Dict[str, Any]:
        """Returns feature metadata for serialization alongside model weights."""
        return {
            "feature_dim": self.feature_dim,
            "num_actions": self.num_actions,
            "actions_order": self.actions_order,
            "numerical_features": self.numerical_feature_names,
            "feature_names": self.get_feature_names(),
            "window_size": self.window_size,
            "stride": self.stride,
        }

    def _event_to_dict(self, event: Any) -> Dict[str, Any]:
        """Converts Event Pydantic model or dict to standard dictionary."""
        if hasattr(event, "model_dump"):
            return event.model_dump()
        if isinstance(event, dict):
            return dict(event)
        raise TypeError(f"Unsupported event type: {type(event)}")

    def extract_features(
        self,
        event: Any,
        prev_event: Optional[Any] = None,
    ) -> List[float]:
        """
        Extracts a single feature vector of length `feature_dim`:
        - [0 .. num_actions-1]: One-hot action indicators
        - [num_actions + 0]: log(1 + seconds_elapsed)
        - [num_actions + 1]: is_executable indicator (1.0 or 0.0)
        - [num_actions + 2]: is_removable indicator (1.0 or 0.0)
        """
        if self._custom_extractor is not None:
            return self._custom_extractor(event, prev_event)

        # If backend ml_features is available and action order matches, reuse backend extractor
        if HAS_BACKEND_ML_FEATURES and self.actions_order == [
            a.value if hasattr(a, "value") else str(a) for a in BACKEND_ACTIONS_ORDER
        ]:
            try:
                return backend_extract_features(event, prev_event)
            except Exception as e:
                logger.debug("[extract_features] backend_extract_features failed (%s); falling back", e)

        # Independent standalone feature extraction
        ev_dict = self._event_to_dict(event)
        prev_dict = self._event_to_dict(prev_event) if prev_event is not None else None

        features = [0.0] * self.feature_dim

        # 1. Action one-hot encoding
        raw_action = ev_dict.get("action")
        action_val = raw_action.value if hasattr(raw_action, "value") else str(raw_action or "")
        if action_val in self.action_to_idx:
            features[self.action_to_idx[action_val]] = 1.0

        # 2. Elapsed time: log(1 + dt_sec)
        dt_sec = 0.0
        if prev_dict:
            t_curr = parse_timestamp_iso(ev_dict.get("ts_utc", ""))
            t_prev = parse_timestamp_iso(prev_dict.get("ts_utc", ""))
            if t_curr and t_prev:
                elapsed = (t_curr - t_prev).total_seconds()
                dt_sec = max(0.0, elapsed)
        features[self.num_actions + 0] = float(math.log(1.0 + dt_sec))

        # 3. Executable flag
        entity = str(ev_dict.get("entity", "") or "").lower()
        executable_exts = {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".sys",
            ".scr", ".msi", ".vbe", ".wsf", ".com", ".cpl"
        }
        is_exec = 1.0 if any(entity.endswith(ext) for ext in executable_exts) else 0.0
        features[self.num_actions + 1] = is_exec

        # 4. Removable drive flag
        src = ev_dict.get("source")
        src_val = src.value if hasattr(src, "value") else str(src or "")
        is_rem = 0.0
        if src_val == "usb":
            is_rem = 1.0
        else:
            drive = ev_dict.get("details", {}).get("drive_letter")
            if drive and isinstance(drive, str) and not drive.upper().startswith("C:"):
                is_rem = 1.0
            elif len(entity) >= 2 and entity[1] == ":" and not entity.upper().startswith("C"):
                is_rem = 1.0
            elif "usbstor" in entity:
                is_rem = 1.0
        features[self.num_actions + 2] = is_rem

        return features

    def create_windows_for_sequence(
        self,
        events: Sequence[Any],
        session_id: str = "default_session",
    ) -> List[FeatureWindow]:
        """
        Creates chronological sliding windows for a single session sequence.
        Guarantees:
        - If len(events) < window_size: generates 1 left-padded window with zeros.
        - If len(events) >= window_size: generates sliding windows with configured stride.
        """
        if not events:
            return []

        # Sort chronologically by timestamp
        def get_ts(e: Any) -> str:
            d = self._event_to_dict(e)
            return d.get("ts_utc", "")

        sorted_events = sorted(events, key=get_ts)

        # Extract features and gather event IDs
        vectors: List[List[float]] = []
        event_ids: List[str] = []
        timestamps: List[str] = []

        for i, ev in enumerate(sorted_events):
            prev = sorted_events[i - 1] if i > 0 else None
            vec = self.extract_features(ev, prev)
            vectors.append(vec)

            ev_dict = self._event_to_dict(ev)
            ev_id = str(ev_dict.get("event_id", f"ev_{i}"))
            ts = str(ev_dict.get("ts_utc", ""))
            event_ids.append(ev_id)
            timestamps.append(ts)

        windows: List[FeatureWindow] = []
        n = len(sorted_events)

        if n < self.window_size:
            pad_count = self.window_size - n
            zero_row = [0.0] * self.feature_dim
            padded_matrix = [zero_row for _ in range(pad_count)] + vectors
            windows.append(
                FeatureWindow(
                    window_index=0,
                    session_id=session_id,
                    ts_start_utc=timestamps[0] if timestamps else "",
                    ts_end_utc=timestamps[-1] if timestamps else "",
                    event_ids=event_ids,
                    feature_matrix=padded_matrix,
                )
            )
            return windows

        # Standard sliding window with stride
        window_idx = 0
        for start in range(0, n - self.window_size + 1, self.stride):
            end = start + self.window_size
            matrix = vectors[start:end]
            windows.append(
                FeatureWindow(
                    window_index=window_idx,
                    session_id=session_id,
                    ts_start_utc=timestamps[start],
                    ts_end_utc=timestamps[end - 1],
                    event_ids=event_ids[start:end],
                    feature_matrix=matrix,
                )
            )
            window_idx += 1

        return windows

    def generate_session_windows(
        self,
        events_or_sessions: Union[Dict[str, Sequence[Any]], Sequence[Any]],
    ) -> List[FeatureWindow]:
        """
        CRITICAL ARCHITECTURAL INVARIANT (docs/ml.md Section 3 & 6):
        Preserves session boundaries. Never creates windows crossing unrelated sessions.

        Accepts either:
        1. A dict mapping session_id -> list of events.
        2. A flat list of events where each event contains `details.session_id`.
           If no session_id is found, events are grouped by host or marked as single session.
        """
        all_windows: List[FeatureWindow] = []

        if isinstance(events_or_sessions, dict):
            # Dict mapping session_id -> events
            for s_id, s_events in sorted(events_or_sessions.items()):
                w_list = self.create_windows_for_sequence(s_events, session_id=s_id)
                all_windows.extend(w_list)
            return all_windows

        # Flat list of events: group strictly by session_id
        session_groups: Dict[str, List[Any]] = {}
        for ev in events_or_sessions:
            ev_dict = self._event_to_dict(ev)
            s_id = (
                ev_dict.get("details", {}).get("session_id")
                or ev_dict.get("session_id")
                or ev_dict.get("host")
                or "session_default"
            )
            session_groups.setdefault(str(s_id), []).append(ev)

        for s_id, s_events in sorted(session_groups.items()):
            w_list = self.create_windows_for_sequence(s_events, session_id=s_id)
            all_windows.extend(w_list)

        logger.debug(
            "[generate_session_windows] Generated %d window(s) across %d session(s)",
            len(all_windows),
            len(session_groups),
        )
        return all_windows
