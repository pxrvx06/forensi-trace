"""
ForensiTrace Normalized Event Schema & Validation Models
Author: Purva (Backend & Data Layer Owner)
Contract: docs/schema.md
"""

from __future__ import annotations

import re
import json
import hashlib
import logging
from enum import Enum
from typing import Any, Optional, Union
from pydantic import BaseModel, Field, field_validator, model_validator

# Configure module logging with clear labeling
logger = logging.getLogger("forensitrace.schema")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class SourceEnum(str, Enum):
    """Allowed evidence sources per docs/schema.md."""
    usb = "usb"
    fs = "fs"
    eventlog = "eventlog"


class ActionEnum(str, Enum):
    """Allowed actions per source per docs/schema.md."""
    # USB actions
    DEVICE_ARRIVED = "DEVICE_ARRIVED"
    DEVICE_REMOVED = "DEVICE_REMOVED"
    
    # File system actions
    FILE_CREATED = "FILE_CREATED"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_DELETED = "FILE_DELETED"
    FILE_MOVED = "FILE_MOVED"
    
    # Windows Event Log actions
    PROCESS_STARTED = "PROCESS_STARTED"
    LOG_CLEARED = "LOG_CLEARED"
    LOGON = "LOGON"


class EntityTypeEnum(str, Enum):
    """Allowed entity classifications per docs/schema.md."""
    device = "device"
    file = "file"
    process = "process"


# Strict mapping of source to allowed actions
ALLOWED_ACTIONS_BY_SOURCE: dict[SourceEnum, set[ActionEnum]] = {
    SourceEnum.usb: {ActionEnum.DEVICE_ARRIVED, ActionEnum.DEVICE_REMOVED},
    SourceEnum.fs: {
        ActionEnum.FILE_CREATED,
        ActionEnum.FILE_MODIFIED,
        ActionEnum.FILE_DELETED,
        ActionEnum.FILE_MOVED
    },
    SourceEnum.eventlog: {
        ActionEnum.PROCESS_STARTED,
        ActionEnum.LOG_CLEARED,
        ActionEnum.LOGON
    }
}

TIMESTAMP_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
HEX64_REGEX = re.compile(r"^[0-9a-f]{64}$")


def compute_event_id(source: str | SourceEnum, raw_record_id: str, ts_utc: str) -> str:
    """
    Deterministic SHA-256 event_id recipe from docs/schema.md:
    event_id = SHA256("{source}|{raw_record_id}|{ts_utc}")
    """
    src_str = source.value if isinstance(source, SourceEnum) else str(source)
    seed = f"{src_str}|{raw_record_id}|{ts_utc}"
    computed = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    logger.debug("[compute_event_id] [RECEIVED] seed='%s' -> [PRODUCED] event_id='%s'", seed, computed)
    return computed


class Event(BaseModel):
    """
    Normalized ForensiTrace Event Model.
    Strictly mirrors docs/schema.md specification.
    """
    event_id: str = Field(
        ...,
        description="Deterministic SHA-256 hash (64 lowercase hex characters)"
    )
    source: SourceEnum = Field(..., description="Telemetry source: eventlog, usb, or fs")
    ts_utc: str = Field(
        ...,
        description="Event timestamp in UTC ISO 8601 with milliseconds (YYYY-MM-DDTHH:MM:SS.mmmZ)"
    )
    host: str = Field(..., description="Hostname/NetBIOS machine name where telemetry originated")
    user: Optional[str] = Field(None, description="Account involved (or null if unattributed)")
    action: ActionEnum = Field(..., description="Standardized action descriptor")
    entity_type: EntityTypeEnum = Field(..., description="Affected entity type: device, file, process")
    entity: str = Field(..., description="Primary affected entity path, device identifier, or binary")
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Source-specific structured parameters (including raw_record_id)"
    )
    raw: Any = Field(..., description="Untouched original telemetry record for explainability")

    @field_validator("ts_utc")
    @classmethod
    def validate_timestamp_format(cls, v: str) -> str:
        if not TIMESTAMP_REGEX.match(v):
            raise ValueError(f"ts_utc '{v}' does not match UTC ISO 8601 format: YYYY-MM-DDTHH:MM:SS.mmmZ")
        return v

    @field_validator("event_id")
    @classmethod
    def validate_event_id_format(cls, v: str) -> str:
        if not HEX64_REGEX.match(v):
            raise ValueError(f"event_id '{v}' must be a 64-character lowercase SHA-256 hex string")
        return v

    @field_validator("entity")
    @classmethod
    def validate_entity_path_conventions(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("entity cannot be empty")
        # Check forward slashes in Windows drive paths
        if "/" in v and (":" in v or "\\" in v):
            raise ValueError(f"entity '{v}' must use Windows backslashes '\\', not forward slashes")
        # Check drive letter casing if present
        if len(v) >= 2 and v[1] == ":" and not v[0].isupper():
            raise ValueError(f"Drive letter in entity '{v}' must be uppercase")
        return v

    @model_validator(mode="after")
    def validate_action_against_source(self) -> Event:
        allowed = ALLOWED_ACTIONS_BY_SOURCE.get(self.source, set())
        if self.action not in allowed:
            allowed_names = [a.value for a in allowed]
            raise ValueError(
                f"Action '{self.action.value}' is not permitted for source '{self.source.value}'. Allowed: {allowed_names}"
            )
        return self


class EventBatch(BaseModel):
    """Batch of events transmitted by the agent HTTP sender."""
    events: list[Event] = Field(..., description="List of normalized events")
    batch_size: Optional[int] = Field(None, description="Reported event count in batch")

    @model_validator(mode="after")
    def sync_batch_size(self) -> EventBatch:
        if self.batch_size is None:
            self.batch_size = len(self.events)
        return self


class Activity(BaseModel):
    """Reconstructed activity produced by Akash's correlation engine."""
    activity_id: str = Field(..., description="Unique activity identifier (e.g. act_20261023_001)")
    rule_id: str = Field(..., description="Triggered correlation rule ID (e.g. R1, R2, R7)")
    rule_name: str = Field(..., description="Human-readable rule title")
    ts_start_utc: str = Field(..., description="Earliest event timestamp in the sequence")
    ts_end_utc: str = Field(..., description="Latest event timestamp in the sequence")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score (0.0 to 1.0)")
    narrative: Optional[str] = Field(None, description="Plain-English explanation citing evidence events")


class ActivityEventLink(BaseModel):
    """Provenance link connecting an activity to an underlying raw event."""
    activity_id: str = Field(..., description="Target activity ID")
    event_id: str = Field(..., description="Supporting event ID")
    rule_id: str = Field(..., description="Rule ID requiring this evidence")
    reason: str = Field(..., description="One-line forensic justification for inclusion")
