"""
ForensiTrace Raw Telemetry Normalizers
Author: Purva (Backend & Data Layer Owner)
Contract: docs/schema.md & Step 3 of Execution Plan
Transforms raw telemetry records from USB, File System (watchdog), and Event Log into normalized Event models.
"""

from __future__ import annotations

import os
import re
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from backend.schema import (
    Event,
    SourceEnum,
    ActionEnum,
    EntityTypeEnum,
    compute_event_id
)

logger = logging.getLogger("forensitrace.normalizers")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def _format_utc_timestamp(dt: Optional[datetime] = None) -> str:
    """Returns an ISO 8601 UTC timestamp with millisecond precision and literal Z."""
    target_dt = dt or datetime.now(timezone.utc)
    if target_dt.tzinfo is None:
        target_dt = target_dt.replace(tzinfo=timezone.utc)
    else:
        target_dt = target_dt.astimezone(timezone.utc)
    return target_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _canonicalize_path(path_str: str) -> str:
    """Standardizes a Windows path with uppercase drive letter and standard backslashes."""
    if not path_str:
        return ""
    normalized = os.path.normpath(path_str.strip())
    # Ensure Windows backslashes
    normalized = normalized.replace("/", "\\")
    # Ensure drive letter is uppercase
    if len(normalized) >= 2 and normalized[1] == ":" and normalized[0].islower():
        normalized = normalized[0].upper() + normalized[1:]
    return normalized


def normalize_usb_event(
    raw_record: dict[str, Any],
    host: str = "UNKNOWN-HOST",
    ts_utc: Optional[str] = None
) -> Event:
    """
    Transforms raw USB telemetry into a normalized Event model.
    Expected raw_record keys (from Chetna's USB collector):
    - 'EventType' or 'event_type': 'DBT_DEVICEARRIVAL' / 'DBT_DEVICEREMOVECOMPLETE' or 'arrival'/'removal'
    - 'DriveLetter' or 'drive_letter': e.g. 'E:'
    - 'DeviceInstanceId' or 'device_instance_id': e.g. 'USBSTOR\\DISK&VEN_SANDISK...\\4C53000123456789'
    - 'FriendlyName' or 'device_name': e.g. 'SanDisk Ultra USB Device'
    """
    logger.debug("[normalize_usb_event] [RECEIVED] raw_record=%s", raw_record)
    timestamp = ts_utc or raw_record.get("ts_utc") or _format_utc_timestamp()

    # Determine action
    raw_event_type = str(
        raw_record.get("EventType") or raw_record.get("event_type") or "DBT_DEVICEARRIVAL"
    ).upper()

    if "REMOVE" in raw_event_type:
        action = ActionEnum.DEVICE_REMOVED
    else:
        action = ActionEnum.DEVICE_ARRIVED

    # Extract drive letter
    drive_letter = str(
        raw_record.get("DriveLetter") or raw_record.get("drive_letter") or ""
    ).upper().strip()
    if drive_letter and not drive_letter.endswith(":"):
        drive_letter += ":"

    # Derive raw_record_id: strip &0 instance suffix from Windows DeviceInstanceId if present
    raw_instance_id = (
        raw_record.get("raw_record_id")
        or raw_record.get("DeviceInstanceId")
        or raw_record.get("device_instance_id")
        or raw_record.get("serial_number")
        or f"USB_{drive_letter}_{raw_event_type}"
    )
    if re.search(r"&\d+$", raw_instance_id):
        raw_record_id = re.sub(r"&\d+$", "", raw_instance_id)
    else:
        raw_record_id = raw_instance_id

    # Friendly device name (strip trailing generic "USB Device" suffix if present)
    friendly = (
        raw_record.get("device_name")
        or raw_record.get("FriendlyName")
        or "USB Mass Storage"
    )
    if friendly.endswith(" USB Device"):
        device_name = friendly[:-11].strip()
    else:
        device_name = friendly

    serial = raw_record.get("serial_number") or raw_record_id.split("\\")[-1]
    entity_str = f"{drive_letter} ({device_name} {serial})".strip() if drive_letter else f"{device_name} ({serial})"

    details = {
        "raw_record_id": raw_record_id,
        "drive_letter": drive_letter,
        "device_name": device_name,
        "serial_number": serial,
        "vendor_id": raw_record.get("vendor_id"),
        "product_id": raw_record.get("product_id")
    }

    event_id = compute_event_id(SourceEnum.usb, raw_record_id, timestamp)

    event = Event(
        event_id=event_id,
        source=SourceEnum.usb,
        ts_utc=timestamp,
        host=raw_record.get("host") or host,
        user=raw_record.get("user") or "SYSTEM",
        action=action,
        entity_type=EntityTypeEnum.device,
        entity=entity_str,
        details=details,
        raw=raw_record
    )
    logger.info("[normalize_usb_event] [PRODUCED] Generated Event id='%s' action='%s'", event.event_id, event.action.value)
    return event


def normalize_fs_event(
    raw_record: dict[str, Any],
    host: str = "UNKNOWN-HOST",
    ts_utc: Optional[str] = None
) -> Event:
    """
    Transforms raw watchdog File System telemetry into a normalized Event model.
    Expected raw_record keys (from Chetna's FS collector):
    - 'event_type': 'created', 'modified', 'deleted', 'moved'
    - 'src_path': e.g. 'E:\\reports\\payload.exe'
    - 'dest_path': (for moved events) e.g. 'E:\\reports\\payload_backup.exe'
    - 'is_directory': bool
    """
    logger.debug("[normalize_fs_event] [RECEIVED] raw_record=%s", raw_record)
    timestamp = ts_utc or raw_record.get("ts_utc") or _format_utc_timestamp()

    raw_event_type = str(raw_record.get("event_type") or "created").lower()
    action_map = {
        "created": ActionEnum.FILE_CREATED,
        "modified": ActionEnum.FILE_MODIFIED,
        "deleted": ActionEnum.FILE_DELETED,
        "moved": ActionEnum.FILE_MOVED
    }
    action = action_map.get(raw_event_type, ActionEnum.FILE_CREATED)

    # For filesystem events, primary entity is src_path (original path of affected file)
    raw_path = raw_record.get("src_path", "")
    canonical_path = _canonicalize_path(raw_path or "")
    dest_canonical = _canonicalize_path(raw_record.get("dest_path", ""))

    drive_letter = ""
    if len(canonical_path) >= 2 and canonical_path[1] == ":":
        drive_letter = canonical_path[:2]

    # Deterministic fallback record id for watchdog filesystem notifications
    raw_record_id = f"{action.value}|{canonical_path}"
    event_id = compute_event_id(SourceEnum.fs, raw_record_id, timestamp)

    filename = os.path.basename(canonical_path)
    extension = os.path.splitext(filename)[1].lower() if "." in filename else ""

    details = {
        "raw_record_id": raw_record_id,
        "drive_letter": drive_letter,
        "file_path": canonical_path,
        "file_name": filename,
        "extension": extension,
        "is_directory": bool(raw_record.get("is_directory", False)),
        "file_size_bytes": raw_record.get("file_size_bytes")
    }
    if action == ActionEnum.FILE_MOVED and dest_canonical:
        details["dest_path"] = dest_canonical

    event = Event(
        event_id=event_id,
        source=SourceEnum.fs,
        ts_utc=timestamp,
        host=raw_record.get("host") or host,
        user=raw_record.get("user"),  # null unless elevated auditing captures user
        action=action,
        entity_type=EntityTypeEnum.file,
        entity=canonical_path,
        details=details,
        raw=raw_record
    )
    logger.info("[normalize_fs_event] [PRODUCED] Generated Event id='%s' path='%s'", event.event_id, event.entity)
    return event


def normalize_eventlog_event(
    raw_record: dict[str, Any],
    host: str = "UNKNOWN-HOST",
    ts_utc: Optional[str] = None
) -> Event:
    """
    Transforms raw Windows Event Log records (pywin32 / python-evtx) into normalized Event models.
    Supports:
    - Event ID 4688 / Sysmon 1 -> PROCESS_STARTED
    - Event ID 1102 / 104 -> LOG_CLEARED
    - Event ID 4624 -> LOGON
    """
    logger.debug("[normalize_eventlog_event] [RECEIVED] raw_record=%s", raw_record)

    # Extract System headers if structured as Windows XML dict
    system_data = raw_record.get("Event", {}).get("System", {}) or raw_record.get("System", {})
    event_data = raw_record.get("Event", {}).get("EventData", {}) or raw_record.get("EventData", {}) or raw_record

    event_id_code = int(
        system_data.get("EventID")
        or raw_record.get("event_code")
        or raw_record.get("EventCode")
        or 4688
    )
    channel = system_data.get("Channel") or raw_record.get("channel") or "Security"
    record_number = (
        system_data.get("EventRecordID")
        or raw_record.get("event_record_id")
        or raw_record.get("RecordNumber")
        or 1
    )

    timestamp = (
        ts_utc
        or system_data.get("TimeCreated", {}).get("SystemTime")
        or raw_record.get("ts_utc")
        or _format_utc_timestamp()
    )
    # Ensure millisecond format
    if timestamp.endswith("Z") and "." not in timestamp:
        timestamp = timestamp[:-1] + ".000Z"

    raw_record_id = f"{channel}:{record_number}"
    event_id = compute_event_id(SourceEnum.eventlog, raw_record_id, timestamp)

    # Determine action and entity
    if event_id_code in (1102, 104):
        action = ActionEnum.LOG_CLEARED
        entity_type = EntityTypeEnum.file
        entity = f"{channel} Event Log"
        proc_path = None
    elif event_id_code == 4624:
        action = ActionEnum.LOGON
        entity_type = EntityTypeEnum.process
        entity = "C:\\Windows\\System32\\lsass.exe"
        proc_path = entity
    else:  # Default process creation 4688
        action = ActionEnum.PROCESS_STARTED
        entity_type = EntityTypeEnum.process
        proc_path = _canonicalize_path(
            event_data.get("NewProcessName")
            or raw_record.get("process_name")
            or "UNKNOWN_PROCESS.EXE"
        )
        entity = proc_path

    # Extract username
    user = event_data.get("SubjectUserName") or raw_record.get("user")
    domain = event_data.get("SubjectDomainName")
    if user and domain and domain not in ("-", "WORKGROUP"):
        user = f"{domain}\\{user}"

    details = {
        "raw_record_id": raw_record_id,
        "event_record_id": record_number,
        "channel": channel,
        "event_code": event_id_code,
        "process_id": event_data.get("ProcessId") or raw_record.get("process_id"),
        "process_name": proc_path,
        "parent_process_id": event_data.get("ParentProcessId") or raw_record.get("parent_process_id"),
        "parent_process_name": _canonicalize_path(
            event_data.get("ParentProcessName") or raw_record.get("parent_process_name") or ""
        ),
        "command_line": event_data.get("CommandLine") or raw_record.get("command_line")
    }

    event = Event(
        event_id=event_id,
        source=SourceEnum.eventlog,
        ts_utc=timestamp,
        host=system_data.get("Computer") or raw_record.get("host") or host,
        user=user,
        action=action,
        entity_type=entity_type,
        entity=entity,
        details=details,
        raw=raw_record
    )
    logger.info("[normalize_eventlog_event] [PRODUCED] Generated Event id='%s' action='%s'", event.event_id, event.action.value)
    return event


def normalize_event(
    source: str | SourceEnum,
    raw_record: dict[str, Any],
    host: str = "UNKNOWN-HOST",
    ts_utc: Optional[str] = None
) -> Event:
    """Unified entrypoint dispatching to the appropriate normalizer by source."""
    src = SourceEnum(source) if isinstance(source, str) else source
    if src == SourceEnum.usb:
        return normalize_usb_event(raw_record, host=host, ts_utc=ts_utc)
    elif src == SourceEnum.fs:
        return normalize_fs_event(raw_record, host=host, ts_utc=ts_utc)
    elif src == SourceEnum.eventlog:
        return normalize_eventlog_event(raw_record, host=host, ts_utc=ts_utc)
    else:
        raise ValueError(f"Unsupported source for normalization: {src}")
