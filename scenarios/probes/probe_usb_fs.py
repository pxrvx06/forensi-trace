#!/usr/bin/env python3
"""
probe_usb_fs.py - Telemetry Probe & Sample Recorder for USB and File-System Collectors.
Author: Chetna (USB and File-System Collectors Owner)
Scope: Step 3 (Page 6) - Generates and saves real sample telemetry files for PURVA and AKASH.
"""

from __future__ import annotations

import os
import sys
import json
import time
import queue
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Ensure project root is on sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from backend.schema import Event, SourceEnum, ActionEnum, EntityTypeEnum
from agent.collectors.usb_collector import (
    USBCollector,
    get_removable_drives,
    resolve_usb_device_info,
    build_usb_event,
)
from agent.collectors.fs_collector import (
    FileSystemCollector,
    canonicalize_windows_path,
    build_fs_event,
)


def get_samples_dir() -> Path:
    """Returns the path to docs/samples/ directory."""
    samples_dir = project_root / "docs" / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)
    return samples_dir


def create_sample_usb_events() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Creates realistic, schema-valid sample events for USB arrival and removal.
    Adheres strictly to docs/schema.md and docs/examples/usb_event.json.
    """
    host = "WIN-FORENSIC-01"
    user = "SYSTEM"
    drive_letter = "E:"
    device_name = "SanDisk Ultra"
    serial = "4C53000123456789"
    raw_rec = r"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA\4C53000123456789"
    entity = f"{drive_letter} ({device_name} {serial})"

    # 1. Arrival Event
    ts_arr = "2026-10-23T10:00:00.120Z"
    ev_id_arr = hashlib.sha256(f"usb|{raw_rec}|{ts_arr}".encode("utf-8")).hexdigest()
    arrival_event = {
        "event_id": ev_id_arr,
        "source": "usb",
        "ts_utc": ts_arr,
        "host": host,
        "user": user,
        "action": "DEVICE_ARRIVED",
        "entity_type": "device",
        "entity": entity,
        "details": {
            "raw_record_id": raw_rec,
            "drive_letter": drive_letter,
            "device_name": device_name,
            "serial_number": serial,
            "vendor_id": "0781",
            "product_id": "5581",
        },
        "raw": {
            "DeviceInstanceId": f"{raw_rec}&0",
            "Class": "DiskDrive",
            "FriendlyName": "SanDisk Ultra USB Device",
            "DriveLetter": drive_letter,
            "EventType": "DBT_DEVICEARRIVAL",
        },
    }

    # 2. Removal Event
    ts_rem = "2026-10-23T10:15:30.800Z"
    ev_id_rem = hashlib.sha256(f"usb|{raw_rec}|{ts_rem}".encode("utf-8")).hexdigest()
    removal_event = {
        "event_id": ev_id_rem,
        "source": "usb",
        "ts_utc": ts_rem,
        "host": host,
        "user": user,
        "action": "DEVICE_REMOVED",
        "entity_type": "device",
        "entity": entity,
        "details": {
            "raw_record_id": raw_rec,
            "drive_letter": drive_letter,
            "device_name": device_name,
            "serial_number": serial,
            "vendor_id": "0781",
            "product_id": "5581",
        },
        "raw": {
            "DeviceInstanceId": f"{raw_rec}&0",
            "Class": "DiskDrive",
            "FriendlyName": "SanDisk Ultra USB Device",
            "DriveLetter": drive_letter,
            "EventType": "DBT_DEVICEREMOVECOMPLETE",
        },
    }

    # Validate against Purva's Pydantic schema
    Event(**arrival_event)
    Event(**removal_event)
    return arrival_event, removal_event


def create_sample_fs_events() -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """
    Creates realistic, schema-valid sample events for file creation, modification, move, and deletion.
    Adheres strictly to docs/schema.md and docs/examples/fs_event.json.
    """
    host = "WIN-FORENSIC-01"
    drive = "E:"
    file_path = r"E:\reports\payload.exe"
    renamed_path = r"E:\reports\payload_backup.exe"

    # 1. FILE_CREATED
    ts_create = "2026-10-23T10:01:15.450Z"
    raw_rec_create = f"FILE_CREATED|{file_path}"
    ev_id_create = hashlib.sha256(f"fs|{raw_rec_create}|{ts_create}".encode("utf-8")).hexdigest()
    event_created = {
        "event_id": ev_id_create,
        "source": "fs",
        "ts_utc": ts_create,
        "host": host,
        "user": None,
        "action": "FILE_CREATED",
        "entity_type": "file",
        "entity": file_path,
        "details": {
            "raw_record_id": raw_rec_create,
            "drive_letter": drive,
            "file_path": file_path,
            "file_name": "payload.exe",
            "extension": ".exe",
            "file_size_bytes": 65536,
            "is_directory": False,
        },
        "raw": {
            "event_type": "created",
            "src_path": file_path,
            "is_directory": False,
        },
    }

    # 2. FILE_MODIFIED
    ts_mod = "2026-10-23T10:02:00.100Z"
    raw_rec_mod = f"FILE_MODIFIED|{file_path}"
    ev_id_mod = hashlib.sha256(f"fs|{raw_rec_mod}|{ts_mod}".encode("utf-8")).hexdigest()
    event_modified = {
        "event_id": ev_id_mod,
        "source": "fs",
        "ts_utc": ts_mod,
        "host": host,
        "user": None,
        "action": "FILE_MODIFIED",
        "entity_type": "file",
        "entity": file_path,
        "details": {
            "raw_record_id": raw_rec_mod,
            "drive_letter": drive,
            "file_path": file_path,
            "file_name": "payload.exe",
            "extension": ".exe",
            "file_size_bytes": 70144,
            "is_directory": False,
        },
        "raw": {
            "event_type": "modified",
            "src_path": file_path,
            "is_directory": False,
        },
    }

    # 3. FILE_MOVED
    ts_move = "2026-10-23T10:05:22.350Z"
    raw_rec_move = f"FILE_MOVED|{file_path}"
    ev_id_move = hashlib.sha256(f"fs|{raw_rec_move}|{ts_move}".encode("utf-8")).hexdigest()
    event_moved = {
        "event_id": ev_id_move,
        "source": "fs",
        "ts_utc": ts_move,
        "host": host,
        "user": None,
        "action": "FILE_MOVED",
        "entity_type": "file",
        "entity": file_path,
        "details": {
            "raw_record_id": raw_rec_move,
            "drive_letter": drive,
            "file_path": file_path,
            "dest_path": renamed_path,
            "file_name": "payload.exe",
            "extension": ".exe",
            "file_size_bytes": 70144,
            "is_directory": False,
        },
        "raw": {
            "event_type": "moved",
            "src_path": file_path,
            "dest_path": renamed_path,
            "is_directory": False,
        },
    }

    # 4. FILE_DELETED
    ts_del = "2026-10-23T10:14:10.900Z"
    raw_rec_del = f"FILE_DELETED|{renamed_path}"
    ev_id_del = hashlib.sha256(f"fs|{raw_rec_del}|{ts_del}".encode("utf-8")).hexdigest()
    event_deleted = {
        "event_id": ev_id_del,
        "source": "fs",
        "ts_utc": ts_del,
        "host": host,
        "user": None,
        "action": "FILE_DELETED",
        "entity_type": "file",
        "entity": renamed_path,
        "details": {
            "raw_record_id": raw_rec_del,
            "drive_letter": drive,
            "file_path": renamed_path,
            "file_name": "payload_backup.exe",
            "extension": ".exe",
            "file_size_bytes": 0,
            "is_directory": False,
        },
        "raw": {
            "event_type": "deleted",
            "src_path": renamed_path,
            "is_directory": False,
        },
    }

    # Validate against Purva's Pydantic schema
    Event(**event_created)
    Event(**event_modified)
    Event(**event_moved)
    Event(**event_deleted)

    return event_created, event_modified, event_moved, event_deleted


def save_samples():
    """Generates and writes all sample events to docs/samples/ directory."""
    samples_dir = get_samples_dir()
    print(f"[PROBE] Generating sample recordings into: {samples_dir}")

    # 1. USB Events
    usb_arrival, usb_removal = create_sample_usb_events()

    with open(samples_dir / "usb_arrival.json", "w", encoding="utf-8") as f:
        json.dump(usb_arrival, f, indent=2)
    print("  [PRODUCED] docs/samples/usb_arrival.json")

    with open(samples_dir / "usb_removal.json", "w", encoding="utf-8") as f:
        json.dump(usb_removal, f, indent=2)
    print("  [PRODUCED] docs/samples/usb_removal.json")

    with open(samples_dir / "usb_samples.json", "w", encoding="utf-8") as f:
        json.dump({"events": [usb_arrival, usb_removal], "batch_size": 2}, f, indent=2)
    print("  [PRODUCED] docs/samples/usb_samples.json (batch)")

    # 2. File System Events
    fs_created, fs_modified, fs_moved, fs_deleted = create_sample_fs_events()

    with open(samples_dir / "fs_created.json", "w", encoding="utf-8") as f:
        json.dump(fs_created, f, indent=2)
    print("  [PRODUCED] docs/samples/fs_created.json")

    with open(samples_dir / "fs_modified.json", "w", encoding="utf-8") as f:
        json.dump(fs_modified, f, indent=2)
    print("  [PRODUCED] docs/samples/fs_modified.json")

    with open(samples_dir / "fs_moved.json", "w", encoding="utf-8") as f:
        json.dump(fs_moved, f, indent=2)
    print("  [PRODUCED] docs/samples/fs_moved.json")

    with open(samples_dir / "fs_deleted.json", "w", encoding="utf-8") as f:
        json.dump(fs_deleted, f, indent=2)
    print("  [PRODUCED] docs/samples/fs_deleted.json")

    with open(samples_dir / "fs_samples.json", "w", encoding="utf-8") as f:
        json.dump(
            {"events": [fs_created, fs_modified, fs_moved, fs_deleted], "batch_size": 4},
            f,
            indent=2,
        )
    print("  [PRODUCED] docs/samples/fs_samples.json (batch)")

    print("[PROBE] All sample events generated and validated against docs/schema.md contract.")


if __name__ == "__main__":
    save_samples()
