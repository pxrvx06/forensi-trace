#!/usr/bin/env python3
"""
generate_synthetic_events.py - Deterministic Synthetic Event & Fixture Generator for ForensiTrace.

Author: Akash (Correlation Engine & Fixtures Owner)
Team Contract: docs/schema.md, backend/schema.py
Task 1: Synthetic Event Generator and Fixtures

Generates deterministic forensic telemetry events simulating:
1. usb_copy_run.json: Correlated USB insertion -> payload file copy -> process execution.
2. normal_noise.json: Everyday legitimate background activity (logons, editor, browser, clean USB files)
   that does not satisfy the suspicious USB-copy-run chain.
3. edge_cases.json: Valid schema edge cases (USB without file write, execution without file write,
   mismatched drive letters/filenames, duplicates, out-of-order events, time window boundary conditions).
4. invalid_events.json: Contract-violating events for negative schema testing (isolated from valid fixtures).

All valid events strictly conform to docs/schema.md and pass validation against backend.schema.Event.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

# Configure labeled logging per project rules
logger = logging.getLogger("forensitrace.generator")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def compute_event_id(source: str, raw_record_id: str, ts_utc: str) -> str:
    """
    Computes deterministic SHA-256 event ID per docs/schema.md:
    event_id = SHA-256("{source}|{raw_record_id}|{ts_utc}")
    """
    seed = f"{source}|{raw_record_id}|{ts_utc}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def make_event(
    source: str,
    ts_utc: str,
    host: str,
    user: Optional[str],
    action: str,
    entity_type: str,
    entity: str,
    details: dict[str, Any],
    raw: Any,
    raw_record_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Constructs a normalized event dictionary conforming to docs/schema.md.
    Automatically assigns raw_record_id if not present in details.
    """
    # Determine raw_record_id based on source convention if not provided
    if raw_record_id is None:
        if "raw_record_id" in details:
            raw_record_id = details["raw_record_id"]
        elif source == "fs":
            raw_record_id = f"{action}|{entity}"
        elif source == "usb":
            raw_record_id = details.get(
                "device_instance_id",
                details.get("serial_number", f"USBSTOR\\DISK\\{entity}"),
            )
        elif source == "eventlog":
            event_rec_id = details.get("event_record_id", "1000")
            channel = details.get("channel", "Security")
            raw_record_id = f"{channel}:{event_rec_id}"
        else:
            raw_record_id = f"{source}:{action}:{entity}"

    # Ensure details has raw_record_id
    event_details = dict(details)
    event_details["raw_record_id"] = raw_record_id

    # Compute deterministic event_id
    event_id = compute_event_id(source, raw_record_id, ts_utc)

    return {
        "event_id": event_id,
        "source": source,
        "ts_utc": ts_utc,
        "host": host,
        "user": user,
        "action": action,
        "entity_type": entity_type,
        "entity": entity,
        "details": event_details,
        "raw": raw,
    }


# ==============================================================================
# Scenario A: USB Copy-and-Execute Sequence
# ==============================================================================
def generate_usb_copy_run(
    host: str = "WIN-FORENSIC-01",
    user: str = "CONTOSO\\analyst",
    drive_letter: str = "E:",
    payload_name: str = "payload.exe",
    device_name: str = "SanDisk Ultra",
    serial_number: str = "4C53000123456789",
) -> list[dict[str, Any]]:
    """
    Scenario A: Positive attack pattern simulating:
    1. Removable USB device inserted.
    2. Malicious payload copied / written to the removable drive.
    3. Payload process launched directly from that removable path.
    """
    payload_path = f"{drive_letter}\\reports\\{payload_name}"
    device_instance = f"USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA\\{serial_number}"

    # 1. USB Arrival Event
    usb_ts = "2026-10-23T10:00:00.120Z"
    usb_event = make_event(
        source="usb",
        ts_utc=usb_ts,
        host=host,
        user="SYSTEM",
        action="DEVICE_ARRIVED",
        entity_type="device",
        entity=f"{drive_letter} ({device_name} {serial_number})",
        details={
            "drive_letter": drive_letter,
            "device_name": device_name,
            "serial_number": serial_number,
            "vendor_id": "0781",
            "product_id": "5581",
        },
        raw={
            "DeviceInstanceId": f"{device_instance}&0",
            "Class": "DiskDrive",
            "FriendlyName": f"{device_name} USB Device",
            "DriveLetter": drive_letter,
            "EventType": "DBT_DEVICEARRIVAL",
        },
        raw_record_id=device_instance,
    )

    # 2. File System File Created Event
    fs_ts = "2026-10-23T10:01:15.450Z"
    fs_event = make_event(
        source="fs",
        ts_utc=fs_ts,
        host=host,
        user=None,  # fs notifications lack user SID without full SACL auditing
        action="FILE_CREATED",
        entity_type="file",
        entity=payload_path,
        details={
            "drive_letter": drive_letter,
            "file_path": payload_path,
            "file_name": payload_name,
            "extension": ".exe",
            "file_size_bytes": 65536,
            "is_directory": False,
        },
        raw={
            "event_type": "created",
            "src_path": payload_path,
            "is_directory": False,
        },
        raw_record_id=f"FILE_CREATED|{payload_path}",
    )

    # 3. Windows Event Log Process Started Event
    proc_ts = "2026-10-23T10:02:30.800Z"
    event_rec_id = 9482104
    domain, username = user.split("\\") if "\\" in user else ("", user)
    proc_event = make_event(
        source="eventlog",
        ts_utc=proc_ts,
        host=host,
        user=user,
        action="PROCESS_STARTED",
        entity_type="process",
        entity=payload_path,
        details={
            "event_record_id": event_rec_id,
            "channel": "Security",
            "event_code": 4688,
            "process_id": "0x1a4c",
            "process_name": payload_path,
            "parent_process_id": "0x0e20",
            "parent_process_name": "C:\\Windows\\explorer.exe",
            "command_line": f'"{payload_path}" --silent',
        },
        raw={
            "Event": {
                "System": {
                    "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
                    "EventID": 4688,
                    "EventRecordID": event_rec_id,
                    "Channel": "Security",
                    "Computer": host,
                    "TimeCreated": {"SystemTime": proc_ts},
                },
                "EventData": {
                    "NewProcessName": payload_path,
                    "ProcessId": "0x1a4c",
                    "ParentProcessName": "C:\\Windows\\explorer.exe",
                    "CommandLine": f'"{payload_path}" --silent',
                    "SubjectUserName": username,
                    "SubjectDomainName": domain,
                },
            }
        },
        raw_record_id=f"Security:{event_rec_id}",
    )

    return [usb_event, fs_event, proc_event]


# ==============================================================================
# Scenario B: Normal Activity & Noise
# ==============================================================================
def generate_normal_noise(
    host: str = "WIN-FORENSIC-01",
    user: str = "CONTOSO\\analyst",
) -> list[dict[str, Any]]:
    """
    Scenario B: Legitimate daily administrative / analyst workstation activity.
    None of these events should fire the suspicious USB-copy-run correlation rule.
    """
    domain, username = user.split("\\") if "\\" in user else ("", user)
    events: list[dict[str, Any]] = []

    # 1. Normal User Logon (Event ID 4624)
    logon_ts = "2026-10-23T09:15:00.000Z"
    logon_rec = 9481900
    events.append(
        make_event(
            source="eventlog",
            ts_utc=logon_ts,
            host=host,
            user=user,
            action="LOGON",
            entity_type="process",
            entity="C:\\Windows\\System32\\winlogon.exe",
            details={
                "event_record_id": logon_rec,
                "channel": "Security",
                "event_code": 4624,
                "logon_type": 2,  # Interactive logon
                "authentication_package": "Negotiate",
            },
            raw={
                "Event": {
                    "System": {
                        "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
                        "EventID": 4624,
                        "EventRecordID": logon_rec,
                        "Channel": "Security",
                        "Computer": host,
                        "TimeCreated": {"SystemTime": logon_ts},
                    },
                    "EventData": {
                        "TargetUserName": username,
                        "TargetDomainName": domain,
                        "LogonType": 2,
                    },
                }
            },
            raw_record_id=f"Security:{logon_rec}",
        )
    )

    # 2. Legitimate process execution on system C: drive (Notepad)
    notepad_ts = "2026-10-23T09:20:10.500Z"
    notepad_rec = 9481920
    events.append(
        make_event(
            source="eventlog",
            ts_utc=notepad_ts,
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="C:\\Windows\\System32\\notepad.exe",
            details={
                "event_record_id": notepad_rec,
                "channel": "Security",
                "event_code": 4688,
                "process_id": "0x0c40",
                "process_name": "C:\\Windows\\System32\\notepad.exe",
                "parent_process_id": "0x0e20",
                "parent_process_name": "C:\\Windows\\explorer.exe",
                "command_line": '"C:\\Windows\\System32\\notepad.exe"',
            },
            raw={"event_type": "process_created", "image": "notepad.exe"},
            raw_record_id=f"Security:{notepad_rec}",
        )
    )

    # 3. Legitimate document creation on local C: drive
    doc_path = "C:\\Users\\analyst\\Documents\\forensics_notes.txt"
    doc_ts = "2026-10-23T09:22:30.100Z"
    events.append(
        make_event(
            source="fs",
            ts_utc=doc_ts,
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity=doc_path,
            details={
                "drive_letter": "C:",
                "file_path": doc_path,
                "file_name": "forensics_notes.txt",
                "extension": ".txt",
                "file_size_bytes": 1024,
                "is_directory": False,
            },
            raw={"event_type": "created", "src_path": doc_path},
            raw_record_id=f"FILE_CREATED|{doc_path}",
        )
    )

    # 4. Legitimate document modified on local C: drive
    mod_ts = "2026-10-23T09:25:00.300Z"
    events.append(
        make_event(
            source="fs",
            ts_utc=mod_ts,
            host=host,
            user=None,
            action="FILE_MODIFIED",
            entity_type="file",
            entity=doc_path,
            details={
                "drive_letter": "C:",
                "file_path": doc_path,
                "file_name": "forensics_notes.txt",
                "extension": ".txt",
                "file_size_bytes": 2048,
                "is_directory": False,
            },
            raw={"event_type": "modified", "src_path": doc_path},
            raw_record_id=f"FILE_MODIFIED|{doc_path}",
        )
    )

    # 5. Legitimate browser startup from C: drive
    chrome_ts = "2026-10-23T09:30:15.000Z"
    chrome_rec = 9481955
    events.append(
        make_event(
            source="eventlog",
            ts_utc=chrome_ts,
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            details={
                "event_record_id": chrome_rec,
                "channel": "Security",
                "event_code": 4688,
                "process_id": "0x12a0",
                "process_name": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "parent_process_id": "0x0e20",
                "parent_process_name": "C:\\Windows\\explorer.exe",
                "command_line": '"chrome.exe" https://forensics.internal',
            },
            raw={"event_type": "process_created", "image": "chrome.exe"},
            raw_record_id=f"Security:{chrome_rec}",
        )
    )

    # 6. Legitimate USB backup drive connected (F: drive)
    usb_backup_ts = "2026-10-23T09:40:00.000Z"
    backup_serial = "KINGSTON9988776655"
    events.append(
        make_event(
            source="usb",
            ts_utc=usb_backup_ts,
            host=host,
            user="SYSTEM",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity=f"F: (Kingston DataTraveler {backup_serial})",
            details={
                "drive_letter": "F:",
                "device_name": "Kingston DataTraveler",
                "serial_number": backup_serial,
                "vendor_id": "0951",
                "product_id": "1666",
            },
            raw={
                "DeviceInstanceId": f"USBSTOR\\DISK&VEN_KINGSTON\\{backup_serial}",
                "Class": "DiskDrive",
                "FriendlyName": "Kingston DataTraveler USB Device",
                "DriveLetter": "F:",
                "EventType": "DBT_DEVICEARRIVAL",
            },
            raw_record_id=f"USBSTOR\\DISK&VEN_KINGSTON\\{backup_serial}",
        )
    )

    # 7. Benign non-executable document copied to backup USB drive
    pdf_path = "F:\\backup\\project_status.pdf"
    pdf_ts = "2026-10-23T09:42:15.200Z"
    events.append(
        make_event(
            source="fs",
            ts_utc=pdf_ts,
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity=pdf_path,
            details={
                "drive_letter": "F:",
                "file_path": pdf_path,
                "file_name": "project_status.pdf",
                "extension": ".pdf",
                "file_size_bytes": 1048576,
                "is_directory": False,
            },
            raw={"event_type": "created", "src_path": pdf_path},
            raw_record_id=f"FILE_CREATED|{pdf_path}",
        )
    )

    # 8. Legitimate PDF reader process started from C: drive to read the backup
    reader_ts = "2026-10-23T09:43:00.800Z"
    reader_rec = 9481980
    events.append(
        make_event(
            source="eventlog",
            ts_utc=reader_ts,
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
            details={
                "event_record_id": reader_rec,
                "channel": "Security",
                "event_code": 4688,
                "process_id": "0x1b30",
                "process_name": "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
                "parent_process_id": "0x0e20",
                "parent_process_name": "C:\\Windows\\explorer.exe",
                "command_line": f'"Acrobat.exe" "{pdf_path}"',
            },
            raw={"event_type": "process_created", "image": "Acrobat.exe"},
            raw_record_id=f"Security:{reader_rec}",
        )
    )

    # 9. USB backup drive safely removed
    remove_ts = "2026-10-23T09:50:00.000Z"
    events.append(
        make_event(
            source="usb",
            ts_utc=remove_ts,
            host=host,
            user="SYSTEM",
            action="DEVICE_REMOVED",
            entity_type="device",
            entity=f"F: (Kingston DataTraveler {backup_serial})",
            details={
                "drive_letter": "F:",
                "device_name": "Kingston DataTraveler",
                "serial_number": backup_serial,
            },
            raw={
                "DeviceInstanceId": f"USBSTOR\\DISK&VEN_KINGSTON\\{backup_serial}",
                "DriveLetter": "F:",
                "EventType": "DBT_DEVICEREMOVECOMPLETE",
            },
            raw_record_id=f"USBSTOR\\DISK&VEN_KINGSTON\\{backup_serial}_REMOVE",
        )
    )

    return events


# ==============================================================================
# Scenario C: Edge Cases
# ==============================================================================
def generate_edge_cases(
    host: str = "WIN-FORENSIC-01",
    user: str = "CONTOSO\\analyst",
) -> list[dict[str, Any]]:
    """
    Scenario C: Edge cases conforming strictly to docs/schema.md contract.
    Covers:
    - Case 1: USB connection without a subsequent file write.
    - Case 2: Process starting from removable drive with no preceding write event in fixture.
    - Case 3: Mismatched drive letters / file paths between write and process start.
    - Case 4: Duplicate event records (idempotency testing).
    - Case 5: Events supplied out of chronological order (correlation engine sorting check).
    - Case 6: Time-window boundaries (just inside, exactly on, and just outside window).
    """
    events: list[dict[str, Any]] = []

    # --------------------------------------------------------------------------
    # Case 1: USB connection with NO subsequent file write or execution
    # --------------------------------------------------------------------------
    c1_usb_ts = "2026-10-23T11:00:00.000Z"
    c1_serial = "CORSAIR_NO_WRITE_001"
    events.append(
        make_event(
            source="usb",
            ts_utc=c1_usb_ts,
            host=host,
            user="SYSTEM",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity=f"G: (Corsair Voyager {c1_serial})",
            details={
                "drive_letter": "G:",
                "device_name": "Corsair Voyager",
                "serial_number": c1_serial,
                "edge_case_note": "USB connection without subsequent file write",
            },
            raw={"EventType": "DBT_DEVICEARRIVAL", "DriveLetter": "G:"},
            raw_record_id=f"USBSTOR\\DISK&VEN_CORSAIR\\{c1_serial}",
        )
    )

    # --------------------------------------------------------------------------
    # Case 2: Process execution on removable drive with NO preceding write event
    # (e.g. payload pre-existed on the flash drive before arrival)
    # --------------------------------------------------------------------------
    c2_usb_ts = "2026-10-23T11:10:00.000Z"
    c2_serial = "SANDISK_EXISTING_BIN_002"
    events.append(
        make_event(
            source="usb",
            ts_utc=c2_usb_ts,
            host=host,
            user="SYSTEM",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity=f"H: (SanDisk Cruzer {c2_serial})",
            details={
                "drive_letter": "H:",
                "device_name": "SanDisk Cruzer",
                "serial_number": c2_serial,
                "edge_case_note": "USB arrival followed by process execution without file write event",
            },
            raw={"EventType": "DBT_DEVICEARRIVAL", "DriveLetter": "H:"},
            raw_record_id=f"USBSTOR\\DISK&VEN_SANDISK\\{c2_serial}",
        )
    )
    c2_proc_ts = "2026-10-23T11:11:30.000Z"
    c2_proc_rec = 9482500
    events.append(
        make_event(
            source="eventlog",
            ts_utc=c2_proc_ts,
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="H:\\tools\\dump_memory.exe",
            details={
                "event_record_id": c2_proc_rec,
                "channel": "Security",
                "event_code": 4688,
                "process_name": "H:\\tools\\dump_memory.exe",
                "edge_case_note": "Execution from USB without preceding file write event in telemetry",
            },
            raw={"EventID": 4688, "NewProcessName": "H:\\tools\\dump_memory.exe"},
            raw_record_id=f"Security:{c2_proc_rec}",
        )
    )

    # --------------------------------------------------------------------------
    # Case 3: Mismatched drive letters and file paths
    # (File created on E:\\staging\\script.bat, but process starts on F:\\staging\\other.bat)
    # --------------------------------------------------------------------------
    c3_fs_ts = "2026-10-23T11:20:00.000Z"
    events.append(
        make_event(
            source="fs",
            ts_utc=c3_fs_ts,
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity="E:\\staging\\setup_script.bat",
            details={
                "drive_letter": "E:",
                "file_path": "E:\\staging\\setup_script.bat",
                "edge_case_note": "File created on E: drive but process started on F: drive",
            },
            raw={"event_type": "created", "src_path": "E:\\staging\\setup_script.bat"},
            raw_record_id="FILE_CREATED|E:\\staging\\setup_script.bat",
        )
    )
    c3_proc_ts = "2026-10-23T11:21:00.000Z"
    c3_proc_rec = 9482600
    events.append(
        make_event(
            source="eventlog",
            ts_utc=c3_proc_ts,
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="F:\\staging\\other_binary.exe",
            details={
                "event_record_id": c3_proc_rec,
                "channel": "Security",
                "event_code": 4688,
                "process_name": "F:\\staging\\other_binary.exe",
                "edge_case_note": "Mismatched drive letter (F: vs E:) and file name",
            },
            raw={"EventID": 4688, "NewProcessName": "F:\\staging\\other_binary.exe"},
            raw_record_id=f"Security:{c3_proc_rec}",
        )
    )

    # --------------------------------------------------------------------------
    # Case 4: Duplicate event records (testing engine idempotency & dedup)
    # --------------------------------------------------------------------------
    dup_ts = "2026-10-23T11:30:00.000Z"
    dup_event_1 = make_event(
        source="fs",
        ts_utc=dup_ts,
        host=host,
        user=None,
        action="FILE_CREATED",
        entity_type="file",
        entity="E:\\reports\\duplicate_test.txt",
        details={
            "drive_letter": "E:",
            "file_path": "E:\\reports\\duplicate_test.txt",
            "edge_case_note": "Duplicate event occurrence 1 of 2",
        },
        raw={"event_type": "created", "src_path": "E:\\reports\\duplicate_test.txt"},
        raw_record_id="FILE_CREATED|E:\\reports\\duplicate_test.txt",
    )
    # Duplicate instance identical in event_id, timestamps, and fields
    dup_event_2 = dict(dup_event_1)
    events.append(dup_event_1)
    events.append(dup_event_2)

    # --------------------------------------------------------------------------
    # Case 5: Out-of-chronological-order sequence
    # (Process start appears in array first, followed by USB arrival, then file creation)
    # --------------------------------------------------------------------------
    c5_usb_ts = "2026-10-23T11:40:00.000Z"
    c5_fs_ts = "2026-10-23T11:41:00.000Z"
    c5_proc_ts = "2026-10-23T11:42:00.000Z"
    c5_serial = "PNY_OUT_OF_ORDER_005"
    c5_path = "E:\\tools\\reorder_test.exe"

    c5_usb = make_event(
        source="usb",
        ts_utc=c5_usb_ts,
        host=host,
        user="SYSTEM",
        action="DEVICE_ARRIVED",
        entity_type="device",
        entity=f"E: (PNY Flash {c5_serial})",
        details={"drive_letter": "E:", "serial_number": c5_serial},
        raw={"DriveLetter": "E:"},
        raw_record_id=f"USBSTOR\\DISK&VEN_PNY\\{c5_serial}",
    )
    c5_fs = make_event(
        source="fs",
        ts_utc=c5_fs_ts,
        host=host,
        user=None,
        action="FILE_CREATED",
        entity_type="file",
        entity=c5_path,
        details={"drive_letter": "E:", "file_path": c5_path},
        raw={"src_path": c5_path},
        raw_record_id=f"FILE_CREATED|{c5_path}",
    )
    c5_proc = make_event(
        source="eventlog",
        ts_utc=c5_proc_ts,
        host=host,
        user=user,
        action="PROCESS_STARTED",
        entity_type="process",
        entity=c5_path,
        details={"event_record_id": 9482700, "channel": "Security", "process_name": c5_path},
        raw={"NewProcessName": c5_path},
        raw_record_id="Security:9482700",
    )
    # Deliberately append in reverse chronological order: proc -> usb -> fs
    events.append(c5_proc)
    events.append(c5_usb)
    events.append(c5_fs)

    # --------------------------------------------------------------------------
    # Case 6: Time-Window Boundary Conditions
    # Assuming a standard correlation window of 10 minutes (600 seconds):
    # Anchor: USB arrival at 12:00:00.000Z, File Created at 12:00:30.000Z.
    # - Just inside:  Process started at 12:09:59.000Z (599s after USB - inside 600s window)
    # - Exactly on:   Process started at 12:10:00.000Z (600s after USB - exact boundary)
    # - Just outside: Process started at 12:10:01.000Z (601s after USB - window expired)
    # --------------------------------------------------------------------------
    boundary_usb_ts = "2026-10-23T12:00:00.000Z"
    boundary_fs_ts = "2026-10-23T12:00:30.000Z"
    boundary_serial = "BOUNDARY_TEST_DRIVE_006"

    events.append(
        make_event(
            source="usb",
            ts_utc=boundary_usb_ts,
            host=host,
            user="SYSTEM",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity=f"E: (BoundaryDrive {boundary_serial})",
            details={"drive_letter": "E:", "serial_number": boundary_serial},
            raw={"DriveLetter": "E:"},
            raw_record_id=f"USBSTOR\\DISK&VEN_TEST\\{boundary_serial}",
        )
    )
    events.append(
        make_event(
            source="fs",
            ts_utc=boundary_fs_ts,
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity="E:\\boundary\\target.exe",
            details={"drive_letter": "E:", "file_path": "E:\\boundary\\target.exe"},
            raw={"src_path": "E:\\boundary\\target.exe"},
            raw_record_id="FILE_CREATED|E:\\boundary\\target.exe",
        )
    )

    # Just inside 10m window (delta = 599s)
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-23T12:09:59.000Z",
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="E:\\boundary\\target.exe",
            details={
                "event_record_id": 9482801,
                "channel": "Security",
                "process_name": "E:\\boundary\\target.exe",
                "boundary_condition": "just_inside_window_599s",
            },
            raw={"NewProcessName": "E:\\boundary\\target.exe"},
            raw_record_id="Security:9482801",
        )
    )

    # Exactly on boundary (delta = 600s)
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-23T12:10:00.000Z",
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="E:\\boundary\\target.exe",
            details={
                "event_record_id": 9482802,
                "channel": "Security",
                "process_name": "E:\\boundary\\target.exe",
                "boundary_condition": "exactly_on_window_boundary_600s",
            },
            raw={"NewProcessName": "E:\\boundary\\target.exe"},
            raw_record_id="Security:9482802",
        )
    )

    # Just outside window (delta = 601s)
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-23T12:10:01.000Z",
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="E:\\boundary\\target.exe",
            details={
                "event_record_id": 9482803,
                "channel": "Security",
                "process_name": "E:\\boundary\\target.exe",
                "boundary_condition": "just_outside_window_601s",
            },
            raw={"NewProcessName": "E:\\boundary\\target.exe"},
            raw_record_id="Security:9482803",
        )
    )

    # --------------------------------------------------------------------------
    # Case 7: Rule R4 Bulk File Creation Scenarios (Burst, Sub-threshold, Boundary)
    # --------------------------------------------------------------------------
    # 7a: USB Arrival for Removable Drive J:
    c7_usb_ts = "2026-10-23T12:00:00.000Z"
    events.append(
        make_event(
            source="usb",
            ts_utc=c7_usb_ts,
            host=host,
            user="SYSTEM",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity="J: (Kingston DataTraveler)",
            details={
                "drive_letter": "J:",
                "device_name": "Kingston DataTraveler",
                "serial_number": "KINGSTON_BULK_001",
                "edge_case_note": "USB arrival establishing removable drive J: for R4 testing",
            },
            raw={"EventType": "DBT_DEVICEARRIVAL", "DriveLetter": "J:"},
            raw_record_id="USBSTOR\\DISK&VEN_KINGSTON\\KINGSTON_BULK_001",
        )
    )
    # 7b: Valid burst of 5 files within 20s (0s to 20s)
    for idx in range(1, 6):
        ts = f"2026-10-23T12:00:{idx * 4:02d}.000Z"
        events.append(
            make_event(
                source="fs",
                ts_utc=ts,
                host=host,
                user=None,
                action="FILE_CREATED",
                entity_type="file",
                entity=f"J:\\burst\\doc_{idx}.pdf",
                details={
                    "drive_letter": "J:",
                    "file_path": f"J:\\burst\\doc_{idx}.pdf",
                    "file_name": f"doc_{idx}.pdf",
                    "extension": ".pdf",
                    "file_size_bytes": 1024 * idx,
                    "edge_case_note": "Valid R4 burst file",
                },
                raw={"event_type": "created", "src_path": f"J:\\burst\\doc_{idx}.pdf"},
                raw_record_id=f"FILE_CREATED|J:\\burst\\doc_{idx}.pdf",
            )
        )

    # 7c: Sub-threshold creation (only 2 files created on drive K: - should NOT fire R4)
    c7c_usb_ts = "2026-10-23T12:10:00.000Z"
    events.append(
        make_event(
            source="usb",
            ts_utc=c7c_usb_ts,
            host=host,
            user="SYSTEM",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity="K: (Transcend JetFlash)",
            details={
                "drive_letter": "K:",
                "device_name": "Transcend JetFlash",
                "serial_number": "TRANSCEND_SUB_002",
            },
            raw={"EventType": "DBT_DEVICEARRIVAL", "DriveLetter": "K:"},
            raw_record_id="USBSTOR\\DISK&VEN_TRANSCEND\\TRANSCEND_SUB_002",
        )
    )
    for idx in range(1, 3):
        events.append(
            make_event(
                source="fs",
                ts_utc=f"2026-10-23T12:10:{idx * 10:02d}.000Z",
                host=host,
                user=None,
                action="FILE_CREATED",
                entity_type="file",
                entity=f"K:\\sub\\note_{idx}.txt",
                details={
                    "drive_letter": "K:",
                    "file_path": f"K:\\sub\\note_{idx}.txt",
                    "file_name": f"note_{idx}.txt",
                    "extension": ".txt",
                    "edge_case_note": "Sub-threshold count (2 files < 5 min_count)",
                },
                raw={"event_type": "created", "src_path": f"K:\\sub\\note_{idx}.txt"},
                raw_record_id=f"FILE_CREATED|K:\\sub\\note_{idx}.txt",
            )
        )

    # --------------------------------------------------------------------------
    # Case 8: Rule R5 Log Clearing Near Other Activity (Positive & Negative)
    # --------------------------------------------------------------------------
    # 8a: Positive R5 - Execution followed by Security log cleared within 45 seconds
    c8_proc_ts = "2026-10-23T12:20:00.000Z"
    events.append(
        make_event(
            source="eventlog",
            ts_utc=c8_proc_ts,
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="C:\\Windows\\System32\\cmd.exe",
            details={
                "event_record_id": 9482901,
                "channel": "Security",
                "event_code": 4688,
                "process_name": "C:\\Windows\\System32\\cmd.exe",
                "edge_case_note": "Target activity preceding log clearing",
            },
            raw={"EventID": 4688, "NewProcessName": "C:\\Windows\\System32\\cmd.exe"},
            raw_record_id="Security:9482901",
        )
    )
    c8_clear_ts = "2026-10-23T12:20:45.000Z"
    events.append(
        make_event(
            source="eventlog",
            ts_utc=c8_clear_ts,
            host=host,
            user=user,
            action="LOG_CLEARED",
            entity_type="file",
            entity="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            details={
                "event_record_id": 9482902,
                "channel": "Security",
                "event_code": 1102,
                "edge_case_note": "Security audit log cleared 45s after cmd.exe execution",
            },
            raw={"EventID": 1102, "Channel": "Security"},
            raw_record_id="Security:9482902",
        )
    )

    # 8b: Negative R5 - Log cleared 20 minutes (> 600s) after unrelated activity on different host
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-23T12:50:00.000Z",
            host="WIN-OTHER-HOST",
            user="CONTOSO\\admin",
            action="LOG_CLEARED",
            entity_type="file",
            entity="C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
            details={
                "event_record_id": 10401,
                "channel": "System",
                "event_code": 104,
                "edge_case_note": "Isolated log clear on separate host with no nearby activity",
            },
            raw={"EventID": 104, "Channel": "System"},
            raw_record_id="System:10401",
        )
    )

    # --------------------------------------------------------------------------
    # Case 9: Rule R6 Timestamp Disagreement (Positive discrepancy > 120s, Normal <= 120s)
    # --------------------------------------------------------------------------
    # 9a: Positive R6 - Reported mtime is 1 hour before observation time (3600s > 120s)
    events.append(
        make_event(
            source="fs",
            ts_utc="2026-10-23T13:00:00.000Z",  # Reported filesystem modified time
            host=host,
            user=None,
            action="FILE_MODIFIED",
            entity_type="file",
            entity="E:\\timestomp\\suspicious.dll",
            details={
                "drive_letter": "E:",
                "file_path": "E:\\timestomp\\suspicious.dll",
                "file_name": "suspicious.dll",
                "ts_observed_utc": "2026-10-23T14:00:00.000Z",  # Collector observed +3600s later
                "mtime_utc": "2026-10-23T13:00:00.000Z",
                "edge_case_note": "Positive R6 timestamp discrepancy (3600s > 120s threshold)",
            },
            raw={"event_type": "modified", "src_path": "E:\\timestomp\\suspicious.dll"},
            raw_record_id="FILE_MODIFIED|E:\\timestomp\\suspicious.dll",
        )
    )
    # 9b: Normal timestamp (discrepancy of 2 seconds <= 120s threshold - should NOT fire R6)
    events.append(
        make_event(
            source="fs",
            ts_utc="2026-10-23T13:05:00.000Z",
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity="E:\\timestomp\\normal.txt",
            details={
                "drive_letter": "E:",
                "file_path": "E:\\timestomp\\normal.txt",
                "file_name": "normal.txt",
                "ts_observed_utc": "2026-10-23T13:05:02.000Z",  # Observed 2s later
                "mtime_utc": "2026-10-23T13:05:00.000Z",
                "edge_case_note": "Normal timestamp alignment (2s <= 120s threshold)",
            },
            raw={"event_type": "created", "src_path": "E:\\timestomp\\normal.txt"},
            raw_record_id="FILE_CREATED|E:\\timestomp\\normal.txt",
        )
    )

    # --------------------------------------------------------------------------
    # Case 10: Rule R7 Composite USB Copy & Run Chain Boundary Testing
    # --------------------------------------------------------------------------
    # 10a: Positive R7 at exact 900s boundary (USB: 13:10:00, Write: 13:15:00, Run: 13:25:00)
    c10_usb_ts = "2026-10-23T13:10:00.000Z"
    events.append(
        make_event(
            source="usb",
            ts_utc=c10_usb_ts,
            host=host,
            user="SYSTEM",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity="L: (SanDisk Boundary Drive)",
            details={
                "drive_letter": "L:",
                "device_name": "SanDisk Boundary Drive",
                "serial_number": "SANDISK_R7_BOUNDARY_900S",
            },
            raw={"EventType": "DBT_DEVICEARRIVAL", "DriveLetter": "L:"},
            raw_record_id="USBSTOR\\DISK&VEN_SANDISK\\SANDISK_R7_BOUNDARY_900S",
        )
    )
    events.append(
        make_event(
            source="fs",
            ts_utc="2026-10-23T13:15:00.000Z",  # +300s
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity="L:\\payloads\\chain_test.exe",
            details={
                "drive_letter": "L:",
                "file_path": "L:\\payloads\\chain_test.exe",
                "file_name": "chain_test.exe",
            },
            raw={"event_type": "created", "src_path": "L:\\payloads\\chain_test.exe"},
            raw_record_id="FILE_CREATED|L:\\payloads\\chain_test.exe",
        )
    )
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-23T13:25:00.000Z",  # +900s exact boundary
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="L:\\payloads\\chain_test.exe",
            details={
                "event_record_id": 9482950,
                "channel": "Security",
                "event_code": 4688,
                "process_name": "L:\\payloads\\chain_test.exe",
                "edge_case_note": "R7 chain exactly at 900s boundary",
            },
            raw={"EventID": 4688, "NewProcessName": "L:\\payloads\\chain_test.exe"},
            raw_record_id="Security:9482950",
        )
    )

    return events



# ==============================================================================
# Invalid Events (Isolated Fixture for Schema Testing)
# ==============================================================================
def generate_invalid_events() -> list[dict[str, Any]]:
    """
    Constructs contract-violating event payloads used to verify that schema validators
    (both backend/schema.py and docs/validate_examples.py) properly reject malformed inputs
    with explicit error messages without crashing.
    """
    valid_base = make_event(
        source="usb",
        ts_utc="2026-10-23T10:00:00.000Z",
        host="WIN-FORENSIC-01",
        user="SYSTEM",
        action="DEVICE_ARRIVED",
        entity_type="device",
        entity="E: (Test SanDisk)",
        details={"drive_letter": "E:", "serial_number": "TEST1234"},
        raw={"DriveLetter": "E:"},
        raw_record_id="USBSTOR\\DISK\\TEST1234",
    )

    invalid_cases: list[dict[str, Any]] = []

    # 1. Missing required field 'event_id'
    case_1 = dict(valid_base)
    del case_1["event_id"]
    invalid_cases.append({
        "case_name": "missing_required_event_id",
        "expected_error": "event_id",
        "payload": case_1,
    })

    # 2. Invalid source enum value
    case_2 = dict(valid_base)
    case_2["source"] = "network_packet"
    invalid_cases.append({
        "case_name": "invalid_source_enum",
        "expected_error": "source",
        "payload": case_2,
    })

    # 3. Disallowed action for source (usb cannot emit PROCESS_STARTED)
    case_3 = dict(valid_base)
    case_3["action"] = "PROCESS_STARTED"
    invalid_cases.append({
        "case_name": "action_source_mismatch",
        "expected_error": "action",
        "payload": case_3,
    })

    # 4. Malformed timestamp format (missing millisecond precision and trailing Z)
    case_4 = dict(valid_base)
    case_4["ts_utc"] = "2026-10-23 10:00:00"
    invalid_cases.append({
        "case_name": "malformed_timestamp_no_ms_no_z",
        "expected_error": "ts_utc",
        "payload": case_4,
    })

    # 5. Invalid event_id format (not 64-char lowercase hex)
    case_5 = dict(valid_base)
    case_5["event_id"] = "not-a-valid-sha256-hex"
    invalid_cases.append({
        "case_name": "invalid_event_id_format",
        "expected_error": "event_id",
        "payload": case_5,
    })

    # 6. Lowercase drive letter in Windows path
    case_6 = dict(valid_base)
    case_6["entity"] = "e:\\reports\\payload.exe"
    invalid_cases.append({
        "case_name": "lowercase_drive_letter",
        "expected_error": "drive letter",
        "payload": case_6,
    })

    # 7. Forward slashes in Windows drive path
    case_7 = dict(valid_base)
    case_7["entity"] = "E:/reports/payload.exe"
    invalid_cases.append({
        "case_name": "forward_slashes_in_path",
        "expected_error": "backslashes",
        "payload": case_7,
    })

    # 8. Missing raw_record_id in details
    case_8 = dict(valid_base)
    case_8["details"] = {"drive_letter": "E:"}  # missing raw_record_id
    invalid_cases.append({
        "case_name": "missing_raw_record_id",
        "expected_error": "raw_record_id",
        "payload": case_8,
    })

    # 9. Null raw field
    case_9 = dict(valid_base)
    case_9["raw"] = None
    invalid_cases.append({
        "case_name": "null_raw_telemetry",
        "expected_error": "raw",
        "payload": case_9,
    })

    return invalid_cases


# ==============================================================================
# Fixture Writing & Verification Orchestrator
# ==============================================================================
def write_fixture_json(output_path: Path, data: Any) -> None:
    """Serializes data into formatted JSON deterministically."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
def generate_bulk_file_creation(host: str = "WIN-FORENSIC-01") -> list[dict[str, Any]]:
    """
    Scenario D: Rule R4 Bulk File Creation on Removable Drive.
    Generates a burst of 6 files created on removable volume F: within 24 seconds.
    """
    events = []
    usb_ts = "2026-10-23T14:00:00.000Z"
    events.append(
        make_event(
            source="usb",
            ts_utc=usb_ts,
            host=host,
            user="SYSTEM",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity="F: (Corsair Flash Survivor)",
            details={
                "drive_letter": "F:",
                "device_name": "Corsair Flash Survivor",
                "serial_number": "CORSAIR_BULK_7701",
            },
            raw={"EventType": "DBT_DEVICEARRIVAL", "DriveLetter": "F:"},
            raw_record_id="USBSTOR\\DISK&VEN_CORSAIR\\CORSAIR_BULK_7701",
        )
    )
    for i in range(1, 7):
        ts = f"2026-10-23T14:00:{i * 4:02d}.000Z"
        events.append(
            make_event(
                source="fs",
                ts_utc=ts,
                host=host,
                user=None,
                action="FILE_CREATED",
                entity_type="file",
                entity=f"F:\\exfil\\data_{i}.csv",
                details={
                    "drive_letter": "F:",
                    "file_path": f"F:\\exfil\\data_{i}.csv",
                    "file_name": f"data_{i}.csv",
                    "extension": ".csv",
                    "file_size_bytes": 2048 * i,
                },
                raw={"event_type": "created", "src_path": f"F:\\exfil\\data_{i}.csv"},
                raw_record_id=f"FILE_CREATED|F:\\exfil\\data_{i}.csv",
            )
        )
    return events


def generate_log_cleared(host: str = "WIN-FORENSIC-01", user: str = "CONTOSO\\analyst") -> list[dict[str, Any]]:
    """
    Scenario E: Rule R5 Log Clearing Near Suspicious Activity.
    Generates file copy + execution followed by Security Log 1102 cleared after 40 seconds.
    """
    events = []
    # 1. File created
    events.append(
        make_event(
            source="fs",
            ts_utc="2026-10-23T15:00:00.000Z",
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity="C:\\temp\\staging_script.ps1",
            details={
                "drive_letter": "C:",
                "file_path": "C:\\temp\\staging_script.ps1",
                "file_name": "staging_script.ps1",
            },
            raw={"event_type": "created", "src_path": "C:\\temp\\staging_script.ps1"},
            raw_record_id="FILE_CREATED|C:\\temp\\staging_script.ps1",
        )
    )
    # 2. Process started
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-23T15:00:20.000Z",
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            details={
                "event_record_id": 9483010,
                "channel": "Security",
                "event_code": 4688,
                "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\temp\\staging_script.ps1",
            },
            raw={"EventID": 4688, "NewProcessName": "powershell.exe"},
            raw_record_id="Security:9483010",
        )
    )
    # 3. Security Log cleared (+40s)
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-23T15:01:00.000Z",
            host=host,
            user=user,
            action="LOG_CLEARED",
            entity_type="file",
            entity="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            details={
                "event_record_id": 9483011,
                "channel": "Security",
                "event_code": 1102,
            },
            raw={"EventID": 1102, "Channel": "Security"},
            raw_record_id="Security:9483011",
        )
    )
    return events


def generate_timestamp_discrepancy(host: str = "WIN-FORENSIC-01") -> list[dict[str, Any]]:
    """
    Scenario F: Rule R6 Timestamp Disagreement (Timestomping).
    Generates a file creation where reported modified time is backdated by ~1 year.
    """
    events = []
    events.append(
        make_event(
            source="fs",
            ts_utc="2025-01-15T08:00:00.000Z",  # Backdated modified time
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity="E:\\tools\\forged_driver.sys",
            details={
                "drive_letter": "E:",
                "file_path": "E:\\tools\\forged_driver.sys",
                "file_name": "forged_driver.sys",
                "mtime_utc": "2025-01-15T08:00:00.000Z",
                "ts_observed_utc": "2026-10-23T16:00:00.000Z",  # Actual collector observation
            },
            raw={"event_type": "created", "src_path": "E:\\tools\\forged_driver.sys"},
            raw_record_id="FILE_CREATED|E:\\tools\\forged_driver.sys",
        )
    )
    return events


def write_fixture_json(output_path: Path, data: Any) -> None:
    """Serializes data into formatted JSON deterministically."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    logger.info("[PRODUCED] Fixture written: %s (%d bytes)", output_path, output_path.stat().st_size)


def generate_all_fixtures(output_dir: Path) -> dict[str, Path]:
    """Generates all synthetic fixture files deterministically."""
    logger.info("[RECEIVED] Generating all synthetic fixtures into: %s", output_dir)
    results: dict[str, Path] = {}

    # 1. usb_copy_run.json
    usb_copy_path = output_dir / "usb_copy_run.json"
    usb_copy_events = generate_usb_copy_run()
    write_fixture_json(usb_copy_path, usb_copy_events)
    results["usb_copy_run"] = usb_copy_path

    # 2. normal_noise.json
    noise_path = output_dir / "normal_noise.json"
    noise_events = generate_normal_noise()
    write_fixture_json(noise_path, noise_events)
    results["normal_noise"] = noise_path

    # 3. edge_cases.json
    edge_path = output_dir / "edge_cases.json"
    edge_events = generate_edge_cases()
    write_fixture_json(edge_path, edge_events)
    results["edge_cases"] = edge_path

    # 4. bulk_file_creation.json (Rule R4 fixture)
    bulk_path = output_dir / "bulk_file_creation.json"
    bulk_events = generate_bulk_file_creation()
    write_fixture_json(bulk_path, bulk_events)
    results["bulk_file_creation"] = bulk_path

    # 5. log_cleared.json (Rule R5 fixture)
    log_path = output_dir / "log_cleared.json"
    log_events = generate_log_cleared()
    write_fixture_json(log_path, log_events)
    results["log_cleared"] = log_path

    # 6. timestamp_discrepancy.json (Rule R6 fixture)
    ts_disc_path = output_dir / "timestamp_discrepancy.json"
    ts_disc_events = generate_timestamp_discrepancy()
    write_fixture_json(ts_disc_path, ts_disc_events)
    results["timestamp_discrepancy"] = ts_disc_path

    # 7. invalid_events.json (isolated negative test cases)
    invalid_path = output_dir / "invalid_events.json"
    invalid_cases = generate_invalid_events()
    write_fixture_json(invalid_path, invalid_cases)
    results["invalid_events"] = invalid_path

    return results



def validate_event_dict(data: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Validates a single event dictionary against both backend.schema.Event (Pydantic model)
    and the strict technical contract rules in docs/schema.md.
    Returns (is_valid, list_of_errors).
    """
    errors: list[str] = []

    # 1. Validate against Pydantic schema model
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    try:
        from backend.schema import Event as PydanticEvent
        PydanticEvent(**data)
    except Exception as exc:
        errors.append(f"Pydantic validation error: {exc}")

    # 2. Contract checks from docs/schema.md:
    # Check details.raw_record_id
    details = data.get("details")
    if not isinstance(details, dict):
        errors.append("Field 'details' must be a JSON object (dict)")
    else:
        raw_record_id = details.get("raw_record_id")
        if not raw_record_id:
            errors.append("Field 'details.raw_record_id' is required for event_id recipe verification")
        else:
            source = data.get("source")
            ts_utc = data.get("ts_utc")
            if source and ts_utc:
                expected_hash = compute_event_id(source, str(raw_record_id), str(ts_utc))
                if data.get("event_id") != expected_hash:
                    errors.append(
                        f"event_id mismatch: expected sha256('{source}|{raw_record_id}|{ts_utc}') = "
                        f"{expected_hash}, got {data.get('event_id')}"
                    )

    # Check raw field is not null
    if data.get("raw") is None:
        errors.append("Field 'raw' cannot be null; must contain untouched original record")

    # Check Windows entity path formatting
    entity = data.get("entity")
    if isinstance(entity, str):
        if "/" in entity and ("\\" in entity or ":" in entity):
            errors.append(f"Entity path '{entity}' must use Windows backslashes '\\', not forward slashes")
        if len(entity) >= 2 and entity[1] == ":" and not entity[0].isupper():
            errors.append(f"Drive letter in entity '{entity}' must be uppercase")

    return (len(errors) == 0), errors


def validate_fixtures(fixtures_dir: Path) -> bool:
    """
    Validates all generated valid fixtures using validate_event_dict.
    """
    logger.info("[RECEIVED] Running schema validation on fixtures in: %s", fixtures_dir)

    valid_files = [
        "usb_copy_run.json",
        "normal_noise.json",
        "edge_cases.json",
        "bulk_file_creation.json",
        "log_cleared.json",
        "timestamp_discrepancy.json",
    ]
    all_valid = True

    for filename in valid_files:
        file_path = fixtures_dir / filename
        if not file_path.exists():
            logger.error("[FAIL] Expected fixture missing: %s", file_path)
            all_valid = False
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                events = json.load(f)
        except Exception as e:
            logger.error("[FAIL] JSON parse error in %s: %s", filename, e)
            all_valid = False
            continue

        if not isinstance(events, list):
            logger.error("[FAIL] Fixture %s root element must be a list of events", filename)
            all_valid = False
            continue

        file_pass = True
        for idx, ev in enumerate(events):
            is_valid, errors = validate_event_dict(ev)
            if not is_valid:
                for err in errors:
                    logger.error("[FAIL] %s[%d] %s", filename, idx, err)
                file_pass = False

        if file_pass:
            logger.info("[PRODUCED] [PASS] %s (%d events) conforms to docs/schema.md", filename, len(events))
        else:
            all_valid = False

    return all_valid


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ForensiTrace Synthetic Event Generator (Task 1: Akash)"
    )
    repo_root = Path(__file__).resolve().parent.parent
    default_fixtures_dir = repo_root / "scenarios" / "fixtures"

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=default_fixtures_dir,
        help=f"Directory to output generated fixtures (default: {default_fixtures_dir})",
    )
    parser.add_argument(
        "--scenario",
        choices=[
            "all",
            "usb_copy_run",
            "normal_noise",
            "edge_cases",
            "bulk_file_creation",
            "log_cleared",
            "timestamp_discrepancy",
            "invalid_events",
        ],
        default="all",
        help="Specify which scenario fixture to generate (default: all)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Run schema validation on generated valid fixtures after writing",
    )

    args = parser.parse_args()
    output_dir = args.output_dir

    if args.scenario == "all":
        generate_all_fixtures(output_dir)
    elif args.scenario == "usb_copy_run":
        write_fixture_json(output_dir / "usb_copy_run.json", generate_usb_copy_run())
    elif args.scenario == "normal_noise":
        write_fixture_json(output_dir / "normal_noise.json", generate_normal_noise())
    elif args.scenario == "edge_cases":
        write_fixture_json(output_dir / "edge_cases.json", generate_edge_cases())
    elif args.scenario == "bulk_file_creation":
        write_fixture_json(output_dir / "bulk_file_creation.json", generate_bulk_file_creation())
    elif args.scenario == "log_cleared":
        write_fixture_json(output_dir / "log_cleared.json", generate_log_cleared())
    elif args.scenario == "timestamp_discrepancy":
        write_fixture_json(output_dir / "timestamp_discrepancy.json", generate_timestamp_discrepancy())
    elif args.scenario == "invalid_events":
        write_fixture_json(output_dir / "invalid_events.json", generate_invalid_events())


    if args.validate or args.scenario == "all":
        is_ok = validate_fixtures(output_dir)
        if not is_ok:
            sys.exit(1)


if __name__ == "__main__":
    main()
