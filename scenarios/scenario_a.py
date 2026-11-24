#!/usr/bin/env python3
"""
scenario_a.py - Scenario A: Direct USB Copy and Execution.

Owner: Daksh (Endpoint Agent & Scenarios Owner)
Reference: Build & Execution Plan v2 (Hybrid ML) - Step 3
Contracts: docs/schema.md, docs/rules.yaml, backend/schema.py

Attack Narrative:
1. Removable USB flash drive is connected (drive E:).
2. Malicious payload executable (payload.exe) is written/copied to E:\\reports\\payload.exe.
3. Process is executed directly from the removable path (E:\\reports\\payload.exe).

Expected Rule Detections:
- R1: Device arrival followed by file activity on same drive (window: 300s)
- R2: File creation followed by process execution from same path (window: 600s)
- R7: Composite USB copy and execution chain (window: 900s)

Ground Truth Label: 'malicious'
Expected Threat Level: 'CRITICAL'
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add repository root to path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scenarios.generate_synthetic_events import make_event

logger = logging.getLogger("forensitrace.scenario_a")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

SCENARIO_ID = "scenario_a"
SCENARIO_NAME = "Scenario A: Direct USB Copy and Execution"
GROUND_TRUTH_LABEL = "malicious"
EXPECTED_RULES = ["R1", "R2", "R7"]
EXPECTED_THREAT_LEVEL = "CRITICAL"


def generate_scenario_a_events(
    host: str = "WIN-FORENSIC-01",
    user: str = "CONTOSO\\analyst",
    drive_letter: str = "E:",
    payload_name: str = "payload.exe",
    device_name: str = "SanDisk Ultra",
    serial_number: str = "4C53000123456789",
    base_timestamp: str = "2026-10-23T10:00:00.000Z",
) -> List[Dict[str, Any]]:
    """
    Generates deterministic telemetry events representing Scenario A:
    USB Arrival -> Payload File Copy -> Process Started from USB.
    """
    domain, username = user.split("\\") if "\\" in user else ("", user)
    device_instance = f"USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA\\{serial_number}"
    payload_path = f"{drive_letter}\\reports\\{payload_name}"
    events: List[Dict[str, Any]] = []

    # 1. USB Arrival Event
    usb_ts = "2026-10-23T10:00:00.120Z"
    events.append(
        make_event(
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
                "raw_record_id": device_instance,
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
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
    )

    # 2. File System File Created Event
    fs_ts = "2026-10-23T10:01:15.450Z"
    events.append(
        make_event(
            source="fs",
            ts_utc=fs_ts,
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity=payload_path,
            details={
                "drive_letter": drive_letter,
                "file_path": payload_path,
                "file_name": payload_name,
                "extension": ".exe",
                "file_size_bytes": 1048576,
                "is_directory": False,
                "raw_record_id": f"FILE_CREATED|{payload_path}",
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={
                "event_type": "created",
                "src_path": payload_path,
                "is_directory": False,
            },
            raw_record_id=f"FILE_CREATED|{payload_path}",
        )
    )

    # 3. Process Execution Event (Launched directly from E:)
    proc_ts = "2026-10-23T10:02:30.800Z"
    proc_record_id = 9481942
    events.append(
        make_event(
            source="eventlog",
            ts_utc=proc_ts,
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity=payload_path,
            details={
                "drive_letter": drive_letter,
                "event_record_id": proc_record_id,
                "channel": "Security",
                "event_code": 4688,
                "process_id": "0x1a2c",
                "process_name": payload_path,
                "parent_process_id": "0x0e20",
                "parent_process_name": "C:\\Windows\\explorer.exe",
                "command_line": f'"{payload_path}"',
                "raw_record_id": f"Security:{proc_record_id}",
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={
                "Event": {
                    "System": {
                        "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
                        "EventID": 4688,
                        "EventRecordID": proc_record_id,
                        "Channel": "Security",
                        "Computer": host,
                        "TimeCreated": {"SystemTime": proc_ts},
                    },
                    "EventData": {
                        "NewProcessName": payload_path,
                        "ProcessId": "0x1a2c",
                        "CommandLine": f'"{payload_path}"',
                        "ParentProcessName": "C:\\Windows\\explorer.exe",
                        "SubjectUserName": username,
                        "SubjectDomainName": domain,
                    },
                }
            },
            raw_record_id=f"Security:{proc_record_id}",
        )
    )

    return events


def get_ground_truth(events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Returns the ground truth specification document for Scenario A."""
    evs = events or generate_scenario_a_events()
    return {
        "scenario_id": SCENARIO_ID,
        "name": SCENARIO_NAME,
        "label": GROUND_TRUTH_LABEL,
        "description": "Removable USB flash drive inserted, executable payload written to the drive, and launched directly from removable media.",
        "expected_rules": EXPECTED_RULES,
        "expected_threat_level": EXPECTED_THREAT_LEVEL,
        "event_count": len(evs),
        "events": evs,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=f"ForensiTrace {SCENARIO_NAME}")
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "scenarios" / "ground_truth" / "scenario_a.json",
        help="Path to write the ground truth JSON (default: scenarios/ground_truth/scenario_a.json)",
    )
    parser.add_argument(
        "--ingest",
        action="store_true",
        help="POST generated events directly to running backend API at http://127.0.0.1:8000/events",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help="Path to SQLite database to ingest events directly",
    )
    args = parser.parse_args()

    logger.info("[RECEIVED] Generating %s...", SCENARIO_NAME)
    events = generate_scenario_a_events()
    gt = get_ground_truth(events)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(gt, f, indent=2, ensure_ascii=False)
        f.write("\n")
    logger.info("[PRODUCED] Wrote %d events to ground truth file: %s", len(events), args.output)

    if args.db:
        from backend.db import init_db, insert_events_batch
        init_db(args.db)
        inserted, dups = insert_events_batch(events, db_path=args.db)
        logger.info("[PRODUCED] Ingested into database '%s': %d inserted, %d duplicates", args.db, inserted, dups)

    if args.ingest:
        import urllib.request
        url = "http://127.0.0.1:8000/events"
        req = urllib.request.Request(
            url,
            data=json.dumps(events).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                logger.info("[PRODUCED] Ingested via API: HTTP %d", resp.status)
        except Exception as e:
            logger.error("[FAIL] API ingestion failed: %s", e)


if __name__ == "__main__":
    main()
