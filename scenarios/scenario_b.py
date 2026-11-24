#!/usr/bin/env python3
"""
scenario_b.py - Scenario B: Staged and Delayed Removable Execution.

Owner: Daksh (Endpoint Agent & Scenarios Owner)
Reference: Build & Execution Plan v2 (Hybrid ML) - Step 3
Contracts: docs/schema.md, docs/rules.yaml, backend/schema.py

Attack Narrative:
1. Removable USB flash drive is connected (drive E:).
2. Staging dropper binary is written to removable media: E:\\staging\\loader.exe.
3. Payload is modified on disk (unpacking / decryption / payload update).
4. Deliberate execution delay is introduced (e.g. 180 seconds to evade instant sandboxes).
5. Loader process is executed directly from the removable device path: E:\\staging\\loader.exe.

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

logger = logging.getLogger("forensitrace.scenario_b")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

SCENARIO_ID = "scenario_b"
SCENARIO_NAME = "Scenario B: Staged and Delayed Removable Execution"
GROUND_TRUTH_LABEL = "malicious"
EXPECTED_RULES = ["R1", "R2", "R7"]
EXPECTED_THREAT_LEVEL = "CRITICAL"


def generate_scenario_b_events(
    host: str = "WIN-FORENSIC-01",
    user: str = "CONTOSO\\analyst",
    usb_drive: str = "E:",
    device_name: str = "SanDisk Extreme",
    serial_number: str = "5C64000098765432",
    staging_file: str = "E:\\staging\\loader.exe",
) -> List[Dict[str, Any]]:
    """
    Generates deterministic telemetry events representing Scenario B:
    USB Arrival -> File Created -> File Modified (staging/unpacking) -> Delay -> Process Started.
    """
    domain, username = user.split("\\") if "\\" in user else ("", user)
    device_instance = f"USBSTOR\\DISK&VEN_SANDISK&PROD_EXTREME\\{serial_number}"
    events: List[Dict[str, Any]] = []

    # 1. USB Arrival Event on E:
    usb_ts = "2026-10-23T14:00:00.100Z"
    events.append(
        make_event(
            source="usb",
            ts_utc=usb_ts,
            host=host,
            user="SYSTEM",
            action="DEVICE_ARRIVED",
            entity_type="device",
            entity=f"{usb_drive} ({device_name} {serial_number})",
            details={
                "drive_letter": usb_drive,
                "device_name": device_name,
                "serial_number": serial_number,
                "vendor_id": "0781",
                "product_id": "5591",
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
                "DriveLetter": usb_drive,
                "EventType": "DBT_DEVICEARRIVAL",
            },
            raw_record_id=device_instance,
        )
    )

    # 2. Dropper Created on E:
    fs_create_ts = "2026-10-23T14:01:00.200Z"
    events.append(
        make_event(
            source="fs",
            ts_utc=fs_create_ts,
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity=staging_file,
            details={
                "drive_letter": usb_drive,
                "file_path": staging_file,
                "file_name": "loader.exe",
                "extension": ".exe",
                "file_size_bytes": 524288,
                "is_directory": False,
                "raw_record_id": f"FILE_CREATED|{staging_file}",
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={
                "event_type": "created",
                "src_path": staging_file,
                "is_directory": False,
            },
            raw_record_id=f"FILE_CREATED|{staging_file}",
        )
    )

    # 3. Payload Modified (Staged / Decrypted / Unpacked)
    fs_mod_ts = "2026-10-23T14:01:30.500Z"
    events.append(
        make_event(
            source="fs",
            ts_utc=fs_mod_ts,
            host=host,
            user=None,
            action="FILE_MODIFIED",
            entity_type="file",
            entity=staging_file,
            details={
                "drive_letter": usb_drive,
                "file_path": staging_file,
                "file_name": "loader.exe",
                "extension": ".exe",
                "file_size_bytes": 1048576,
                "is_directory": False,
                "raw_record_id": f"FILE_MODIFIED|{staging_file}",
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={
                "event_type": "modified",
                "src_path": staging_file,
                "is_directory": False,
            },
            raw_record_id=f"FILE_MODIFIED|{staging_file}",
        )
    )

    # 4. Process Started After 180s Delay (at 14:04:30)
    proc_ts = "2026-10-23T14:04:30.800Z"
    proc_record_id = 9483320
    events.append(
        make_event(
            source="eventlog",
            ts_utc=proc_ts,
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity=staging_file,
            details={
                "drive_letter": usb_drive,
                "event_record_id": proc_record_id,
                "channel": "Security",
                "event_code": 4688,
                "process_id": "0x3c10",
                "process_name": staging_file,
                "parent_process_id": "0x0e20",
                "parent_process_name": "C:\\Windows\\explorer.exe",
                "command_line": f'"{staging_file}" --staged',
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
                        "NewProcessName": staging_file,
                        "ProcessId": "0x3c10",
                        "CommandLine": f'"{staging_file}" --staged',
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
    """Returns the ground truth specification document for Scenario B."""
    evs = events or generate_scenario_b_events()
    return {
        "scenario_id": SCENARIO_ID,
        "name": SCENARIO_NAME,
        "label": GROUND_TRUTH_LABEL,
        "description": "Multi-stage deployment on removable drive with file modification and deliberate execution delay.",
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
        default=REPO_ROOT / "scenarios" / "ground_truth" / "scenario_b.json",
        help="Path to write the ground truth JSON (default: scenarios/ground_truth/scenario_b.json)",
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
    events = generate_scenario_b_events()
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
