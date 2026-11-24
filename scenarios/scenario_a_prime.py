#!/usr/bin/env python3
"""
scenario_a_prime.py - Scenario A': Staged Execution via System Drive (Evasion Variant).

Owner: Daksh (Endpoint Agent & Scenarios Owner)
Reference: Build & Execution Plan v2 (Hybrid ML) - Step 3
Contracts: docs/schema.md, docs/rules.yaml, backend/schema.py

Attack Narrative:
1. Removable USB flash drive is connected (drive E:).
2. Attacker copies executable payload from removable media into local system drive:
   C:\\Users\\analyst\\AppData\\Local\\Temp\\staged_payload.exe.
3. Attacker executes the payload directly from the local C: drive path.

Forensic Comparison with Scenario A:
- Designed to test evasion of direct removable-execution alerts (e.g. Rule R7).
- Rule R2 fires because a file was created on disk and executed within 10 minutes (600s).
- Rule R7 does NOT fire because the process execution is hosted on local volume C:,
  not on the removable storage path E:.

Expected Rule Detections:
- R2: File creation followed by process execution from same path (window: 600s)

Ground Truth Label: 'malicious'
Expected Threat Level: 'HIGH'
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

logger = logging.getLogger("forensitrace.scenario_a_prime")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

SCENARIO_ID = "scenario_a_prime"
SCENARIO_NAME = "Scenario A': Staged Execution via System Drive (Evasion Variant)"
GROUND_TRUTH_LABEL = "malicious"
EXPECTED_RULES = ["R2"]
EXPECTED_THREAT_LEVEL = "HIGH"


def generate_scenario_a_prime_events(
    host: str = "WIN-FORENSIC-01",
    user: str = "CONTOSO\\analyst",
    usb_drive: str = "E:",
    device_name: str = "Kingston DataTraveler",
    serial_number: str = "80000000000123",
    staged_path: str = "C:\\Users\\analyst\\AppData\\Local\\Temp\\staged_payload.exe",
) -> List[Dict[str, Any]]:
    """
    Generates deterministic telemetry events representing Scenario A':
    USB Arrival on E: -> Staged File Copy to C: -> Process Execution from C:.
    """
    domain, username = user.split("\\") if "\\" in user else ("", user)
    device_instance = f"USBSTOR\\DISK&VEN_KINGSTON&PROD_DATATRAVELER\\{serial_number}"
    events: List[Dict[str, Any]] = []

    # 1. USB Arrival Event on E:
    usb_ts = "2026-10-23T11:00:00.050Z"
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
                "vendor_id": "0951",
                "product_id": "1666",
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

    # 2. File Creation on Local System Drive C:
    fs_ts = "2026-10-23T11:01:20.300Z"
    events.append(
        make_event(
            source="fs",
            ts_utc=fs_ts,
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity=staged_path,
            details={
                "drive_letter": "C:",
                "file_path": staged_path,
                "file_name": "staged_payload.exe",
                "extension": ".exe",
                "file_size_bytes": 2097152,
                "is_directory": False,
                "source_media": usb_drive,
                "raw_record_id": f"FILE_CREATED|{staged_path}",
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={
                "event_type": "created",
                "src_path": staged_path,
                "is_directory": False,
            },
            raw_record_id=f"FILE_CREATED|{staged_path}",
        )
    )

    # 3. Process Execution from Local System Drive C:
    proc_ts = "2026-10-23T11:02:45.600Z"
    proc_record_id = 9482150
    events.append(
        make_event(
            source="eventlog",
            ts_utc=proc_ts,
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity=staged_path,
            details={
                "drive_letter": "C:",
                "event_record_id": proc_record_id,
                "channel": "Security",
                "event_code": 4688,
                "process_id": "0x2b40",
                "process_name": staged_path,
                "parent_process_id": "0x0e20",
                "parent_process_name": "C:\\Windows\\explorer.exe",
                "command_line": f'"{staged_path}"',
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
                        "NewProcessName": staged_path,
                        "ProcessId": "0x2b40",
                        "CommandLine": f'"{staged_path}"',
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
    """Returns the ground truth specification document for Scenario A'."""
    evs = events or generate_scenario_a_prime_events()
    return {
        "scenario_id": SCENARIO_ID,
        "name": SCENARIO_NAME,
        "label": GROUND_TRUTH_LABEL,
        "description": "Payload staged from removable media to local disk C:\\Users\\...\\Temp before execution to evade direct removable-execution alerts.",
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
        default=REPO_ROOT / "scenarios" / "ground_truth" / "scenario_a_prime.json",
        help="Path to write the ground truth JSON (default: scenarios/ground_truth/scenario_a_prime.json)",
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
    events = generate_scenario_a_prime_events()
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
