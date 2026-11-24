#!/usr/bin/env python3
"""
scenario_c.py - Scenario C: Multi-Vector Anti-Forensics and Exfiltration.

Owner: Daksh (Endpoint Agent & Scenarios Owner)
Reference: Build & Execution Plan v2 (Hybrid ML) - Step 3
Contracts: docs/schema.md, docs/rules.yaml, backend/schema.py

Attack Narrative:
1. Removable USB flash drive is connected (drive G:).
2. Bulk Exfiltration Burst: Attacker rapidly copies 6 data archive files
   to removable drive G: within 25 seconds (exfil_01.dat through exfil_06.dat).
3. Log Clearing: Attacker clears the Windows Security event log (Event ID 1102)
   to obscure activity and hinder forensic timeline reconstruction.
4. Timestomping / Discrepancy: Attacker manipulates filesystem timestamps on G:\\exfil_01.dat,
   resulting in a ~3900s discrepancy between the reported timestamp and the
   collector observation time (details.ts_observed_utc).

Expected Rule Detections:
- R4: Bulk file creation on removable drive (burst >= 5 files in 60s)
- R5: Log clearing near other activity (window: 600s)
- R6: Timestamp disagreement (discrepancy > 120s)

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

logger = logging.getLogger("forensitrace.scenario_c")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

SCENARIO_ID = "scenario_c"
SCENARIO_NAME = "Scenario C: Multi-Vector Anti-Forensics and Exfiltration"
GROUND_TRUTH_LABEL = "malicious"
EXPECTED_RULES = ["R4", "R5", "R6"]
EXPECTED_THREAT_LEVEL = "CRITICAL"


def generate_scenario_c_events(
    host: str = "WIN-FORENSIC-01",
    user: str = "CONTOSO\\analyst",
    usb_drive: str = "G:",
    device_name: str = "Transcend JetFlash",
    serial_number: str = "1234567890ABCDEF",
) -> List[Dict[str, Any]]:
    """
    Generates deterministic telemetry events representing Scenario C:
    USB Arrival -> Bulk File Burst (R4) -> Log Cleared (R5) -> Timestomp (R6).
    """
    domain, username = user.split("\\") if "\\" in user else ("", user)
    device_instance = f"USBSTOR\\DISK&VEN_TRANSCEND&PROD_JETFLASH\\{serial_number}"
    events: List[Dict[str, Any]] = []

    # 1. USB Arrival Event on G:
    usb_ts = "2026-10-23T15:00:00.100Z"
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
                "vendor_id": "058f",
                "product_id": "6387",
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

    # 2. Bulk File Creation Burst (6 files in 25 seconds on G:) -> Triggers R4
    burst_start_sec = 10
    for idx in range(1, 7):
        file_name = f"exfil_{idx:02d}.dat"
        file_path = f"{usb_drive}\\{file_name}"
        sec = burst_start_sec + (idx * 4)  # 14s, 18s, 22s, 26s, 30s, 34s
        ts_str = f"2026-10-23T15:00:{sec:02d}.200Z"
        events.append(
            make_event(
                source="fs",
                ts_utc=ts_str,
                host=host,
                user=None,
                action="FILE_CREATED",
                entity_type="file",
                entity=file_path,
                details={
                    "drive_letter": usb_drive,
                    "file_path": file_path,
                    "file_name": file_name,
                    "extension": ".dat",
                    "file_size_bytes": 5242880,
                    "is_directory": False,
                    "raw_record_id": f"FILE_CREATED|{file_path}",
                    "scenario_id": SCENARIO_ID,
                    "label": GROUND_TRUTH_LABEL,
                    "is_synthetic": True,
                    "dataset_type": "scenario",
                },
                raw={
                    "event_type": "created",
                    "src_path": file_path,
                    "is_directory": False,
                },
                raw_record_id=f"FILE_CREATED|{file_path}",
            )
        )

    # 3. Security Event Log Cleared (Event 1102) -> Triggers R5 (within 600s of file activity)
    log_clear_ts = "2026-10-23T15:02:00.000Z"
    log_clear_rec = 9484100
    events.append(
        make_event(
            source="eventlog",
            ts_utc=log_clear_ts,
            host=host,
            user=user,
            action="LOG_CLEARED",
            entity_type="process",
            entity="C:\\Windows\\System32\\wevtutil.exe",
            details={
                "event_record_id": log_clear_rec,
                "channel": "Security",
                "event_code": 1102,
                "process_name": "C:\\Windows\\System32\\wevtutil.exe",
                "command_line": "wevtutil cl Security",
                "raw_record_id": f"Security:{log_clear_rec}",
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={
                "Event": {
                    "System": {
                        "Provider": {"Name": "Microsoft-Windows-Eventlog"},
                        "EventID": 1102,
                        "EventRecordID": log_clear_rec,
                        "Channel": "Security",
                        "Computer": host,
                        "TimeCreated": {"SystemTime": log_clear_ts},
                    },
                    "UserData": {
                        "LogFileCleared": {
                            "SubjectUserName": username,
                            "SubjectDomainName": domain,
                            "Channel": "Security",
                        }
                    },
                }
            },
            raw_record_id=f"Security:{log_clear_rec}",
        )
    )

    # 4. Timestomped File Modification -> Triggers R6 (> 120s discrepancy)
    # File modification reported as 14:00:00 (backdated by 1 hour), but observed at 15:05:00
    timestomp_reported = "2026-10-23T14:00:00.000Z"
    timestomp_observed = "2026-10-23T15:05:00.000Z"
    timestomp_path = f"{usb_drive}\\exfil_01.dat"
    events.append(
        make_event(
            source="fs",
            ts_utc=timestomp_reported,
            host=host,
            user=None,
            action="FILE_MODIFIED",
            entity_type="file",
            entity=timestomp_path,
            details={
                "drive_letter": usb_drive,
                "file_path": timestomp_path,
                "file_name": "exfil_01.dat",
                "extension": ".dat",
                "file_size_bytes": 5242880,
                "is_directory": False,
                "ts_observed_utc": timestomp_observed,
                "time_discrepancy_seconds": 3900.0,
                "raw_record_id": f"FILE_MODIFIED|{timestomp_path}",
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={
                "event_type": "modified",
                "src_path": timestomp_path,
                "is_directory": False,
                "reported_mtime": timestomp_reported,
                "observed_time": timestomp_observed,
            },
            raw_record_id=f"FILE_MODIFIED|{timestomp_path}",
        )
    )

    return events


def get_ground_truth(events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Returns the ground truth specification document for Scenario C."""
    evs = events or generate_scenario_c_events()
    return {
        "scenario_id": SCENARIO_ID,
        "name": SCENARIO_NAME,
        "label": GROUND_TRUTH_LABEL,
        "description": "Bulk exfiltration burst on removable media, followed by Security log clearing and NTFS timestamp manipulation.",
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
        default=REPO_ROOT / "scenarios" / "ground_truth" / "scenario_c.json",
        help="Path to write the ground truth JSON (default: scenarios/ground_truth/scenario_c.json)",
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
    events = generate_scenario_c_events()
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
