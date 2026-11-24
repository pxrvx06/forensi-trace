#!/usr/bin/env python3
"""
normal_noise.py - Normal Workstation Background Telemetry & Benign Noise Generator.

Owner: Daksh (Endpoint Agent & Scenarios Owner)
Reference: Build & Execution Plan v2 (Hybrid ML) - Step 3 & False-Positive Evaluation
Contracts: docs/schema.md, docs/rules.yaml, backend/schema.py

Legitimate Activity Narrative:
1. User logon (Windows Security Event 4624).
2. Google Chrome browser launched for everyday web navigation (Event 4688).
3. Text editor (Notepad) launched for task planning (Event 4688).
4. Local notes created and updated on C:\\Users\\analyst\\Documents\\daily_tasks.txt.
5. Local spreadsheet created on C:\\Users\\analyst\\Documents\\quarterly_budget.xlsx.
6. Ordinary Kingston USB drive connected on F: (DEVICE_ARRIVED).
7. Adobe Acrobat Reader launched from system drive to inspect existing PDF on F:.
8. USB drive safely removed after viewing (DEVICE_REMOVED).
9. Standard calculator application launched (calc.exe).
10. Windows background taskhost maintenance process (taskhostw.exe).

Expected Rule Detections:
- Zero rule firings (confidence 0.0, no malicious activities formed).
- Serves as the negative control / false-positive evaluation baseline.

Ground Truth Label: 'normal'
Expected Threat Level: 'LOW'
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

logger = logging.getLogger("forensitrace.normal_noise")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

SCENARIO_ID = "normal_noise"
SCENARIO_NAME = "Normal Workstation Background Telemetry"
GROUND_TRUTH_LABEL = "normal"
EXPECTED_RULES: List[str] = []
EXPECTED_THREAT_LEVEL = "LOW"


def generate_normal_noise_events(
    host: str = "WIN-FORENSIC-01",
    user: str = "CONTOSO\\analyst",
    usb_drive: str = "F:",
    device_name: str = "Kingston DataTraveler",
    serial_number: str = "AA00000000000456",
) -> List[Dict[str, Any]]:
    """
    Generates deterministic telemetry events representing routine, legitimate workstation activity.
    None of these events satisfy any suspicious attack chain.
    """
    domain, username = user.split("\\") if "\\" in user else ("", user)
    device_instance = f"USBSTOR\\DISK&VEN_KINGSTON&PROD_DATATRAVELER\\{serial_number}"
    events: List[Dict[str, Any]] = []

    # 1. Interactive User Logon (Event 4624)
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-24T08:30:00.000Z",
            host=host,
            user=user,
            action="LOGON",
            entity_type="process",
            entity="C:\\Windows\\System32\\winlogon.exe",
            details={
                "event_record_id": 9501001,
                "channel": "Security",
                "event_code": 4624,
                "logon_type": 2,
                "authentication_package": "Negotiate",
                "raw_record_id": "Security:9501001",
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={
                "Event": {
                    "System": {
                        "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
                        "EventID": 4624,
                        "EventRecordID": 9501001,
                        "Channel": "Security",
                        "Computer": host,
                        "TimeCreated": {"SystemTime": "2026-10-24T08:30:00.000Z"},
                    },
                    "EventData": {"TargetUserName": username, "TargetDomainName": domain, "LogonType": 2},
                }
            },
            raw_record_id="Security:9501001",
        )
    )

    # 2. Chrome Browser Launch
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-24T08:31:15.200Z",
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            details={
                "event_record_id": 9501010,
                "channel": "Security",
                "event_code": 4688,
                "process_id": "0x1b20",
                "process_name": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "parent_process_id": "0x0e20",
                "parent_process_name": "C:\\Windows\\explorer.exe",
                "command_line": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"',
                "raw_record_id": "Security:9501010",
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
                        "EventRecordID": 9501010,
                        "Channel": "Security",
                        "Computer": host,
                        "TimeCreated": {"SystemTime": "2026-10-24T08:31:15.200Z"},
                    },
                    "EventData": {
                        "NewProcessName": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                        "ProcessId": "0x1b20",
                        "CommandLine": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"',
                        "SubjectUserName": username,
                        "SubjectDomainName": domain,
                    },
                }
            },
            raw_record_id="Security:9501010",
        )
    )

    # 3. Notepad Launch
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-24T08:32:30.400Z",
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="C:\\Windows\\System32\\notepad.exe",
            details={
                "event_record_id": 9501020,
                "channel": "Security",
                "event_code": 4688,
                "process_id": "0x1c34",
                "process_name": "C:\\Windows\\System32\\notepad.exe",
                "parent_process_id": "0x0e20",
                "parent_process_name": "C:\\Windows\\explorer.exe",
                "command_line": '"C:\\Windows\\System32\\notepad.exe" C:\\Users\\analyst\\Documents\\daily_tasks.txt',
                "raw_record_id": "Security:9501020",
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
                        "EventRecordID": 9501020,
                        "Channel": "Security",
                        "Computer": host,
                        "TimeCreated": {"SystemTime": "2026-10-24T08:32:30.400Z"},
                    },
                    "EventData": {
                        "NewProcessName": "C:\\Windows\\System32\\notepad.exe",
                        "ProcessId": "0x1c34",
                        "CommandLine": '"C:\\Windows\\System32\\notepad.exe" C:\\Users\\analyst\\Documents\\daily_tasks.txt',
                        "SubjectUserName": username,
                        "SubjectDomainName": domain,
                    },
                }
            },
            raw_record_id="Security:9501020",
        )
    )

    # 4. Document Created on C: (daily_tasks.txt)
    doc_path = "C:\\Users\\analyst\\Documents\\daily_tasks.txt"
    events.append(
        make_event(
            source="fs",
            ts_utc="2026-10-24T08:33:05.100Z",
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity=doc_path,
            details={
                "drive_letter": "C:",
                "file_path": doc_path,
                "file_name": "daily_tasks.txt",
                "extension": ".txt",
                "file_size_bytes": 512,
                "is_directory": False,
                "raw_record_id": f"FILE_CREATED|{doc_path}",
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={"event_type": "created", "src_path": doc_path, "is_directory": False},
            raw_record_id=f"FILE_CREATED|{doc_path}",
        )
    )

    # 5. Document Modified on C: (daily_tasks.txt)
    events.append(
        make_event(
            source="fs",
            ts_utc="2026-10-24T08:34:10.500Z",
            host=host,
            user=None,
            action="FILE_MODIFIED",
            entity_type="file",
            entity=doc_path,
            details={
                "drive_letter": "C:",
                "file_path": doc_path,
                "file_name": "daily_tasks.txt",
                "extension": ".txt",
                "file_size_bytes": 1024,
                "is_directory": False,
                "raw_record_id": f"FILE_MODIFIED|{doc_path}",
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={"event_type": "modified", "src_path": doc_path, "is_directory": False},
            raw_record_id=f"FILE_MODIFIED|{doc_path}",
        )
    )

    # 6. Spreadsheet Created on C: (quarterly_budget.xlsx)
    budget_path = "C:\\Users\\analyst\\Documents\\quarterly_budget.xlsx"
    events.append(
        make_event(
            source="fs",
            ts_utc="2026-10-24T08:34:55.200Z",
            host=host,
            user=None,
            action="FILE_CREATED",
            entity_type="file",
            entity=budget_path,
            details={
                "drive_letter": "C:",
                "file_path": budget_path,
                "file_name": "quarterly_budget.xlsx",
                "extension": ".xlsx",
                "file_size_bytes": 45056,
                "is_directory": False,
                "raw_record_id": f"FILE_CREATED|{budget_path}",
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={"event_type": "created", "src_path": budget_path, "is_directory": False},
            raw_record_id=f"FILE_CREATED|{budget_path}",
        )
    )

    # 7. Benign USB Arrival on F:
    events.append(
        make_event(
            source="usb",
            ts_utc="2026-10-24T08:35:20.100Z",
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
            raw={"EventType": "DBT_DEVICEARRIVAL", "DriveLetter": usb_drive, "FriendlyName": f"{device_name} USB Device"},
            raw_record_id=device_instance,
        )
    )

    # 8. Adobe Acrobat Reader launched from C: viewing pre-existing PDF on F: (No writes to F:)
    pdf_path = f"{usb_drive}\\client_presentation.pdf"
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-24T08:37:12.600Z",
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AcroRd32.exe",
            details={
                "event_record_id": 9501045,
                "channel": "Security",
                "event_code": 4688,
                "process_id": "0x1d40",
                "process_name": "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AcroRd32.exe",
                "parent_process_id": "0x0e20",
                "parent_process_name": "C:\\Windows\\explorer.exe",
                "command_line": f'"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AcroRd32.exe" "{pdf_path}"',
                "raw_record_id": "Security:9501045",
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={
                "Event": {
                    "System": {
                        "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
                        "EventID": 9501045,
                        "Channel": "Security",
                        "Computer": host,
                        "TimeCreated": {"SystemTime": "2026-10-24T08:37:12.600Z"},
                    },
                    "EventData": {
                        "NewProcessName": "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AcroRd32.exe",
                        "ProcessId": "0x1d40",
                        "CommandLine": f'"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AcroRd32.exe" "{pdf_path}"',
                        "SubjectUserName": username,
                        "SubjectDomainName": domain,
                    },
                }
            },
            raw_record_id="Security:9501045",
        )
    )

    # 9. USB Drive Safely Removed
    events.append(
        make_event(
            source="usb",
            ts_utc="2026-10-24T08:40:00.000Z",
            host=host,
            user="SYSTEM",
            action="DEVICE_REMOVED",
            entity_type="device",
            entity=f"{usb_drive} ({device_name} {serial_number})",
            details={
                "drive_letter": usb_drive,
                "device_name": device_name,
                "serial_number": serial_number,
                "raw_record_id": device_instance,
                "scenario_id": SCENARIO_ID,
                "label": GROUND_TRUTH_LABEL,
                "is_synthetic": True,
                "dataset_type": "scenario",
            },
            raw={"EventType": "DBT_DEVICEREMOVECOMPLETE", "DriveLetter": usb_drive},
            raw_record_id=device_instance,
        )
    )

    # 10. Calculator Launch
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-24T08:42:15.300Z",
            host=host,
            user=user,
            action="PROCESS_STARTED",
            entity_type="process",
            entity="C:\\Windows\\System32\\calc.exe",
            details={
                "event_record_id": 9501060,
                "channel": "Security",
                "event_code": 4688,
                "process_id": "0x1e50",
                "process_name": "C:\\Windows\\System32\\calc.exe",
                "parent_process_id": "0x0e20",
                "parent_process_name": "C:\\Windows\\explorer.exe",
                "command_line": '"C:\\Windows\\System32\\calc.exe"',
                "raw_record_id": "Security:9501060",
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
                        "EventRecordID": 9501060,
                        "Channel": "Security",
                        "Computer": host,
                        "TimeCreated": {"SystemTime": "2026-10-24T08:42:15.300Z"},
                    },
                    "EventData": {
                        "NewProcessName": "C:\\Windows\\System32\\calc.exe",
                        "ProcessId": "0x1e50",
                        "CommandLine": '"C:\\Windows\\System32\\calc.exe"',
                        "SubjectUserName": username,
                        "SubjectDomainName": domain,
                    },
                }
            },
            raw_record_id="Security:9501060",
        )
    )

    # 11. Windows Background Maintenance Taskhost
    events.append(
        make_event(
            source="eventlog",
            ts_utc="2026-10-24T08:45:00.000Z",
            host=host,
            user="SYSTEM",
            action="PROCESS_STARTED",
            entity_type="process",
            entity="C:\\Windows\\System32\\taskhostw.exe",
            details={
                "event_record_id": 9501070,
                "channel": "Security",
                "event_code": 4688,
                "process_id": "0x1f60",
                "process_name": "C:\\Windows\\System32\\taskhostw.exe",
                "parent_process_id": "0x0280",
                "parent_process_name": "C:\\Windows\\System32\\services.exe",
                "command_line": '"C:\\Windows\\System32\\taskhostw.exe" {222A245B-E637-4AE9-A93F-A2408C012C6B}',
                "raw_record_id": "Security:9501070",
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
                        "EventRecordID": 9501070,
                        "Channel": "Security",
                        "Computer": host,
                        "TimeCreated": {"SystemTime": "2026-10-24T08:45:00.000Z"},
                    },
                    "EventData": {
                        "NewProcessName": "C:\\Windows\\System32\\taskhostw.exe",
                        "ProcessId": "0x1f60",
                        "CommandLine": '"C:\\Windows\\System32\\taskhostw.exe" {222A245B-E637-4AE9-A93F-A2408C012C6B}',
                        "SubjectUserName": "SYSTEM",
                        "SubjectDomainName": "NT AUTHORITY",
                    },
                }
            },
            raw_record_id="Security:9501070",
        )
    )

    return events


def get_ground_truth(events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Returns the ground truth specification document for Normal Noise."""
    evs = events or generate_normal_noise_events()
    return {
        "scenario_id": SCENARIO_ID,
        "name": SCENARIO_NAME,
        "label": GROUND_TRUTH_LABEL,
        "description": "Routine workstation productivity events including office documents, web browsing, and benign USB usage.",
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
        default=REPO_ROOT / "scenarios" / "ground_truth" / "normal_noise.json",
        help="Path to write the ground truth JSON (default: scenarios/ground_truth/normal_noise.json)",
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
    events = generate_normal_noise_events()
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
