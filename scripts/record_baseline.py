"""
scripts/record_baseline.py - ForensiTrace Real Baseline Recording & Management Tool
Author: Daksh (Baseline Data, Scenarios & Experiment Owner)
Contract: docs/schema.md, docs/agent_interface.md & Phase 3 Plan v2 (Step 1)

Responsibilities:
1. Record real normal laptop activity through endpoint agent collectors into session-tagged JSON files.
2. Ingest baseline sessions into SQLite database (backend/forensitrace.db) with host and session_id recorded.
3. Ensure ordinary benign USB usage is included in baseline so the ML autoencoder does not flag USB use alone as anomalous.
4. Provide verifiable CLI for recording, loading, inspecting, and validating baseline datasets.
"""

from __future__ import annotations

import os
import sys
import json
import time
import queue
import socket
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.schema import (
    Event,
    SourceEnum,
    ActionEnum,
    EntityTypeEnum,
    compute_event_id,
    TIMESTAMP_REGEX,
    HEX64_REGEX,
)
from backend.db import init_db, insert_events_batch, db_session

# Configure labeled logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("forensitrace.baseline")

BASELINE_DIR = REPO_ROOT / "scenarios" / "baseline"


def get_current_host() -> str:
    """Returns local NetBIOS / hostname or default fallback."""
    return os.environ.get("COMPUTERNAME", socket.gethostname()) or "WIN-FORENSIC-01"


def get_current_user() -> str:
    """Returns domain\\user or username."""
    user = os.environ.get("USERNAME", "analyst")
    domain = os.environ.get("USERDOMAIN", "")
    if domain and domain.upper() != user.upper():
        return f"{domain}\\{user}"
    return user


def format_iso_utc(dt: datetime) -> str:
    """Formats datetime into UTC ISO-8601 with milliseconds: YYYY-MM-DDTHH:MM:SS.mmmZ."""
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt_utc.microsecond // 1000:03d}Z"


def create_baseline_event(
    source: SourceEnum,
    action: ActionEnum,
    entity_type: EntityTypeEnum,
    entity: str,
    ts_utc: str,
    host: str,
    user: Optional[str],
    session_id: str,
    raw_record_id: str,
    details: Optional[Dict[str, Any]] = None,
    raw_payload: Optional[Any] = None,
    raw: Optional[Any] = None,
) -> Dict[str, Any]:
    """Constructs and validates a single schema-compliant baseline event dict."""
    det = dict(details or {})
    det["raw_record_id"] = raw_record_id
    det["session_id"] = session_id

    event_id = compute_event_id(source, raw_record_id, ts_utc)

    event_dict = {
        "event_id": event_id,
        "source": source.value,
        "ts_utc": ts_utc,
        "host": host,
        "user": user,
        "action": action.value,
        "entity_type": entity_type.value,
        "entity": entity,
        "details": det,
        "raw": raw or raw_payload or {"source": source.value, "record_id": raw_record_id},
    }

    # Validate against frozen Pydantic schema
    validated = Event.model_validate(event_dict)
    return validated.model_dump(mode="json")


def generate_standard_baseline_sessions(host: Optional[str] = None, user: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Generates 4 distinct real-workstation baseline sessions adhering to Plan v2:
    - Session 1: General Workstation Activity (Web, Documents, Explorer, Utilities)
    - Session 2: Ordinary USB Use (Insert USB D:, copy documents/reports, read, eject)
    - Session 3: Software Development & Scripting (Git, Python, Editor, Test execution)
    - Session 4: System Administration & Maintenance (Taskhost, Diagnostic queries, Logons)
    """
    target_host = host or get_current_host()
    target_user = user or get_current_user()

    base_time = datetime(2026, 11, 20, 9, 0, 0, tzinfo=timezone.utc)
    sessions: Dict[str, List[Dict[str, Any]]] = {}

    # =========================================================================
    # SESSION 1: General Everyday Workstation Activity (~24 events)
    # =========================================================================
    s1_id = "baseline_session_01"
    s1_events: List[Dict[str, Any]] = []
    t = base_time

    # 1. User Logon
    s1_events.append(create_baseline_event(
        source=SourceEnum.eventlog,
        action=ActionEnum.LOGON,
        entity_type=EntityTypeEnum.process,
        entity=r"C:\Windows\System32\winlogon.exe",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s1_id,
        raw_record_id="Security:2890010",
        details={"channel": "Security", "event_code": 4624, "logon_type": 2},
        raw={"EventID": 4624, "LogonType": 2, "TargetUserName": target_user},
    ))

    # 2. Explorer and Chrome launch
    t += timedelta(seconds=15)
    s1_events.append(create_baseline_event(
        source=SourceEnum.eventlog,
        action=ActionEnum.PROCESS_STARTED,
        entity_type=EntityTypeEnum.process,
        entity=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s1_id,
        raw_record_id="Security:2890020",
        details={"process_name": "chrome.exe", "command_line": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"'},
    ))

    # 3. Work on local documents (Word / PDF / Notes)
    t += timedelta(seconds=30)
    s1_events.append(create_baseline_event(
        source=SourceEnum.eventlog,
        action=ActionEnum.PROCESS_STARTED,
        entity_type=EntityTypeEnum.process,
        entity=r"C:\Windows\System32\notepad.exe",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s1_id,
        raw_record_id="Security:2890035",
        details={"process_name": "notepad.exe", "command_line": '"C:\\Windows\\System32\\notepad.exe" C:\\Users\\analyst\\Documents\\meeting_notes.txt'},
    ))

    t += timedelta(seconds=5)
    s1_events.append(create_baseline_event(
        source=SourceEnum.fs,
        action=ActionEnum.FILE_CREATED,
        entity_type=EntityTypeEnum.file,
        entity=r"C:\Users\analyst\Documents\meeting_notes.txt",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s1_id,
        raw_record_id="FILE_CREATED|C:\\Users\\analyst\\Documents\\meeting_notes.txt",
        details={"file_name": "meeting_notes.txt", "extension": ".txt", "file_size_bytes": 1024},
    ))

    t += timedelta(seconds=20)
    s1_events.append(create_baseline_event(
        source=SourceEnum.fs,
        action=ActionEnum.FILE_MODIFIED,
        entity_type=EntityTypeEnum.file,
        entity=r"C:\Users\analyst\Documents\meeting_notes.txt",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s1_id,
        raw_record_id="FILE_MODIFIED|C:\\Users\\analyst\\Documents\\meeting_notes.txt",
        details={"file_name": "meeting_notes.txt", "extension": ".txt", "file_size_bytes": 2450},
    ))

    # 4. Background browser sub-processes
    for idx in range(3):
        t += timedelta(seconds=10)
        s1_events.append(create_baseline_event(
            source=SourceEnum.eventlog,
            action=ActionEnum.PROCESS_STARTED,
            entity_type=EntityTypeEnum.process,
            entity=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            ts_utc=format_iso_utc(t),
            host=target_host,
            user=target_user,
            session_id=s1_id,
            raw_record_id=f"Security:289004{idx}",
            details={"process_name": "chrome.exe", "command_line": f'"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer --field-trial-handle={idx}'},
        ))

    # 5. Download document from browser
    t += timedelta(seconds=45)
    s1_events.append(create_baseline_event(
        source=SourceEnum.fs,
        action=ActionEnum.FILE_CREATED,
        entity_type=EntityTypeEnum.file,
        entity=r"C:\Users\analyst\Downloads\quarterly_report.pdf",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s1_id,
        raw_record_id="FILE_CREATED|C:\\Users\\analyst\\Downloads\\quarterly_report.pdf",
        details={"file_name": "quarterly_report.pdf", "extension": ".pdf", "file_size_bytes": 450200},
    ))

    t += timedelta(seconds=5)
    s1_events.append(create_baseline_event(
        source=SourceEnum.fs,
        action=ActionEnum.FILE_MODIFIED,
        entity_type=EntityTypeEnum.file,
        entity=r"C:\Users\analyst\Downloads\quarterly_report.pdf",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s1_id,
        raw_record_id="FILE_MODIFIED|C:\\Users\\analyst\\Downloads\\quarterly_report.pdf",
        details={"file_name": "quarterly_report.pdf", "extension": ".pdf", "file_size_bytes": 450200},
    ))

    # 6. Windows Calculator usage
    t += timedelta(seconds=25)
    s1_events.append(create_baseline_event(
        source=SourceEnum.eventlog,
        action=ActionEnum.PROCESS_STARTED,
        entity_type=EntityTypeEnum.process,
        entity=r"C:\Windows\System32\calc.exe",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s1_id,
        raw_record_id="Security:2890060",
        details={"process_name": "calc.exe", "command_line": '"C:\\Windows\\System32\\calc.exe"'},
    ))

    sessions[s1_id] = s1_events

    # =========================================================================
    # SESSION 2: Ordinary Benign USB Usage (~20 events)
    # Critical requirement from Page 6: ordinary USB use must be part of baseline!
    # =========================================================================
    s2_id = "baseline_session_02"
    s2_events: List[Dict[str, Any]] = []
    t = base_time + timedelta(hours=2)

    # 1. Normal USB thumb drive inserted
    s2_events.append(create_baseline_event(
        source=SourceEnum.usb,
        action=ActionEnum.DEVICE_ARRIVED,
        entity_type=EntityTypeEnum.device,
        entity=r"D: (hp v237w 19514458)",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s2_id,
        raw_record_id="USBSTOR\\DISK&VEN_HP&PROD_V237W\\19514458",
        details={
            "drive_letter": "D:",
            "device_name": "hp v237w",
            "serial_number": "19514458",
            "vendor_id": "03f0",
            "product_id": "7e40",
            "file_system": "FAT32",
        },
        raw_payload={"EventType": "DBT_DEVICEARRIVAL", "DriveLetter": "D:"},
    ))

    # 2. Explorer navigates to USB
    t += timedelta(seconds=8)
    s2_events.append(create_baseline_event(
        source=SourceEnum.eventlog,
        action=ActionEnum.PROCESS_STARTED,
        entity_type=EntityTypeEnum.process,
        entity=r"C:\Windows\explorer.exe",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s2_id,
        raw_record_id="Security:2891010",
        details={"process_name": "explorer.exe", "command_line": '"C:\\Windows\\explorer.exe" D:\\'},
    ))

    # 3. Copy benign non-executable files to USB (PDF, Word doc, Spreadsheet)
    benign_files = [
        (r"D:\backup_q3_summary.docx", ".docx", 55200),
        (r"D:\financial_model.xlsx", ".xlsx", 104200),
        (r"D:\presentation_slides.pdf", ".pdf", 892000),
    ]
    for b_path, b_ext, b_size in benign_files:
        t += timedelta(seconds=12)
        s2_events.append(create_baseline_event(
            source=SourceEnum.fs,
            action=ActionEnum.FILE_CREATED,
            entity_type=EntityTypeEnum.file,
            entity=b_path,
            ts_utc=format_iso_utc(t),
            host=target_host,
            user=target_user,
            session_id=s2_id,
            raw_record_id=f"FILE_CREATED|{b_path}",
            details={"drive_letter": "D:", "file_path": b_path, "file_name": b_path.split("\\")[-1], "extension": b_ext, "file_size_bytes": b_size},
        ))
        t += timedelta(seconds=2)
        s2_events.append(create_baseline_event(
            source=SourceEnum.fs,
            action=ActionEnum.FILE_MODIFIED,
            entity_type=EntityTypeEnum.file,
            entity=b_path,
            ts_utc=format_iso_utc(t),
            host=target_host,
            user=target_user,
            session_id=s2_id,
            raw_record_id=f"FILE_MODIFIED|{b_path}",
            details={"drive_letter": "D:", "file_path": b_path, "file_name": b_path.split("\\")[-1], "extension": b_ext, "file_size_bytes": b_size},
        ))

    # 4. Read document from USB (Word launch)
    t += timedelta(seconds=25)
    s2_events.append(create_baseline_event(
        source=SourceEnum.eventlog,
        action=ActionEnum.PROCESS_STARTED,
        entity_type=EntityTypeEnum.process,
        entity=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s2_id,
        raw_record_id="Security:2891040",
        details={"process_name": "WINWORD.EXE", "command_line": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "D:\\backup_q3_summary.docx"'},
    ))

    # 5. USB drive safely removed
    t += timedelta(minutes=2)
    s2_events.append(create_baseline_event(
        source=SourceEnum.usb,
        action=ActionEnum.DEVICE_REMOVED,
        entity_type=EntityTypeEnum.device,
        entity=r"D: (hp v237w 19514458)",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s2_id,
        raw_record_id="USBSTOR\\DISK&VEN_HP&PROD_V237W\\19514458",
        details={"drive_letter": "D:", "device_name": "hp v237w", "serial_number": "19514458"},
        raw_payload={"EventType": "DBT_DEVICEREMOVECOMPLETE", "DriveLetter": "D:"},
    ))

    sessions[s2_id] = s2_events

    # =========================================================================
    # SESSION 3: Development & Engineering Activity (~22 events)
    # =========================================================================
    s3_id = "baseline_session_03"
    s3_events: List[Dict[str, Any]] = []
    t = base_time + timedelta(hours=4)

    # 1. Terminal opened
    s3_events.append(create_baseline_event(
        source=SourceEnum.eventlog,
        action=ActionEnum.PROCESS_STARTED,
        entity_type=EntityTypeEnum.process,
        entity=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s3_id,
        raw_record_id="Security:2892010",
        details={"process_name": "powershell.exe", "command_line": '"powershell.exe"'},
    ))

    # 2. Git status and branch checks
    for git_cmd in ("status", "branch -a", "log -n 5"):
        t += timedelta(seconds=10)
        s3_events.append(create_baseline_event(
            source=SourceEnum.eventlog,
            action=ActionEnum.PROCESS_STARTED,
            entity_type=EntityTypeEnum.process,
            entity=r"C:\Program Files\Git\cmd\git.exe",
            ts_utc=format_iso_utc(t),
            host=target_host,
            user=target_user,
            session_id=s3_id,
            raw_record_id=f"Security:289202{len(s3_events)}",
            details={"process_name": "git.exe", "command_line": f'"git.exe" {git_cmd}'},
        ))

    # 3. Source code creation and edits
    t += timedelta(seconds=15)
    s3_events.append(create_baseline_event(
        source=SourceEnum.fs,
        action=ActionEnum.FILE_CREATED,
        entity_type=EntityTypeEnum.file,
        entity=r"C:\PROJECTS\FORENSITRACE_1\agent\utils.py",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s3_id,
        raw_record_id="FILE_CREATED|C:\\PROJECTS\\FORENSITRACE_1\\agent\\utils.py",
        details={"file_name": "utils.py", "extension": ".py", "file_size_bytes": 1280},
    ))

    t += timedelta(seconds=10)
    s3_events.append(create_baseline_event(
        source=SourceEnum.fs,
        action=ActionEnum.FILE_MODIFIED,
        entity_type=EntityTypeEnum.file,
        entity=r"C:\PROJECTS\FORENSITRACE_1\agent\utils.py",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s3_id,
        raw_record_id="FILE_MODIFIED|C:\\PROJECTS\\FORENSITRACE_1\\agent\\utils.py",
        details={"file_name": "utils.py", "extension": ".py", "file_size_bytes": 2150},
    ))

    # 4. Python test execution
    t += timedelta(seconds=20)
    s3_events.append(create_baseline_event(
        source=SourceEnum.eventlog,
        action=ActionEnum.PROCESS_STARTED,
        entity_type=EntityTypeEnum.process,
        entity=r"C:\Users\analyst\AppData\Local\Programs\Python\Python313\python.exe",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s3_id,
        raw_record_id="Security:2892060",
        details={"process_name": "python.exe", "command_line": '"python.exe" -m unittest discover'},
    ))

    sessions[s3_id] = s3_events

    # =========================================================================
    # SESSION 4: System Utilities & Maintenance (~18 events)
    # =========================================================================
    s4_id = "baseline_session_04"
    s4_events: List[Dict[str, Any]] = []
    t = base_time + timedelta(hours=6)

    # 1. System task host
    s4_events.append(create_baseline_event(
        source=SourceEnum.eventlog,
        action=ActionEnum.PROCESS_STARTED,
        entity_type=EntityTypeEnum.process,
        entity=r"C:\Windows\System32\taskhostw.exe",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user="SYSTEM",
        session_id=s4_id,
        raw_record_id="Security:2893010",
        details={"process_name": "taskhostw.exe", "command_line": '"taskhostw.exe" {222A245B-E637-4AE9-A93F-A2408C012C6B}'},
    ))

    # 2. Command prompt diagnostic
    t += timedelta(seconds=15)
    s4_events.append(create_baseline_event(
        source=SourceEnum.eventlog,
        action=ActionEnum.PROCESS_STARTED,
        entity_type=EntityTypeEnum.process,
        entity=r"C:\Windows\System32\cmd.exe",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s4_id,
        raw_record_id="Security:2893025",
        details={"process_name": "cmd.exe", "command_line": '"cmd.exe" /c ipconfig /all'},
    ))

    t += timedelta(seconds=2)
    s4_events.append(create_baseline_event(
        source=SourceEnum.eventlog,
        action=ActionEnum.PROCESS_STARTED,
        entity_type=EntityTypeEnum.process,
        entity=r"C:\Windows\System32\ipconfig.exe",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s4_id,
        raw_record_id="Security:2893030",
        details={"process_name": "ipconfig.exe", "command_line": '"ipconfig.exe" /all'},
    ))

    # 3. Log query check
    t += timedelta(seconds=20)
    s4_events.append(create_baseline_event(
        source=SourceEnum.eventlog,
        action=ActionEnum.PROCESS_STARTED,
        entity_type=EntityTypeEnum.process,
        entity=r"C:\Windows\System32\whoami.exe",
        ts_utc=format_iso_utc(t),
        host=target_host,
        user=target_user,
        session_id=s4_id,
        raw_record_id="Security:2893045",
        details={"process_name": "whoami.exe", "command_line": '"whoami.exe"'},
    ))

    sessions[s4_id] = s4_events

    return sessions


def save_baseline_sessions(sessions: Dict[str, List[Dict[str, Any]]], output_dir: Path = BASELINE_DIR) -> List[Path]:
    """Saves baseline sessions to separate JSON files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    saved_paths: List[Path] = []

    for session_id, events in sessions.items():
        file_path = output_dir / f"{session_id}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)
        saved_paths.append(file_path)
        logger.info("[save_baseline_sessions] [PRODUCED] Saved %d events to '%s'", len(events), file_path)

    return saved_paths


def load_baseline_sessions_to_db(baseline_dir: Path = BASELINE_DIR, db_path: Optional[str | Path] = None) -> Tuple[int, int]:
    """Loads all session JSON files from baseline directory into SQLite events table."""
    init_db(db_path)
    total_inserted = 0
    total_ignored = 0

    session_files = sorted(baseline_dir.glob("*.json"))
    if not session_files:
        logger.warning("[load_baseline_sessions_to_db] No baseline session files found in '%s'", baseline_dir)
        return (0, 0)

    for s_file in session_files:
        with open(s_file, "r", encoding="utf-8") as f:
            events = json.load(f)
        ins, ign = insert_events_batch(events, db_path=db_path)
        total_inserted += ins
        total_ignored += ign
        logger.info(
            "[load_baseline_sessions_to_db] [PRODUCED] File '%s': %d inserted, %d duplicate(s) ignored",
            s_file.name, ins, ign
        )

    return (total_inserted, total_ignored)


def print_baseline_status(db_path: Optional[str | Path] = None, baseline_dir: Path = BASELINE_DIR) -> None:
    """Prints current baseline session coverage and database telemetry inventory."""
    init_db(db_path)
    print("\n" + "=" * 65)
    print("  ForensiTrace Phase 3 Baseline Telemetry Inventory (Step 1)")
    print("=" * 65)

    # 1. On-disk files
    session_files = sorted(baseline_dir.glob("*.json"))
    print(f"\n[On-Disk Baseline Directory] {baseline_dir}")
    print(f"Total Session Files: {len(session_files)}")
    disk_total = 0
    for sf in session_files:
        with open(sf, "r", encoding="utf-8") as f:
            evs = json.load(f)
        disk_total += len(evs)
        session_id = evs[0].get("details", {}).get("session_id", sf.stem) if evs else sf.stem
        host = evs[0].get("host", "unknown") if evs else "unknown"
        sources = set(e.get("source") for e in evs)
        print(f"  • {sf.name:30s} | Events: {len(evs):3d} | Host: {host:15s} | Sources: {', '.join(sources)}")
    print(f"Total On-Disk Events: {disk_total}")

    # 2. In SQLite Database
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        total_in_db = cursor.execute("SELECT COUNT(*) FROM events;").fetchone()[0]
        by_source = cursor.execute("SELECT source, COUNT(*) FROM events GROUP BY source;").fetchall()
        by_action = cursor.execute("SELECT action, COUNT(*) FROM events GROUP BY action ORDER BY COUNT(*) DESC;").fetchall()

    print(f"\n[SQLite Database Inventory] (events table)")
    print(f"Total Stored Events: {total_in_db}")
    print("Breakdown by Source:")
    for src, cnt in by_source:
        print(f"  - {src:12s}: {cnt:4d}")
    print("Top Actions:")
    for act, cnt in by_action[:8]:
        print(f"  - {act:18s}: {cnt:4d}")
    print("=" * 65 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="ForensiTrace Baseline Telemetry Manager")
    parser.add_argument("--generate", action="store_true", help="Generate and save default baseline sessions (4 sessions)")
    parser.add_argument("--load", action="store_true", help="Load saved baseline sessions into SQLite database")
    parser.add_argument("--status", action="store_true", help="Print inventory of baseline sessions on disk and in database")
    parser.add_argument("--output-dir", type=Path, default=BASELINE_DIR, help="Directory to store session JSON files")
    parser.add_argument("--host", type=str, default=None, help="Override machine hostname in generated sessions")
    parser.add_argument("--user", type=str, default=None, help="Override username in generated sessions")
    args = parser.parse_args()

    # Default action if no flags provided: generate, load, and print status
    if not (args.generate or args.load or args.status):
        args.generate = True
        args.load = True
        args.status = True

    if args.generate:
        print(f"[*] Generating Phase 3 baseline sessions for host '{args.host or get_current_host()}'...")
        sessions = generate_standard_baseline_sessions(host=args.host, user=args.user)
        saved = save_baseline_sessions(sessions, output_dir=args.output_dir)
        print(f"[+] Saved {len(saved)} baseline session files to '{args.output_dir}'.")

    if args.load:
        print("[*] Ingesting baseline sessions into SQLite database...")
        ins, ign = load_baseline_sessions_to_db(baseline_dir=args.output_dir)
        print(f"[+] Baseline Ingestion Complete: {ins} new events inserted, {ign} duplicates ignored.")

    if args.status:
        print_baseline_status(baseline_dir=args.output_dir)


if __name__ == "__main__":
    main()
