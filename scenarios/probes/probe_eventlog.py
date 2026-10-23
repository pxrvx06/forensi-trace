#!/usr/bin/env python3
"""
probe_eventlog.py - Read-only Windows Event Log probe for ForensiTrace.

Checks for the presence of target event records in Windows Event Log:
  1. Security 4688: Process Created
  2. Security 1102: Audit Log Cleared
  3. System 104:    System Log Cleared

Prints extracted fields and raw XML representation to verify event structure.
Handles permission errors (non-elevated terminal) and disabled audit policies.
"""

import sys
import json
import xml.etree.ElementTree as ET

# Target definitions for evidence investigation
TARGET_EVENTS = [
    {
        "channel": "Security",
        "event_id": 4688,
        "name": "PROCESS_STARTED (Process Creation)",
        "audit_policy": 'Audit Process Creation (auditpol /set /subcategory:"Process Creation" /success:enable)',
        "expected_fields": ["NewProcessName", "ProcessId", "CommandLine", "ParentProcessName", "SubjectUserName"],
    },
    {
        "channel": "Security",
        "event_id": 1102,
        "name": "LOG_CLEARED (Security Log Cleared)",
        "audit_policy": "Default Windows Security Auditing",
        "expected_fields": ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId"],
    },
    {
        "channel": "System",
        "event_id": 104,
        "name": "LOG_CLEARED (System Log Cleared)",
        "audit_policy": "Default Windows Event Logging",
        "expected_fields": ["BackupPath", "SubjectUserName", "SubjectDomainName"],
    },
]


def check_windows_platform() -> bool:
    """Verifies that the script is running on a Windows platform."""
    if sys.platform != "win32":
        print("[ERROR] This script queries Windows Event Log and must be run on Windows 10/11.")
        print(f"        Current platform detected: {sys.platform}")
        return False
    return True


def check_admin_privileges() -> bool:
    """Checks whether the current process is running with Administrator privileges."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as exc:
        print(f"[WARN] Unable to determine admin privileges via shell32: {exc}")
        return False


def parse_event_xml(xml_content: str) -> dict:
    """
    Parses Windows Event Log XML string into a structured dictionary.
    Extracts both <System> header attributes and <EventData> elements.
    """
    root = ET.fromstring(xml_content)
    # Strip XML namespace if present
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    data = {
        "system": {},
        "event_data": {},
    }

    # Extract System header fields
    system_elem = root.find(f"{ns}System")
    if system_elem is not None:
        for child in system_elem:
            tag = child.tag[len(ns):] if child.tag.startswith(ns) else child.tag
            if child.attrib:
                data["system"][tag] = {**child.attrib, "_text": child.text}
            else:
                data["system"][tag] = child.text

    # Extract EventData / UserData fields
    event_data_elem = root.find(f"{ns}EventData")
    if event_data_elem is not None:
        for child in event_data_elem:
            name = child.attrib.get("Name")
            value = child.text
            if name:
                data["event_data"][name] = value
            elif child.text:
                data["event_data"][f"data_{len(data['event_data'])}"] = value

    # Check for UserData container if EventData was empty
    user_data_elem = root.find(f"{ns}UserData")
    if user_data_elem is not None:
        for item in user_data_elem.iter():
            tag = item.tag[len(ns):] if item.tag.startswith(ns) else item.tag
            if tag != "UserData" and item.text and item.text.strip():
                data["event_data"][tag] = item.text.strip()

    return data


def probe_target(win32evtlog, target: dict) -> None:
    """
    Queries the most recent event for a specific channel and Event ID.
    Outputs structured fields and diagnostics.
    """
    channel = target["channel"]
    event_id = target["event_id"]
    name = target["name"]
    query = f"*[System[(EventID={event_id})]]"

    print("=" * 72)
    print(f"PROBE TARGET: Channel '{channel}' | Event ID {event_id} ({name})")
    print(f"QUERY: {query}")
    print("-" * 72)

    try:
        # Open reverse query to get the newest events first
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
        query_handle = win32evtlog.EvtQuery(channel, flags, query)
    except Exception as exc:
        err_msg = str(exc)
        print(f"[ACCESS DENIED / ERROR] Failed to query channel '{channel}':")
        print(f"  Exception: {err_msg}")
        if "Access is denied" in err_msg or (hasattr(exc, "winerror") and exc.winerror == 5):
            print("  Reason: Insufficient privileges. Reading the Security log requires elevation.")
            print("  Fix: Run this script from an elevated command prompt (Run as Administrator).")
            print("       Refer to scripts/setup_windows.md for full instructions.")
        print()
        return

    try:
        events = win32evtlog.EvtNext(query_handle, 1)
        if not events:
            print(f"[STATUS] No events found for Event ID {event_id} in '{channel}' channel.")
            if event_id == 4688:
                print("  Possible causes:")
                print("    1. Process Creation auditing is not enabled.")
                print(f"       Enable command: {target['audit_policy']}")
                print("    2. No new processes were created since auditing was enabled.")
                print("       Try running a command (e.g., cmd /c echo test) and rerun this probe.")
            elif event_id in (1102, 104):
                print(f"  Note: This is expected if the {channel} log has not been cleared recently.")
                print("        Clearing logs should only be performed during scenario testing on a test VM.")
            print()
            return

        # Render XML for the found event
        event_handle = events[0]
        xml_content = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
        parsed = parse_event_xml(xml_content)

        print("[STATUS] EVENT FOUND! Telemetry record details:")
        system_info = parsed.get("system", {})
        time_created = system_info.get("TimeCreated", {})
        ts = time_created.get("SystemTime") if isinstance(time_created, dict) else time_created
        record_id = system_info.get("EventRecordID")
        computer = system_info.get("Computer")

        print(f"  Record ID   : {record_id}")
        print(f"  TimeCreated : {ts}")
        print(f"  Computer    : {computer}")
        print()
        print("  EventData Fields Found:")
        event_data = parsed.get("event_data", {})
        if event_data:
            for k, v in event_data.items():
                print(f"    - {k:25}: {v}")
        else:
            print("    (No EventData fields extracted; check raw XML)")

        # Verify expected fields
        missing_fields = [f for f in target["expected_fields"] if f not in event_data]
        if missing_fields:
            print()
            print(f"  [NOTE] Target fields not found in EventData: {missing_fields}")
            if event_id == 4688 and "CommandLine" in missing_fields:
                print("         Notice: 'CommandLine' is missing. To include command line arguments,")
                print("         enable 'Include command line in process creation events' via Group Policy or Registry.")
                print("         See Step 3 in scripts/setup_windows.md.")

        print()
        print("  Raw XML Snippet (first 400 chars):")
        snippet = xml_content.strip()[:400].replace("\n", " ")
        print(f"    {snippet}...")
        print()

    except Exception as exc:
        print(f"[ERROR] Failed while rendering event data: {exc}")
    print()


def main() -> int:
    print("=" * 72)
    print(" ForensiTrace - Windows Event Log Telemetry Probe")
    print("=" * 72)
    print()

    if not check_windows_platform():
        return 1

    try:
        import win32evtlog
    except ImportError:
        print("[ERROR] 'pywin32' is not installed in the current Python environment.")
        print("        Install it by running: pip install pywin32")
        return 1

    is_admin = check_admin_privileges()
    if is_admin:
        print("[PRIVILEGE CHECK] Process is running with ADMINISTRATOR privileges.")
    else:
        print("[PRIVILEGE CHECK] Process is running as STANDARD USER (not elevated).")
        print("                  Security event log queries will likely return 'Access is denied'.")
        print("                  For complete results, re-run this script in an elevated terminal.")
    print()

    for target in TARGET_EVENTS:
        probe_target(win32evtlog, target)

    print("=" * 72)
    print("Probe execution complete.")
    print("Record real output in 'docs/evidence_notes/eventlog.md'.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
