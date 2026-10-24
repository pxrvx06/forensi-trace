"""
engine/narratives.py - Evidence-Grounded Plain-English Narrative Generator for ForensiTrace.

Author: Akash (Correlation Engine & Rules Owner)
Contract: docs/schema.md, docs/rules.yaml, backend/schema.py
Scope: Task 3 - Evidence Provenance and Plain-English Narratives

Forensic Principle:
Narratives describe observed sequences strictly based on recorded telemetry.
They cite supporting event IDs, avoid asserting unrecorded facts, and maintain
objective, cautious phrasing (e.g. distinguishing potential anti-forensics from proven malice).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("forensitrace.engine.narratives")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def _short_id(event_id: str) -> str:
    """Returns truncated event ID for clean inline citation."""
    return event_id[:8] if event_id else "unknown"


def generate_narrative(
    rule_id: str,
    events: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generates a concise, evidence-grounded narrative citing supporting event IDs.
    """
    ctx = context or {}
    
    if rule_id == "R1":
        # USB Arrival -> File Created/Modified
        usb = next((e for e in events if e.get("source") == "usb"), {})
        fs = next((e for e in events if e.get("source") == "fs"), {})
        drive = ctx.get("drive_letter") or usb.get("details", {}).get("drive_letter", "removable drive")
        dev_name = usb.get("details", {}).get("device_name", "Removable USB Device")
        fs_action = fs.get("action", "FILE_ACTIVITY").lower().replace("_", " ")
        delta_sec = int(ctx.get("delta_seconds", 0))
        window_sec = ctx.get("window_seconds", 300)

        return (
            f"Removable storage device '{dev_name}' mounted on volume {drive} at {usb.get('ts_utc', 'N/A')} "
            f"[event:{_short_id(usb.get('event_id', ''))}], followed by file {fs_action} "
            f"for '{fs.get('entity', 'N/A')}' at {fs.get('ts_utc', 'N/A')} "
            f"[event:{_short_id(fs.get('event_id', ''))}] after {delta_sec}s (within {window_sec}s threshold)."
        )

    elif rule_id == "R2":
        # File Created -> Process Started
        fs = next((e for e in events if e.get("source") == "fs"), {})
        proc = next((e for e in events if e.get("source") == "eventlog"), {})
        delta_sec = int(ctx.get("delta_seconds", 0))
        window_sec = ctx.get("window_seconds", 600)
        user_info = f" by user '{proc.get('user')}'" if proc.get("user") else ""

        return (
            f"File '{fs.get('entity', 'N/A')}' was created at {fs.get('ts_utc', 'N/A')} "
            f"[event:{_short_id(fs.get('event_id', ''))}], then executed as process "
            f"'{proc.get('entity', 'N/A')}'{user_info} at {proc.get('ts_utc', 'N/A')} "
            f"[event:{_short_id(proc.get('event_id', ''))}] after {delta_sec}s (within {window_sec}s threshold)."
        )

    elif rule_id == "R3":
        # Process Started without preceding write
        proc = next((e for e in events if e.get("source") == "eventlog"), {})
        usb = next((e for e in events if e.get("source") == "usb"), {})
        drive = ctx.get("drive_letter", "removable drive")
        window_sec = ctx.get("window_seconds", 600)
        user_info = f" under user '{proc.get('user')}'" if proc.get("user") else ""
        usb_cite = f" [confirmed by USB arrival event:{_short_id(usb.get('event_id', ''))}]" if usb.get("event_id") else ""

        return (
            f"Process '{proc.get('entity', 'N/A')}' executed{user_info} from confirmed removable drive {drive} "
            f"at {proc.get('ts_utc', 'N/A')} [event:{_short_id(proc.get('event_id', ''))}]{usb_cite} "
            f"with no preceding file creation observed in the preceding {window_sec}s window. "
            f"This pattern indicates pre-existing binary execution or write activity outside monitored scope."
        )

    elif rule_id == "R4":
        # Bulk File Creation
        drive = ctx.get("drive_letter", "removable drive")
        host = ctx.get("host") or (events[0].get("host") if events else "UNKNOWN")
        file_count = ctx.get("file_count", len(events))
        window_sec = ctx.get("window_seconds", 60)
        span_sec = int(ctx.get("span_seconds", 0))
        event_ids_str = ", ".join(_short_id(e.get("event_id", "")) for e in events[:5])
        if len(events) > 5:
            event_ids_str += f", ... (+{len(events) - 5} more)"

        return (
            f"Burst of {file_count} files created on removable drive {drive} on host '{host}' "
            f"within a {span_sec}s span (configured burst window: {window_sec}s). "
            f"Supporting events include [{event_ids_str}]. "
            f"High-frequency file creation on removable media warrants review for potential bulk data staging or exfiltration."
        )

    elif rule_id == "R5":
        # Log Cleared near activity
        log_ev = next((e for e in events if e.get("action") == "LOG_CLEARED"), {})
        act_ev = next((e for e in events if e.get("action") != "LOG_CLEARED"), {})
        host = log_ev.get("host") or act_ev.get("host", "UNKNOWN")
        channel = log_ev.get("details", {}).get("channel", "Security/System")
        user = log_ev.get("user", "unspecified account")
        delta_sec = int(abs(ctx.get("delta_seconds", 0)))
        direction = "following" if ctx.get("delta_seconds", 0) >= 0 else "preceding"
        act_desc = f"{act_ev.get('action', 'activity')} on '{act_ev.get('entity', 'N/A')}'"

        return (
            f"{channel} log cleared on host '{host}' by user '{user}' at {log_ev.get('ts_utc', 'N/A')} "
            f"[event:{_short_id(log_ev.get('event_id', ''))}], occurring {delta_sec}s {direction} "
            f"observed activity ({act_desc} [event:{_short_id(act_ev.get('event_id', ''))}]). "
            f"While log clearing may occur during routine maintenance, temporal proximity to external media or execution "
            f"is a known indicator of anti-forensics and warrants review."
        )

    elif rule_id == "R6":
        # Timestamp Disagreement
        fs_ev = events[0] if events else {}
        discrepancy = int(abs(ctx.get("discrepancy_seconds", 0)))
        threshold = ctx.get("threshold_seconds", 120)
        mtime = ctx.get("mtime_utc", fs_ev.get("ts_utc", "N/A"))
        observed = ctx.get("ts_observed_utc", "N/A")

        return (
            f"Significant timestamp discrepancy detected on host '{fs_ev.get('host', 'UNKNOWN')}' "
            f"for file '{fs_ev.get('entity', 'N/A')}' [event:{_short_id(fs_ev.get('event_id', ''))}]: "
            f"filesystem modified time reported as {mtime}, but collector observed event at {observed} "
            f"(discrepancy of {discrepancy}s exceeds {threshold}s threshold). "
            f"Such discrepancies may indicate filesystem timestomping, archive extraction with preserved metadata, or clock drift."
        )

    elif rule_id == "R7":
        # Composite USB Copy & Run Chain
        usb = next((e for e in events if e.get("source") == "usb"), {})
        fs = next((e for e in events if e.get("source") == "fs"), {})
        proc = next((e for e in events if e.get("source") == "eventlog"), {})
        host = usb.get("host") or fs.get("host") or proc.get("host", "UNKNOWN")
        drive = ctx.get("drive_letter") or fs.get("details", {}).get("drive_letter", "E:")
        dev_name = usb.get("details", {}).get("device_name", "Removable Storage Device")
        total_sec = int(ctx.get("total_seconds", 0))
        t1_sec = int(ctx.get("usb_to_fs_seconds", 0))
        t2_sec = int(ctx.get("fs_to_proc_seconds", 0))
        user_info = f" under user '{proc.get('user')}'" if proc.get("user") else ""

        return (
            f"Composite USB copy-and-execution sequence reconstructed on host '{host}': "
            f"Removable device '{dev_name}' mounted on volume {drive} at {usb.get('ts_utc', 'N/A')} [event:{_short_id(usb.get('event_id', ''))}]. "
            f"Executable file '{fs.get('entity', 'N/A')}' was written to {drive} after {t1_sec}s at {fs.get('ts_utc', 'N/A')} [event:{_short_id(fs.get('event_id', ''))}]. "
            f"Process was subsequently executed from that exact path{user_info} after an additional {t2_sec}s at {proc.get('ts_utc', 'N/A')} [event:{_short_id(proc.get('event_id', ''))}]. "
            f"Entire chain concluded in {total_sec}s (within 900s threshold). "
            f"Observed telemetry provides complete end-to-end evidence linking device arrival, payload staging, and execution."
        )

    # Fallback
    return (
        f"Reconstructed activity under rule {rule_id} across {len(events)} event(s): "
        f"[{', '.join(_short_id(e.get('event_id', '')) for e in events)}]."
    )
