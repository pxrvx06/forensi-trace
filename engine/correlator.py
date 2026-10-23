"""
engine/correlator.py - Core Correlation Engine for ForensiTrace.

Author: Akash (Correlation Engine & Rules Owner)
Technical Contracts: docs/schema.md, docs/rules.yaml, backend/schema.py, backend/db.py
Scope: Task 2 - Rules R1, R2, R3
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from backend.schema import Activity, ActivityEventLink, Event
from engine.config import RulesConfig, load_rules_config

logger = logging.getLogger("forensitrace.engine.correlator")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def parse_iso_utc(ts_str: str) -> datetime:
    """Parses UTC ISO-8601 timestamp string (e.g. '2026-10-23T10:00:00.120Z') to datetime."""
    cleaned = ts_str.replace("Z", "+00:00")
    return datetime.fromisoformat(cleaned)


def normalize_windows_path(path: str) -> str:
    """
    Normalizes Windows paths for reliable forensic equality comparison:
    - Standardizes forward slashes to backslashes
    - Case-folds path to lowercase (Windows NTFS is case-preserving but case-insensitive)
    - Strips redundant separators and enclosing quotes
    """
    if not path:
        return ""
    p = path.strip().strip('"').strip("'")
    p = p.replace("/", "\\")
    return os.path.normpath(p).lower()


def extract_drive_letter(entity_or_path: str, details: Optional[dict[str, Any]] = None) -> Optional[str]:
    """
    Extracts uppercase drive letter (e.g. 'E:') from entity string, file path, or details dict.
    """
    if details and "drive_letter" in details and details["drive_letter"]:
        d = str(details["drive_letter"]).strip().upper()
        if len(d) == 1:
            return f"{d}:"
        if len(d) >= 2 and d[1] == ":":
            return d[:2]

    if entity_or_path:
        match = re.search(r"\b([a-zA-Z]):", entity_or_path)
        if match:
            return f"{match.group(1).upper()}:"

    return None


def generate_activity_id(rule_id: str, host: str, supporting_event_ids: list[str]) -> str:
    """
    Generates a deterministic activity ID to guarantee idempotency and avoid duplicates:
    activity_id = act_{rule_id.lower()}_{hash[:12]}
    """
    sorted_ids = sorted(supporting_event_ids)
    seed = f"{rule_id}|{host}|{'|'.join(sorted_ids)}"
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    return f"act_{rule_id.lower()}_{h}"


@dataclass
class CorrelatedResult:
    """Represents a reconstructed activity along with its provenance links."""
    activity: Activity
    links: list[ActivityEventLink]


class CorrelationEngine:
    """
    ForensiTrace Correlation Engine (Akash).
    Evaluates rules R1, R2, and R3 across normalized telemetry events within configured time windows.
    """

    def __init__(self, rules_config: Optional[RulesConfig] = None, rules_path: Optional[Path | str] = None):
        self.config = rules_config or load_rules_config(rules_path)
        logger.info(
            "[CorrelationEngine] [PRODUCED] Engine initialized with rules: %s",
            list(self.config.rules.keys()),
        )

    def _event_dict(self, event: Union[Event, dict[str, Any]]) -> dict[str, Any]:
        """Converts Event or dictionary to standard dictionary."""
        if isinstance(event, Event):
            return event.model_dump()
        return dict(event)

    def correlate_events(
        self,
        events: list[Union[Event, dict[str, Any]]],
    ) -> list[CorrelatedResult]:
        """
        In-memory correlation entrypoint.
        Evaluates R1, R2, and R3 on the provided events and returns reconstructed activities.
        Handles out-of-order input by sorting events chronologically before evaluation.
        """
        logger.info("[correlate_events] [RECEIVED] Received %d events for correlation", len(events))
        if not events:
            return []

        # Convert to dicts and sort chronologically by ts_utc
        raw_list = [self._event_dict(e) for e in events]
        sorted_events = sorted(raw_list, key=lambda x: parse_iso_utc(x["ts_utc"]))

        results: list[CorrelatedResult] = []

        # Evaluate rules R1, R2, R3
        if self.config.get_rule("R1") and self.config.get_rule("R1").enabled:
            results.extend(self._evaluate_r1(sorted_events))

        if self.config.get_rule("R2") and self.config.get_rule("R2").enabled:
            results.extend(self._evaluate_r2(sorted_events))

        if self.config.get_rule("R3") and self.config.get_rule("R3").enabled:
            results.extend(self._evaluate_r3(sorted_events))

        # Deduplicate results by activity_id
        unique_results: dict[str, CorrelatedResult] = {}
        for r in results:
            if r.activity.activity_id not in unique_results:
                unique_results[r.activity.activity_id] = r

        deduped = list(unique_results.values())
        logger.info(
            "[correlate_events] [PRODUCED] Reconstructed %d activity chain(s) from %d events",
            len(deduped),
            len(events),
        )
        return deduped

    # --------------------------------------------------------------------------
    # Rule R1: Device arrival followed by file activity (Window: 5 min / 300s)
    # --------------------------------------------------------------------------
    def _evaluate_r1(self, events: list[dict[str, Any]]) -> list[CorrelatedResult]:
        """
        R1: A removable device arrives, then a file is created or modified on that
        same drive within 5 minutes (default: 300 seconds).
        """
        rule = self.config.get_rule("R1")
        if not rule:
            return []

        window_sec = rule.window_seconds
        results: list[CorrelatedResult] = []

        # Find candidate USB arrival triggers
        usb_arrivals = [
            e for e in events
            if e.get("source") == "usb" and e.get("action") == "DEVICE_ARRIVED"
        ]

        # Find file creation / modification targets
        fs_events = [
            e for e in events
            if e.get("source") == "fs" and e.get("action") in ("FILE_CREATED", "FILE_MODIFIED")
        ]

        for usb in usb_arrivals:
            usb_drive = extract_drive_letter(usb.get("entity", ""), usb.get("details"))
            if not usb_drive:
                continue

            usb_ts = parse_iso_utc(usb["ts_utc"])
            host = usb.get("host", "")

            for fs in fs_events:
                # Must match host
                if fs.get("host", "") != host:
                    continue

                fs_drive = extract_drive_letter(fs.get("entity", ""), fs.get("details"))
                if not fs_drive or fs_drive != usb_drive:
                    continue

                fs_ts = parse_iso_utc(fs["ts_utc"])
                delta = (fs_ts - usb_ts).total_seconds()

                # Boundary rule: 0 <= delta <= window_sec (inclusive)
                if 0.0 <= delta <= float(window_sec):
                    event_ids = [usb["event_id"], fs["event_id"]]
                    act_id = generate_activity_id("R1", host, event_ids)
                    action_name = fs.get("action", "").lower().replace("_", " ")

                    narrative = (
                        f"Removable device arrived on {usb_drive} ({usb.get('details', {}).get('device_name', 'USB Device')}) "
                        f"at {usb['ts_utc']}, followed by file {action_name} for '{fs.get('entity')}' "
                        f"after {int(delta)}s (within {window_sec}s threshold)."
                    )

                    activity = Activity(
                        activity_id=act_id,
                        rule_id="R1",
                        rule_name=rule.name,
                        ts_start_utc=usb["ts_utc"],
                        ts_end_utc=fs["ts_utc"],
                        confidence=1.0,
                        narrative=narrative,
                    )

                    links = [
                        ActivityEventLink(
                            activity_id=act_id,
                            event_id=usb["event_id"],
                            rule_id="R1",
                            reason=f"USB removable drive arrival on volume {usb_drive}",
                        ),
                        ActivityEventLink(
                            activity_id=act_id,
                            event_id=fs["event_id"],
                            rule_id="R1",
                            reason=f"File activity on {usb_drive} within {window_sec}s of USB arrival",
                        ),
                    ]
                    results.append(CorrelatedResult(activity=activity, links=links))

        return results

    # --------------------------------------------------------------------------
    # Rule R2: File creation followed by process execution (Window: 10 min / 600s)
    # --------------------------------------------------------------------------
    def _evaluate_r2(self, events: list[dict[str, Any]]) -> list[CorrelatedResult]:
        """
        R2: A file is created, then a process starts from that same file path
        within 10 minutes (default: 600 seconds).
        """
        rule = self.config.get_rule("R2")
        if not rule:
            return []

        window_sec = rule.window_seconds
        results: list[CorrelatedResult] = []

        # Find candidate file creation triggers
        fs_creations = [
            e for e in events
            if e.get("source") == "fs" and e.get("action") == "FILE_CREATED"
        ]

        # Find candidate process execution targets
        proc_starts = [
            e for e in events
            if e.get("source") == "eventlog" and e.get("action") == "PROCESS_STARTED"
        ]

        for fs in fs_creations:
            fs_path_norm = normalize_windows_path(fs.get("entity", ""))
            if not fs_path_norm:
                continue

            fs_ts = parse_iso_utc(fs["ts_utc"])
            host = fs.get("host", "")

            for proc in proc_starts:
                if proc.get("host", "") != host:
                    continue

                proc_path_norm = normalize_windows_path(proc.get("entity", ""))
                if not proc_path_norm or proc_path_norm != fs_path_norm:
                    continue

                proc_ts = parse_iso_utc(proc["ts_utc"])
                delta = (proc_ts - fs_ts).total_seconds()

                # Boundary rule: 0 <= delta <= window_sec (inclusive)
                if 0.0 <= delta <= float(window_sec):
                    event_ids = [fs["event_id"], proc["event_id"]]
                    act_id = generate_activity_id("R2", host, event_ids)

                    narrative = (
                        f"File '{fs.get('entity')}' was created at {fs['ts_utc']}, then executed as process "
                        f"at {proc['ts_utc']} after {int(delta)}s (within {window_sec}s threshold)."
                    )

                    activity = Activity(
                        activity_id=act_id,
                        rule_id="R2",
                        rule_name=rule.name,
                        ts_start_utc=fs["ts_utc"],
                        ts_end_utc=proc["ts_utc"],
                        confidence=1.0,
                        narrative=narrative,
                    )

                    links = [
                        ActivityEventLink(
                            activity_id=act_id,
                            event_id=fs["event_id"],
                            rule_id="R2",
                            reason="File created on disk",
                        ),
                        ActivityEventLink(
                            activity_id=act_id,
                            event_id=proc["event_id"],
                            rule_id="R2",
                            reason=f"Process executed from created path within {window_sec}s",
                        ),
                    ]
                    results.append(CorrelatedResult(activity=activity, links=links))

        return results

    # --------------------------------------------------------------------------
    # Rule R3: Process starts from a removable drive without earlier write seen
    # (Window: 10 min / 600s preceding the process start)
    # --------------------------------------------------------------------------
    def _evaluate_r3(self, events: list[dict[str, Any]]) -> list[CorrelatedResult]:
        """
        R3: A process starts from a confirmed removable drive, with no earlier write
        event observed within the preceding 10-minute window (default: 600 seconds).

        Removability determination:
        - A drive is established as removable only if telemetry contains a confirmed
          DEVICE_ARRIVED event for that drive letter, or details explicitly flag is_removable.
        - Arbitrary drive letters (like C: or unobserved letters) are NOT assumed removable.
        - The result represents an *absence of observed telemetry write evidence*,
          not definitive proof that a write never occurred.
        """
        rule = self.config.get_rule("R3")
        if not rule:
            return []

        window_sec = rule.window_seconds
        results: list[CorrelatedResult] = []

        # Step 1: Discover confirmed removable drives per host from telemetry
        removable_drives_by_host: dict[str, dict[str, dict[str, Any]]] = {}
        for ev in events:
            if ev.get("source") == "usb" and ev.get("action") == "DEVICE_ARRIVED":
                host = ev.get("host", "")
                drive = extract_drive_letter(ev.get("entity", ""), ev.get("details"))
                if drive:
                    if host not in removable_drives_by_host:
                        removable_drives_by_host[host] = {}
                    removable_drives_by_host[host][drive] = ev

        # Step 2: Identify candidate process start events
        proc_starts = [
            e for e in events
            if e.get("source") == "eventlog" and e.get("action") == "PROCESS_STARTED"
        ]

        # Step 3: Identify all file write events (creation / modification)
        write_events = [
            e for e in events
            if e.get("source") == "fs" and e.get("action") in ("FILE_CREATED", "FILE_MODIFIED")
        ]

        for proc in proc_starts:
            host = proc.get("host", "")
            proc_path = proc.get("entity", "")
            proc_drive = extract_drive_letter(proc_path, proc.get("details"))

            if not proc_drive:
                continue

            # Check if drive is confirmed removable
            host_removables = removable_drives_by_host.get(host, {})
            is_confirmed_removable = (proc_drive in host_removables) or bool(
                proc.get("details", {}).get("is_removable", False)
            )

            # If removability cannot be established from evidence, skip (do not guess)
            if not is_confirmed_removable:
                logger.debug(
                    "[R3] Drive %s for process '%s' is not confirmed removable. Skipping.",
                    proc_drive, proc_path
                )
                continue

            proc_ts = parse_iso_utc(proc["ts_utc"])
            proc_path_norm = normalize_windows_path(proc_path)

            # Search preceding window [proc_ts - window_sec, proc_ts] for matching write
            write_observed = False
            for w in write_events:
                if w.get("host", "") != host:
                    continue

                w_path_norm = normalize_windows_path(w.get("entity", ""))
                if w_path_norm != proc_path_norm:
                    continue

                w_ts = parse_iso_utc(w["ts_utc"])
                # Elapsed time between write and process
                delta = (proc_ts - w_ts).total_seconds()
                # If write occurred within the preceding window: 0 <= delta <= window_sec
                if 0.0 <= delta <= float(window_sec):
                    write_observed = True
                    break

            # If NO write was observed in the preceding window: R3 fires!
            if not write_observed:
                usb_context_ev = host_removables.get(proc_drive)
                supporting_ids = [proc["event_id"]]
                if usb_context_ev:
                    supporting_ids.append(usb_context_ev["event_id"])

                act_id = generate_activity_id("R3", host, supporting_ids)
                start_ts = usb_context_ev["ts_utc"] if usb_context_ev else proc["ts_utc"]

                narrative = (
                    f"Process '{proc_path}' started from removable drive {proc_drive} at {proc['ts_utc']} "
                    f"with no preceding file write event observed within the preceding {window_sec}s window. "
                    f"(Indicates pre-existing binary or unmonitored write activity)."
                )

                activity = Activity(
                    activity_id=act_id,
                    rule_id="R3",
                    rule_name=rule.name,
                    ts_start_utc=start_ts,
                    ts_end_utc=proc["ts_utc"],
                    confidence=0.85,
                    narrative=narrative,
                )

                links = [
                    ActivityEventLink(
                        activity_id=act_id,
                        event_id=proc["event_id"],
                        rule_id="R3",
                        reason="Process executed from removable volume without observed preceding write in window",
                    )
                ]
                if usb_context_ev:
                    links.append(
                        ActivityEventLink(
                            activity_id=act_id,
                            event_id=usb_context_ev["event_id"],
                            rule_id="R3",
                            reason=f"USB arrival evidence confirming {proc_drive} is a removable volume",
                        )
                    )

                results.append(CorrelatedResult(activity=activity, links=links))

        return results

    # --------------------------------------------------------------------------
    # Database Integration (Purva's SQLite backend/db.py handoff)
    # --------------------------------------------------------------------------
    def correlate_from_db(
        self,
        ts_start_utc: str,
        ts_end_utc: str,
        db_path: Optional[Union[str, Path]] = None,
        persist: bool = True,
    ) -> list[str]:
        """
        Queries events in [ts_start_utc, ts_end_utc] using backend.db.get_events_in_window(),
        correlates them, and optionally persists the reconstructed activities and
        evidence provenance links using backend.db.insert_activity().
        Returns list of generated activity IDs.
        """
        logger.info(
            "[correlate_from_db] [RECEIVED] Correlating events from DB window '%s' to '%s'",
            ts_start_utc, ts_end_utc
        )
        try:
            from backend.db import get_events_in_window, insert_activity
        except ImportError as exc:
            logger.error("[correlate_from_db] Could not import backend.db functions: %s", exc)
            raise

        events = get_events_in_window(ts_start_utc, ts_end_utc, db_path=db_path)
        correlated = self.correlate_events(events)

        persisted_ids: list[str] = []
        for item in correlated:
            if persist:
                insert_activity(item.activity, item.links, db_path=db_path)
            persisted_ids.append(item.activity.activity_id)

        logger.info(
            "[correlate_from_db] [PRODUCED] Stored/returned %d activity chain(s)",
            len(persisted_ids)
        )
        return persisted_ids
