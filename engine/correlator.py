"""
engine/correlator.py - Core Correlation Engine for ForensiTrace.

Author: Akash (Correlation Engine & Rules Owner)
Technical Contracts: docs/schema.md, docs/rules.yaml, backend/schema.py, backend/db.py
Scope: Complete Task 3 Implementation (Rules R1-R7, Confidence Scoring, Evidence Provenance)
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from backend.schema import Activity, ActivityEventLink, Event
from engine.config import RuleDefinition, RulesConfig, load_rules_config
from engine.narratives import generate_narrative
from engine.scoring import compute_confidence

logger = logging.getLogger("forensitrace.engine.correlator")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def parse_iso_utc(ts_str: str) -> datetime:
    """
    Parses UTC ISO-8601 timestamp string (e.g. '2026-10-23T10:00:00.120Z') to datetime.
    Safely normalizes trailing 'Z' to '+00:00'.
    """
    if not ts_str or not isinstance(ts_str, str):
        raise ValueError(f"Invalid timestamp value: {ts_str}")
    cleaned = ts_str.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


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
    seed = f"{rule_id.upper()}|{host}|{'|'.join(sorted_ids)}"
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
    Evaluates rules R1 through R7 across normalized telemetry events within configured time windows.
    Generates deterministic confidence scores and evidence provenance links.
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
        Evaluates rules R1-R7 on the provided events and returns reconstructed activities.
        Handles out-of-order input by sorting events chronologically before evaluation.
        """
        logger.info("[correlate_events] [RECEIVED] Received %d events for correlation", len(events))
        if not events:
            return []

        # Convert to dicts and filter out any items with unparseable timestamps
        raw_list = []
        for e in events:
            d = self._event_dict(e)
            try:
                parse_iso_utc(d.get("ts_utc", ""))
                raw_list.append(d)
            except Exception as exc:
                logger.warning("[correlate_events] Skipping event with unparseable timestamp: %s", exc)

        sorted_events = sorted(raw_list, key=lambda x: parse_iso_utc(x["ts_utc"]))

        results: list[CorrelatedResult] = []

        # Evaluate rules R1 through R7
        if self._is_rule_enabled("R1"):
            results.extend(self._evaluate_r1(sorted_events))

        if self._is_rule_enabled("R2"):
            results.extend(self._evaluate_r2(sorted_events))

        if self._is_rule_enabled("R3"):
            results.extend(self._evaluate_r3(sorted_events))

        if self._is_rule_enabled("R4"):
            results.extend(self._evaluate_r4(sorted_events))

        if self._is_rule_enabled("R5"):
            results.extend(self._evaluate_r5(sorted_events))

        if self._is_rule_enabled("R6"):
            results.extend(self._evaluate_r6(sorted_events))

        if self._is_rule_enabled("R7"):
            results.extend(self._evaluate_r7(sorted_events))

        # Deduplicate results by activity_id to prevent any duplicate records
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

    def _is_rule_enabled(self, rule_id: str) -> bool:
        r = self.config.get_rule(rule_id)
        return bool(r and r.enabled)

    # --------------------------------------------------------------------------
    # Helper: Discover confirmed removable drives per host from telemetry
    # --------------------------------------------------------------------------
    def _discover_removable_drives(self, events: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
        """
        Discovers confirmed removable drives per host based strictly on observed telemetry:
        - Must have an actual DEVICE_ARRIVED event on that drive letter, or
        - Event details explicitly flag is_removable = True.
        """
        removables: dict[str, dict[str, dict[str, Any]]] = {}
        for ev in events:
            host = ev.get("host", "")
            if not host:
                continue

            if ev.get("source") == "usb" and ev.get("action") == "DEVICE_ARRIVED":
                drive = extract_drive_letter(ev.get("entity", ""), ev.get("details"))
                if drive:
                    removables.setdefault(host, {})[drive] = ev
            elif ev.get("details", {}).get("is_removable"):
                drive = extract_drive_letter(ev.get("entity", ""), ev.get("details"))
                if drive:
                    removables.setdefault(host, {})[drive] = ev

        return removables

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

        usb_arrivals = [
            e for e in events
            if e.get("source") == "usb" and e.get("action") == "DEVICE_ARRIVED"
        ]
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
                if fs.get("host", "") != host:
                    continue

                fs_drive = extract_drive_letter(fs.get("entity", ""), fs.get("details"))
                if not fs_drive or fs_drive != usb_drive:
                    continue

                fs_ts = parse_iso_utc(fs["ts_utc"])
                delta = (fs_ts - usb_ts).total_seconds()

                if 0.0 <= delta <= float(window_sec):
                    event_ids = [usb["event_id"], fs["event_id"]]
                    act_id = generate_activity_id("R1", host, event_ids)

                    ctx = {
                        "drive_letter": usb_drive,
                        "delta_seconds": delta,
                        "window_seconds": window_sec,
                    }
                    confidence, _ = compute_confidence("R1", [usb, fs], ctx)
                    narrative = generate_narrative("R1", [usb, fs], ctx)

                    activity = Activity(
                        activity_id=act_id,
                        rule_id="R1",
                        rule_name=rule.name,
                        ts_start_utc=usb["ts_utc"],
                        ts_end_utc=fs["ts_utc"],
                        confidence=confidence,
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

        fs_creations = [
            e for e in events
            if e.get("source") == "fs" and e.get("action") == "FILE_CREATED"
        ]
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

                if 0.0 <= delta <= float(window_sec):
                    event_ids = [fs["event_id"], proc["event_id"]]
                    act_id = generate_activity_id("R2", host, event_ids)

                    ctx = {
                        "delta_seconds": delta,
                        "window_seconds": window_sec,
                    }
                    confidence, _ = compute_confidence("R2", [fs, proc], ctx)
                    narrative = generate_narrative("R2", [fs, proc], ctx)

                    activity = Activity(
                        activity_id=act_id,
                        rule_id="R2",
                        rule_name=rule.name,
                        ts_start_utc=fs["ts_utc"],
                        ts_end_utc=proc["ts_utc"],
                        confidence=confidence,
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
        """
        rule = self.config.get_rule("R3")
        if not rule:
            return []

        window_sec = rule.window_seconds
        results: list[CorrelatedResult] = []

        removable_drives_by_host = self._discover_removable_drives(events)

        proc_starts = [
            e for e in events
            if e.get("source") == "eventlog" and e.get("action") == "PROCESS_STARTED"
        ]
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

            host_removables = removable_drives_by_host.get(host, {})
            is_confirmed_removable = (proc_drive in host_removables) or bool(
                proc.get("details", {}).get("is_removable", False)
            )

            if not is_confirmed_removable:
                continue

            proc_ts = parse_iso_utc(proc["ts_utc"])
            proc_path_norm = normalize_windows_path(proc_path)

            write_observed = False
            for w in write_events:
                if w.get("host", "") != host:
                    continue

                w_path_norm = normalize_windows_path(w.get("entity", ""))
                if w_path_norm != proc_path_norm:
                    continue

                w_ts = parse_iso_utc(w["ts_utc"])
                delta = (proc_ts - w_ts).total_seconds()
                if 0.0 <= delta <= float(window_sec):
                    write_observed = True
                    break

            if not write_observed:
                usb_context_ev = host_removables.get(proc_drive)
                supporting_ids = [proc["event_id"]]
                if usb_context_ev:
                    supporting_ids.append(usb_context_ev["event_id"])

                act_id = generate_activity_id("R3", host, supporting_ids)
                start_ts = usb_context_ev["ts_utc"] if usb_context_ev else proc["ts_utc"]

                ctx = {
                    "drive_letter": proc_drive,
                    "window_seconds": window_sec,
                }
                ev_list = [proc] + ([usb_context_ev] if usb_context_ev else [])
                confidence, _ = compute_confidence("R3", ev_list, ctx)
                narrative = generate_narrative("R3", ev_list, ctx)

                activity = Activity(
                    activity_id=act_id,
                    rule_id="R3",
                    rule_name=rule.name,
                    ts_start_utc=start_ts,
                    ts_end_utc=proc["ts_utc"],
                    confidence=confidence,
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
    # Rule R4: Bulk file creation on removable drive (Window: 60s, min_count: 5)
    # --------------------------------------------------------------------------
    def _evaluate_r4(self, events: list[dict[str, Any]]) -> list[CorrelatedResult]:
        """
        R4: Detects a rapid burst of file creation events on a confirmed removable drive
        within a sliding 60-second window (default threshold: min_count = 5 distinct files).
        """
        rule = self.config.get_rule("R4")
        if not rule:
            return []

        window_sec = rule.window_seconds
        min_count = rule.get_min_count(default=5)
        results: list[CorrelatedResult] = []

        removables = self._discover_removable_drives(events)

        # Filter candidate FS file creation events
        fs_creations = [
            e for e in events
            if e.get("source") == "fs" and e.get("action") == "FILE_CREATED"
        ]

        # Group by (host, drive)
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for ev in fs_creations:
            host = ev.get("host", "")
            drive = extract_drive_letter(ev.get("entity", ""), ev.get("details"))
            if not host or not drive:
                continue

            # Check if drive is confirmed removable on this host
            host_removables = removables.get(host, {})
            if (drive not in host_removables) and not ev.get("details", {}).get("is_removable"):
                continue

            grouped.setdefault((host, drive), []).append(ev)

        # Evaluate burst window for each (host, drive) group
        for (host, drive), ev_list in grouped.items():
            # Deduplicate events by event_id and normalized entity path
            seen_entities: set[str] = set()
            unique_evs: list[dict[str, Any]] = []
            for e in ev_list:
                key = (e.get("event_id"), normalize_windows_path(e.get("entity", "")))
                if key not in seen_entities:
                    seen_entities.add(key)
                    unique_evs.append(e)

            # Chronological sort
            unique_evs.sort(key=lambda x: parse_iso_utc(x["ts_utc"]))

            if len(unique_evs) < min_count:
                continue

            # Sliding window algorithm to identify maximal bursts
            n = len(unique_evs)
            i = 0
            while i < n:
                start_ev = unique_evs[i]
                start_ts = parse_iso_utc(start_ev["ts_utc"])

                # Expand window while delta <= window_sec
                j = i
                burst_group: list[dict[str, Any]] = []
                while j < n:
                    curr_ev = unique_evs[j]
                    curr_ts = parse_iso_utc(curr_ev["ts_utc"])
                    delta = (curr_ts - start_ts).total_seconds()
                    if 0.0 <= delta <= float(window_sec):
                        burst_group.append(curr_ev)
                        j += 1
                    else:
                        break

                if len(burst_group) >= min_count:
                    # Fire R4 for this burst!
                    first_ev = burst_group[0]
                    last_ev = burst_group[-1]
                    span_sec = (parse_iso_utc(last_ev["ts_utc"]) - parse_iso_utc(first_ev["ts_utc"])).total_seconds()

                    event_ids = [e["event_id"] for e in burst_group]
                    act_id = generate_activity_id("R4", host, event_ids)

                    ctx = {
                        "drive_letter": drive,
                        "host": host,
                        "file_count": len(burst_group),
                        "window_seconds": window_sec,
                        "span_seconds": span_sec,
                    }
                    confidence, _ = compute_confidence("R4", burst_group, ctx)
                    narrative = generate_narrative("R4", burst_group, ctx)

                    activity = Activity(
                        activity_id=act_id,
                        rule_id="R4",
                        rule_name=rule.name,
                        ts_start_utc=first_ev["ts_utc"],
                        ts_end_utc=last_ev["ts_utc"],
                        confidence=confidence,
                        narrative=narrative,
                    )

                    links = [
                        ActivityEventLink(
                            activity_id=act_id,
                            event_id=e["event_id"],
                            rule_id="R4",
                            reason=f"File created on removable drive {drive} during burst sequence",
                        )
                        for e in burst_group
                    ]

                    # Add USB arrival context link if present
                    usb_ev = removables.get(host, {}).get(drive)
                    if usb_ev:
                        links.append(
                            ActivityEventLink(
                                activity_id=act_id,
                                event_id=usb_ev["event_id"],
                                rule_id="R4",
                                reason=f"USB arrival evidence confirming {drive} is removable",
                            )
                        )

                    results.append(CorrelatedResult(activity=activity, links=links))
                    # Advance to next non-overlapping position
                    i = j
                else:
                    i += 1

        return results

    # --------------------------------------------------------------------------
    # Rule R5: Log clearing near other activity (Window: 10 min / 600s)
    # --------------------------------------------------------------------------
    def _evaluate_r5(self, events: list[dict[str, Any]]) -> list[CorrelatedResult]:
        """
        R5: Detects a LOG_CLEARED event occurring within 10 minutes (600s) of relevant
        telemetry activity (creation, execution, or insertion) on the same host.
        """
        rule = self.config.get_rule("R5")
        if not rule:
            return []

        window_sec = rule.window_seconds
        results: list[CorrelatedResult] = []

        log_cleared_events = [
            e for e in events
            if e.get("action") == "LOG_CLEARED"
        ]

        relevant_activity_events = [
            e for e in events
            if e.get("action") in (
                "PROCESS_STARTED", "FILE_CREATED", "FILE_MODIFIED",
                "FILE_DELETED", "FILE_MOVED", "DEVICE_ARRIVED"
            )
        ]

        for log_ev in log_cleared_events:
            host = log_ev.get("host", "")
            if not host:
                continue

            log_ts = parse_iso_utc(log_ev["ts_utc"])

            # Find matching relevant activity on the same host within window_sec
            for act_ev in relevant_activity_events:
                if act_ev.get("host", "") != host:
                    continue

                act_ts = parse_iso_utc(act_ev["ts_utc"])
                delta = (log_ts - act_ts).total_seconds()

                # Within 10 minutes either before or after: abs(delta) <= window_sec
                if abs(delta) <= float(window_sec):
                    start_ts = min(log_ts, act_ts).isoformat().replace("+00:00", "Z")
                    # Format to 3 ms digits if needed
                    ts_start_str = log_ev["ts_utc"] if log_ts <= act_ts else act_ev["ts_utc"]
                    ts_end_str = act_ev["ts_utc"] if log_ts <= act_ts else log_ev["ts_utc"]

                    event_ids = [log_ev["event_id"], act_ev["event_id"]]
                    act_id = generate_activity_id("R5", host, event_ids)

                    ctx = {
                        "delta_seconds": delta,
                        "window_seconds": window_sec,
                    }
                    confidence, _ = compute_confidence("R5", [log_ev, act_ev], ctx)
                    narrative = generate_narrative("R5", [log_ev, act_ev], ctx)

                    activity = Activity(
                        activity_id=act_id,
                        rule_id="R5",
                        rule_name=rule.name,
                        ts_start_utc=ts_start_str,
                        ts_end_utc=ts_end_str,
                        confidence=confidence,
                        narrative=narrative,
                    )

                    links = [
                        ActivityEventLink(
                            activity_id=act_id,
                            event_id=log_ev["event_id"],
                            rule_id="R5",
                            reason=f"Event log cleared ({log_ev.get('details', {}).get('channel', 'Log')})",
                        ),
                        ActivityEventLink(
                            activity_id=act_id,
                            event_id=act_ev["event_id"],
                            rule_id="R5",
                            reason=f"Observed telemetry activity ({act_ev.get('action')}) within {window_sec}s of log clearing",
                        ),
                    ]
                    results.append(CorrelatedResult(activity=activity, links=links))

        return results

    # --------------------------------------------------------------------------
    # Rule R6: Timestamp disagreement (Threshold: > 120s)
    # --------------------------------------------------------------------------
    def _evaluate_r6(self, events: list[dict[str, Any]]) -> list[CorrelatedResult]:
        """
        R6: Detects a significant discrepancy between a file's reported filesystem
        modified time and the collector observation time (details.ts_observed_utc).
        Strictly schema-preserving per docs/decisions.md D-001.
        Boundary convention: A discrepancy strictly greater than threshold_seconds (120s)
        triggers the rule (i.e. abs(delta) > 120.0).
        """
        rule = self.config.get_rule("R6")
        if not rule:
            return []

        threshold_sec = rule.get_threshold_seconds(default=120)
        results: list[CorrelatedResult] = []

        # Target file system events
        fs_events = [
            e for e in events
            if e.get("source") == "fs" and e.get("action") in ("FILE_CREATED", "FILE_MODIFIED")
        ]

        for ev in fs_events:
            host = ev.get("host", "")
            details = ev.get("details", {})

            # 1. Look for observation time in details (team consensus: details.ts_observed_utc)
            observed_str = details.get("ts_observed_utc") or details.get("ts_collected_utc")
            if not observed_str:
                # If observation timestamp was not collected, safely skip
                continue

            # 2. Look for reported file modified time (details.mtime_utc or event.ts_utc)
            mtime_str = details.get("mtime_utc") or details.get("file_modified_utc") or ev.get("ts_utc")
            if not mtime_str:
                continue

            try:
                t_obs = parse_iso_utc(observed_str)
                t_mtime = parse_iso_utc(mtime_str)
            except Exception as exc:
                # Malformed or unparseable timestamps handled safely without crashing
                logger.debug("[R6] Could not parse timestamps for event %s: %s", ev.get("event_id"), exc)
                continue

            delta = (t_mtime - t_obs).total_seconds()
            discrepancy = abs(delta)

            # Boundary rule: strictly greater than threshold (120s)
            if discrepancy > float(threshold_sec):
                event_ids = [ev["event_id"]]
                act_id = generate_activity_id("R6", host, event_ids)

                ctx = {
                    "discrepancy_seconds": discrepancy,
                    "threshold_seconds": threshold_sec,
                    "mtime_utc": mtime_str,
                    "ts_observed_utc": observed_str,
                }
                confidence, _ = compute_confidence("R6", [ev], ctx)
                narrative = generate_narrative("R6", [ev], ctx)

                start_ts = min(t_obs, t_mtime).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                end_ts = max(t_obs, t_mtime).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

                activity = Activity(
                    activity_id=act_id,
                    rule_id="R6",
                    rule_name=rule.name,
                    ts_start_utc=start_ts,
                    ts_end_utc=end_ts,
                    confidence=confidence,
                    narrative=narrative,
                )

                links = [
                    ActivityEventLink(
                        activity_id=act_id,
                        event_id=ev["event_id"],
                        rule_id="R6",
                        reason=(
                            f"File modified time ({mtime_str}) differs from collector observation time "
                            f"({observed_str}) by {int(discrepancy)}s (exceeds {threshold_sec}s threshold)"
                        ),
                    )
                ]
                results.append(CorrelatedResult(activity=activity, links=links))

        return results

    # --------------------------------------------------------------------------
    # Rule R7: Composite USB copy-and-execution correlation (Window: 15 min / 900s)
    # --------------------------------------------------------------------------
    def _evaluate_r7(self, events: list[dict[str, Any]]) -> list[CorrelatedResult]:
        """
        R7: Reconstructs a single composite activity representing the complete attack chain:
        USB arrival -> file copied or created on the USB drive -> process executed from that file.

        Requirements:
        - Correlates events on the same host (usb.host == fs.host == proc.host).
        - Verifies that the device is removable using actual device-arrival evidence.
        - Matches copied executable path to executed process path with Windows normalization.
        - Enforces 15-minute maximum chain window (900 seconds) from USB arrival to execution.
        - Rejects incomplete chains, path mismatches, wrong-host events, and expired chains.
        - Preserves event IDs and evidence links for all 3 stages.
        - Produces one composite activity per chain without duplicate or confusing representations.
        """
        rule = self.config.get_rule("R7")
        if not rule:
            return []

        window_sec = rule.window_seconds  # 900 seconds
        results: list[CorrelatedResult] = []

        removable_drives_by_host = self._discover_removable_drives(events)

        usb_arrivals = [
            e for e in events
            if e.get("source") == "usb" and e.get("action") == "DEVICE_ARRIVED"
        ]
        fs_writes = [
            e for e in events
            if e.get("source") == "fs" and e.get("action") in ("FILE_CREATED", "FILE_MODIFIED")
        ]
        proc_starts = [
            e for e in events
            if e.get("source") == "eventlog" and e.get("action") == "PROCESS_STARTED"
        ]

        # Evaluate complete chains
        for usb in usb_arrivals:
            host = usb.get("host", "")
            if not host:
                continue

            usb_drive = extract_drive_letter(usb.get("entity", ""), usb.get("details"))
            if not usb_drive:
                continue

            # Removable verification: must match host's confirmed removable drives
            host_removables = removable_drives_by_host.get(host, {})
            if usb_drive not in host_removables:
                continue

            usb_ts = parse_iso_utc(usb["ts_utc"])

            for fs in fs_writes:
                # Must be same host
                if fs.get("host", "") != host:
                    continue

                # Must be on the exact same removable drive
                fs_drive = extract_drive_letter(fs.get("entity", ""), fs.get("details"))
                if not fs_drive or fs_drive != usb_drive:
                    continue

                fs_ts = parse_iso_utc(fs["ts_utc"])
                delta_usb_fs = (fs_ts - usb_ts).total_seconds()

                # USB arrival must precede or be equal to file creation
                if delta_usb_fs < 0.0:
                    continue

                fs_path_norm = normalize_windows_path(fs.get("entity", ""))
                if not fs_path_norm:
                    continue

                for proc in proc_starts:
                    # Must be same host
                    if proc.get("host", "") != host:
                        continue

                    # Path matching: normalized executable path must match normalized created file path
                    proc_path_norm = normalize_windows_path(proc.get("entity", ""))
                    if not proc_path_norm or proc_path_norm != fs_path_norm:
                        continue

                    proc_ts = parse_iso_utc(proc["ts_utc"])
                    delta_fs_proc = (proc_ts - fs_ts).total_seconds()

                    # File creation must precede or be equal to process execution
                    if delta_fs_proc < 0.0:
                        continue

                    # Total chain window: from USB arrival to process start
                    total_chain_sec = (proc_ts - usb_ts).total_seconds()

                    # Enforce inclusive 15-minute maximum window (0 <= total <= 900)
                    if 0.0 <= total_chain_sec <= float(window_sec):
                        event_ids = [usb["event_id"], fs["event_id"], proc["event_id"]]
                        act_id = generate_activity_id("R7", host, event_ids)

                        ctx = {
                            "drive_letter": usb_drive,
                            "usb_to_fs_seconds": delta_usb_fs,
                            "fs_to_proc_seconds": delta_fs_proc,
                            "total_seconds": total_chain_sec,
                            "window_seconds": window_sec,
                            "elapsed_seconds": total_chain_sec,
                        }
                        confidence, _ = compute_confidence("R7", [usb, fs, proc], ctx)
                        narrative = generate_narrative("R7", [usb, fs, proc], ctx)

                        activity = Activity(
                            activity_id=act_id,
                            rule_id="R7",
                            rule_name=rule.name,
                            ts_start_utc=usb["ts_utc"],
                            ts_end_utc=proc["ts_utc"],
                            confidence=confidence,
                            narrative=narrative,
                        )

                        links = [
                            ActivityEventLink(
                                activity_id=act_id,
                                event_id=usb["event_id"],
                                rule_id="R7",
                                reason=f"Stage 1: Removable USB storage arrival mounted on {usb_drive}",
                            ),
                            ActivityEventLink(
                                activity_id=act_id,
                                event_id=fs["event_id"],
                                rule_id="R7",
                                reason=f"Stage 2: Executable payload written to removable volume ({fs.get('action')})",
                            ),
                            ActivityEventLink(
                                activity_id=act_id,
                                event_id=proc["event_id"],
                                rule_id="R7",
                                reason=f"Stage 3: Process executed from payload path within {window_sec}s chain window",
                            ),
                        ]
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
