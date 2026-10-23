"""
ForensiTrace Windows Event Log Collector
Author: Daksh (Agent Core & Event Log Collector Owner)
Contract: docs/schema.md, docs/agent_interface.md & scripts/setup_windows.md

Monitors and normalizes:
  - Security Event ID 4688: Process Created -> PROCESS_STARTED
  - Security Event ID 1102: Security Audit Log Cleared -> LOG_CLEARED
  - System Event ID 104:    System Log Cleared -> LOG_CLEARED

The parsing and mapping layer (parse_eventlog_xml) is strictly isolated from pywin32
so that unit tests with fake records can run on any OS without Windows admin rights.
"""

from __future__ import annotations

import re
import sys
import time
import queue
import logging
import threading
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from agent.config import AgentConfig
from agent.collectors.base import BaseCollector
from backend.schema import (
    Event,
    SourceEnum,
    ActionEnum,
    EntityTypeEnum,
    compute_event_id,
    TIMESTAMP_REGEX,
)

logger = logging.getLogger("forensitrace.agent.collector.eventlog")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Canonical Windows Event Log paths for LOG_CLEARED evidence
LOG_CHANNEL_PATHS = {
    "Security": r"C:\Windows\System32\winevt\Logs\Security.evtx",
    "System": r"C:\Windows\System32\winevt\Logs\System.evtx",
}


def normalize_eventlog_timestamp(system_time_str: str) -> str:
    """
    Normalizes Windows Event Log ISO timestamps (e.g. '2026-10-23T10:02:30.8000000Z')
    to strictly UTC ISO 8601 with millisecond precision ('YYYY-MM-DDTHH:MM:SS.mmmZ')
    per docs/schema.md contract.
    """
    if not system_time_str:
        now_utc = datetime.now(timezone.utc)
        return now_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now_utc.microsecond // 1000:03d}Z"

    # Truncate fractional seconds exceeding 6 digits for standard library compatibility
    cleaned = re.sub(r"(\.\d{6})\d+", r"\1", system_time_str)
    cleaned = cleaned.replace("Z", "+00:00")

    dt = datetime.fromisoformat(cleaned)
    dt_utc = dt.astimezone(timezone.utc)
    formatted = dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt_utc.microsecond // 1000:03d}Z"
    return formatted


def parse_eventlog_xml(
    xml_content: str,
    default_host: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Pure Python parser converting raw Windows Event Log XML into a normalized ForensiTrace event.
    
    Zero pywin32 dependencies: can be unit-tested with synthetic XML fixtures on any operating system.
    
    Returns:
      Normalized event dictionary strictly adhering to docs/schema.md, or None if the record
      is not a target Event ID (must not fire) or is malformed.
    """
    if not xml_content or not xml_content.strip():
        logger.debug("[parse_eventlog_xml] Received empty XML content; skipping.")
        return None

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as exc:
        logger.warning("[parse_eventlog_xml] Malformed XML could not be parsed: %s", exc)
        return None

    # Handle XML namespace if present
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    # Extract System header elements
    system_elem = root.find(f"{ns}System")
    if system_elem is None:
        logger.debug("[parse_eventlog_xml] Missing <System> element in XML; skipping.")
        return None

    event_id_elem = system_elem.find(f"{ns}EventID")
    if event_id_elem is None or not event_id_elem.text:
        return None

    try:
        event_code = int(event_id_elem.text.strip())
    except ValueError:
        return None

    # Target filter: must be one of [4688, 1102, 104]
    if event_code not in (4688, 1102, 104):
        # Must not fire on unmonitored event codes
        return None

    # Extract System header properties
    record_id_elem = system_elem.find(f"{ns}EventRecordID")
    record_id = int(record_id_elem.text.strip()) if (record_id_elem is not None and record_id_elem.text) else 0

    channel_elem = system_elem.find(f"{ns}Channel")
    channel = channel_elem.text.strip() if (channel_elem is not None and channel_elem.text) else "Security"

    computer_elem = system_elem.find(f"{ns}Computer")
    host = computer_elem.text.strip() if (computer_elem is not None and computer_elem.text) else (default_host or "UNKNOWN-HOST")

    time_created_elem = system_elem.find(f"{ns}TimeCreated")
    raw_time_str = time_created_elem.attrib.get("SystemTime", "") if time_created_elem is not None else ""
    ts_utc = normalize_eventlog_timestamp(raw_time_str)

    # Extract EventData / UserData key-values
    event_data: Dict[str, str] = {}
    event_data_elem = root.find(f"{ns}EventData")
    if event_data_elem is not None:
        for child in event_data_elem:
            name = child.attrib.get("Name")
            text = child.text or ""
            if name:
                event_data[name] = text
            elif child.text and child.text.strip():
                clean_tag = child.tag.split("}")[-1]
                event_data[clean_tag] = child.text.strip()

    # Also check UserData container (used in some System events like 104)
    user_data_elem = root.find(f"{ns}UserData")
    if user_data_elem is not None:
        for item in user_data_elem.iter():
            clean_tag = item.tag.split("}")[-1]
            if clean_tag not in ("UserData", "LogFileCleared") and item.text and item.text.strip():
                event_data[clean_tag] = item.text.strip()

    # Formulate raw_record_id: "{Channel}:{RecordID}"
    raw_record_id = f"{channel}:{record_id}"
    event_id = compute_event_id(SourceEnum.eventlog, raw_record_id, ts_utc)

    # -----------------------------------------------------------------------
    # Case 1: Security 4688 (PROCESS_STARTED)
    # -----------------------------------------------------------------------
    if event_code == 4688:
        new_process_name = event_data.get("NewProcessName", "").strip()
        if not new_process_name:
            logger.warning("[parse_eventlog_xml] Event 4688 missing 'NewProcessName'; rejecting record.")
            return None

        # Canonicalize Windows path backslashes and drive letter
        new_process_name = new_process_name.replace("/", "\\")
        if len(new_process_name) >= 2 and new_process_name[1] == ":":
            new_process_name = new_process_name[0].upper() + new_process_name[1:]

        # Derive user account
        user_name = event_data.get("SubjectUserName", "")
        domain_name = event_data.get("SubjectDomainName", "")
        user: Optional[str] = None
        if user_name and user_name != "-":
            user = f"{domain_name}\\{user_name}" if domain_name and domain_name != "-" else user_name

        details = {
            "raw_record_id": raw_record_id,
            "event_record_id": record_id,
            "channel": channel,
            "event_code": 4688,
            "process_id": event_data.get("NewProcessId", ""),
            "process_name": new_process_name,
            "parent_process_id": event_data.get("ProcessId", ""),
            "parent_process_name": event_data.get("ParentProcessName", "").replace("/", "\\"),
            "command_line": event_data.get("CommandLine", ""),
            "subject_user_sid": event_data.get("SubjectUserSid", ""),
            "subject_logon_id": event_data.get("TargetLogonId", event_data.get("SubjectLogonId", "")),
            "mandatory_label": event_data.get("MandatoryLabel", ""),
        }

        event_dict = {
            "event_id": event_id,
            "source": SourceEnum.eventlog.value,
            "ts_utc": ts_utc,
            "host": host,
            "user": user,
            "action": ActionEnum.PROCESS_STARTED.value,
            "entity_type": EntityTypeEnum.process.value,
            "entity": new_process_name,
            "details": details,
            "raw": xml_content,
        }

    # -----------------------------------------------------------------------
    # Case 2: Security 1102 / System 104 (LOG_CLEARED)
    # -----------------------------------------------------------------------
    elif event_code in (1102, 104):
        target_entity = LOG_CHANNEL_PATHS.get(channel, f"C:\\Windows\\System32\\winevt\\Logs\\{channel}.evtx")

        user_name = event_data.get("SubjectUserName", "")
        domain_name = event_data.get("SubjectDomainName", "")
        user = None
        if user_name and user_name != "-":
            user = f"{domain_name}\\{user_name}" if domain_name and domain_name != "-" else user_name

        details = {
            "raw_record_id": raw_record_id,
            "event_record_id": record_id,
            "channel": channel,
            "event_code": event_code,
            "subject_user_sid": event_data.get("SubjectUserSid", ""),
            "subject_logon_id": event_data.get("SubjectLogonId", ""),
            "backup_path": event_data.get("BackupPath", ""),
        }

        event_dict = {
            "event_id": event_id,
            "source": SourceEnum.eventlog.value,
            "ts_utc": ts_utc,
            "host": host,
            "user": user,
            "action": ActionEnum.LOG_CLEARED.value,
            "entity_type": EntityTypeEnum.file.value,
            "entity": target_entity,
            "details": details,
            "raw": xml_content,
        }

    else:
        return None

    # Validate against frozen Pydantic schema before returning
    try:
        validated = Event.model_validate(event_dict)
        logger.debug(
            "[parse_eventlog_xml] [PRODUCED] Validated Event: action='%s', entity='%s', id='%s'",
            validated.action.value,
            validated.entity,
            validated.event_id,
        )
        return validated.model_dump(mode="json")
    except Exception as exc:
        logger.warning("[parse_eventlog_xml] Schema validation error on parsed event: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Live Collector
# ---------------------------------------------------------------------------
class EventLogCollector(BaseCollector):
    """
    Live Windows Event Log Telemetry Collector.
    Uses pywin32 (win32evtlog) to monitor Security and System channels for:
      - 4688: PROCESS_STARTED
      - 1102: LOG_CLEARED (Security)
      - 104:  LOG_CLEARED (System)
    """

    def __init__(self, event_queue: queue.Queue[Dict[str, Any]], config: Optional[AgentConfig] = None) -> None:
        super().__init__(event_queue, config, name="EventLogCollector")
        self.poll_interval: float = 1.0
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._watermarks: Dict[str, int] = {"Security": 0, "System": 0}

        # Safe dynamic import of pywin32
        self._win32evtlog: Any = None
        self._pywintypes: Any = None
        self._has_win32 = False

        try:
            import win32evtlog
            import pywintypes
            self._win32evtlog = win32evtlog
            self._pywintypes = pywintypes
            self._has_win32 = True
            logger.info("[%s] [PRODUCED] pywin32 available for live Windows Event Log monitoring", self.name)
        except ImportError:
            logger.warning(
                "[%s] pywin32 not available or not on Windows. Live eventlog subscription disabled.",
                self.name,
            )

    def start(self) -> None:
        """Starts the background eventlog monitoring worker thread."""
        if not self._has_win32 or sys.platform != "win32":
            logger.warning(
                "[%s] Collector cannot start live capture without pywin32 on Windows. "
                "(Parsing layer remains fully operational for test fixtures).",
                self.name,
            )
            return

        if self._worker_thread and self._worker_thread.is_alive():
            return

        self._stop_event.clear()
        self._init_watermarks()
        self._worker_thread = threading.Thread(target=self._read_loop, name="EventLogCollectorWorker", daemon=True)
        self._worker_thread.start()
        self._running = True
        logger.info("[%s] [PRODUCED] Live Event Log reader thread started", self.name)

    def stop(self) -> None:
        """Stops the live eventlog reader thread."""
        self._running = False
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=3.0)
        logger.info("[%s] [PRODUCED] Live Event Log reader thread stopped", self.name)

    def _init_watermarks(self) -> None:
        """Queries the newest existing record in each channel to avoid ingesting historical logs."""
        for channel in ("Security", "System"):
            try:
                flags = self._win32evtlog.EvtQueryChannelPath | self._win32evtlog.EvtQueryReverseDirection
                h_query = self._win32evtlog.EvtQuery(channel, flags, "*")
                events = self._win32evtlog.EvtNext(h_query, 1)
                if events:
                    xml_str = self._win32evtlog.EvtRender(events[0], self._win32evtlog.EvtRenderEventXml)
                    root = ET.fromstring(xml_str)
                    ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
                    rec_elem = root.find(f"{ns}System/{ns}EventRecordID")
                    if rec_elem is not None and rec_elem.text:
                        self._watermarks[channel] = int(rec_elem.text.strip())
                        logger.info(
                            "[%s] Set initial watermark for '%s' to RecordID %d",
                            self.name,
                            channel,
                            self._watermarks[channel],
                        )
            except Exception as exc:
                if hasattr(exc, "winerror") and exc.winerror == 5:
                    logger.error(
                        "[%s] [ACCESS DENIED] Unable to query channel '%s': permission denied. "
                        "Run terminal as Administrator per scripts/setup_windows.md.",
                        self.name,
                        channel,
                    )
                else:
                    logger.debug("[%s] Channel '%s' initial watermark query error: %s", self.name, channel, exc)

    def _read_channel(self, channel: str, xpath_query: str) -> None:
        """Queries and emits any new events on the channel since last watermark."""
        last_id = self._watermarks.get(channel, 0)
        query = f"*[System[({xpath_query}) and EventRecordID > {last_id}]]"

        try:
            flags = self._win32evtlog.EvtQueryChannelPath | self._win32evtlog.EvtQueryForwardDirection
            h_query = self._win32evtlog.EvtQuery(channel, flags, query)
            while not self._stop_event.is_set():
                events = self._win32evtlog.EvtNext(h_query, 20)
                if not events:
                    break

                for ev_handle in events:
                    try:
                        xml_str = self._win32evtlog.EvtRender(ev_handle, self._win32evtlog.EvtRenderEventXml)
                        parsed = parse_eventlog_xml(
                            xml_str,
                            default_host=getattr(self.config, "host", None) if self.config else None,
                        )
                        if parsed:
                            rec_id = parsed.get("details", {}).get("event_record_id", 0)
                            if rec_id > self._watermarks[channel]:
                                self._watermarks[channel] = rec_id
                            self.emit(parsed)
                    except Exception as parse_exc:
                        logger.debug("[%s] Error rendering event handle: %s", self.name, parse_exc)

        except Exception as exc:
            if hasattr(exc, "winerror") and exc.winerror == 5:
                # Log once per check if elevation is missing
                logger.error(
                    "[%s] [ACCESS DENIED] Failed to query '%s': Elevation required. "
                    "Run terminal as Administrator.",
                    self.name,
                    channel,
                )
            else:
                logger.debug("[%s] Query error on channel '%s': %s", self.name, channel, exc)

    def _read_loop(self) -> None:
        """Main polling loop reading target event IDs from Security and System."""
        while not self._stop_event.is_set():
            # Query Security channel: 4688 (Process Start), 1102 (Log Cleared)
            self._read_channel("Security", "EventID=4688 or EventID=1102")

            # Query System channel: 104 (Log Cleared)
            self._read_channel("System", "EventID=104")

            self._stop_event.wait(self.poll_interval)
