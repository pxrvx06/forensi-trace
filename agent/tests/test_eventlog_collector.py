"""
Unit tests for ForensiTrace Event Log Collector & Isolated Parsing Layer
Author: Daksh (Agent Core & Event Log Collector Owner)
Contract: docs/schema.md, docs/agent_interface.md & scripts/setup_windows.md

Test coverage:
  - Firing tests:
      1. Security 4688 -> PROCESS_STARTED
      2. Security 1102 -> LOG_CLEARED
      3. System 104    -> LOG_CLEARED
  - Must-not-fire tests:
      4. Unmonitored Event ID (e.g. 4624, 7036) -> None
      5. Event 4688 missing NewProcessName -> None
      6. Malformed / corrupted XML -> None
      7. Empty string -> None
  - Timestamp normalization & Schema conformance tests.
"""

from __future__ import annotations

import os
import json
import queue
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from typing import Any

from agent.config import AgentConfig
from agent.sender import EventSender
from agent.collectors.eventlog_collector import (
    parse_eventlog_xml,
    normalize_eventlog_timestamp,
    EventLogCollector,
)
from backend.schema import (
    Event,
    EventBatch,
    SourceEnum,
    ActionEnum,
    EntityTypeEnum,
    compute_event_id,
    TIMESTAMP_REGEX,
)
from backend.db import init_db, insert_events_batch, get_events

# ---------------------------------------------------------------------------
# Synthetic Windows Event Log XML Fixtures
# ---------------------------------------------------------------------------
XML_4688_VALID = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-23T10:02:30.8000000Z" />
    <EventRecordID>9482104</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN-FORENSIC-01</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-123456789-123456789-123456789-1001</Data>
    <Data Name="SubjectUserName">analyst</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="NewProcessId">0x1a4c</Data>
    <Data Name="NewProcessName">E:\\reports\\payload.exe</Data>
    <Data Name="TokenElevationType">%%1936</Data>
    <Data Name="ProcessId">0x0e20</Data>
    <Data Name="CommandLine">&quot;E:\\reports\\payload.exe&quot; --silent</Data>
    <Data Name="TargetUserSid">S-1-5-21-123456789-123456789-123456789-1001</Data>
    <Data Name="TargetUserName">analyst</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="TargetLogonId">0x3e7</Data>
    <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-8192</Data>
  </EventData>
</Event>"""

XML_1102_VALID = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>1102</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>104</Task>
    <TimeCreated SystemTime="2026-10-23T11:00:00.1234567Z" />
    <EventRecordID>9482200</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN-FORENSIC-01</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-123456789-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="SubjectLogonId">0x1f4</Data>
  </EventData>
</Event>"""

XML_104_VALID = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog" />
    <EventID>104</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>104</Task>
    <TimeCreated SystemTime="2026-10-23T11:05:15.5000000Z" />
    <EventRecordID>54321</EventRecordID>
    <Channel>System</Channel>
    <Computer>WIN-FORENSIC-01</Computer>
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserName>Administrator</SubjectUserName>
      <SubjectDomainName>CONTOSO</SubjectDomainName>
      <Channel>System</Channel>
      <BackupPath>C:\\backup\\syslog.evtx</BackupPath>
    </LogFileCleared>
  </UserData>
</Event>"""

XML_4624_UNMONITORED = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-10-23T10:00:00.0000000Z" />
    <EventRecordID>9482000</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN-FORENSIC-01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">analyst</Data>
  </EventData>
</Event>"""

XML_4688_MISSING_PROCESS_NAME = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-10-23T10:02:30.8000000Z" />
    <EventRecordID>9482105</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN-FORENSIC-01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">analyst</Data>
  </EventData>
</Event>"""


class TestEventLogCollector(unittest.TestCase):

    # -----------------------------------------------------------------------
    # Firing Tests
    # -----------------------------------------------------------------------
    def test_process_started_event_4688_must_fire(self):
        """Security 4688 must fire and produce a valid PROCESS_STARTED event."""
        result = parse_eventlog_xml(XML_4688_VALID)
        self.assertIsNotNone(result)

        self.assertEqual(result["source"], "eventlog")
        self.assertEqual(result["action"], "PROCESS_STARTED")
        self.assertEqual(result["entity_type"], "process")
        self.assertEqual(result["entity"], r"E:\reports\payload.exe")
        self.assertEqual(result["user"], r"CONTOSO\analyst")
        self.assertEqual(result["host"], "WIN-FORENSIC-01")
        self.assertEqual(result["ts_utc"], "2026-10-23T10:02:30.800Z")

        # Verify deterministic hash
        expected_raw_id = "Security:9482104"
        expected_hash = compute_event_id("eventlog", expected_raw_id, "2026-10-23T10:02:30.800Z")
        self.assertEqual(result["event_id"], expected_hash)

        # Verify details
        details = result["details"]
        self.assertEqual(details["raw_record_id"], expected_raw_id)
        self.assertEqual(details["event_record_id"], 9482104)
        self.assertEqual(details["channel"], "Security")
        self.assertEqual(details["event_code"], 4688)
        self.assertEqual(details["process_id"], "0x1a4c")
        self.assertEqual(details["process_name"], r"E:\reports\payload.exe")
        self.assertEqual(details["parent_process_id"], "0x0e20")
        self.assertEqual(details["parent_process_name"], r"C:\Windows\explorer.exe")
        self.assertEqual(details["command_line"], '"E:\\reports\\payload.exe" --silent')

        # Conforms strictly to schema
        validated = Event.model_validate(result)
        self.assertEqual(validated.action, ActionEnum.PROCESS_STARTED)

    def test_security_log_cleared_event_1102_must_fire(self):
        """Security 1102 must fire and produce a valid LOG_CLEARED event."""
        result = parse_eventlog_xml(XML_1102_VALID)
        self.assertIsNotNone(result)

        self.assertEqual(result["source"], "eventlog")
        self.assertEqual(result["action"], "LOG_CLEARED")
        self.assertEqual(result["entity_type"], "file")
        self.assertEqual(result["entity"], r"C:\Windows\System32\winevt\Logs\Security.evtx")
        self.assertEqual(result["user"], r"CONTOSO\Administrator")
        self.assertEqual(result["details"]["channel"], "Security")
        self.assertEqual(result["details"]["event_code"], 1102)

        # Conforms strictly to schema
        validated = Event.model_validate(result)
        self.assertEqual(validated.action, ActionEnum.LOG_CLEARED)

    def test_system_log_cleared_event_104_must_fire(self):
        """System 104 must fire and produce a valid LOG_CLEARED event."""
        result = parse_eventlog_xml(XML_104_VALID)
        self.assertIsNotNone(result)

        self.assertEqual(result["source"], "eventlog")
        self.assertEqual(result["action"], "LOG_CLEARED")
        self.assertEqual(result["entity_type"], "file")
        self.assertEqual(result["entity"], r"C:\Windows\System32\winevt\Logs\System.evtx")
        self.assertEqual(result["user"], r"CONTOSO\Administrator")
        self.assertEqual(result["details"]["channel"], "System")
        self.assertEqual(result["details"]["event_code"], 104)
        self.assertEqual(result["details"]["backup_path"], r"C:\backup\syslog.evtx")

        # Conforms strictly to schema
        validated = Event.model_validate(result)
        self.assertEqual(validated.action, ActionEnum.LOG_CLEARED)

    # -----------------------------------------------------------------------
    # Must Not Fire Tests
    # -----------------------------------------------------------------------
    def test_unmonitored_event_code_must_not_fire(self):
        """Event ID 4624 (Logon) is not monitored and must NOT produce an event."""
        result = parse_eventlog_xml(XML_4624_UNMONITORED)
        self.assertIsNone(result)

    def test_missing_process_name_must_not_fire(self):
        """Event 4688 missing NewProcessName cannot form a valid entity and must NOT fire."""
        result = parse_eventlog_xml(XML_4688_MISSING_PROCESS_NAME)
        self.assertIsNone(result)

    def test_malformed_xml_must_not_fire(self):
        """Malformed XML syntax must be handled safely and return None without raising."""
        malformed = "<Event><System><EventID>4688</EventID></System><unclosed>"
        result = parse_eventlog_xml(malformed)
        self.assertIsNone(result)

    def test_empty_string_must_not_fire(self):
        """Empty or whitespace-only XML input must safely return None."""
        self.assertIsNone(parse_eventlog_xml(""))
        self.assertIsNone(parse_eventlog_xml("   \n\t  "))

    # -----------------------------------------------------------------------
    # Timestamp Normalization Tests
    # -----------------------------------------------------------------------
    def test_timestamp_normalization_formats(self):
        # 7-digit fractional seconds (Windows filetime)
        ts1 = normalize_eventlog_timestamp("2026-10-23T10:02:30.8000000Z")
        self.assertEqual(ts1, "2026-10-23T10:02:30.800Z")
        self.assertTrue(bool(TIMESTAMP_REGEX.match(ts1)))

        # 3-digit fractional seconds
        ts2 = normalize_eventlog_timestamp("2026-10-23T10:02:30.123Z")
        self.assertEqual(ts2, "2026-10-23T10:02:30.123Z")
        self.assertTrue(bool(TIMESTAMP_REGEX.match(ts2)))

        # No fractional seconds
        ts3 = normalize_eventlog_timestamp("2026-10-23T10:02:30Z")
        self.assertEqual(ts3, "2026-10-23T10:02:30.000Z")
        self.assertTrue(bool(TIMESTAMP_REGEX.match(ts3)))

    # -----------------------------------------------------------------------
    # Collector Queue Integration Test
    # -----------------------------------------------------------------------
    def test_collector_emit_integration(self):
        """Verifies that parsed eventlog telemetry integrates with BaseCollector emission queue."""
        q = queue.Queue()
        collector = EventLogCollector(event_queue=q)

        event_dict = parse_eventlog_xml(XML_4688_VALID)
        self.assertIsNotNone(event_dict)

        collector.emit(event_dict)
        self.assertEqual(q.qsize(), 1)
        item = q.get_nowait()
        self.assertEqual(item["event_id"], event_dict["event_id"])
        self.assertEqual(item["action"], "PROCESS_STARTED")

    @patch("urllib.request.urlopen")
    def test_full_pipeline_eventlog_to_sender_to_database(self, mock_urlopen):
        """
        Full end-to-end pipeline test for Daksh's Phase 2 slice:
        1. Event Log XML (Security 4688) parsed into schema-compliant event.
        2. Collector emits event to agent queue.
        3. EventSender drains queue and posts EventBatch via HTTP.
        4. Mock HTTP server verifies transmitted payload.
        5. Database layer ingests EventBatch into SQLite.
        """
        # Step 1: Parse 4688 XML
        event_dict = parse_eventlog_xml(XML_4688_VALID)
        self.assertIsNotNone(event_dict)

        # Step 2: Collector emits event
        q = queue.Queue()
        collector = EventLogCollector(event_queue=q)
        collector.emit(event_dict)
        self.assertEqual(q.qsize(), 1)

        # Step 3: Setup sender and mock response
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b'{"status": "ok", "ingested": 1}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        cfg = AgentConfig(
            backend_url="http://127.0.0.1:8000",
            batch_size=1,
            flush_interval_seconds=0.05,
        )
        sender = EventSender(event_queue=q, config=cfg)
        sender.start()
        import time
        time.sleep(0.2)
        sender.stop()

        # Step 4: Verify payload delivered to HTTP endpoint
        self.assertTrue(mock_urlopen.called)
        call_req = mock_urlopen.call_args[0][0]
        sent_body = json.loads(call_req.data.decode("utf-8"))
        batch = EventBatch.model_validate(sent_body)
        self.assertEqual(len(batch.events), 1)
        self.assertEqual(batch.events[0].event_id, event_dict["event_id"])
        self.assertEqual(batch.events[0].action, ActionEnum.PROCESS_STARTED)

        # Step 5: Verify SQLite database layer stores the transmitted event
        test_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(test_dir, "pipeline_test.db")
            init_db(db_path)
            inserted, dups = insert_events_batch(batch.events, db_path=db_path)
            self.assertEqual(inserted, 1)
            self.assertEqual(dups, 0)

            stored_events = get_events(db_path=db_path)
            self.assertEqual(len(stored_events), 1)
            self.assertEqual(stored_events[0]["event_id"], event_dict["event_id"])
            self.assertEqual(stored_events[0]["action"], "PROCESS_STARTED")
            self.assertEqual(stored_events[0]["entity"], r"E:\reports\payload.exe")
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)


    def test_resolve_nt_device_path(self):
        """Verifies that NT device paths are resolved to DOS drive letter paths."""
        from agent.collectors.eventlog_collector import resolve_nt_device_path
        # Non-NT path returns unchanged
        self.assertEqual(resolve_nt_device_path(r"C:\Windows\cmd.exe"), r"C:\Windows\cmd.exe")
        self.assertEqual(resolve_nt_device_path(""), "")
        # Fallback via command_line
        resolved = resolve_nt_device_path(
            r"\Device\HarddiskVolume99\payload.exe",
            command_line=r'"D:\tools\payload.exe" --silent'
        )
        self.assertEqual(resolved, r"D:\tools\payload.exe")

    def test_4688_with_nt_device_path(self):
        """Verifies that Event 4688 with NT device path resolves to DOS drive letter in event dict."""
        xml_nt = XML_4688_VALID.replace(
            r'<Data Name="NewProcessName">E:\reports\payload.exe</Data>',
            r'<Data Name="NewProcessName">\Device\HarddiskVolume11\payload.exe</Data>'
        )
        res = parse_eventlog_xml(xml_nt)
        self.assertIsNotNone(res)
        self.assertEqual(res["entity"], r"E:\reports\payload.exe")


if __name__ == "__main__":
    unittest.main()
