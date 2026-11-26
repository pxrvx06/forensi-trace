"""
Unit Tests for Forensic PDF Report Generation
Author: Purva
Validates: backend/reports.py and GET /report/{activity_id} endpoint against Step 4 requirements
"""

import json
import re
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException

from backend.db import init_db, insert_activity, insert_events_batch, get_activity_by_id
from backend.main import download_activity_report
from backend.reports import generate_activity_pdf_bytes


class TestForensicPDFReports(unittest.TestCase):
    def setUp(self):
        examples_dir = Path(__file__).resolve().parent.parent.parent / "docs" / "examples"
        self.sample_events = []
        for name in ["usb_event.json", "fs_event.json", "eventlog_event.json"]:
            with open(examples_dir / name, "r", encoding="utf-8") as f:
                self.sample_events.append(json.load(f))

    def _count_pdf_pages(self, pdf_bytes: bytes) -> int:
        # ReportLab writes /Type /Page for each page (distinct from /Type /Pages)
        matches = re.findall(rb"/Type\s*/Page(?!s)\b", pdf_bytes)
        return len(matches)

    def test_generate_three_page_pdf_report_must_succeed(self):
        """
        MUST-FIRE TEST:
        Valid R7 activity with 3 evidence events, ML anomaly score, and CRITICAL threat badge
        must produce a valid 3-page PDF starting with %PDF-.
        """
        activity = {
            "activity_id": "act_report_001",
            "rule_id": "R7",
            "rule_name": "Full USB Staging & Execution Chain",
            "ts_start_utc": "2026-10-23T10:00:00.120Z",
            "ts_end_utc": "2026-10-23T10:02:30.800Z",
            "confidence": 0.95,
            "ml_anomaly_score": 0.88,
            "threat_level": "CRITICAL",
            "narrative": (
                "Removable device mounted on E:, executable payload.exe written to E:\\reports\\payload.exe, "
                "and executed under CONTOSO\\analyst. [ML Analysis: Sequence anomaly score=0.88, threat level: CRITICAL.]"
            ),
            "evidence_chain": [
                {**self.sample_events[0], "reason": "USB volume mounted on E:"},
                {**self.sample_events[1], "reason": "Executable binary payload.exe created on E:"},
                {**self.sample_events[2], "reason": "Process launched from matching path E:\\reports\\payload.exe"},
            ],
        }

        pdf_bytes = generate_activity_pdf_bytes(activity)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"), "Output must have valid PDF header")
        self.assertIn(b"%%EOF", pdf_bytes[-64:], "Output must have valid PDF EOF trailer")
        self.assertGreater(len(pdf_bytes), 2000)

        page_count = self._count_pdf_pages(pdf_bytes)
        self.assertEqual(page_count, 3, f"Standard forensic report must be 3 pages, got {page_count}")

    def test_generate_pdf_fallback_missing_ml_and_special_chars(self):
        """
        EDGE-CASE TEST:
        Ensures PDF generation handles None ml_anomaly_score, empty narrative,
        and XML special characters (<, >, &) in raw telemetry without crashing.
        """
        activity = {
            "activity_id": "act_edge_002",
            "rule_id": "R3",
            "rule_name": "Untracked Execution",
            "ts_start_utc": "2026-10-23T11:00:00.000Z",
            "ts_end_utc": "2026-10-23T11:00:05.000Z",
            "confidence": 0.80,
            "ml_anomaly_score": None,
            "threat_level": "MEDIUM",
            "narrative": None,
            "evidence_chain": [
                {
                    "event_id": "abc12345" * 8,
                    "source": "eventlog",
                    "ts_utc": "2026-10-23T11:00:00.000Z",
                    "host": "WIN-TEST",
                    "user": "DOMAIN\\user&admin",
                    "action": "PROCESS_STARTED",
                    "entity_type": "process",
                    "entity": "E:\\tools\\run<test>.exe",
                    "reason": "Executed binary with special characters & flags",
                    "raw": {"CommandLine": "run<test>.exe --arg=\"a & b > c\""},
                }
            ],
        }

        pdf_bytes = generate_activity_pdf_bytes(activity)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertEqual(self._count_pdf_pages(pdf_bytes), 3)

    def test_report_endpoint_not_found_must_raise_404(self):
        """
        MUST-NOT-FIRE TEST:
        Requesting /report/{activity_id} for a non-existent activity ID must raise HTTP 404.
        """
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_report_404.db"
            init_db(db_path)
            old_env = os.environ.get("FORENSITRACE_DB_PATH")
            os.environ["FORENSITRACE_DB_PATH"] = str(db_path)
            try:
                with self.assertRaises(HTTPException) as ctx:
                    download_activity_report("nonexistent_activity_999")
                self.assertEqual(ctx.exception.status_code, 404)
            finally:
                if old_env is None:
                    os.environ.pop("FORENSITRACE_DB_PATH", None)
                else:
                    os.environ["FORENSITRACE_DB_PATH"] = old_env

    def test_report_endpoint_streams_pdf_from_db(self):
        """
        INTEGRATION TEST:
        Inserts events + activity into SQLite and invokes download_activity_report handler.
        Verifies Content-Type application/pdf and Content-Disposition attachment header.
        """
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_report_db.db"
            init_db(db_path)
            insert_events_batch(self.sample_events, db_path=db_path)

            activity_data = {
                "activity_id": "act_db_pdf_001",
                "rule_id": "R7",
                "rule_name": "USB Staging Chain",
                "ts_start_utc": "2026-10-23T10:00:00.120Z",
                "ts_end_utc": "2026-10-23T10:02:30.800Z",
                "confidence": 0.95,
                "ml_anomaly_score": 0.91,
                "threat_level": "CRITICAL",
                "narrative": "Full three-stage USB staging activity detected."
            }
            links = [
                {
                    "activity_id": "act_db_pdf_001",
                    "event_id": self.sample_events[0]["event_id"],
                    "rule_id": "R1",
                    "reason": "USB arrival"
                },
                {
                    "activity_id": "act_db_pdf_001",
                    "event_id": self.sample_events[1]["event_id"],
                    "rule_id": "R1",
                    "reason": "Payload written"
                },
            ]
            insert_activity(activity_data, links, db_path=db_path)

            old_env = os.environ.get("FORENSITRACE_DB_PATH")
            os.environ["FORENSITRACE_DB_PATH"] = str(db_path)
            try:
                response = download_activity_report("act_db_pdf_001")
                self.assertEqual(response.media_type, "application/pdf")
                self.assertIn("ForensiTrace_Report_act_db_pdf_001.pdf", response.headers.get("Content-Disposition", ""))
                self.assertTrue(response.body.startswith(b"%PDF-"))
                self.assertEqual(self._count_pdf_pages(response.body), 3)
            finally:
                if old_env is None:
                    os.environ.pop("FORENSITRACE_DB_PATH", None)
                else:
                    os.environ["FORENSITRACE_DB_PATH"] = old_env


if __name__ == "__main__":
    unittest.main()
