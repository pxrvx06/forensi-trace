"""
Unit tests for ForensiTrace Agent Core
Author: Daksh (Agent Core Owner)
Scope: Config, BaseCollector, EventSender, retry/backoff, downtime survival, schema validation.
"""

from __future__ import annotations

import io
import os
import json
import time
import queue
import shutil
import tempfile
import unittest
import urllib.request
import urllib.error
from unittest.mock import patch, MagicMock
from typing import Any, Dict, List

from agent.config import AgentConfig, load_config
from agent.collectors.base import BaseCollector
from agent.sender import EventSender
from backend.schema import Event, EventBatch, SourceEnum, ActionEnum, compute_event_id
from backend.db import init_db, insert_events_batch, get_events


class MockCollector(BaseCollector):
    """Concrete implementation of BaseCollector for testing."""
    def __init__(self, event_queue: queue.Queue, config: Any = None):
        super().__init__(event_queue, config, name="MockCollector")

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False


class TestAgentCore(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_sample_event(
        self,
        event_code: int = 4688,
        record_id: int = 1001,
        ts_utc: str = "2026-10-23T10:00:00.000Z",
        entity: str = r"C:\Windows\System32\cmd.exe",
    ) -> Dict[str, Any]:
        source = "eventlog"
        raw_rec_id = f"Security:{record_id}"
        ev_id = compute_event_id(source, raw_rec_id, ts_utc)
        return {
            "event_id": ev_id,
            "source": source,
            "ts_utc": ts_utc,
            "host": "TEST-HOST",
            "user": "TEST-USER",
            "action": "PROCESS_STARTED",
            "entity_type": "process",
            "entity": entity,
            "details": {
                "raw_record_id": raw_rec_id,
                "event_record_id": record_id,
                "channel": "Security",
                "event_code": event_code,
            },
            "raw": {"EventID": event_code, "RecordID": record_id},
        }

    # 1. Configuration tests
    def test_config_defaults_and_env_overrides(self):
        cfg = load_config()
        self.assertEqual(cfg.batch_size, 10)
        self.assertEqual(cfg.flush_interval_seconds, 2.0)
        self.assertEqual(cfg.full_events_url, "http://127.0.0.1:8000/events")

        os.environ["FORENSITRACE_BACKEND_URL"] = "http://testserver:9000"
        os.environ["FORENSITRACE_BATCH_SIZE"] = "25"
        os.environ["FORENSITRACE_FLUSH_INTERVAL"] = "0.5"
        try:
            custom_cfg = load_config()
            self.assertEqual(custom_cfg.backend_url, "http://testserver:9000")
            self.assertEqual(custom_cfg.batch_size, 25)
            self.assertEqual(custom_cfg.flush_interval_seconds, 0.5)
            self.assertEqual(custom_cfg.full_events_url, "http://testserver:9000/events")
        finally:
            os.environ.pop("FORENSITRACE_BACKEND_URL", None)
            os.environ.pop("FORENSITRACE_BATCH_SIZE", None)
            os.environ.pop("FORENSITRACE_FLUSH_INTERVAL", None)

    def test_config_file_loading(self):
        cfg_path = os.path.join(self.test_dir, "agent_config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump({
                "backend_url": "http://192.168.1.50:8000",
                "batch_size": 5,
                "flush_interval_seconds": 1.5,
                "enabled_collectors": ["eventlog"]
            }, f)

        cfg = load_config(cfg_path)
        self.assertEqual(cfg.backend_url, "http://192.168.1.50:8000")
        self.assertEqual(cfg.batch_size, 5)
        self.assertEqual(cfg.flush_interval_seconds, 1.5)
        self.assertEqual(cfg.enabled_collectors, ["eventlog"])

    # 2. BaseCollector lifecycle and emission
    def test_base_collector_lifecycle_and_emit(self):
        q = queue.Queue(maxsize=5)
        collector = MockCollector(event_queue=q)

        self.assertFalse(collector.is_alive)
        collector.start()
        self.assertTrue(collector.is_alive)

        sample_event = self._create_sample_event()
        collector.emit(sample_event)
        self.assertEqual(q.qsize(), 1)
        queued = q.get_nowait()
        self.assertEqual(queued["event_id"], sample_event["event_id"])

        collector.stop()
        self.assertFalse(collector.is_alive)

    def test_inter_collector_drive_hook(self):
        q = queue.Queue()
        collector = MockCollector(event_queue=q)

        notified_drives = []
        def drive_callback(drive_letter: str, event_type: str):
            notified_drives.append((drive_letter, event_type))

        collector.register_drive_listener(drive_callback)
        collector.notify_drive_listeners("E:", "ATTACHED")
        collector.notify_drive_listeners("E:", "REMOVED")

        self.assertEqual(len(notified_drives), 2)
        self.assertEqual(notified_drives[0], ("E:", "ATTACHED"))
        self.assertEqual(notified_drives[1], ("E:", "REMOVED"))

    # 3. Sender successful batch flush
    @patch("urllib.request.urlopen")
    def test_sender_successful_flush_to_backend(self, mock_urlopen):
        # Mock HTTP 200 response
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b'{"status": "ok", "ingested": 2, "duplicates": 0}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        cfg = AgentConfig(
            backend_url="http://127.0.0.1:8000",
            batch_size=2,
            flush_interval_seconds=0.1,
            retry_initial_delay=0.05,
        )
        q = queue.Queue()
        sender = EventSender(event_queue=q, config=cfg)

        ev1 = self._create_sample_event(record_id=101)
        ev2 = self._create_sample_event(record_id=102)
        q.put(ev1)
        q.put(ev2)

        sender.start()
        time.sleep(0.3)
        sender.stop()

        self.assertTrue(mock_urlopen.called)
        # Check payload passed to urlopen
        call_args = mock_urlopen.call_args[0]
        req = call_args[0]
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["batch_size"], 2)
        self.assertEqual(len(payload["events"]), 2)
        self.assertEqual(payload["events"][0]["event_id"], ev1["event_id"])
        self.assertEqual(payload["events"][1]["event_id"], ev2["event_id"])
        self.assertEqual(sender.buffered_count, 0)

    # 4. Sender survives backend downtime and retries
    @patch("urllib.request.urlopen")
    def test_sender_survives_backend_downtime_and_retries(self, mock_urlopen):
        # First call fails (Connection refused); second call succeeds (200 OK)
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b'{"status": "ok", "ingested": 2}'
        mock_resp.__enter__.return_value = mock_resp

        mock_urlopen.side_effect = [
            urllib.error.URLError("Connection refused"),
            mock_resp,
        ]

        cfg = AgentConfig(
            backend_url="http://127.0.0.1:8000",
            batch_size=2,
            flush_interval_seconds=0.05,
            retry_initial_delay=0.1,
            retry_backoff_factor=1.5,
        )
        q = queue.Queue()
        sender = EventSender(event_queue=q, config=cfg)

        ev1 = self._create_sample_event(record_id=201)
        ev2 = self._create_sample_event(record_id=202)
        q.put(ev1)
        q.put(ev2)

        # Start sender; worker attempts flush -> fails -> retains events
        sender.start()
        # Wait enough time for the first failure (at 0.05s) and the retry (after 0.1s backoff)
        time.sleep(0.4)
        sender.stop()

        # Both calls occurred
        self.assertGreaterEqual(mock_urlopen.call_count, 2)
        # After second call succeeds, buffer is drained to 0
        self.assertEqual(sender.buffered_count, 0)

    # 5. Schema validation of generated batch payload
    def test_batch_format_conforms_to_pydantic_schema(self):
        ev1 = self._create_sample_event(record_id=301)
        ev2 = self._create_sample_event(record_id=302)
        batch_payload = {
            "events": [ev1, ev2],
            "batch_size": 2,
        }

        # Validate with Purva's Pydantic model
        validated_batch = EventBatch.model_validate(batch_payload)
        self.assertEqual(len(validated_batch.events), 2)
        self.assertEqual(validated_batch.events[0].source, SourceEnum.eventlog)
        self.assertEqual(validated_batch.events[0].action, ActionEnum.PROCESS_STARTED)

    # 6. Harmless duplicate event_id idempotency
    def test_duplicate_event_id_idempotency_in_database(self):
        db_path = os.path.join(self.test_dir, "test_agent_db.db")
        init_db(db_path)

        ev1 = self._create_sample_event(record_id=401)
        ev1_duplicate = self._create_sample_event(record_id=401)

        # Ingest first batch
        ins1, dup1 = insert_events_batch([Event.model_validate(ev1)], db_path=db_path)
        self.assertEqual(ins1, 1)
        self.assertEqual(dup1, 0)

        # Ingest duplicate batch
        ins2, dup2 = insert_events_batch([Event.model_validate(ev1_duplicate)], db_path=db_path)
        self.assertEqual(ins2, 0)
        self.assertEqual(dup2, 1)

        # Database contains exactly 1 unique event record
        events = get_events(db_path=db_path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], ev1["event_id"])

    # 7. Sender handles 422 schema error without getting stuck
    @patch("urllib.request.urlopen")
    def test_sender_handles_422_schema_error(self, mock_urlopen):
        # Backend returns 422 Unprocessable Entity
        error_body = io.BytesIO(b'{"detail": "validation error: invalid entity"}')
        http_error = urllib.error.HTTPError(
            url="http://127.0.0.1:8000/events",
            code=422,
            msg="Unprocessable Entity",
            hdrs={},
            fp=error_body,
        )
        mock_urlopen.side_effect = http_error

        cfg = AgentConfig(
            backend_url="http://127.0.0.1:8000",
            batch_size=1,
            flush_interval_seconds=0.05,
        )
        q = queue.Queue()
        sender = EventSender(event_queue=q, config=cfg)

        q.put({"bad": "payload"})

        sender.start()
        time.sleep(0.3)
        sender.stop()

        # The 422 error was logged and the bad record discarded so buffer drops to 0
        self.assertEqual(sender.buffered_count, 0)


if __name__ == "__main__":
    unittest.main()
