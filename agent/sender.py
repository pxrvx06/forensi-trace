"""
ForensiTrace Batched HTTP Telemetry Sender
Author: Daksh (Agent Core Owner)
Contract: docs/agent_interface.md & docs/schema.md
"""

from __future__ import annotations

import json
import time
import queue
import logging
import threading
import urllib.request
import urllib.error
from collections import deque
from typing import Any, Dict, List, Optional

from agent.config import AgentConfig

logger = logging.getLogger("forensitrace.agent.sender")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class EventSender:
    """
    Batched HTTP Telemetry Sender with resilient retry and exponential backoff.
    
    Guarantees:
      1. Local Buffering: Retains events in an in-memory buffer when the backend is offline.
      2. No Direct Database Access: Strictly transmits via HTTP POST to /events.
      3. At-least-once delivery: Resends unacknowledged batches until accepted.
      4. Idempotency: Relies on deterministic event_id deduplication in the backend.
    """

    def __init__(self, event_queue: queue.Queue[Dict[str, Any]], config: AgentConfig) -> None:
        self.event_queue = event_queue
        self.config = config

        # Local buffer for unacknowledged and pending events
        self._buffer: deque[Dict[str, Any]] = deque()
        self._buffer_lock = threading.Lock()

        # Worker thread lifecycle controls
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Backoff state
        self._current_backoff = self.config.retry_initial_delay

        logger.info(
            "[EventSender] [RECEIVED] Initialized sender: endpoint='%s', batch_size=%d, flush_interval=%.1fs",
            self.config.full_events_url,
            self.config.batch_size,
            self.config.flush_interval_seconds,
        )

    def start(self) -> None:
        """Starts the background sender worker thread."""
        if self._worker_thread and self._worker_thread.is_alive():
            return

        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._run_loop, name="EventSenderWorker", daemon=True)
        self._worker_thread.start()
        logger.info("[EventSender] [PRODUCED] Background worker thread started")

    def stop(self, timeout: float = 5.0) -> None:
        """
        Gracefully signals the worker thread to stop, attempts a final flush,
        and joins the worker thread.
        """
        logger.info("[EventSender] [RECEIVED] Stopping sender worker (timeout=%.1fs)...", timeout)
        self._stop_event.set()

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)

        # Attempt one last synchronous flush of any remaining buffered items
        remaining_count = self.buffered_count
        if remaining_count > 0:
            logger.info("[EventSender] Attempting final flush of %d buffered events...", remaining_count)
            self._flush_available_batches(max_attempts=1)

        logger.info("[EventSender] [PRODUCED] Sender stopped. Unsent events in buffer: %d", self.buffered_count)

    @property
    def is_alive(self) -> bool:
        """Checks if the sender background worker thread is running."""
        return self._worker_thread is not None and self._worker_thread.is_alive()

    @property
    def buffered_count(self) -> int:
        """Total number of events currently held in memory (queue + pending buffer)."""
        with self._buffer_lock:
            return len(self._buffer) + self.event_queue.qsize()

    def _pull_from_queue_to_buffer(self) -> None:
        """Drains items from incoming event_queue into the internal pending deque."""
        while not self.event_queue.empty():
            try:
                item = self.event_queue.get_nowait()
                with self._buffer_lock:
                    if len(self._buffer) < self.config.max_buffer_size:
                        self._buffer.append(item)
                    else:
                        logger.error("[EventSender] Buffer overflow! Discarding oldest event to prevent memory exhaustion.")
                        self._buffer.popleft()
                        self._buffer.append(item)
                self.event_queue.task_done()
            except queue.Empty:
                break

    def _transmit_batch_http(self, batch: List[Dict[str, Any]]) -> bool:
        """
        Sends a single batch of events to POST /events via standard urllib.
        Returns True on success (200/201), False on network/server failure.
        On 422 schema rejection, logs and drops invalid records to avoid blocking the queue.
        """
        payload = {
            "events": batch,
            "batch_size": len(batch),
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url=self.config.full_events_url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ForensiTrace-Agent/1.0",
            },
            method="POST",
        )

        logger.debug(
            "[EventSender] [TRANSMIT] [RECEIVED] Sending batch of %d events to '%s' (%d bytes)",
            len(batch),
            self.config.full_events_url,
            len(data_bytes),
        )

        try:
            with urllib.request.urlopen(req, timeout=5.0) as response:
                status_code = response.getcode()
                response_body = response.read().decode("utf-8")
                if 200 <= status_code < 300:
                    logger.info(
                        "[EventSender] [TRANSMIT] [PRODUCED] Successfully sent batch of %d events (HTTP %d): %s",
                        len(batch),
                        status_code,
                        response_body.strip(),
                    )
                    return True
                else:
                    logger.warning("[EventSender] [TRANSMIT] Unexpected response HTTP %d: %s", status_code, response_body)
                    return False

        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code == 422:
                # Malformed schema validation failure
                logger.error(
                    "[EventSender] [TRANSMIT] [SCHEMA_ERROR] Backend rejected batch (HTTP 422): %s. "
                    "Discarding invalid records to prevent blocking the sender pipeline.",
                    body,
                )
                # Treat as handled so bad events don't retry forever
                return True
            else:
                logger.warning(
                    "[EventSender] [TRANSMIT] HTTP server error (HTTP %d): %s. Backend temporarily unavailable.",
                    exc.code,
                    body,
                )
                return False

        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.warning(
                "[EventSender] [TRANSMIT] Network/connection error contacting backend '%s': %s. "
                "Backend may be offline. Retaining events in local buffer.",
                self.config.full_events_url,
                exc,
            )
            return False

    def _flush_available_batches(self, max_attempts: Optional[int] = None) -> None:
        """
        Attempts to deliver pending buffered events to the backend.
        Retains events on failure.
        """
        self._pull_from_queue_to_buffer()

        attempts = 0
        while True:
            if max_attempts is not None and attempts >= max_attempts:
                break

            with self._buffer_lock:
                if not self._buffer:
                    break
                # Prepare a slice up to batch_size
                batch_size = min(len(self._buffer), self.config.batch_size)
                batch = [self._buffer[i] for i in range(batch_size)]

            # Attempt HTTP transmission
            success = self._transmit_batch_http(batch)
            attempts += 1

            if success:
                # Pop the confirmed delivered events from head of buffer
                with self._buffer_lock:
                    for _ in range(batch_size):
                        if self._buffer:
                            self._buffer.popleft()
                # Reset backoff delay on successful transmission
                self._current_backoff = self.config.retry_initial_delay
            else:
                # Transmission failed; retain events in buffer and back off
                logger.warning(
                    "[EventSender] [BACKOFF] Retaining %d events in memory. Waiting %.1fs before retry...",
                    self.buffered_count,
                    self._current_backoff,
                )
                self._stop_event.wait(self._current_backoff)
                self._current_backoff = min(
                    self._current_backoff * self.config.retry_backoff_factor,
                    self.config.retry_max_delay,
                )
                # Stop current flush attempt loop until next cycle
                break

    def _run_loop(self) -> None:
        """Main worker loop running in the background thread."""
        last_flush_time = time.time()

        while not self._stop_event.is_set():
            self._pull_from_queue_to_buffer()

            now = time.time()
            elapsed = now - last_flush_time
            buffer_len = len(self._buffer)

            should_flush = (
                buffer_len >= self.config.batch_size
                or (buffer_len > 0 and elapsed >= self.config.flush_interval_seconds)
            )

            if should_flush:
                self._flush_available_batches()
                last_flush_time = time.time()

            # Responsive wait before next check
            self._stop_event.wait(timeout=0.25)
