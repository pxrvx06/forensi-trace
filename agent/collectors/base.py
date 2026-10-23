"""
ForensiTrace Base Collector Interface
Author: Daksh (Agent Core Owner)
Contract: docs/agent_interface.md
"""

from __future__ import annotations

import queue
import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("forensitrace.agent.collector.base")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class BaseCollector(ABC):
    """
    Abstract Base Class for all ForensiTrace telemetry collectors.
    Implements standardized lifecycle methods and non-blocking event emission.
    """

    def __init__(
        self,
        event_queue: queue.Queue[Dict[str, Any]],
        config: Optional[Any] = None,
        name: str = "BaseCollector",
    ) -> None:
        self.event_queue = event_queue
        self.config = config
        self.name = name
        self._running = False
        self._drive_listeners: List[Callable[[str, str], None]] = []
        logger.debug("[%s] Initialized base collector", self.name)

    @abstractmethod
    def start(self) -> None:
        """
        Begins telemetry collection.
        Must be non-blocking (spawns background worker thread or listener).
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """
        Stops telemetry collection and releases OS resources.
        Must be idempotent and safe to call multiple times.
        """
        pass

    @property
    def is_alive(self) -> bool:
        """Indicates if the collector worker thread/process is currently active."""
        return self._running

    def emit(self, event_dict: Dict[str, Any]) -> None:
        """
        Emits a normalized event dictionary onto the agent's central thread-safe queue.
        Non-blocking: if the queue is full, logs a warning and avoids locking worker threads.
        """
        event_id = event_dict.get("event_id", "unknown")
        action = event_dict.get("action", "unknown")
        source = event_dict.get("source", "unknown")

        logger.debug(
            "[%s] [EMIT] [RECEIVED] Telemetry event: source='%s', action='%s', event_id='%s'",
            self.name,
            source,
            action,
            event_id,
        )

        try:
            self.event_queue.put_nowait(event_dict)
            logger.info(
                "[%s] [EMIT] [PRODUCED] Queued event_id='%s' (action='%s', qsize=%d)",
                self.name,
                event_id,
                action,
                self.event_queue.qsize(),
            )
        except queue.Full:
            logger.error(
                "[%s] [EMIT] [DROPPED] Queue full! Dropping event_id='%s' (action='%s')",
                self.name,
                event_id,
                action,
            )

    # ------------------------------------------------------------------
    # Inter-Collector Hand-off Hook (per docs/agent_interface.md Section 3)
    # ------------------------------------------------------------------

    def register_drive_listener(self, listener: Callable[[str, str], None]) -> None:
        """
        Registers a callback listener for removable drive notifications.
        Used to connect Chetna's USB collector to the File-System collector.
        """
        if listener not in self._drive_listeners:
            self._drive_listeners.append(listener)
            logger.info("[%s] Registered drive event listener: %s", self.name, getattr(listener, "__name__", str(listener)))

    def notify_drive_listeners(self, drive_letter: str, event_type: str) -> None:
        """
        Invokes registered listeners when a removable drive is attached or removed.
        
        :param drive_letter: Drive letter with trailing colon, e.g. "E:"
        :param event_type: "ATTACHED" or "REMOVED"
        """
        logger.info(
            "[%s] [DRIVE_HOOK] [PRODUCED] Notifying %d listener(s) of drive '%s' (%s)",
            self.name,
            len(self._drive_listeners),
            drive_letter,
            event_type,
        )
        for listener in self._drive_listeners:
            try:
                listener(drive_letter, event_type)
            except Exception as exc:
                logger.error("[%s] [DRIVE_HOOK] Error in drive listener: %s", self.name, exc, exc_info=True)
