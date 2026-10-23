"""
ForensiTrace Endpoint Agent Entrypoint
Author: Daksh (Agent Core Owner)
Contract: docs/agent_interface.md & docs/schema.md
"""

from __future__ import annotations

import sys
import time
import queue
import signal
import logging
import argparse
from typing import Any, List

from agent.config import AgentConfig, load_config
from agent.collectors.base import BaseCollector
from agent.sender import EventSender

# Configure labeled root logger
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("forensitrace.agent.main")


class ForensiTraceAgent:
    """
    Unified ForensiTrace Endpoint Agent Manager.
    Orchestrates collector lifecycles, inter-collector hand-off hooks,
    and batched telemetry shipping to the FastAPI backend.
    """

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.event_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=config.max_buffer_size)
        self.sender = EventSender(event_queue=self.event_queue, config=self.config)
        self.collectors: List[BaseCollector] = []
        self._shutdown_event = False

        logger.info("[Agent] [RECEIVED] Initializing agent on host '%s'", self.config.host)
        self._init_collectors()

    def _init_collectors(self) -> None:
        """
        Dynamically initializes enabled collectors.
        Tolerates collectors still under development by teammates.
        """
        enabled = set(self.config.enabled_collectors)

        # 1. Event Log Collector (Daksh)
        if "eventlog" in enabled:
            try:
                from agent.collectors.eventlog_collector import EventLogCollector
                collector = EventLogCollector(event_queue=self.event_queue, config=self.config)
                self.collectors.append(collector)
                logger.info("[Agent] [PRODUCED] Registered EventLogCollector")
            except ImportError:
                logger.warning(
                    "[Agent] EventLogCollector not found (Task 4 in progress). Skipping live eventlog collection."
                )

        # 2. USB Collector (Chetna)
        usb_collector: Any = None
        if "usb" in enabled:
            try:
                from agent.collectors.usb_collector import USBCollector
                usb_collector = USBCollector(event_queue=self.event_queue, config=self.config)
                self.collectors.append(usb_collector)
                logger.info("[Agent] [PRODUCED] Registered USBCollector")
            except ImportError:
                logger.info("[Agent] USBCollector not yet present (owned by Chetna).")

        # 3. File System Watchdog Collector (Chetna)
        fs_collector: Any = None
        if "fs" in enabled:
            try:
                from agent.collectors.fs_collector import FileSystemCollector
                fs_collector = FileSystemCollector(event_queue=self.event_queue, config=self.config)
                self.collectors.append(fs_collector)
                logger.info("[Agent] [PRODUCED] Registered FileSystemCollector")
            except ImportError:
                logger.info("[Agent] FileSystemCollector not yet present (owned by Chetna).")

        # 4. Wire inter-collector drive hand-off hook if both USB & FS collectors exist
        if usb_collector and fs_collector and hasattr(usb_collector, "register_drive_listener") and hasattr(fs_collector, "handle_drive_event"):
            usb_collector.register_drive_listener(fs_collector.handle_drive_event)
            logger.info("[Agent] [PRODUCED] Wrote USB -> FS drive arrival hook (docs/agent_interface.md)")

    def start(self) -> None:
        """Starts the sender and all active collectors."""
        logger.info("[Agent] [START] Starting telemetry sender...")
        self.sender.start()

        for collector in self.collectors:
            try:
                collector.start()
                logger.info("[Agent] [START] Started collector: %s", collector.name)
            except Exception as exc:
                logger.error("[Agent] Failed to start collector '%s': %s", collector.name, exc, exc_info=True)

        logger.info(
            "[Agent] [PRODUCED] ForensiTrace Agent is ACTIVE. Monitoring endpoint telemetry (%d active collector(s)).",
            len(self.collectors),
        )

    def stop(self) -> None:
        """Orderly, graceful shutdown of collectors and telemetry sender."""
        if self._shutdown_event:
            return
        self._shutdown_event = True

        logger.info("[Agent] [STOP] Initiating shutdown sequence...")

        # 1. Stop collectors first so no new telemetry is produced
        for collector in self.collectors:
            try:
                logger.info("[Agent] Stopping collector: %s...", collector.name)
                collector.stop()
            except Exception as exc:
                logger.warning("[Agent] Error stopping collector '%s': %s", collector.name, exc)

        # 2. Stop sender worker and flush remaining buffered events
        logger.info("[Agent] Stopping sender worker and flushing buffer...")
        self.sender.stop()

        logger.info("[Agent] [PRODUCED] ForensiTrace Agent shutdown complete.")

    def run_forever(self) -> None:
        """Main execution loop that keeps the agent process active until interrupted."""
        self.start()
        try:
            while not self._shutdown_event:
                time.sleep(1.0)
        except (KeyboardInterrupt, SystemExit):
            logger.info("[Agent] Interrupt signal received.")
        finally:
            self.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="ForensiTrace Endpoint Agent")
    parser.add_argument("--config", "-c", type=str, default=None, help="Path to JSON configuration file")
    parser.add_argument("--backend-url", "-b", type=str, default=None, help="Backend URL (e.g. http://127.0.0.1:8000)")
    parser.add_argument("--batch-size", type=int, default=None, help="Events per transmission batch")
    parser.add_argument("--flush-interval", type=float, default=None, help="Batch flush interval in seconds")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.backend_url:
        config.backend_url = args.backend_url
    if args.batch_size:
        config.batch_size = args.batch_size
    if args.flush_interval:
        config.flush_interval_seconds = args.flush_interval

    agent = ForensiTraceAgent(config=config)

    # Attach signal handlers for graceful shutdown
    def _sig_handler(sig, frame):
        logger.info("[Agent] Caught signal %s. Exiting gracefully...", sig)
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    agent.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
