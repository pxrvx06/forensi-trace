"""
ForensiTrace Agent Configuration Module
Author: Daksh (Agent Core Owner)
Contract: docs/agent_interface.md & docs/schema.md
"""

from __future__ import annotations

import os
import json
import socket
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

logger = logging.getLogger("forensitrace.agent.config")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


@dataclass
class AgentConfig:
    """
    Configuration parameters for the ForensiTrace endpoint agent.
    """
    # Backend connectivity
    backend_url: str = "http://127.0.0.1:8000"
    events_endpoint: str = "/events"

    # Batching and local memory buffer
    batch_size: int = 10
    flush_interval_seconds: float = 2.0
    max_buffer_size: int = 10000

    # Retry and backoff parameters
    retry_initial_delay: float = 1.0
    retry_max_delay: float = 30.0
    retry_backoff_factor: float = 2.0

    # Telemetry collectors
    enabled_collectors: List[str] = field(default_factory=lambda: ["eventlog", "usb", "fs"])

    # Windows Event Log target configuration
    eventlog_ids: List[int] = field(default_factory=lambda: [4688, 1102, 104])
    eventlog_channels: List[str] = field(default_factory=lambda: ["Security", "System"])

    # Endpoint host identifier
    host: str = field(default_factory=socket.gethostname)

    @property
    def full_events_url(self) -> str:
        """Returns the fully qualified URL for the POST /events endpoint."""
        base = self.backend_url.rstrip("/")
        endpoint = self.events_endpoint.lstrip("/")
        return f"{base}/{endpoint}"

    def to_dict(self) -> dict[str, Any]:
        """Serializes configuration to a dictionary."""
        return {
            "backend_url": self.backend_url,
            "events_endpoint": self.events_endpoint,
            "full_events_url": self.full_events_url,
            "batch_size": self.batch_size,
            "flush_interval_seconds": self.flush_interval_seconds,
            "max_buffer_size": self.max_buffer_size,
            "retry_initial_delay": self.retry_initial_delay,
            "retry_max_delay": self.retry_max_delay,
            "retry_backoff_factor": self.retry_backoff_factor,
            "enabled_collectors": self.enabled_collectors,
            "eventlog_ids": self.eventlog_ids,
            "eventlog_channels": self.eventlog_channels,
            "host": self.host,
        }


def load_config(config_path: Optional[str | Path] = None) -> AgentConfig:
    """
    Loads agent configuration from:
      1. Default configuration parameters.
      2. Optional JSON configuration file.
      3. Environment variable overrides (prefixed with FORENSITRACE_).

    Labeled logging provides visibility into inputs received and final configuration produced.
    """
    logger.info("[load_config] [RECEIVED] config_path='%s'", config_path)
    config = AgentConfig()

    # 1. Load from file if provided and present
    if config_path:
        target_file = Path(config_path)
        if target_file.is_file():
            try:
                with open(target_file, "r", encoding="utf-8") as f:
                    file_data = json.load(f)
                logger.info("[load_config] [RECEIVED] Read %d keys from '%s'", len(file_data), target_file)

                if "backend_url" in file_data:
                    config.backend_url = str(file_data["backend_url"])
                if "events_endpoint" in file_data:
                    config.events_endpoint = str(file_data["events_endpoint"])
                if "batch_size" in file_data:
                    config.batch_size = int(file_data["batch_size"])
                if "flush_interval_seconds" in file_data:
                    config.flush_interval_seconds = float(file_data["flush_interval_seconds"])
                if "max_buffer_size" in file_data:
                    config.max_buffer_size = int(file_data["max_buffer_size"])
                if "retry_initial_delay" in file_data:
                    config.retry_initial_delay = float(file_data["retry_initial_delay"])
                if "retry_max_delay" in file_data:
                    config.retry_max_delay = float(file_data["retry_max_delay"])
                if "retry_backoff_factor" in file_data:
                    config.retry_backoff_factor = float(file_data["retry_backoff_factor"])
                if "enabled_collectors" in file_data:
                    config.enabled_collectors = list(file_data["enabled_collectors"])
                if "eventlog_ids" in file_data:
                    config.eventlog_ids = [int(x) for x in file_data["eventlog_ids"]]
                if "eventlog_channels" in file_data:
                    config.eventlog_channels = list(file_data["eventlog_channels"])
                if "host" in file_data:
                    config.host = str(file_data["host"])
            except Exception as exc:
                logger.warning("[load_config] Failed to parse config file '%s': %s. Falling back.", target_file, exc)

    # 2. Environment variable overrides
    if "FORENSITRACE_BACKEND_URL" in os.environ:
        config.backend_url = os.environ["FORENSITRACE_BACKEND_URL"]
    if "FORENSITRACE_BATCH_SIZE" in os.environ:
        try:
            config.batch_size = int(os.environ["FORENSITRACE_BATCH_SIZE"])
        except ValueError:
            pass
    if "FORENSITRACE_FLUSH_INTERVAL" in os.environ:
        try:
            config.flush_interval_seconds = float(os.environ["FORENSITRACE_FLUSH_INTERVAL"])
        except ValueError:
            pass
    if "FORENSITRACE_MAX_BUFFER_SIZE" in os.environ:
        try:
            config.max_buffer_size = int(os.environ["FORENSITRACE_MAX_BUFFER_SIZE"])
        except ValueError:
            pass
    if "FORENSITRACE_ENABLED_COLLECTORS" in os.environ:
        collectors_raw = os.environ["FORENSITRACE_ENABLED_COLLECTORS"]
        config.enabled_collectors = [c.strip() for c in collectors_raw.split(",") if c.strip()]
    if "FORENSITRACE_HOST" in os.environ:
        config.host = os.environ["FORENSITRACE_HOST"]

    logger.info(
        "[load_config] [PRODUCED] Active config: backend_url='%s', batch_size=%d, flush_interval=%.1fs, collectors=%s",
        config.full_events_url,
        config.batch_size,
        config.flush_interval_seconds,
        config.enabled_collectors,
    )
    return config
