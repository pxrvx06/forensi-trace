"""
ForensiTrace File-System Telemetry Collector
Author: Chetna (USB and File-System Collectors Owner)
Contract: docs/schema.md & docs/agent_interface.md
Scope: Step 2 (Page 6) - File-system collector with watchdog: create, modify, delete, move; ignore temp-file noise.
"""

from __future__ import annotations

import os
import time
import queue
import hashlib
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEvent,
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileDeletedEvent,
    FileMovedEvent,
)

from agent.collectors.base import BaseCollector

# Configure labeled logger per project rules
logger = logging.getLogger("forensitrace.agent.collector.fs")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Temp-file and noise filters to protect correlation engine from disk I/O floods
IGNORED_EXTENSIONS: Set[str] = {
    ".tmp",
    ".part",
    ".crdownload",
    ".bak",
    ".swp",
    ".swo",
    ".log",
    ".dat",
    ".temp",
    ".partial",
    ".laccdb",
    ".ldb",
}

IGNORED_PREFIXES: Tuple[str, ...] = (
    "~$",         # Microsoft Office temporary lock files
    ".~",         # Temporary / lock prefixes
    "tmp",        # Standard temp prefixes
    "temp",
    ".~lock.",    # LibreOffice / OpenOffice lock files
    "._",         # macOS metadata on FAT/exFAT
    "__",
)

IGNORED_FILENAMES: Set[str] = {
    "desktop.ini",
    "thumbs.db",
    "autorun.inf",
    ".ds_store",
    "bootmgr",
    "bootsect.bak",
}

IGNORED_PATH_PATTERNS: Tuple[str, ...] = (
    "$recycle.bin",
    "system volume information",
    ".git\\",
    ".gemini\\",
)


def get_iso_utc_timestamp() -> str:
    """Returns current UTC timestamp in ISO 8601 format with millisecond precision and 'Z'."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def canonicalize_windows_path(path: str) -> str:
    """
    Normalizes a filesystem path to standard Windows formatting:
    - Standard backslashes (\\)
    - Uppercase drive letter (e.g., E:\\reports\\payload.exe)
    - Resolves redundant dots and relative segments
    """
    if not path:
        return ""
    norm = os.path.normpath(str(path)).replace("/", "\\")
    if len(norm) >= 2 and norm[1] == ":":
        norm = norm[0].upper() + norm[1:]
    return norm


def is_ignored_path(path: str, is_directory: bool = False) -> bool:
    """
    Evaluates whether a filesystem path constitutes noise:
    - Directories themselves (we monitor file payloads)
    - System volume folders ($RECYCLE.BIN, System Volume Information)
    - Office/browser temporary and partial download files
    """
    if is_directory:
        return True

    clean_path = canonicalize_windows_path(path)
    lower_path = clean_path.lower()

    # 1. System paths and volume metadata
    for pattern in IGNORED_PATH_PATTERNS:
        if pattern in lower_path:
            logger.debug("[is_ignored_path] [IGNORED] System/temp path: %s", clean_path)
            return True

    filename = os.path.basename(clean_path)
    lower_filename = filename.lower()

    # 2. Ignored exact filenames
    if lower_filename in IGNORED_FILENAMES:
        logger.debug("[is_ignored_path] [IGNORED] System filename: %s", clean_path)
        return True

    # 3. Ignored prefixes (e.g. ~$document.docx)
    if any(lower_filename.startswith(prefix) for prefix in IGNORED_PREFIXES):
        logger.debug("[is_ignored_path] [IGNORED] Temp file prefix: %s", clean_path)
        return True

    # 4. Ignored extensions (e.g. .tmp, .crdownload)
    _, ext = os.path.splitext(lower_filename)
    if ext in IGNORED_EXTENSIONS or lower_filename.endswith("~"):
        logger.debug("[is_ignored_path] [IGNORED] Temp file extension: %s", clean_path)
        return True

    return False


def build_fs_event(
    action: str,
    file_path: str,
    host: str,
    dest_path: Optional[str] = None,
    is_directory: bool = False,
) -> Dict[str, Any]:
    """
    Constructs a normalized file-system telemetry event strictly adhering to docs/schema.md.
    """
    source = "fs"
    canonical_path = canonicalize_windows_path(file_path)
    ts_utc = get_iso_utc_timestamp()

    # Extract drive letter
    drive_letter = ""
    if len(canonical_path) >= 2 and canonical_path[1] == ":":
        drive_letter = canonical_path[:2]

    file_name = os.path.basename(canonical_path)
    _, ext = os.path.splitext(file_name)

    # Safely obtain file size if file exists on disk
    file_size_bytes = 0
    try:
        if os.path.isfile(canonical_path):
            file_size_bytes = os.path.getsize(canonical_path)
    except (OSError, PermissionError):
        file_size_bytes = 0

    # Deterministic event_id recipe: SHA256("{source}|{raw_record_id}|{ts_utc}")
    raw_record_id = f"{action}|{canonical_path}"
    seed = f"{source}|{raw_record_id}|{ts_utc}"
    event_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()

    # Source-specific details dictionary
    details: Dict[str, Any] = {
        "raw_record_id": raw_record_id,
        "drive_letter": drive_letter,
        "file_path": canonical_path,
        "file_name": file_name,
        "extension": ext.lower(),
        "file_size_bytes": file_size_bytes,
        "is_directory": is_directory,
    }

    raw_event_type = {
        "FILE_CREATED": "created",
        "FILE_MODIFIED": "modified",
        "FILE_DELETED": "deleted",
        "FILE_MOVED": "moved",
    }.get(action, action.lower())

    raw_payload: Dict[str, Any] = {
        "event_type": raw_event_type,
        "src_path": canonical_path,
        "is_directory": is_directory,
    }

    if dest_path and action == "FILE_MOVED":
        clean_dest = canonicalize_windows_path(dest_path)
        details["dest_path"] = clean_dest
        raw_payload["dest_path"] = clean_dest

    event = {
        "event_id": event_id,
        "source": source,
        "ts_utc": ts_utc,
        "host": host,
        "user": None,  # FS watchdog notifications lack reliable OS user attribution
        "action": action,
        "entity_type": "file",
        "entity": canonical_path,
        "details": details,
        "raw": raw_payload,
    }

    logger.debug("[build_fs_event] [PRODUCED] Built %s event_id='%s' for entity='%s'", action, event_id, canonical_path)
    return event


class ForensiTraceWatchdogHandler(FileSystemEventHandler):
    """
    Receives raw OS filesystem mutations from watchdog and forwards them
    to FileSystemCollector for noise filtering and debouncing.
    """

    def __init__(self, collector: FileSystemCollector) -> None:
        super().__init__()
        self.collector = collector

    def on_created(self, event: FileSystemEvent) -> None:
        self.collector.process_fs_event("FILE_CREATED", event.src_path, is_directory=event.is_directory)

    def on_modified(self, event: FileSystemEvent) -> None:
        self.collector.process_fs_event("FILE_MODIFIED", event.src_path, is_directory=event.is_directory)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self.collector.process_fs_event("FILE_DELETED", event.src_path, is_directory=event.is_directory)

    def on_moved(self, event: FileMovedEvent) -> None:
        self.collector.process_fs_event(
            "FILE_MOVED",
            event.src_path,
            is_directory=event.is_directory,
            dest_path=event.dest_path,
        )


class FileSystemCollector(BaseCollector):
    """
    ForensiTrace File-System Telemetry Collector.
    Monitors removable drive volumes using watchdog.
    Filters out temporary file noise and debounces burst mutations so that
    copying a file produces a single clean FILE_CREATED event.
    """

    def __init__(
        self,
        event_queue: queue.Queue[Dict[str, Any]],
        config: Optional[Any] = None,
        debounce_seconds: float = 1.0,
        modify_suppression_window: float = 1.5,
        watch_paths: Optional[List[str]] = None,
    ) -> None:
        super().__init__(event_queue, config, name="FileSystemCollector")
        self.debounce_seconds = debounce_seconds
        self.modify_suppression_window = modify_suppression_window
        self.host = getattr(config, "host", os.environ.get("COMPUTERNAME", "WIN-FORENSIC-01")) if config else "WIN-FORENSIC-01"

        self.initial_watch_paths = list(watch_paths) if watch_paths else []
        self.observer: Optional[Observer] = None
        self.handler = ForensiTraceWatchdogHandler(self)
        self.active_watches: Dict[str, Any] = {}

        # Debounce state
        self._recent_events: Dict[Tuple[str, str], float] = {}
        self._recent_creations: Dict[str, float] = {}
        self._lock = threading.Lock()

        logger.info(
            "[%s] [RECEIVED] Initialized FileSystemCollector: debounce=%.1fs, modify_suppression=%.1fs, host='%s'",
            self.name,
            self.debounce_seconds,
            self.modify_suppression_window,
            self.host,
        )

    def start(self) -> None:
        """
        Starts the watchdog background observer thread.
        Non-blocking: observer manages its own worker threads.
        """
        with self._lock:
            if self._running:
                logger.warning("[%s] start() called but collector is already running.", self.name)
                return

            self._running = True
            self.observer = Observer()

            # Schedule any configured initial directories
            for path in self.initial_watch_paths:
                self._schedule_watch(path)

            try:
                self.observer.start()
                logger.info(
                    "[%s] [START] [PRODUCED] Watchdog observer started (%d active watch(es)).",
                    self.name,
                    len(self.active_watches),
                )
            except Exception as exc:
                logger.error("[%s] Failed to start watchdog observer: %s", self.name, exc, exc_info=True)

    def stop(self) -> None:
        """
        Gracefully terminates the watchdog observer and releases filesystem handles.
        Idempotent and safe to call multiple times.
        """
        with self._lock:
            if not self._running:
                return

            logger.info("[%s] [STOP] Stopping FileSystemCollector observer...", self.name)
            self._running = False

            if self.observer:
                try:
                    self.observer.stop()
                    self.observer.join(timeout=2.0)
                except Exception as exc:
                    logger.debug("[%s] Error stopping watchdog observer: %s", self.name, exc)
                self.observer = None

            self.active_watches.clear()
            self._recent_events.clear()
            self._recent_creations.clear()
            logger.info("[%s] [PRODUCED] FileSystemCollector stopped.", self.name)

    @property
    def is_alive(self) -> bool:
        """Returns True if the observer thread is active."""
        return self._running and (self.observer is not None and self.observer.is_alive())

    # ------------------------------------------------------------------
    # Inter-Collector Hand-off Hook (per docs/agent_interface.md Section 3)
    # ------------------------------------------------------------------

    def handle_drive_event(self, drive_letter: str, event_type: str) -> None:
        """
        Hook invoked by Chetna's USBCollector when a removable drive is attached or removed.
        
        :param drive_letter: Uppercase Windows drive string, e.g. "E:"
        :param event_type: "ATTACHED" | "REMOVED"
        """
        letter = drive_letter.upper()
        if not letter.endswith(":"):
            letter = f"{letter}:"

        logger.info("[%s] [HOOK] [RECEIVED] Received drive event: drive='%s', action='%s'", self.name, letter, event_type)

        if event_type == "ATTACHED":
            root_path = f"{letter}\\"
            self.watch_directory(root_path)
        elif event_type == "REMOVED":
            root_path = f"{letter}\\"
            self.unwatch_directory(root_path)

    def watch_directory(self, dir_path: str) -> bool:
        """Dynamically attaches a watchdog observer to the specified directory."""
        with self._lock:
            return self._schedule_watch(dir_path)

    def unwatch_directory(self, dir_path: str) -> bool:
        """Dynamically detaches a watchdog observer from the specified directory."""
        with self._lock:
            clean_path = canonicalize_windows_path(dir_path)
            watch = self.active_watches.pop(clean_path, None)
            if watch and self.observer:
                try:
                    self.observer.unschedule(watch)
                    logger.info("[%s] [UNSCHEDULE] [PRODUCED] Unscheduled observer for '%s'", self.name, clean_path)
                    return True
                except Exception as exc:
                    logger.warning("[%s] Failed to unschedule watch for '%s': %s", self.name, clean_path, exc)
            return False

    def _schedule_watch(self, dir_path: str) -> bool:
        """Internal helper to schedule a watch on an existing path."""
        clean_path = canonicalize_windows_path(dir_path)
        if clean_path in self.active_watches:
            logger.debug("[%s] Watch already active for: %s", self.name, clean_path)
            return True

        if not os.path.isdir(clean_path):
            logger.warning("[%s] [SCHEDULE] Directory does not exist yet: %s. Skipping.", self.name, clean_path)
            return False

        if self.observer and self._running:
            try:
                watch = self.observer.schedule(self.handler, clean_path, recursive=True)
                self.active_watches[clean_path] = watch
                logger.info("[%s] [SCHEDULE] [PRODUCED] Scheduled watchdog observer on '%s'", self.name, clean_path)
                return True
            except Exception as exc:
                logger.error("[%s] [SCHEDULE] Failed to schedule watch on '%s': %s", self.name, clean_path, exc)
                return False
        return False

    # ------------------------------------------------------------------
    # Telemetry Processing, Filtering & Debouncing
    # ------------------------------------------------------------------

    def process_fs_event(
        self,
        action: str,
        src_path: str,
        is_directory: bool = False,
        dest_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Filters noise, debounces rapid duplicate events, constructs normalized schema payload,
        and emits to the agent central queue.
        """
        # 1. Filter out directory creation & temp/system noise
        if is_ignored_path(src_path, is_directory=is_directory):
            return None

        canonical_path = canonicalize_windows_path(src_path)
        now = time.monotonic()

        with self._lock:
            # 2. Debounce burst: suppress subsequent FILE_MODIFIED events following FILE_CREATED
            if action == "FILE_MODIFIED":
                last_created = self._recent_creations.get(canonical_path)
                if last_created and (now - last_created < self.modify_suppression_window):
                    logger.debug(
                        "[%s] [DEBOUNCE] Suppressed FILE_MODIFIED following FILE_CREATED on '%s' (delta=%.3fs)",
                        self.name,
                        canonical_path,
                        now - last_created,
                    )
                    return None

            # 3. Debounce identical duplicate actions on same path
            key = (action, canonical_path)
            last_seen = self._recent_events.get(key)
            if last_seen and (now - last_seen < self.debounce_seconds):
                logger.debug(
                    "[%s] [DEBOUNCE] Suppressed duplicate %s on '%s' (delta=%.3fs)",
                    self.name,
                    action,
                    canonical_path,
                    now - last_seen,
                )
                return None

            self._recent_events[key] = now
            if action == "FILE_CREATED":
                self._recent_creations[canonical_path] = now

            # Clean expired entries periodically
            if len(self._recent_events) > 500:
                cutoff = now - 10.0
                self._recent_events = {k: t for k, t in self._recent_events.items() if t > cutoff}
                self._recent_creations = {k: t for k, t in self._recent_creations.items() if t > cutoff}

        logger.info("[%s] [RECEIVED] File event: action='%s', path='%s'", self.name, action, canonical_path)

        # 4. Build and emit normalized schema event
        event = build_fs_event(
            action=action,
            file_path=canonical_path,
            host=self.host,
            dest_path=dest_path,
            is_directory=is_directory,
        )

        self.emit(event)
        logger.info(
            "[%s] [PRODUCED] Emitted %s event_id='%s' for '%s'",
            self.name,
            action,
            event["event_id"],
            canonical_path,
        )
        return event

    # ------------------------------------------------------------------
    # Simulation & Verification Interface (For Automated Tests & Demos)
    # ------------------------------------------------------------------

    def simulate_event(
        self,
        action: str,
        src_path: str,
        is_directory: bool = False,
        dest_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Simulates a file system event directly (used in tests and verification)."""
        return self.process_fs_event(
            action=action,
            src_path=src_path,
            is_directory=is_directory,
            dest_path=dest_path,
        )
