"""
ForensiTrace SQLite Database & Data-Access Layer
Author: Purva (Backend & Data Layer Owner)
Contract: docs/schema.md & Execution Plan Step 2
Provides SQLite storage for normalized events, reconstructed activities,
evidence provenance links, and time-window queries for Akash's correlation engine.
"""

from __future__ import annotations

import os
import json
import sqlite3
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from backend.schema import Event, Activity, ActivityEventLink

logger = logging.getLogger("forensitrace.db")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Default database location in backend/
DEFAULT_DB_PATH = Path(__file__).resolve().parent / "forensitrace.db"


def get_connection(db_path: Optional[Union[str, Path]] = None) -> sqlite3.Connection:
    """Creates a configured SQLite connection with foreign keys and row factory enabled."""
    target_path = Path(db_path or os.getenv("FORENSITRACE_DB_PATH", DEFAULT_DB_PATH))
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def db_session(db_path: Optional[Union[str, Path]] = None):
    """Context manager that yields a connection and guarantees it is closed on exit."""
    conn = get_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: Optional[Union[str, Path]] = None) -> None:
    """
    Initializes the ForensiTrace SQLite schema:
    1. events: Core normalized telemetry storage with PRIMARY KEY event_id
    2. activities: Correlated activity chains
    3. activity_events: Provenance link table linking activities to supporting events
    """
    logger.info("[init_db] [RECEIVED] Initializing database at '%s'", db_path or DEFAULT_DB_PATH)
    with db_session(db_path) as conn:
        cursor = conn.cursor()

        # 1. Events Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                ts_utc TEXT NOT NULL,
                host TEXT NOT NULL,
                user TEXT,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity TEXT NOT NULL,
                details_json TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_utc);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_entity ON events(entity);")

        # 2. Activities Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activities (
                activity_id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                ts_start_utc TEXT NOT NULL,
                ts_end_utc TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 1.0,
                narrative TEXT,
                created_at_utc TEXT NOT NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_activities_ts ON activities(ts_start_utc);")

        # 3. Evidence Provenance Link Table (activity_events)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_events (
                activity_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                PRIMARY KEY (activity_id, event_id),
                FOREIGN KEY (activity_id) REFERENCES activities(activity_id) ON DELETE CASCADE,
                FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ae_activity ON activity_events(activity_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ae_event ON activity_events(event_id);")

        conn.commit()
    logger.info("[init_db] [PRODUCED] Database tables (events, activities, activity_events) and indices ready")


def reset_db(db_path: Optional[Union[str, Path]] = None) -> None:
    """Clears all records from tables for fresh demonstration runs."""
    logger.warning("[reset_db] [RECEIVED] Resetting database at '%s'", db_path or DEFAULT_DB_PATH)
    with db_session(db_path) as conn:
        conn.execute("DELETE FROM activity_events;")
        conn.execute("DELETE FROM activities;")
        conn.execute("DELETE FROM events;")
        conn.commit()
    logger.info("[reset_db] [PRODUCED] All database tables cleared")


def _row_to_event_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Helper to convert a database row into an Event dictionary with parsed JSON fields."""
    d = dict(row)
    d["details"] = json.loads(d.pop("details_json"))
    d["raw"] = json.loads(d.pop("raw_json"))
    return d


def insert_event(event: Union[Event, dict[str, Any]], db_path: Optional[Union[str, Path]] = None) -> bool:
    """
    Inserts a single event using INSERT OR IGNORE.
    Returns True if inserted, False if duplicate was ignored.
    """
    if isinstance(event, dict):
        event_obj = Event(**event)
    else:
        event_obj = event

    now_utc = datetime.now(timezone.utc).isoformat()
    logger.debug("[insert_event] [RECEIVED] event_id='%s' source='%s'", event_obj.event_id, event_obj.source)

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO events (
                event_id, source, ts_utc, host, user, action, entity_type, entity,
                details_json, raw_json, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            event_obj.event_id,
            event_obj.source.value,
            event_obj.ts_utc,
            event_obj.host,
            event_obj.user,
            event_obj.action.value,
            event_obj.entity_type.value,
            event_obj.entity,
            json.dumps(event_obj.details),
            json.dumps(event_obj.raw),
            now_utc
        ))
        conn.commit()
        inserted = (cursor.rowcount > 0)

    if inserted:
        logger.info("[insert_event] [PRODUCED] Stored event_id='%s'", event_obj.event_id)
    else:
        logger.info("[insert_event] [PRODUCED] Ignored duplicate event_id='%s'", event_obj.event_id)
    return inserted


def insert_events_batch(
    events: list[Union[Event, dict[str, Any]]],
    db_path: Optional[Union[str, Path]] = None
) -> tuple[int, int]:
    """
    Batch inserts events inside a single transaction using INSERT OR IGNORE.
    Returns (inserted_count, ignored_duplicate_count).
    """
    logger.info("[insert_events_batch] [RECEIVED] Received batch of %d events", len(events))
    if not events:
        return (0, 0)

    now_utc = datetime.now(timezone.utc).isoformat()
    rows = []
    for item in events:
        e = Event(**item) if isinstance(item, dict) else item
        rows.append((
            e.event_id,
            e.source.value,
            e.ts_utc,
            e.host,
            e.user,
            e.action.value,
            e.entity_type.value,
            e.entity,
            json.dumps(e.details),
            json.dumps(e.raw),
            now_utc
        ))

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.executemany("""
            INSERT OR IGNORE INTO events (
                event_id, source, ts_utc, host, user, action, entity_type, entity,
                details_json, raw_json, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, rows)
        conn.commit()
        inserted_count = cursor.rowcount
        ignored_count = len(rows) - inserted_count

    logger.info(
        "[insert_events_batch] [PRODUCED] Ingested batch: %d inserted, %d duplicate(s) ignored",
        inserted_count, ignored_count
    )
    return (inserted_count, ignored_count)


def get_event_by_id(event_id: str, db_path: Optional[Union[str, Path]] = None) -> Optional[dict[str, Any]]:
    """Retrieves an event by event_id."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events WHERE event_id = ?;", (event_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return _row_to_event_dict(row)


def get_events(
    source: Optional[str] = None,
    action: Optional[str] = None,
    host: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db_path: Optional[Union[str, Path]] = None
) -> list[dict[str, Any]]:
    """Retrieves events matching optional filters with pagination, ordered chronologically."""
    query = "SELECT * FROM events WHERE 1=1"
    params: list[Any] = []

    if source:
        query += " AND source = ?"
        params.append(source)
    if action:
        query += " AND action = ?"
        params.append(action)
    if host:
        query += " AND host = ?"
        params.append(host)

    query += " ORDER BY ts_utc ASC LIMIT ? OFFSET ?;"
    params.extend([limit, offset])

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [_row_to_event_dict(r) for r in rows]


def get_events_in_window(
    ts_start_utc: str,
    ts_end_utc: str,
    sources: Optional[list[str]] = None,
    actions: Optional[list[str]] = None,
    db_path: Optional[Union[str, Path]] = None
) -> list[dict[str, Any]]:
    """
    CRITICAL HANDOFF CONTRACT FOR AKASH'S CORRELATION ENGINE:
    Retrieves events within [ts_start_utc, ts_end_utc] sorted by timestamp ascending.
    """
    logger.debug("[get_events_in_window] [RECEIVED] Window: %s to %s", ts_start_utc, ts_end_utc)
    query = "SELECT * FROM events WHERE ts_utc >= ? AND ts_utc <= ?"
    params: list[Any] = [ts_start_utc, ts_end_utc]

    if sources:
        placeholders = ",".join("?" for _ in sources)
        query += f" AND source IN ({placeholders})"
        params.extend(sources)

    if actions:
        placeholders = ",".join("?" for _ in actions)
        query += f" AND action IN ({placeholders})"
        params.extend(actions)

    query += " ORDER BY ts_utc ASC;"

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        results = [_row_to_event_dict(r) for r in rows]

    logger.debug("[get_events_in_window] [PRODUCED] Found %d event(s) in window", len(results))
    return results


def insert_activity(
    activity: Union[Activity, dict[str, Any]],
    supporting_events: list[Union[ActivityEventLink, dict[str, Any]]],
    db_path: Optional[Union[str, Path]] = None
) -> str:
    """
    Inserts an activity and its provenance links into activity_events inside a transaction.
    """
    act = Activity(**activity) if isinstance(activity, dict) else activity
    now_utc = datetime.now(timezone.utc).isoformat()
    logger.info("[insert_activity] [RECEIVED] activity_id='%s' rule_id='%s'", act.activity_id, act.rule_id)

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO activities (
                activity_id, rule_id, rule_name, ts_start_utc, ts_end_utc,
                confidence, narrative, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            act.activity_id,
            act.rule_id,
            act.rule_name,
            act.ts_start_utc,
            act.ts_end_utc,
            act.confidence,
            act.narrative,
            now_utc
        ))

        # Insert provenance link rows
        link_rows = []
        for link in supporting_events:
            l_obj = ActivityEventLink(**link) if isinstance(link, dict) else link
            link_rows.append((l_obj.activity_id, l_obj.event_id, l_obj.rule_id, l_obj.reason))

        if link_rows:
            cursor.executemany("""
                INSERT OR REPLACE INTO activity_events (
                    activity_id, event_id, rule_id, reason
                ) VALUES (?, ?, ?, ?);
            """, link_rows)

        conn.commit()

    logger.info(
        "[insert_activity] [PRODUCED] Stored activity '%s' with %d supporting evidence link(s)",
        act.activity_id, len(supporting_events)
    )
    return act.activity_id


def get_activities(
    limit: int = 100,
    offset: int = 0,
    db_path: Optional[Union[str, Path]] = None
) -> list[dict[str, Any]]:
    """Retrieves all activities ordered by start time descending."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM activities ORDER BY ts_start_utc DESC LIMIT ? OFFSET ?;
        """, (limit, offset))
        return [dict(r) for r in cursor.fetchall()]


def get_activity_by_id(
    activity_id: str,
    include_evidence: bool = True,
    db_path: Optional[Union[str, Path]] = None
) -> Optional[dict[str, Any]]:
    """
    Retrieves an activity by ID, including its full evidence chain (provenance).
    """
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM activities WHERE activity_id = ?;", (activity_id,))
        act_row = cursor.fetchone()
        if not act_row:
            return None

        activity = dict(act_row)
        if include_evidence:
            cursor.execute("""
                SELECT ae.event_id, ae.rule_id, ae.reason, e.*
                FROM activity_events ae
                JOIN events e ON ae.event_id = e.event_id
                WHERE ae.activity_id = ?
                ORDER BY e.ts_utc ASC;
            """, (activity_id,))
            evidence = []
            for row in cursor.fetchall():
                ev_dict = dict(row)
                ev_dict["details"] = json.loads(ev_dict.pop("details_json"))
                ev_dict["raw"] = json.loads(ev_dict.pop("raw_json"))
                evidence.append(ev_dict)
            activity["evidence_chain"] = evidence

        return activity
