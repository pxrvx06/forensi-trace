"""
ForensiTrace FastAPI Ingestion & Presentation API
Author: Purva (Backend & Data Layer Owner)
Contract: docs/schema.md, docs/agent_interface.md & Step 4 of Execution Plan
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Union

from fastapi import FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.schema import Event, EventBatch
from backend.reports import generate_activity_pdf_bytes
from backend.db import (
    init_db,
    reset_db,
    insert_event,
    insert_events_batch,
    get_event_by_id,
    get_events,
    get_events_in_window,
    insert_activity,
    get_activities,
    get_activity_by_id,
    get_timeline
)

logger = logging.getLogger("forensitrace.api")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

app = FastAPI(
    title="ForensiTrace Backend Ingestion API",
    description="Centralized ingestion, query, and evidence provenance API for ForensiTrace.",
    version="1.0.0"
)

# Enable CORS for Chetna's React dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    """Ensure database tables and indices are initialized on startup."""
    logger.info("[startup_event] [RECEIVED] Server starting up. Initializing SQLite tables...")
    init_db()
    logger.info("[startup_event] [PRODUCED] Database initialized successfully.")


# ---------------------------------------------------------
# Health Check Endpoint
# ---------------------------------------------------------
@app.get("/health", status_code=status.HTTP_200_OK, tags=["Health"])
def health_check():
    """Health check endpoint to verify backend service readiness."""
    now_utc = datetime.now(timezone.utc).isoformat()
    logger.info("[health_check] [RECEIVED] Health check query -> [PRODUCED] Status OK")
    return {
        "status": "ok",
        "service": "ForensiTrace Ingestion & Forensics API",
        "timestamp_utc": now_utc
    }


# ---------------------------------------------------------
# Event Ingestion & Query Endpoints (Step 4)
# ---------------------------------------------------------
class IngestionResponse(BaseModel):
    status: str = "success"
    received: int
    inserted: int
    duplicates_ignored: int
    # Aliases for Daksh's agent interface contract (docs/agent_interface.md)
    ingested: int
    duplicates: int


@app.post(
    "/events",
    response_model=IngestionResponse,
    status_code=status.HTTP_200_OK,
    tags=["Events"]
)
def ingest_events(payload: Union[EventBatch, Event, List[Event]]):
    """
    Batched event ingestion endpoint for Daksh's agent HTTP sender.
    Supports:
    - EventBatch: {"events": [...], "batch_size": ...}
    - Direct list of events: [...]
    - Single Event object: {...}
    Duplicates (matching event_id) are safely ignored without error via INSERT OR IGNORE.
    """
    if isinstance(payload, EventBatch):
        events_list = payload.events
    elif isinstance(payload, list):
        events_list = payload
    else:
        events_list = [payload]

    logger.info("[ingest_events] [RECEIVED] Ingest request with %d event(s)", len(events_list))
    inserted, ignored = insert_events_batch(events_list)

    # Live event-to-analysis integration: correlate newly ingested events
    if inserted > 0 and events_list:
        try:
            from datetime import datetime, timedelta, timezone
            from backend.db import get_events_in_window, insert_activity
            from engine.correlator import CorrelationEngine, parse_iso_utc
            from engine.ml.scoring import AnomalyScorer

            timestamps = []
            for ev in events_list:
                ts_str = ev.ts_utc if hasattr(ev, "ts_utc") else ev.get("ts_utc")
                if ts_str:
                    timestamps.append(parse_iso_utc(ts_str))

            if timestamps:
                t_min = min(timestamps) - timedelta(minutes=20)
                t_max = max(timestamps) + timedelta(minutes=1)
                ts_start = t_min.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                ts_end = t_max.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                window_events = get_events_in_window(ts_start, ts_end)
            else:
                window_events = events_list

            artifacts_dir = Path(__file__).resolve().parent.parent / "engine" / "ml" / "artifacts"
            scorer = AnomalyScorer(artifacts_dir=artifacts_dir) if artifacts_dir.is_dir() else None
            engine = CorrelationEngine(ml_scorer=scorer)
            correlated = engine.correlate_events(window_events)
            for item in correlated:
                insert_activity(item.activity, item.links)
            logger.info(
                "[ingest_events] [CORRELATED] Persisted %d activity chain(s) from %d window event(s)",
                len(correlated), len(window_events),
            )
        except Exception as exc:
            logger.error("[ingest_events] [CORRELATION_ERROR] Live correlation failed: %s", exc)

    response = IngestionResponse(
        status="success",
        received=len(events_list),
        inserted=inserted,
        duplicates_ignored=ignored,
        ingested=inserted,
        duplicates=ignored
    )
    logger.info(
        "[ingest_events] [PRODUCED] Finished ingestion: %d inserted, %d ignored",
        inserted, ignored
    )
    return response


@app.get("/events", tags=["Events"])
def list_events(
    source: Optional[str] = Query(None, description="Filter by source: usb, fs, eventlog"),
    action: Optional[str] = Query(None, description="Filter by action name"),
    host: Optional[str] = Query(None, description="Filter by machine hostname"),
    limit: int = Query(100, ge=1, le=1000, description="Max events to return"),
    offset: int = Query(0, ge=0, description="Pagination offset")
):
    """Query normalized events chronologically with optional filters."""
    logger.info(
        "[list_events] [RECEIVED] Filters source='%s' action='%s' host='%s' limit=%d offset=%d",
        source, action, host, limit, offset
    )
    events = get_events(source=source, action=action, host=host, limit=limit, offset=offset)
    logger.info("[list_events] [PRODUCED] Returning %d event(s)", len(events))
    return {
        "count": len(events),
        "limit": limit,
        "offset": offset,
        "events": events
    }


@app.get("/events/window", tags=["Events"])
def query_events_window(
    ts_start_utc: str = Query(..., description="Start of time window (ISO 8601 UTC)"),
    ts_end_utc: str = Query(..., description="End of time window (ISO 8601 UTC)"),
    sources: Optional[List[str]] = Query(None, description="Optional source filters"),
    actions: Optional[List[str]] = Query(None, description="Optional action filters")
):
    """
    Query events inside a specific time window.
    Designed for Akash's correlation engine to evaluate sliding time-window rules.
    """
    logger.info(
        "[query_events_window] [RECEIVED] Window [%s to %s] sources=%s",
        ts_start_utc, ts_end_utc, sources
    )
    events = get_events_in_window(
        ts_start_utc=ts_start_utc,
        ts_end_utc=ts_end_utc,
        sources=sources,
        actions=actions
    )
    logger.info("[query_events_window] [PRODUCED] Returning %d window event(s)", len(events))
    return {
        "ts_start_utc": ts_start_utc,
        "ts_end_utc": ts_end_utc,
        "count": len(events),
        "events": events
    }


@app.get("/events/{event_id}", tags=["Events"])
def get_single_event(event_id: str):
    """Retrieve details and raw evidence of an individual event by ID."""
    logger.info("[get_single_event] [RECEIVED] Query for event_id='%s'", event_id)
    event = get_event_by_id(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with id '{event_id}' not found"
        )
    logger.info("[get_single_event] [PRODUCED] Found event_id='%s'", event_id)
    return event


# ---------------------------------------------------------
# Interactive Timeline Endpoint (Step 1 of Phase 3 / docs/ml.md)
# ---------------------------------------------------------
@app.get("/timeline", tags=["Timeline"])
def get_unified_timeline(
    limit: int = Query(100, ge=1, le=1000, description="Max timeline items to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    source: Optional[str] = Query(None, description="Filter by event source: usb, fs, eventlog"),
    order: str = Query("asc", pattern="^(asc|desc)$", description="Sort order by UTC timestamp (asc or desc)")
):
    """
    Unified chronological timeline endpoint for Chetna's React dashboard.
    Merges normalized events and reconstructed activities in strict UTC timestamp order.
    """
    logger.info("[get_unified_timeline] [RECEIVED] limit=%d offset=%d source=%s order=%s", limit, offset, source, order)
    timeline = get_timeline(limit=limit, offset=offset, source=source, order=order)
    logger.info("[get_unified_timeline] [PRODUCED] Returning %d timeline items", len(timeline))
    return {
        "count": len(timeline),
        "limit": limit,
        "offset": offset,
        "timeline": timeline
    }


# ---------------------------------------------------------
# Activities & Evidence Provenance Endpoints
# ---------------------------------------------------------
@app.get("/activities", tags=["Activities"])
def list_activities(
    limit: int = Query(100, ge=1, le=1000, description="Max activities to return"),
    offset: int = Query(0, ge=0, description="Pagination offset")
):
    """Query reconstructed activities ordered chronologically descending."""
    logger.info("[list_activities] [RECEIVED] limit=%d offset=%d", limit, offset)
    activities = get_activities(limit=limit, offset=offset)
    logger.info("[list_activities] [PRODUCED] Returning %d activity record(s)", len(activities))
    return {
        "count": len(activities),
        "limit": limit,
        "offset": offset,
        "activities": activities
    }


@app.get("/activities/{activity_id}", tags=["Activities"])
def get_single_activity(activity_id: str):
    """Retrieve details and complete evidence provenance chain of an activity by ID."""
    logger.info("[get_single_activity] [RECEIVED] Query for activity_id='%s'", activity_id)
    activity = get_activity_by_id(activity_id, include_evidence=True)
    if not activity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Activity with id '{activity_id}' not found"
        )
    logger.info("[get_single_activity] [PRODUCED] Found activity_id='%s'", activity_id)
    return activity


# ---------------------------------------------------------
# Forensic PDF Report Endpoint (Step 4 of Phase 3 / docs/ml.md)
# ---------------------------------------------------------
@app.get("/report/{activity_id}", tags=["Reports"])
def download_activity_report(activity_id: str):
    """
    Generates and streams a standardized 3-page Forensic Investigation Report PDF
    for the requested activity ID (Page 1: Summary & Threat Badge, Page 2: Timeline Table,
    Page 3: Unedited Raw Evidence Appendix).
    """
    logger.info("[download_activity_report] [RECEIVED] PDF report request for activity_id='%s'", activity_id)
    activity = get_activity_by_id(activity_id, include_evidence=True)
    if not activity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Activity with id '{activity_id}' not found"
        )

    pdf_bytes = generate_activity_pdf_bytes(activity)
    safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", activity_id)
    filename = f"ForensiTrace_Report_{safe_id}.pdf"
    logger.info("[download_activity_report] [PRODUCED] Streaming %d bytes as '%s'", len(pdf_bytes), filename)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


# ---------------------------------------------------------
# Demo & Administration Helper Endpoint
# ---------------------------------------------------------
@app.post("/reset", tags=["Admin"])
def reset_database():
    """Resets the database tables for clean test runs and scenario demonstrations."""
    logger.warning("[reset_database] [RECEIVED] Database reset request received")
    reset_db()
    logger.info("[reset_database] [PRODUCED] Database reset complete")
    return {"status": "success", "message": "All database tables cleared"}
