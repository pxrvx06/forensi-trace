# ForensiTrace Backend & Data Subsystem

> **Owner:** Purva (Backend, Data Layer & Report Lead)  
> **Contract References:** [`docs/schema.md`](../docs/schema.md), [`docs/api.md`](../docs/api.md), [`docs/agent_interface.md`](../docs/agent_interface.md)  
> **Status:** Phase 2 Complete — Production-Grade SQLite & FastAPI Ingestion Pipeline

---

## 1. Subsystem Architecture

The ForensiTrace Backend provides the centralized storage, normalization, and query infrastructure for the entire forensic investigation pipeline. It receives high-throughput batched telemetry from the endpoint agent, eliminates duplicates, normalizes raw Windows OS structures into a frozen schema, and exposes query interfaces for Akash's correlation engine and Chetna's React dashboard.

```
                    ┌──────────────────────────────────────────────┐
                    │       Endpoint Agent (Daksh & Chetna)        │
                    │   EventLog  │  USB Collector  │ FS Watchdog  │
                    └──────────────────────┬───────────────────────┘
                                           │ HTTP POST /events (Batches)
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │           FastAPI Ingestion Engine           │
                    │   • Route Validation (Pydantic models)       │
                    │   • Telemetry Normalizers (backend/)         │
                    └──────────────────────┬───────────────────────┘
                                           │ INSERT OR IGNORE
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │            SQLite Storage Layer              │
                    │  • events (Indexed on ts_utc, source, etc.)  │
                    │  • activities (Correlated activity chains)   │
                    │  • activity_events (Evidence provenance link)│
                    └──────────────┬───────────────────────────────┘
                                   │
                ┌──────────────────┴──────────────────┐
                ▼                                     ▼
┌───────────────────────────────┐     ┌───────────────────────────────┐
│  Correlation Engine (Akash)   │     │   React Dashboard (Chetna)    │
│  • GET /events/window         │     │  • GET /events                │
│  • POST /activities           │     │  • GET /activities/{id}       │
└───────────────────────────────┘     └───────────────────────────────┘
```

---

## 2. Directory Structure

```
backend/
├── main.py                  # FastAPI application with ingestion & query endpoints
├── schema.py                # Frozen Pydantic models & validation rules
├── normalizers.py           # Multi-source telemetry normalizers (USB, FS, EventLog)
├── db.py                    # SQLite data-access layer & connection lifecycle manager
├── forensitrace.db          # SQLite database file (created on runtime, git-ignored)
├── README.md                # Subsystem architecture & developer guide
└── tests/                   # Comprehensive automated test suite
    ├── test_db.py           # Database CRUD, deduplication, and window query tests
    ├── test_normalizers.py  # Normalizer validation using real collector sample fixtures
    └── test_api.py          # FastAPI endpoint integration tests via TestClient
```

---

## 3. Database Schema

The database is built on SQLite with `PRAGMA foreign_keys = ON;` and structured into three relational tables:

### 3.1. `events` Table (Telemetry Storage)
Stores all normalized telemetry records received from endpoints.
```sql
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
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_utc);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
CREATE INDEX IF NOT EXISTS idx_events_entity ON events(entity);
```

### 3.2. `activities` Table (Correlated Sequences)
Stores reconstructed high-level activities identified by Akash's correlation engine.
```sql
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
CREATE INDEX IF NOT EXISTS idx_activities_ts ON activities(ts_start_utc);
```

### 3.3. `activity_events` Table (Evidence Provenance Link)
Establishes the forensic evidence provenance chain linking high-level activities to raw events.
```sql
CREATE TABLE IF NOT EXISTS activity_events (
    activity_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    PRIMARY KEY (activity_id, event_id),
    FOREIGN KEY (activity_id) REFERENCES activities(activity_id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ae_activity ON activity_events(activity_id);
CREATE INDEX IF NOT EXISTS idx_ae_event ON activity_events(event_id);
```

---

## 4. API Endpoints Reference

Base URL: `http://localhost:8000` (interactive documentation at `/docs` or `/redoc`).

| Method | Endpoint | Description | Consumed By |
|---|---|---|---|
| `GET` | `/health` | Service health status and current UTC time | Monitoring & Startup checks |
| `POST` | `/events` | Ingests telemetry batches (`EventBatch`) with deduplication | Agent Core (`agent/sender.py`) |
| `GET` | `/events` | Query normalized events with filtering (`source`, `action`, `host`, `limit`, `offset`) | Dashboard (`dashboard/`) |
| `GET` | `/events/window` | Query past events inside a sliding time window (`ts_start_utc`, `ts_end_utc`) | Correlation Engine (`engine/`) |
| `GET` | `/events/{id}` | Inspect a single event along with its raw original payload | Dashboard Evidence Drawer |
| `POST` | `/reset` | Flushes all tables for clean scenario test runs | Demo Runner & Test Suites |

---

## 5. Setup & Running Locally

### 5.1. Prerequisites
* Python 3.10+ (tested on Python 3.12)
* Core libraries: `fastapi`, `uvicorn`, `pydantic`, `httpx`

Install dependencies:
```bash
pip install fastapi uvicorn pydantic httpx
```

### 5.2. Starting the Backend Server
Start the server on `127.0.0.1:8000`:
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Verify health check:
```bash
curl http://localhost:8000/health
```

### 5.3. Running the Test Suite
The backend contains a comprehensive unit test suite covering database operations, normalizers, and API endpoints:

```bash
# Run all backend tests
python -m unittest discover -s backend/tests -v

# Run individual test modules
python -m unittest backend/tests/test_db.py
python -m unittest backend/tests/test_normalizers.py
python -m unittest backend/tests/test_api.py
```
*(All 21 automated tests execute in `< 1.0s` with zero errors).*

---

## 6. Shared Team Contracts
* **To Daksh (Agent Core):** Ingestion batch schema specified in [`docs/agent_interface.md`](../docs/agent_interface.md) is fully implemented on `POST /events`.
* **To Chetna (Dashboard):** Endpoints and CORS headers are established. Reconstructed activities and evidence links are exposed.
* **To Akash (Correlation Engine):** Time-window queries (`get_events_in_window` & `GET /events/window`) are active and indexed.
