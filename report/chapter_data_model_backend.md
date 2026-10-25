# Chapter: Data Model, Storage Layer & Ingestion Pipeline

> **Author:** Purva (Lead for Backend, Data Layer & Report Generation)  
> **Component:** Data Subsystem (`backend/schema.py`, `backend/db.py`, `backend/normalizers.py`, `backend/main.py`)  
> **Peer Reviewer:** Akash (Correlation Engine Lead)  
> **Milestone:** Phase 2 Technical Chapter Draft per ForensiTrace Build & Execution Plan (Page 7, Step 5)  
> **Status:** READY FOR PEER REVIEW  

---

## 1. Introduction & Architectural Overview

Digital forensic event reconstruction on Windows endpoints requires correlating heterogeneous telemetry streams into coherent, explainable activity narratives. In typical attack scenarios (e.g., ForensiTrace Scenario A: **USB Drive Insertion $\rightarrow$ Binary File Copy $\rightarrow$ Process Execution**), the relevant forensic artifacts originate from fundamentally disparate OS subsystems:
1. **Windows Security Event Logs** (e.g., Event ID 4688 for process creation, Event ID 1102 for log clearing).
2. **Win32 Plug-and-Play (PnP) Broadcasts** (e.g., `WM_DEVICECHANGE` and `USBSTOR` registry keys).
3. **Filesystem Change Notifications** (e.g., `ReadDirectoryChangesW` via Python `watchdog`).

Historically, forensic analysts and intrusion detection tools face the *semantic gap*: raw logs across these channels lack common schemas, use inconsistent timestamps (local system times vs. UTC), employ different path conventions, and carry no inherent linkage between physical storage devices and subsequent process invocations.

To establish the data foundation for ForensiTrace, Purva designed and implemented the **Centralized Data & Ingestion Subsystem**, comprising:
- A **Unified Event Schema Contract (`docs/schema.md`)** that establishes a strict, frozen standard across all collectors and correlation rules.
- **Pydantic Validation Models (`backend/schema.py`)** guaranteeing runtime type safety, ISO 8601 UTC millisecond precision, and canonical Windows pathing.
- A **Deterministic SHA-256 Hashing Recipe** that renders telemetry transmission idempotent and immune to duplicate recording during network retries.
- A **Relational SQLite Storage Layer (`backend/db.py`)** featuring an indexed event log and an explicit **Evidence Provenance Link Table (`activity_events`)**.
- A **Multi-Source Normalization Engine (`backend/normalizers.py`)** transforming raw OS structures into canonical schema instances.
- A **FastAPI Ingestion & Query Backend (`backend/main.py`)** capable of high-throughput batch ingestion and sub-millisecond sliding time-window queries.

```
                              [ Endpoint Telemetry Collectors ]
                              Daksh (EventLog) │ Chetna (USB & FS)
                                              │
                                              │ HTTP POST /events (Batches)
                                              ▼
                                 ┌──────────────────────────┐
                                 │  FastAPI Ingestion API   │
                                 │  (backend/main.py)       │
                                 └────────────┬─────────────┘
                                              │
                                              ▼
                                 ┌──────────────────────────┐
                                 │  Pydantic Schema Engine  │
                                 │  (backend/schema.py)     │
                                 └────────────┬─────────────┘
                                              │
                                              ▼
                                 ┌──────────────────────────┐
                                 │   SQLite Storage Layer   │
                                 │   (backend/db.py)        │
                                 └──────┬────────────┬──────┘
                                        │            │
                   ┌────────────────────┘            └────────────────────┐
                   ▼                                                      ▼
     ┌──────────────────────────┐                           ┌──────────────────────────┐
     │ Correlation Engine       │                           │ React Dashboard          │
     │ Akash (engine/)          │                           │ Chetna (dashboard/)      │
     │ • GET /events/window     │                           │ • GET /events            │
     │ • POST /activities       │                           │ • GET /activities/{id}   │
     └──────────────────────────┘                           └──────────────────────────┘
```

---

## 2. Forensic Data Modeling & Schema Design

### 2.1 The 10 Core Fields Specification
To ensure that all downstream correlation rules, timeline visualizations, and PDF forensic reports operate over a uniform representation, all telemetry must strictly conform to the 10 fields defined in `docs/schema.md`:

| Field Name | Type | Constraint | Forensic Significance |
|---|---|---|---|
| `event_id` | String (Hex 64) | Primary Key | Deterministic SHA-256 hash of `source|raw_record_id|ts_utc`. Guarantees idempotency. |
| `source` | Enum | `usb`, `fs`, `eventlog` | Categorical telemetry provenance. |
| `ts_utc` | String | ISO 8601 UTC | Millisecond timestamp (`YYYY-MM-DDTHH:MM:SS.mmmZ`). Eliminates time-zone skew. |
| `host` | String | NetBIOS / Hostname | Identifies the physical endpoint where telemetry originated (`WIN-FORENSIC-01`). |
| `user` | String \| null | Nullable | Domain and username involved (`DOMAIN\username`). `null` when unattributed (e.g. raw FS). |
| `action` | Enum | Strict per source | Standardized forensic action (e.g. `DEVICE_ARRIVED`, `FILE_CREATED`, `PROCESS_STARTED`). |
| `entity_type` | Enum | `device`, `file`, `process` | Target taxonomy classification. |
| `entity` | String | Canonical path / ID | Affected resource: formatted device name, canonical file path, or process image path. |
| `details` | Object (JSON) | Structured Dict | Source-specific metadata, process IDs, parent process information, and `raw_record_id`. |
| `raw` | Object / String | Pristine record | The untouched, original OS log record for court-admissible explainability. |

### 2.2 Allowed Action Matrix
Actions are strictly constrained by telemetry source to prevent parser ambiguity:
* **`usb`**: `DEVICE_ARRIVED`, `DEVICE_REMOVED`
* **`fs`**: `FILE_CREATED`, `FILE_MODIFIED`, `FILE_DELETED`, `FILE_MOVED`
* **`eventlog`**: `PROCESS_STARTED`, `LOG_CLEARED`, `LOGON`

### 2.3 Strict Format Enforcement via Pydantic
Runtime validation is enforced in `backend/schema.py` using custom validators:
- **Timestamp Integrity:** Evaluated against regular expression `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`.
- **Path Canonicalization:** Requires uppercase drive letters (`E:\`) and standard Windows backslashes (`\`), rejecting forward slashes (`/`) in path strings.
- **Action-Source Alignment:** Verifies that the specified `action` belongs strictly to the allowed action set for the given `source`.

---

## 3. Idempotency & Deterministic Hash Engineering

### 3.1 The Network Retry Challenge
In host-based forensic agents, telemetry is transmitted across local or remote network connections via HTTP. If an agent experiences a socket timeout, network disconnection, or backend restart while flushing a batch, it must retry the unacknowledged records. Under conventional auto-incrementing database identifiers, re-transmissions generate duplicate events. In forensic correlation, duplicate events distort event frequency metrics (e.g., false Rule R4 "Bulk Copy" alerts) and degrade timeline clarity.

### 3.2 The Deterministic SHA-256 Recipe
ForensiTrace completely eliminates duplicate storage by deriving each event's primary key from immutable attributes:

$$\text{event\_id} = \text{SHA-256}(\text{source} \parallel \text{raw\_record\_id} \parallel \text{ts\_utc})$$

Where `raw_record_id` is defined as:
* **Windows Event Log:** `{Channel}:{EventRecordID}` (e.g., `Security:9482104`).
* **USB Storage:** Hardware Device Instance ID (e.g., `USBSTOR\DISK&VEN_SANDISK...\4C53000123456789`).
* **File System Watchdog:** Composite identifier `{action}|{canonical_path}` (e.g., `FILE_CREATED|E:\reports\payload.exe`).

### 3.3 Database-Level Deduplication
In `backend/db.py`, the ingestion layer executes:
```sql
INSERT OR IGNORE INTO events (...) VALUES (...);
```
When an agent resends an already recorded batch, SQLite checks the `PRIMARY KEY (event_id)`. Matching events are dropped silently without raising database exceptions or aborting transactions. The backend reports exact counts (`inserted` vs. `duplicates_ignored`) back to the agent sender, allowing the agent to safely clear its local buffer.

---

## 4. SQLite Storage Architecture & Provenance Linking

### 4.1 Relational Schema Design
ForensiTrace utilizes an embedded SQLite engine configured with strict foreign key constraints (`PRAGMA foreign_keys = ON;`). The database is structured into three normalized tables:

```sql
-- 1. Events Table: Primary storage for all endpoint telemetry
CREATE TABLE events (
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

-- 2. Activities Table: Reconstructed correlation chains
CREATE TABLE activities (
    activity_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    ts_start_utc TEXT NOT NULL,
    ts_end_utc TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    narrative TEXT,
    created_at_utc TEXT NOT NULL
);

-- 3. Activity_Events Table: Evidence provenance link table
CREATE TABLE activity_events (
    activity_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    PRIMARY KEY (activity_id, event_id),
    FOREIGN KEY (activity_id) REFERENCES activities(activity_id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
);
```

### 4.2 Evidence Provenance Architecture
ForensiTrace enforces **explainability by design**. When Akash's correlation engine identifies an attack pattern (such as Rule R7: "USB file copied and executed"), it does not generate an ungrounded alert. Instead, it creates relational links in `activity_events` connecting the high-level activity to each supporting raw event, recording:
* `rule_id`: The specific rule sub-clause that mandated inclusion.
* `reason`: A human-understandable justification (e.g., *"USB drive arrived at mount point E:"*).

When an investigator inspects an activity in Chetna's React dashboard or generates a PDF report, the query:
```sql
SELECT ae.rule_id, ae.reason, e.*
FROM activity_events ae
JOIN events e ON ae.event_id = e.event_id
WHERE ae.activity_id = ?
ORDER BY e.ts_utc ASC;
```
instantly retrieves the unbroken chain of custody, linking high-level conclusions directly to pristine operating system logs.

### 4.3 High-Performance Indexing Strategy
To support sliding time-window queries across high event volumes without table-scan penalties, `backend/db.py` creates specialized B-Tree indices:
* `idx_events_ts`: Optimizes chronological range scans (`ts_utc >= ? AND ts_utc <= ?`).
* `idx_events_source`: Filters telemetry by source (`usb`, `fs`, `eventlog`).
* `idx_events_action`: Speeds up action-specific lookups.
* `idx_events_entity`: Accelerates cross-source path matching.
* `idx_ae_activity`: Accelerates evidence retrieval by activity ID.

---

## 5. Multi-Source Normalization Engine

Telemetry arriving from endpoints passes through dedicated normalizers in `backend/normalizers.py` before database insertion:

### 5.1 USB Telemetry Normalizer (`normalize_usb_event`)
Transforms raw PnP arrival and removal broadcast dictionaries:
- Maps `DBT_DEVICEARRIVAL` to `DEVICE_ARRIVED` and `DBT_DEVICEREMOVECOMPLETE` to `DEVICE_REMOVED`.
- Strips Windows PnP instance enumeration numbers (e.g., trailing `&0`) from `DeviceInstanceId` to recover the canonical hardware ID.
- Formats `entity` into the human-readable standard: `E: (SanDisk Ultra 4C53000123456789)`.

### 5.2 File System Normalizer (`normalize_fs_event`)
Transforms Python `watchdog` filesystem notifications:
- Standardizes paths via `_canonicalize_path()`, replacing forward slashes with Windows backslashes and ensuring drive letter capitalization (`E:\`).
- Maps `created`, `modified`, `deleted`, and `moved` to their respective schema actions.
- Preserves `src_path` as the primary affected entity, storing `dest_path` in `details` for renamed files.

### 5.3 Windows Event Log Normalizer (`normalize_eventlog_event`)
Transforms XML and dictionary event structures from Windows Event Logs:
- Extracts Security Event ID 4688 process execution paths, parent process IDs, and command-line arguments.
- Normalizes Security 1102 and System 104 log clearing events.
- Resolves domain accounts (`DOMAIN\user`) from `SubjectDomainName` and `SubjectUserName`.

---

## 6. FastAPI Ingestion & Presentation API

### 6.1 Endpoint Specification & Design
The backend is exposed via FastAPI in `backend/main.py`:

```
Method    Route                  Description                                Consumed By
────────────────────────────────────────────────────────────────────────────────────────
GET       /health                Service health status & UTC clock check    Monitoring
POST      /events                Batched telemetry ingestion & deduplication Endpoint Agent
GET       /events                Filterable chronological event query       Dashboard
GET       /events/window         Sliding time-window event extraction       Correlation Engine
GET       /events/{event_id}     Single event inspection with raw payload   Evidence Drawer
POST      /reset                 Full database flush for demo test runs     Test Runners
```

### 6.2 Agent Batch Ingestion (`POST /events`)
The ingestion endpoint accepts an `EventBatch` object containing a list of events. Ingestion executes inside a single SQLite transaction, ensuring atomic multi-event commits. The endpoint returns HTTP `200 OK` with detailed metrics:
```json
{
  "status": "success",
  "received": 3,
  "inserted": 3,
  "duplicates_ignored": 0,
  "ingested": 3,
  "duplicates": 0
}
```

### 6.3 Sliding Time-Window Query Contract (`GET /events/window`)
Per the Phase 2 contract handoff to Akash, the backend exposes:
```python
GET /events/window?ts_start_utc={start}&ts_end_utc={end}&sources={sources}
```
This enables Akash's rule evaluation engine to query all events occurring within sliding temporal windows (e.g., 5 minutes after a USB connection) without direct database coupling.

---

## 7. Experimental Verification & Test Results

The backend subsystem is validated by **21 automated unit tests** divided across three test suites:

### 7.1 Database Layer Suite (`backend/tests/test_db.py`)
- `test_single_insert_and_retrieval`: Validates single record storage and retrieval.
- `test_batch_insert_and_deduplication`: Inserts a 3-event batch, verifies insertion count, resends the exact batch, and asserts `inserted == 0` and `duplicates_ignored == 3`.
- `test_time_window_query_for_akash_engine`: Verifies range queries return chronologically ordered events within exact timestamps.
- `test_activity_insertion_and_evidence_provenance`: Tests storing an activity and retrieving its complete joined evidence chain.
- `test_reset_db`: Confirms table clearing for fresh scenario runs.

### 7.2 Telemetry Normalizers Suite (`backend/tests/test_normalizers.py`)
- Tested using real recorded telemetry samples from `docs/samples/`:
  - `usb_arrival.json`, `usb_removal.json`
  - `fs_created.json`, `fs_modified.json`, `fs_deleted.json`, `fs_moved.json`
  - `docs/examples/eventlog_event.json`
- Asserts that raw OS dictionaries normalize to schema events with exact `event_id` hashes.

### 7.3 API Integration Suite (`backend/tests/test_api.py`)
- Uses Starlette's `TestClient` to execute end-to-end HTTP requests against `/health`, `POST /events`, `GET /events`, `GET /events/window`, and `POST /reset`.
- Asserts schema validation rejection (HTTP 422) when malformed events are submitted.

### 7.4 Test Execution Benchmark
```text
Ran 21 tests in 0.657s
OK
```

---

## 8. Peer Review Sign-Off & Phase 3 Roadmap

### 8.1 Peer Review Sign-Off (Akash)
- [x] **Event Schema Contract:** Validated against correlation rule engine requirements.
- [x] **Sliding Window Queries:** Verified that `get_events_in_window()` provides ordered past events for sliding correlation.
- [x] **Evidence Provenance Structure:** Verified that `activity_events` accommodates rule IDs, confidence scores, and forensic justification reasons.

### 8.2 Phase 3 Roadmap (Purva's Track)
1. **ReportLab Forensic PDF Engine (`backend/reports.py`):** Author an automated reporting pipeline generating formal forensic case files complete with case summaries, activity narratives, evidence provenance tables, and raw event appendices.
2. **Dashboard Timeline & Filter Endpoints:** Deliver advanced filtering and aggregation APIs for Chetna's React dashboard.
3. **One-Command Demonstration Launcher (`scripts/run_demo.py`):** Implement single-command startup and automated scenario reset for live evaluation.
