# ForensiTrace — Phase 2 Presentation Slides: Data Model, Storage & Ingestion Pipeline

> **Author:** Purva (Backend, Data Layer & Report Lead)  
> **Review Partner:** Akash (Correlation Engine Lead)  
> **Evaluator:** Ms. Rajeshwari K R  
> **Milestone:** Phase 2 Evaluation — Working Endpoint Telemetry Pipeline  
> **Related Contracts:** [`docs/schema.md`](../docs/schema.md), [`docs/api.md`](../docs/api.md), [`docs/agent_interface.md`](../docs/agent_interface.md)  
> **Source Code:** [`backend/schema.py`](../backend/schema.py), [`backend/db.py`](../backend/db.py), [`backend/normalizers.py`](../backend/normalizers.py), [`backend/main.py`](../backend/main.py)

---

## Presentation Overview

| Slide # | Slide Title | Core Theme |
|:---:|---|---|
| **1** | Title & Component Ownership | Purva's Role in ForensiTrace Phase 2 |
| **2** | The Data Foundation of ForensiTrace | Bridging the semantic gap through standardized data modeling |
| **3** | Unified Normalized Event Schema | The 10 core fields, UTC millisecond precision, and action constraints |
| **4** | Idempotency & Deterministic Hashing | The SHA-256 `event_id` recipe eliminating duplicate risks |
| **5** | SQLite Database Architecture & Indexing | Relational design, foreign keys, and query optimization |
| **6** | Evidence Provenance Link Table (`activity_events`) | Connecting reconstructed high-level activities to immutable raw logs |
| **7** | High-Throughput Telemetry Ingestion API | `POST /events`, batching, and resilient error recovery |
| **8** | Multi-Source Normalization Engine | Ingestion pipelines for Windows Event Log, USB PnP, and File System |
| **9** | Sliding Time-Window Contract for Correlation | Handing off temporal queries to Akash's correlation engine |
| **10** | Comprehensive Test Suite & Verification | 21 unit tests covering schema, database, normalizers, and API |
| **11** | Live Evaluation Demo Execution | Purva's role in Steps 2 & 6 of the evaluation demo |
| **12** | Review Sign-Off & Phase 3 Roadmap | Deliverables sign-off, Akash review, and ReportLab PDF roadmap |

---

<!-- slide -->

## Slide 1: Title & Component Ownership

### ForensiTrace — Phase 2 Progress Presentation
#### Component: Centralized Data Model, SQLite Storage & FastAPI Ingestion Service

**Presenter:** Purva  
**Team Role:** Backend, Data Layer & Report Lead (Phase 2 & Phase 3)  
**Review Partner:** Akash (Correlation Engine Lead)  
**Faculty Evaluator:** Ms. Rajeshwari K R  

---

### Phase 2 Scope & Objectives (Purva's Slice)
- **Event Schema v1 Contract (`docs/schema.md`):** Designed and frozen as the baseline contract for all collectors and the correlation engine.
- **Pydantic Validation Models (`backend/schema.py`):** Enforces strict runtime validation on timestamps, path casing, and allowed actions.
- **SQLite Data-Access Layer (`backend/db.py`):** Relational storage for `events`, `activities`, and the `activity_events` evidence provenance link table.
- **Telemetry Normalizers (`backend/normalizers.py`):** Maps raw USB, File System, and Event Log records to the normalized schema.
- **FastAPI Ingestion Backend (`backend/main.py`):** Implements `POST /events` with batching and deduplication, `GET /events`, and health checks.
- **Handoff Contracts:** Provides sliding time-window queries (`GET /events/window`) to Akash's engine and API endpoints to Chetna's dashboard.

> **Speaker Notes (Purva):**  
> *"Good morning, Ms. Rajeshwari and evaluators. Today I am presenting my component of ForensiTrace for Phase 2: the Centralized Data Model, SQLite Storage Layer, and FastAPI Ingestion Service. In ForensiTrace, our objective is to connect disconnected endpoint logs into explainable attack stories. My responsibility has been building the entire data pipeline: defining our frozen schema contract, implementing deterministic deduplication, managing SQLite persistence with evidence provenance, normalizing telemetry across three disparate sources, and providing high-performance APIs for the agent and correlation engine."*

---

<!-- slide -->

## Slide 2: The Data Foundation of ForensiTrace

### The Semantic Gap in Raw Forensic Telemetry
Endpoint forensics traditionally deals with three fundamentally incompatible data models:
1. **Windows Event Log:** Deep, deeply nested XML records with hex IDs (`0x1a4c`), Windows SIDs, and channel metadata.
2. **USB Device Telemetry:** Win32 `WM_DEVICECHANGE` broadcast packets and registry hardware descriptors.
3. **File System Telemetry:** Low-level OS filesystem change notifications (`ReadDirectoryChangesW`) tracking raw path strings.

```
[ Windows Event Log (XML) ]     [ USB PnP Broadcasts ]     [ Watchdog File Events ]
             │                             │                           │
             └──────────────────────┬──────┴───────────────────────────┘
                                    │
                                    ▼
                      ┌───────────────────────────┐
                      │    Purva's Normalizers    │
                      └─────────────┬─────────────┘
                                    │
                                    ▼
                     [ Unified ForensiTrace Event ]
                       (Canonical, Frozen Schema)
```

### Why a Frozen Schema Must Come First
* **Team Dependency:** Daksh (Event Log), Chetna (USB/FS), and Akash (Engine) all depend on the schema.
* **Contract Stability:** Freezing `docs/schema.md` in Step 1 prevented API churn and allowed parallel development across all 4 team members.

> **Speaker Notes (Purva):**  
> *"As shown here, each Windows source formats its data in completely different ways. An investigator or correlation rule cannot compare an Event Log XML structure directly with a filesystem watcher notification. Our normalized schema bridges this semantic gap by extracting the essential forensic primitives—Who, What, Where, When, and How—into one uniform structure before any correlation takes place."*

---

<!-- slide -->

## Slide 3: Unified Normalized Event Schema

### The 10 Core Forensic Fields (`docs/schema.md`)

| Field | Type | Required? | Meaning & Forensic Role |
|---|---|:---:|---|
| `event_id` | String (Hex 64) | **Yes** | Deterministic SHA-256 hash; guarantees idempotent storage |
| `source` | Enum (`usb`, `fs`, `eventlog`) | **Yes** | Provenance source identifier |
| `ts_utc` | String (ISO 8601) | **Yes** | UTC event timestamp with millisecond precision and literal `Z` |
| `host` | String | **Yes** | Originating machine NetBIOS/hostname (`WIN-FORENSIC-01`) |
| `user` | String \| null | Optional | Account involved (`DOMAIN\user`); `null` if unattributed |
| `action` | String (Enum) | **Yes** | Standard action (e.g. `DEVICE_ARRIVED`, `FILE_CREATED`, `PROCESS_STARTED`) |
| `entity_type` | Enum (`device`, `file`, `process`) | **Yes** | Target classification |
| `entity` | String | **Yes** | Canonical affected path or hardware identifier |
| `details` | Object (JSON) | **Yes** | Source-specific metadata, process IDs, and `raw_record_id` |
| `raw` | Object \| String | **Yes** | Untouched original telemetry record for court-admissible evidence |

### Formatting Constraints Enforced by Pydantic
* **Timestamps:** Strict ISO 8601 UTC with milliseconds: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
* **Path Conventions:** Canonical Windows backslashes (`\`) and uppercase drive letters (`E:\`).

> **Speaker Notes (Purva):**  
> *"Every single event in ForensiTrace contains these 10 fields. Notice the distinction between 'entity' and 'raw': 'entity' provides the standardized Windows path or device name used by Akash's correlation rules, while 'raw' stores the pristine, untouched operating system record. That ensures that when an investigator opens our evidence drawer, they can see the exact underlying OS record as evidence."*

---

<!-- slide -->

## Slide 4: Idempotency & Deterministic Hashing

### The Problem: Network Drops & Duplicate Retries
* The endpoint agent transmits telemetry over HTTP.
* If a network hiccup or backend restart occurs mid-transmission, the agent retries the unacknowledged batch.
* **The Risk:** Naive auto-increment IDs cause duplicate events, skewing correlation counts and triggering false alarms.

### The Solution: Deterministic SHA-256 Hash Recipe
Every event generates its primary key deterministically using our stated recipe:

$$\text{event\_id} = \text{SHA-256}(\text{source} \parallel \text{raw\_record\_id} \parallel \text{ts\_utc})$$

```python
# In backend/schema.py:
def compute_event_id(source: str, raw_record_id: str, ts_utc: str) -> str:
    seed = f"{source}|{raw_record_id}|{ts_utc}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()
```

### Source-Specific `raw_record_id` Mappings
* **Windows Event Log:** `{Channel}:{EventRecordID}` (e.g. `Security:9482104`)
* **USB Storage:** PnP Device Instance ID (e.g. `USBSTOR\DISK&VEN_SANDISK...\4C53000123456789`)
* **File System:** Fallback composite `{action}|{canonical_path}` (e.g. `FILE_CREATED|E:\reports\payload.exe`)

> **Speaker Notes (Purva):**  
> *"Because the event_id is calculated from immutable properties of the event itself, re-transmitting the exact same event produces the exact same hash. In SQLite, we use INSERT OR IGNORE, which means duplicate transmissions are dropped silently without crashing the server or polluting our timeline."*

---

<!-- slide -->

## Slide 5: SQLite Database Architecture & Indexing

### Database Schema Design (`backend/db.py`)
ForensiTrace uses an embedded, zero-maintenance SQLite database configured with write-ahead capability and strict foreign keys (`PRAGMA foreign_keys = ON;`).

```sql
-- Core Telemetry Table
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
```

### High-Performance Indexing Strategy
To allow Akash's correlation engine to query millions of records across sliding time windows in milliseconds:
* `idx_events_ts`: B-Tree index on `ts_utc` (supports range scans: `ts_utc >= ? AND ts_utc <= ?`).
* `idx_events_source`: Index on `source` (`usb`, `fs`, `eventlog`).
* `idx_events_action`: Index on `action` (`DEVICE_ARRIVED`, `FILE_CREATED`, `PROCESS_STARTED`).
* `idx_events_entity`: Index on `entity` path for entity-matching correlation.

> **Speaker Notes (Purva):**  
> *"We designed the schema specifically for temporal range queries. By indexing ts_utc, source, and entity, when Akash's engine asks for all file and process events occurring within 10 minutes of a USB insertion, SQLite performs an indexed index-range lookup rather than a full table scan."*

---

<!-- slide -->

## Slide 6: Evidence Provenance Link Table (`activity_events`)

### Forensic Explainability by Design
A major objective in our synopsis is **Evidence Provenance**: the system must never produce an alert without linking back to the exact supporting logs.

```
       [ Reconstructed Activity ]
       ID: act_20261023_001
       Rule: R7 ("USB File Copied and Executed")
                   │
                   ▼
┌────────────────────────────────────────────────────────┐
│         Table: activity_events (Link Table)            │
│  activity_id  │  event_id  │ rule_id │     reason      │
├───────────────┼────────────┼─────────┼─────────────────┤
│ act_...001    │ 8fdfc6...  │ R1      │ USB mounted E:  │
│ act_...001    │ 8376a8...  │ R1      │ Payload copied  │
│ act_...001    │ d8d4e6...  │ R2      │ Binary executed │
└───────┬──────────────┬───────────────┴─────────────────┘
        │              │
        ▼              ▼
[ Raw USB Event ]  [ Raw FS Event ]  [ Raw EventLog Event ]
```

### Cascading Integrity & Provenance Queries
* Uses composite primary key `(activity_id, event_id)` with `ON DELETE CASCADE`.
* `get_activity_by_id()` joins `activity_events` with `events` to deliver the complete evidence chain to Chetna's React evidence drawer.

> **Speaker Notes (Purva):**  
> *"This link table represents the core explainability feature of ForensiTrace. When our correlation engine detects Rule R7—a USB file copied and launched—it doesn't just output a message. It inserts three rows into activity_events, citing the exact USB arrival event, the file creation event, and the process start event, along with the specific forensic reason for each."*

---

<!-- slide -->

## Slide 7: High-Throughput Telemetry Ingestion API

### Endpoint Specification (`POST /events`)
Daksh's endpoint agent core (`agent/sender.py`) flushes batches of telemetry to the FastAPI backend.

```
[ Agent Sender Thread ] ─── HTTP POST /events (Batch) ───► [ FastAPI Ingestion Route ]
                                                                      │
                                                           ┌──────────┴──────────┐
                                                           ▼                     ▼
                                                    [ Valid Schema ]      [ Malformed ]
                                                           │                     │
                                                           ▼                     ▼
                                                 INSERT OR IGNORE           HTTP 422
                                                    (SQLite DB)         (Drop & Log Err)
```

### Ingestion Response Contract
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
* Returns HTTP `200 OK` on successful persistence.
* Compatible with both Purva's API contract and Daksh's agent sender expectations.

> **Speaker Notes (Purva):**  
> *"The ingestion endpoint is built using FastAPI and Pydantic. It validates batches in memory, executes single-transaction batch inserts into SQLite, and returns a detailed breakdown of inserted versus ignored records in less than 5 milliseconds."*

---

<!-- slide -->

## Slide 8: Multi-Source Normalization Engine

### Telemetry Normalizers (`backend/normalizers.py`)
To ensure raw telemetry from any collector can be ingested safely:

1. **`normalize_usb_event()`:**
   * Parses Win32 `DBT_DEVICEARRIVAL` / `DBT_DEVICEREMOVECOMPLETE`.
   * Strips Windows device instance suffixes (`&0`).
   * Canonicalizes device entity strings: `E: (SanDisk Ultra 4C53000123456789)`.
2. **`normalize_fs_event()`:**
   * Maps watchdog change notifications (`created`, `modified`, `deleted`, `moved`).
   * Standardizes paths: ensures uppercase drive letters (`E:\`) and Windows backslashes.
   * Preserves `src_path` as primary entity and `dest_path` for renamed binaries.
3. **`normalize_eventlog_event()`:**
   * Extracts Security ID 4688, 1102, and System ID 104 records.
   * Maps process execution paths, parent PIDs, and domain user accounts.

> **Speaker Notes (Purva):**  
> *"Our normalizers handle real-world Windows idiosyncrasies. For instance, Windows device IDs often append an instance number like '&0', and filesystem paths might use forward slashes. The normalizer canonicalizes all paths and identifiers so that downstream correlation rules can match file paths with process paths reliably."*

---

<!-- slide -->

## Slide 9: Sliding Time-Window Engine Contract

### Hand-off Contract for Akash's Correlation Engine
Per our project execution plan (Page 2), Purva hands over:
> *"Database tables and a way to read events in a time window so the engine queries past events."*

### Implementation: `get_events_in_window()`
```python
# In backend/db.py & GET /events/window:
def get_events_in_window(ts_start_utc: str, ts_end_utc: str, sources=None, actions=None):
    """
    Returns events within [ts_start_utc, ts_end_utc] sorted ascending by ts_utc.
    Utilizes B-Tree index on ts_utc for sub-millisecond range lookups.
    """
```

### Why This Architecture Succeeds:
* **Decoupled Architecture:** Akash's engine does not need to know about SQLite connection strings or low-level file locks.
* **Deterministic Replay:** Tests can inject synthetic or recorded events and query exact time windows reproducibly.

> **Speaker Notes (Purva):**  
> *"This slide shows the exact technical contract between my data layer and Akash's correlation engine. When Akash's engine evaluates Rule R1—device arrives, then a file is copied within 5 minutes—it simply invokes get_events_in_window with the device arrival timestamp and a 5-minute upper bound. The database returns all relevant events in chronological order."*

---

<!-- slide -->

## Slide 10: Automated Test Suite & Verification

### Comprehensive Test Coverage (21 Automated Tests)
Every component in `backend/` is rigorously tested with zero mock shortcuts:

```
backend/tests/
├── test_db.py            (5 tests)  ──► SQLite CRUD, deduplication, time windows, reset
├── test_normalizers.py   (9 tests)  ──► Real samples (USB arrival/removal, FS lifecycle)
└── test_api.py           (7 tests)  ──► Ingestion, deduplication, filtering, schema 422
```

### Test Execution Results
```text
Ran 21 tests in 0.657s
OK
```

### Key Verification Milestones:
- **Deduplication Test:** Verified that posting a batch of 3 events twice inserts 3 on the first pass, and inserts 0 / ignores 3 on the second pass.
- **Real Sample Telemetry:** Tested against real USB and File System sample recordings handed over by Chetna in `docs/samples/`.

> **Speaker Notes (Purva):**  
> *"We have 21 automated unit tests across three test modules, running in under 0.7 seconds. Every test verifies a concrete requirement from our plan: duplicate suppression, schema validation rejections, time-window retrieval, and real collector recordings."*

---

<!-- slide -->

## Slide 11: Live Evaluation Demo Execution

### Purva's Role in the Phase 2 Evaluation Script
The Build & Execution Plan specifies a 6-step demo script for our Phase 2 evaluation:

```
[ Step 1: Raw Event Viewer ] ──────────────► Daksh shows unlinked, separate event lines
[ Step 2: Start Agent & Backend ] ─────────► Purva & Daksh start FastAPI & Agent service
[ Step 3: Insert USB & Copy Program ] ─────► Chetna copies payload.exe to E:\reports\
[ Step 4: Execute Program ] ───────────────► Run payload.exe from USB drive
[ Step 5: Query Activities Endpoint ] ─────► Akash displays single correlated activity
[ Step 6: Explain Schema & Database ] ─────► Purva demonstrates schema, DB & provenance
```

### Demo Talking Points (Step 6):
1. **Show SQLite Database:** Display `events` table showing the 3 distinct events unified in one schema.
2. **Show Evidence Provenance:** Inspect `activity_events` showing the 3 evidence links supporting the single correlated activity.
3. **Show Deduplication in Action:** Demonstrate re-ingesting telemetry without duplicating records.

> **Speaker Notes (Purva):**  
> *"During our live evaluation demo, after Chetna copies and runs the payload and Akash shows the reconstructed activity, I will take the floor for Step 6. I will open SQLite and show the evaluators how the USB arrival, file copy, and process creation are stored in our unified schema, and highlight the activity_events link table that provides the proof behind the activity."*

---

<!-- slide -->

## Slide 12: Review Sign-Off & Phase 3 Roadmap

### Phase 2 Completion Checklist (Purva's Track)
- [x] Frozen event schema v1 contract published (`docs/schema.md`).
- [x] Pydantic models with strict validation implemented (`backend/schema.py`).
- [x] SQLite data-access layer with deduplication and time-window queries completed (`backend/db.py`).
- [x] Telemetry normalizers verified with real sample recordings (`backend/normalizers.py`).
- [x] FastAPI ingestion and query backend operational (`backend/main.py`).
- [x] 21 automated unit tests passing (`Ran 21 tests in 0.657s - OK`).
- [x] Setup README guide published (`backend/README.md`).

---

### Phase 3 Roadmap & Planned Deliverables
1. **ReportLab Forensic PDF Generation (`backend/reports.py`):**
   * One-click generation of court-admissible forensic investigation reports.
   * Incorporates case metadata, reconstructed activity narratives (Akash), and tabular evidence provenance.
2. **Dashboard Query API Expansion:**
   * Timeline feeds and filter endpoints for Chetna's React dashboard.
3. **One-Command Packaging (`scripts/run_demo.py`):**
   * Single-command startup that resets the database, seeds demo scenarios, and launches backend and agent.

---

### Questions & Discussion

**Thank you, Ms. Rajeshwari K R and Evaluators.**  
*Ready for questions and demonstration.*
