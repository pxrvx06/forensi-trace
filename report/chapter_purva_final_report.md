# ForensiTrace Final Report Chapters — Data Model, Backend, Report Generation, and ML Data & Evaluation

> **Author:** Purva (Backend, Data Layer, PDF Reporting & ML Data/Evaluation Owner)  
> **Peer Reviewer:** Akash (Correlation Engine & ML Model Owner)  
> **Reference Specification:** `ForensiTrace — Build & Execution Plan v2 (Hybrid ML)`  
> **Contracts Implemented:** `docs/schema.md`, `docs/ml.md`  
> **Status:** Complete Draft Ready for Peer Review by Akash

---

## Positioning & Architectural Alignment Statement

ForensiTrace performs cross-source Windows endpoint forensic reconstruction without heavyweight ontology infrastructure, using a lightweight sequence-based anomaly detector that supports—but never replaces—explainable correlation rules (`R1`–`R7`). Every forensic conclusion remains traceable to raw telemetry events through deterministic rule chains; the machine learning signal serves strictly as a complementary behavioral score (`ml_anomaly_score`, a normalized LSTM reconstruction error between `0.0` and `1.0`) displayed alongside deterministic rule confidence.

---

## Chapter 1: Forensic Data Model & Hybrid ML Contract

### 1.1 Normalized Telemetry Schema (`docs/schema.md`, `backend/schema.py`)
Endpoint telemetry from Windows Security/System Event Logs, Win32 USB PnP broadcasts, and filesystem change notifications differs significantly in timestamp formatting, path casing, and nesting depth. To bridge this semantic gap before correlation or anomaly scoring, all collectors emit events conforming strictly to a frozen 10-field schema validated at runtime via Pydantic (`backend/schema.py`):

- **Identity & Deduplication:** `event_id` is a deterministic 64-character lowercase SHA-256 hash:
  $$\text{event\_id} = \text{SHA-256}(\text{source} \parallel \text{raw\_record\_id} \parallel \text{ts\_utc})$$
- **Temporal Standardization:** `ts_utc` enforces millisecond-precision UTC ISO 8601 strings (`YYYY-MM-DDTHH:MM:SS.mmmZ`), preventing timezone skew across OS subsystems.
- **Canonical Windows Paths:** All drive letters are uppercase (`E:`) and path separators use standard Windows backslashes (`\`).
- **Explainability Preservation:** Every event embeds the untouched `raw` source record alongside structured `details`, guaranteeing direct raw-evidence inspection in both the React evidence drawer and the PDF appendix.

### 1.2 Phase 3 Hybrid Activity Schema Extensions (`docs/ml.md`)
To support the hybrid ML + rule architecture defined in Phase 3 without breaking existing Phase 2 components, the `Activity` model in `backend/schema.py` was extended with two optional, backward-compatible fields:

| Field | Type / Constraint | Default | Role in Hybrid Architecture |
|---|---|---|---|
| `ml_anomaly_score` | `Optional[float]` (`0.0` to `1.0`) | `None` | Maximum normalized LSTM reconstruction error across overlapping sliding windows. Stored separately from `confidence`. |
| `threat_level` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | `"MEDIUM"` | Discrete triage level computed from the combined hybrid index ($0.5 \times \text{rule\_confidence} + 0.5 \times \text{ml\_anomaly\_score}$) and rule severity overrides. |

If the ML subsystem is offline or artifacts are unavailable, `ml_anomaly_score` remains `None` (`null`), and `threat_level` falls back cleanly to rule confidence alone.

---

## Chapter 2: Backend Storage, Schema Migration & Interactive Timeline API

### 2.1 SQLite Storage & Backward-Compatible Migration (`backend/db.py`)
The storage layer uses SQLite with foreign-key enforcement (`PRAGMA foreign_keys = ON;`) across three normalized tables:
1. **`events`**: Primary telemetry store indexed on `ts_utc`, `source`, `action`, and `entity`. Ingestion executes `INSERT OR IGNORE` so network retries from Daksh’s buffered agent sender never produce duplicate records.
2. **`activities`**: Stores correlated incident chains along with `confidence`, `narrative`, `ml_anomaly_score`, and `threat_level`.
3. **`activity_events`**: Provenance link table joining `activities` to supporting `events` with per-link `rule_id` and human-readable `reason` justification.

To protect existing local databases created during Phase 2, `init_db()` inspects `PRAGMA table_info(activities)` on startup and executes conditional `ALTER TABLE` statements if `ml_anomaly_score` or `threat_level` columns are absent.

### 2.2 FastAPI Ingestion, Timeline & Retrieval Endpoints (`backend/main.py`)
All backend capabilities are exposed via FastAPI with CORS enabled for Chetna’s React frontend:

| Endpoint | Method | Purpose | Consumer |
|---|---|---|---|
| `/health` | `GET` | Readiness status and UTC clock check | Monitoring / Demo Runner |
| `/events` | `POST` | Atomic batched event ingestion with duplicate counts | Endpoint Agent |
| `/events` | `GET` | Paginated, source/action/host-filtered event query | React Dashboard |
| `/events/window` | `GET` | Sliding time-window telemetry query (`ts_start_utc` to `ts_end_utc`) | Correlation Engine |
| `/events/{event_id}` | `GET` | Individual normalized event + untouched `raw` payload | Evidence Drawer |
| `/timeline` | `GET` | Unified chronological feed merging `events` and `activities` | Interactive Timeline UI |
| `/activities` | `GET` | Reconstructed activities with rule confidence, ML score, and threat level | Activity Feed |
| `/activities/{id}` | `GET` | Full activity details joined with ordered `evidence_chain` provenance | Evidence Drawer |
| `/report/{activity_id}` | `GET` | Streams a 3-page forensic investigation PDF report | Export Forensic PDF Button |
| `/reset` | `POST` | Clears all tables between scenario runs | Demo & Test Runners |

#### Unified Chronological Timeline (`GET /timeline`)
To allow Chetna’s dashboard to visualize low-level endpoint events alongside high-level reconstructed activities along a single time axis, `get_timeline()` queries both `events` and `activities`, wraps each record in a uniform envelope (`{"type": "event" | "activity", "ts_utc": "...", "data": {...}}`), sorts strictly by UTC timestamp, and supports pagination (`limit`, `offset`) and `source` filtering.

---

## Chapter 3: Automated 3-Page Forensic PDF Report Generation

### 3.1 Reporting Architecture (`backend/reports.py`)
Investigators require a self-contained artifact that summarizes automated findings while retaining raw OS evidence for independent verification. Using ReportLab (`reportlab 5.1.2`), `generate_activity_pdf_bytes()` constructs a standardized **3-page Forensic Investigation Report with Raw Evidence Appendix**, streamed directly over HTTP from `GET /report/{activity_id}` with `Content-Type: application/pdf` and sanitized `Content-Disposition` attachment headers.

### 3.2 Standardized Three-Page Structure
1. **Page 1 — Executive Case Summary, Threat Badge & Hybrid Scores:**
   - Top banner displaying the ForensiTrace title, `activity_id`, UTC generation timestamp, and a color-coded **Threat Level Badge** (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
   - Target Attribution table summarizing triggered rule (`rule_id`, `rule_name`), affected host(s), observed user account(s), detection window boundaries, and supporting event count.
   - **Side-by-Side Dual-Tier Scoring Panel:** Displays **Tier 2 Rule Confidence**, **Tier 1 ML Anomaly Score** (normalized reconstruction error `0.00–1.00`, or graceful `"N/A (Offline)"`), and the **Combined Risk Index**.
   - Highlighted callout box containing the evidence-grounded incident narrative and a methodology note clarifying that ML scores aid triage and never replace evidentiary provenance.
2. **Page 2 — Reconstructed Evidence Timeline & Provenance Table:**
   - Chronological table of all linked evidence events (`#`, `Timestamp UTC`, `Source`, `Action`, `Target Entity`, `Provenance Justification`).
   - Wrapped `Paragraph` cells prevent clipping of long Windows paths and command lines.
3. **Page 3 — Appendix: Unedited Raw Telemetry Records:**
   - Verbatim pretty-printed JSON payloads (`ev["raw"]`) for every supporting event, escaped via `xml.sax.saxutils.escape` and chunked across shaded code boxes so multi-line XML/JSON logs paginate cleanly without ReportLab layout overflow errors.

### 3.3 Verification (`backend/tests/test_reports.py`)
Automated tests verify:
- Valid 3-page `%PDF-` generation for full R7 multi-source chains.
- Safe handling of XML special characters (`<`, `>`, `&`) and missing `ml_anomaly_score` (`None`).
- HTTP `404` error when requesting a non-existent `activity_id`, and end-to-end DB retrieval through `GET /report/{activity_id}`.

---

## Chapter 4: ML Feature Engineering, Session Splitting & Comparative Evaluation

### 4.1 Dynamic Feature Extraction Contract (`backend/ml_features.py`)
Per `docs/ml.md` and project rules, the feature dimension is **never hard-coded**. It is computed dynamically from the frozen schema actions (`ActionEnum`) plus three contextual flags:

$$\text{Feature Dimension} = |\text{ActionEnum}| + 3 = 9 + 3 = 12$$

For each event $e_i$ preceded chronologically by $e_{i-1}$:
- **Indices `0..8` (Action One-Hot):** Binary indicator across `DEVICE_ARRIVED`, `DEVICE_REMOVED`, `FILE_CREATED`, `FILE_MODIFIED`, `FILE_DELETED`, `FILE_MOVED`, `PROCESS_STARTED`, `LOG_CLEARED`, and `LOGON`.
- **Index `9` (`DELTA_T_LOG`):** $\log_e(1 + \max(0.0, t_i - t_{i-1}))$ in seconds (`0.0` for the first event in a sequence).
- **Index `10` (`IS_EXECUTABLE`):** `1.0` if `entity` ends with an executable or script extension (`.exe`, `.bat`, `.ps1`, `.dll`, `.cmd`, `.vbs`, `.sys`, `.scr`, `.msi`, etc.); `0.0` otherwise.
- **Index `11` (`IS_REMOVABLE`):** `1.0` if `source == "usb"`, `drive_letter != "C:"`, or non-system drive path is referenced; `0.0` otherwise.

Events within a session are grouped into consecutive sliding windows of size $N = 10$ with stride $S = 1$. Sequences shorter than 10 events are left-padded with zero vectors so inference executes uniformly on $(10, 12)$ matrices.

### 4.2 Leakage-Free Session Partitioning
To prevent temporal data leakage across adjacent events, `partition_sessions_by_recording()` partitions data strictly by **recording session ID**, asserting mutual disjointness:

$$\text{Sessions}(\text{train}) \cap \text{Sessions}(\text{val}) \cap \text{Sessions}(\text{test}) = \emptyset$$

During model training (`engine/ml/train.py`), Akash partitioned the four recorded workstation sessions (`scenarios/baseline/`) as:
- **Training (`train`):** `baseline_session_01`, `baseline_session_02` (3 windows)
- **Validation (`val`):** `baseline_session_03` (1 window; used to select the 99th-percentile baseline threshold $\tau = 0.289622$)
- **Held-Out Real Baseline (`test`):** `baseline_session_04` (never seen during training or threshold selection)

### 4.3 Evaluation Methodology & Held-Out Test Results (`backend/evaluate_ml.py`)
The evaluation script `backend/evaluate_ml.py` strictly enforces zero leakage by excluding `baseline_session_01`, `baseline_session_02`, and `baseline_session_03` dynamically via `engine/ml/artifacts/threshold_metadata.json`. The held-out evaluation set comprises **6 unseen sessions**:
- **2 Benign Sessions:** `baseline_session_04` (real recorded baseline, 4 events) and `normal_noise` (background productivity + benign USB usage, 11 events).
- **4 Malicious Scenarios:** `scenario_a` (direct USB copy & run), `scenario_a_prime` (matched evaluation variant), `scenario_b` (staged execution), and `scenario_c` (bulk file creation + log clearing + timestamp discrepancy).

#### Table 4.1: Rules Alone vs. ML Alone vs. Hybrid on Held-Out Test Set
*(Decision threshold $\tau = 0.289622$, 99th percentile of normal validation loss; normalized anomaly score boundary `0.50`.)*

| Approach | TP | FP | TN | FN | Precision | Recall | F1 Score | False Positive Rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Rules Alone** | 4 | 0 | 2 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| **ML Alone** | 4 | 2 | 0 | 0 | 0.6667 | 1.0000 | 0.8000 | 1.0000 |
| **Hybrid (Rules + ML)** *(OR-gated $\text{Rules} \lor \text{ML} \ge 0.50$)* | 4 | 2 | 0 | 0 | 0.6667 | 1.0000 | 0.8000 | 1.0000 |

#### Table 4.2: Per-Session Breakdown (Measured Outputs)

| Session ID | Ground Truth | Events | Rules Triggered | Max Raw MSE | Normalized ML Score | ML Flagged ($\ge 0.50$) | Hybrid Threat Levels |
|---|---|---:|---|---:|---:|---|---|
| `baseline_session_04` | `normal` | 4 | None | `0.4884` | `0.84` | True *(FP)* | `-` *(0 rule activities)* |
| `normal_noise` | `normal` | 11 | None | `0.3650` | `0.63` | True *(FP)* | `-` *(0 rule activities)* |
| `scenario_a` | `malicious` | 3 | `R1, R2, R7` | `0.5777` | `1.00` | True *(TP)* | `CRITICAL` (3 chains) |
| `scenario_a_prime` | `malicious` | 3 | `R2` | `0.5753` | `0.99` | True *(TP)* | `CRITICAL` (1 chain) |
| `scenario_b` | `malicious` | 4 | `R1, R2, R7` | `0.5503` | `0.95` | True *(TP)* | `CRITICAL` (5 chains) |
| `scenario_c` | `malicious` | 9 | `R1, R4, R5, R6` | `0.5293` | `0.91` | True *(TP)* | `CRITICAL` (15 chains) |

### 4.4 Critical Analysis: Strengths, Weaknesses & Limitations
1. **What Rules Catch vs. Miss:** Deterministic rules (`R1`–`R7`) achieved **1.0000 Precision and 0.0000 FPR** because every rule requires explicit causal and temporal preconditions. However, rules alone cannot flag novel behavioral anomalies that fall outside predefined YAML signatures.
2. **What ML Catches vs. Misses:** The LSTM Autoencoder achieved **1.0000 Recall**, ranking every attack scenario (`0.5293–0.5777` MSE; normalized score `0.91–1.00`) strictly higher than both benign sessions (`0.3650–0.4884` MSE; normalized score `0.63–0.84`). However, at $\tau = 0.289622$, ML alone produced **2 false positives (`FPR = 1.0000`)**.
3. **Root Cause of Benign False Positives (Honest Limitation):** The ML baseline was trained on a small amount of recorded workstation activity (2 training sessions producing 3 windows, and 1 validation session producing only **1 validation window**). Consequently, $\tau = 0.289622$ underestimated normal reconstruction variance for:
   - Short sequences requiring heavy zero-padding (`baseline_session_04`, 4 events), and
   - Normal USB workflows (`normal_noise`) underrepresented in the initial training baseline.
4. **Why Hybrid Preserves Usability:** In ForensiTrace’s rule-anchored `CorrelationEngine`, benign sessions still produced **zero false-positive incident records** because alerts require rule provenance, while confirmed rule detections (`scenario_a`, `scenario_a_prime`, `scenario_b`, `scenario_c`) received elevated Tier 1 anomaly scores (`0.91–1.00`) and `CRITICAL` triage badges. Note that on `scenario_a_prime` (where only `R2` fired), the ML anomaly score (`0.99`) elevated the `R2` activity from `MEDIUM` to `CRITICAL`.

### 4.5 Automated Backend Test & Smoke Verification
- **Unit Test Suites:** All **29 automated tests** across `test_db.py`, `test_normalizers.py`, `test_ml_features.py`, `test_reports.py`, and `test_evaluate_ml.py` pass in `0.834s` with zero warnings (`must-fire` and `must-not-fire` coverage verified).
- **One-Command End-to-End Smoke Test (`backend/smoke_test.py`):** Validates `Scenario A -> EventBatch -> POST /events -> SQLite -> Hybrid CorrelationEngine -> Activity Persistence -> GET /timeline -> GET /report/{activity_id}` in an isolated database, returning `FORENSITRACE END-TO-END SMOKE TEST: PASS` and streaming an 8,318-byte 3-page PDF.

---

## Peer Review Checklist (For Akash)
- [ ] Verify data model (`docs/schema.md`, `docs/ml.md`) descriptions match `backend/schema.py` and `engine/ml/`.
- [ ] Verify ML feature vector length formula (`len(ActionEnum) + 3`) and session split metrics in Chapter 4 match `engine/ml/artifacts/threshold_metadata.json`.
- [ ] Confirm evaluation metrics in Tables 4.1 & 4.2 reflect `backend/ml_evaluation_results.json` (and re-run `python backend/evaluate_ml.py` if threshold tuning Step 8 updates `engine/ml/artifacts/`).
