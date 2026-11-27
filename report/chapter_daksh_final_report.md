# ForensiTrace Final Report Chapters — System Overview, Endpoint Agent, Baseline Data & Scenarios, Overhead Study & Human Experiment

> **Author:** Daksh Shaparia (Endpoint Agent, Baseline Data, Scenarios, Demo Runner & Human Experiment Owner)  
> **Peer Reviewer:** Chetna Bothra (USB/FS Collectors & React Dashboard Owner)  
> **Reference Specification:** `ForensiTrace — Build & Execution Plan v2 (Hybrid ML)`  
> **Contracts Implemented:** `docs/schema.md`, `docs/agent_interface.md`, `docs/ml.md`, `docs/rules.yaml`  
> **Status:** Complete Draft Ready for Peer Review by Chetna (Human experiment results table to be populated after live classmate sessions)

---

## Positioning & Architectural Alignment Statement

ForensiTrace performs cross-source Windows endpoint forensic reconstruction without heavyweight ontology infrastructure, using a lightweight sequence-based anomaly detector that supports—but never replaces—explainable correlation rules (`R1`–`R7`). Every forensic conclusion traces directly to unedited raw endpoint telemetry through deterministic rule chains; the machine learning signal (`ml_anomaly_score`, a normalized LSTM autoencoder reconstruction error between `0.00` and `1.00`, never described as a percentage of risk) serves strictly as a complementary behavioral score displayed alongside rule confidence. Exported PDFs are forensic investigation reports with an unedited raw evidence appendix.

---

## Chapter 1: System Overview & One-Command Demo Architecture

### 1.1 Cross-Source Hybrid Architecture
Endpoint investigations commonly fail when analysts must manually correlate isolated Windows Event Logs, USB device insertion histories, and filesystem changes across separate tools. ForensiTrace unifies these telemetry streams into a four-tier pipeline governed by frozen JSON contracts:

| Tier | Module | Owner | Responsibility |
|---|---|---|---|
| **1. Endpoint Telemetry** | `agent/` | Daksh, Chetna | Captures Windows Event Logs (`4688`, `1102`, `104`), Win32 USB PnP arrivals/removals, and `watchdog` filesystem mutations; normalizes into `docs/schema.md` and ships resiliently over HTTP. |
| **2. Ingestion & Storage** | `backend/` | Purva | FastAPI ingestion (`POST /events`), SQLite storage with `INSERT OR IGNORE` deduplication, unified `/timeline` query, and 3-page PDF forensic report generation (`GET /report/{activity_id}`). |
| **3. Hybrid Correlation & ML** | `engine/` | Akash | Evaluates deterministic rules `R1`–`R7` (`docs/rules.yaml`) alongside a CPU-default PyTorch LSTM autoencoder (`engine/ml/`) to attach `ml_anomaly_score` and `threat_level` while preserving rule provenance. |
| **4. Investigation UI** | `dashboard/` | Chetna | React + Vite interface displaying rule confidence and ML anomaly score side by side, unified chronological timeline, raw JSON Evidence Drawer, and one-click PDF export. |

### 1.2 One-Command Demo Orchestration (`scripts/run_demo.py`)
To guarantee reproducible demonstrations from a fresh clone without manual multi-terminal setup, `scripts/run_demo.py` automates the entire lifecycle:
1. **Clean State:** Initializes and resets `backend/forensitrace.db` (or a custom `--db` path).
2. **ML Initialization:** Loads the trained LSTM autoencoder weights and validation threshold ($\tau = 0.2896$) from `engine/ml/artifacts/` via `AnomalyScorer`, falling back gracefully to rules-only mode if artifacts are absent.
3. **Backend Startup:** Launches `uvicorn backend.main:app` on port `8000` and polls `GET /health` until ready.
4. **Scenario Replay & Hybrid Scoring:** Replays Scenario A (default; supports `scenario_a_prime`, `scenario_b`, `scenario_c`, and `normal_noise` via `--scenario`) through `POST /events`, executes `CorrelationEngine(ml_scorer=scorer)`, and persists reconstructed activities. On Scenario A, the runner verifies all 3 expected rule chains (`R1`, `R2`, `R7`) with `ML=0.9973` and `Threat=CRITICAL`.
5. **Frontend Launch:** Automatically executes `npm install` in `dashboard/` if `node_modules/` is absent (fresh-clone support), starts the Vite dev server on port `5173`, opens the browser, and terminates both child processes cleanly on `Ctrl+C`.

---

## Chapter 2: Endpoint Agent Core & Windows Event Log Collector

### 2.1 Agent Lifecycle, Configuration & Resilient Sender (`agent/main.py`, `agent/config.py`, `agent/sender.py`)
`ForensiTraceAgent` manages collector initialization, inter-collector drive handoff hooks (`usb_collector.register_drive_listener(fs_collector.handle_drive_event)`), and orderly shutdown.
- **Configuration (`agent/config.py`):** Loads defaults, optional JSON config, and `FORENSITRACE_*` environment overrides (`backend_url`, `batch_size=10`, `flush_interval_seconds=2.0`, `max_buffer_size=10000`, `enabled_collectors=["eventlog", "usb", "fs"]`).
- **Buffered Resilient Shipping (`agent/sender.py`):** Drains the thread-safe `queue.Queue` in batches and posts to `POST /events`. Transient network or backend outages trigger exponential backoff (`retry_initial_delay=1.0s`, `retry_backoff_factor=2.0`, `retry_max_delay=30.0s`) while retaining events in memory. Schema-invalid `HTTP 422` batches are logged and discarded to avoid head-of-line blocking, and deterministic `event_id` hashing prevents duplicates on retry.

### 2.2 Windows Event Log Collector & NT Device Path Resolution (`agent/collectors/eventlog_collector.py`)
The Event Log collector polls Windows `Security` and `System` channels via `pywin32` (`win32evtlog`) for:
- **Process Creation (`Security` Event ID `4688`):** Extracts `NewProcessName`, `CommandLine`, `ParentProcessName`, `ProcessId`, and `SubjectUserName`/`SubjectDomainName`, emitting normalized `PROCESS_STARTED` events.
- **Log Clearing (`Security` `1102`, `System` `104`):** Emits `LOG_CLEARED` events to expose anti-forensic log tampering (`Rule R5`).

**Hardware Verification Finding — NT Device Path Resolution:** During live Windows 11 testing with a FAT32 USB flash drive (`D:\`), Windows Security Event `4688` recorded `NewProcessName` using kernel NT device paths (`\Device\HarddiskVolume11\calc_payload.exe`) rather than DOS drive letters (`D:\calc_payload.exe`), breaking exact path matching against `FileSystemCollector` events. Implementing `resolve_nt_device_path()` via `kernel32.QueryDosDeviceW` across `A:`–`Z:` (with a `CommandLine` regex fallback) resolved `\Device\HarddiskVolumeXX` prefixes to canonical uppercase DOS drive paths, restoring full Rule `R7` correlation on live hardware.

---

## Chapter 3: Baseline Data Collection, Synthetic Labeling & Evaluation Scenarios

### 3.1 Real Baseline Workstation Recordings (`scenarios/baseline/`)
To ensure the LSTM autoencoder learns authentic workstation behavior rather than synthetic patterns alone, four separate normal sessions were recorded through the endpoint agent on Windows 11 (`scripts/record_baseline.py`), totaling **32 real baseline events**:

| Session File | Events | Telemetry Sources | Activity Summary |
|---|---:|---|---|
| `baseline_session_01.json` | 11 | `eventlog`, `fs` | Interactive logon, productivity apps, local document edits |
| `baseline_session_02.json` | 10 | `usb`, `eventlog`, `fs` | Ordinary benign USB flash drive insertion, document access, safe removal |
| `baseline_session_03.json` | 7 | `eventlog`, `fs` | Routine system utilities and local file activity |
| `baseline_session_04.json` | 4 | `eventlog` | Held-out normal session (excluded from training and threshold selection) |

Including ordinary benign USB usage in `baseline_session_02.json` ensures removable-media insertion alone is not treated as anomalous. All recordings conform to `docs/schema.md` and remain strictly in `scenarios/baseline/` (`scenarios/test_baseline.py`: 5/5 tests passing).

### 3.2 Synthetic Generator Labeling & Isolation (`scenarios/generate_synthetic_events.py`)
Per the Plan v2 research-integrity contract, `make_event()` enforces explicit synthetic provenance metadata (`details.is_synthetic = true`, `details.dataset_type = "synthetic"`). A dedicated `generate_synthetic_normal()` function generates `scenarios/fixtures/synthetic_normal.json` (12 routine workstation events labeled `normal`), stored strictly in `scenarios/fixtures/` and verified by `test_09_synthetic_labeling_and_separation` (`scenarios/test_synthetic_events.py`: 9/9 tests passing) to prevent unlabelled mixing with real baseline sessions.

### 3.3 Scripted Attack & Noise Scenarios (`scenarios/` & `scenarios/ground_truth/`)
Five standalone replay scripts (`--output`, `--db`, `--ingest`) produce deterministic telemetry paired with ground-truth JSON specifications (`scenarios/test_scenarios.py`: 9/9 tests passing):

| Scenario | Script | Events | Ground Truth Label | Expected Rules | Threat Level |
|---|---|---:|---|---|---|
| **Scenario A** | `scenarios/scenario_a.py` | 3 | `malicious` | `R1`, `R2`, `R7` | `CRITICAL` |
| **Scenario A′** | `scenarios/scenario_a_prime.py` | 3 | `malicious` | `R2` *(evades `R7` via `C:\` staging)* | `HIGH` |
| **Scenario B** | `scenarios/scenario_b.py` | 4 | `malicious` | `R1`, `R2`, `R7` *(modify + 180s delay)* | `CRITICAL` |
| **Scenario C** | `scenarios/scenario_c.py` | 9 | `malicious` | `R4`, `R5`, `R6` *(burst + log clear + timestomp)* | `CRITICAL` |
| **Normal Noise** | `scenarios/normal_noise.py` | 11 | `normal` | `[]` *(0 rule activities)* | `LOW` |

**Honest Limitation:** While real baseline sessions were captured live on Windows 11, the four attack scenarios (`A`, `A′`, `B`, `C`) and `normal_noise` are controlled deterministic replays designed to verify rule boundaries, ML scoring separation, and human-experiment repeatability without executing live malware on shared machines.

---

## Chapter 4: Empirical Overhead Study & Human Experiment Design

### 4.1 Agent & Hybrid ML Overhead Study (`scripts/measure_overhead.py`)
Resource consumption was measured empirically on Windows 11 (`Windows-11-10.0.26300-SP0`, 20 logical CPU cores, 15.71 GB RAM) using `psutil 7.2.2` across two states: a 5.0-second **Idle** baseline and an **Active Copy + ML** burst (50 `.txt` files totaling 9.77 MB created in a watched directory, captured by `FileSystemCollector`, shipped over HTTP to FastAPI, and scored by the PyTorch CPU LSTM autoencoder):

| Component | State | Avg CPU (%) | Peak CPU (%) | Avg Memory (MB) | Peak Memory (MB) |
|---|---|---:|---:|---:|---:|
| **Endpoint Agent** | Idle | 0.31 | 3.10 | 39.30 | 39.30 |
| **Endpoint Agent** | Active Copy + ML | 8.05 | 12.50 | 42.04 | 42.05 |
| **FastAPI Backend** | Idle | 0.00 | 0.00 | 57.96 | 57.96 |
| **FastAPI Backend** | Active Copy + Ingestion | 2.92 | 5.90 | 58.42 | 58.59 |
| **ML Scorer + Engine (PyTorch CPU)** | Idle | 0.00 | 0.00 | 211.55 | 211.55 |
| **ML Scorer + Engine (PyTorch CPU)** | Active Copy + ML Correlation | 5.08 | 7.20 | 213.06 | 220.28 |

- **Lightweight Endpoint Footprint:** The agent consumes **0.31% CPU and 39.30 MB RSS** while idle, rising modestly to **8.05% avg CPU (12.50% peak) and 42.04 MB RSS** during a 50-file burst.
- **CPU ML Inference Latency:** Correlating and scoring all 50 captured events completed in **28.05 ms** on CPU (`report/overhead_results.json`), confirming real-time viability on standard laptops without a GPU.

### 4.2 Human Experiment Protocol & Analysis Pipeline (`scenarios/experiment/`)
To evaluate investigator speed and accuracy against manual log inspection, a counterbalanced 2×2 within-subjects study compares **Windows Event Viewer** against **ForensiTrace** (`scenarios/experiment/protocol_and_worksheet.md`):
- **Participants & Counterbalancing:** 8–10 classmates unfamiliar with the dashboard investigate matched scenarios **A** and **A′** (one per tool) using a Latin-square assignment alternating both tool order and scenario order so no participant sees the same attack chain twice. A single-teammate pilot validates question clarity prior to participant runs.
- **Standardized 5 Questions:** (1) USB device used, (2) copied/created file path, (3) executing user account, (4) whether logs were cleared, and (5) chronological event order, scored strictly against `scenarios/ground_truth/scenario_a.json` and `scenario_a_prime.json`.
- **Descriptive Reporting (`scenarios/experiment/analyze_experiment.py`):** Computes per-tool completion time (mean, min–max seconds) and correct answers (`/5`) from `results.csv` (`scenarios/experiment/test_experiment.py`: 2/2 tests passing). Per Plan v2 Page 12, results report descriptive averages and counts only without claiming statistical significance. *(Live participant data table to be inserted after classmate sessions are conducted.)*

---

## Peer Review Checklist (For Chetna)
- [ ] Verify Chapter 2 accurately reflects the USB $\rightarrow$ FS inter-collector handoff hook (`register_drive_listener` $\rightarrow$ `handle_drive_event`).
- [ ] Verify Chapter 1 & Chapter 4 accurately reference `dashboard/` and the Evidence Drawer workflow for the human experiment.
- [ ] Confirm Plan v2 positioning rules are respected (no *"percentage of risk"*, no *"court-admissible"*, no statistical significance claims on 8–10 participants).
- [ ] Populate the Chapter 4.2 participant results table once the live classmate runs are recorded in `scenarios/experiment/results.csv`.
