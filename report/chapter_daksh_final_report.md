# ForensiTrace Final Report Chapters — System Overview, Endpoint Agent, Baseline & Scenarios, Overhead & Experiment

> **Author:** Daksh (Endpoint Agent, Baseline Data, Scenarios, Demo Runner & Experiment Owner)  
> **Peer Reviewer:** Chetna (USB/FS Collectors & React Dashboard Owner)  
> **Reference Specification:** `ForensiTrace — Build & Execution Plan v2 (Hybrid ML)`  
> **Contracts Implemented:** `docs/schema.md`, `docs/agent_interface.md`, `docs/ml.md`  
> **Status:** Complete Draft Ready for Peer Review by Chetna (Human experiment participant table to be populated after live classmate sessions)

---

## Positioning & Architectural Alignment Statement

ForensiTrace performs cross-source Windows endpoint forensic reconstruction without heavyweight ontology infrastructure, using a lightweight sequence-based anomaly detector that supports—but never replaces—explainable correlation rules (`R1`–`R7`). Every forensic conclusion traces directly to raw endpoint telemetry events through deterministic rule chains; the machine learning signal (`ml_anomaly_score`, a normalized LSTM reconstruction error between `0.0` and `1.0`) provides a complementary behavioral signal alongside rule confidence, and PDF exports serve as forensic investigation reports with an unedited raw evidence appendix.

---

## Chapter 1: System Overview & One-Command Demo Architecture

### 1.1 End-to-End Pipeline
ForensiTrace integrates four decoupled subsystems communicating over strict JSON contracts:
1. **Endpoint Agent (`agent/`):** Captures Windows Security/System Event Logs (`4688`, `1102`, `104`), Win32 USB PnP device arrivals/removals, and `watchdog` filesystem mutations, normalizing all records into the 10-field schema (`docs/schema.md`) before batched HTTP delivery.
2. **Backend & Data Layer (`backend/`):** FastAPI ingestion service (`POST /events`) backed by SQLite with `INSERT OR IGNORE` idempotency, unified `/timeline` streaming, and 3-page PDF forensic report generation (`GET /report/{activity_id}`).
3. **Hybrid Correlation & ML Engine (`engine/`):** Evaluates deterministic rules `R1`–`R7` alongside a CPU-compatible PyTorch LSTM autoencoder (`engine/ml/`) trained on real normal workstation activity.
4. **Investigation Dashboard (`dashboard/`):** React + Vite interface displaying rule confidence, `ml_anomaly_score`, `threat_level`, an interactive cross-source timeline, and an evidence drawer exposing untouched raw telemetry.

### 1.2 One-Command Demo Orchestration (`scripts/run_demo.py`)
To guarantee reproducible demonstrations from a fresh clone without manual multi-terminal setup, `scripts/run_demo.py` automates the full workflow:
1. Initializes and resets `backend/forensitrace.db`.
2. Loads the trained LSTM autoencoder and validation threshold (`0.2896`) from `engine/ml/artifacts/`.
3. Starts the FastAPI backend (`uvicorn backend.main:app`) and polls `/health`.
4. Replays Scenario A (or any selected scenario) via `POST /events` and executes `CorrelationEngine(ml_scorer=scorer)` to persist hybrid-scored activities.
5. Installs `dashboard/node_modules` automatically if absent, starts the Vite dev server, and opens the dashboard in the default browser.

---

## Chapter 2: Endpoint Agent Core & Windows Event Log Collector

### 2.1 Agent Lifecycle & Resilient HTTP Sender (`agent/main.py`, `agent/config.py`, `agent/sender.py`)
`ForensiTraceAgent` orchestrates collector startup, inter-collector USB-to-FS drive handoff hooks (`register_drive_listener` $\rightarrow$ `handle_drive_event`), and graceful shutdown. Events enter a thread-safe bounded `queue.Queue` (`max_buffer_size = 10000`) drained by `EventSender` in configurable batches (`batch_size = 10`, `flush_interval_seconds = 2.0`). Transient backend outages trigger exponential backoff retries (`1.0s` initial, factor `2.0`, max `30.0s`) without dropping queued telemetry, while deterministic `event_id` hashing prevents duplicates on retry.

### 2.2 Windows Event Log Collector & NT Device Path Resolution (`agent/collectors/eventlog_collector.py`)
The Event Log collector polls Windows `Security` and `System` channels via `pywin32` (`win32evtlog`) for:
- **Process Creation (`Security` Event ID `4688`):** Captures `NewProcessName`, `CommandLine`, `ParentProcessName`, `ProcessId`, and user SID/domain.
- **Audit / System Log Clearing (`Security` `1102`, `System` `104`):** Emits `LOG_CLEARED` events to detect anti-forensic tampering.

**Windows 11 Removable Media Path Fix:** During live hardware testing on Windows 11 FAT32 USB drives, Event `4688` recorded `NewProcessName` using kernel NT device paths (`\Device\HarddiskVolume11\calc_payload.exe`) rather than DOS drive letters (`D:\`). `resolve_nt_device_path()` resolves `\Device\HarddiskVolumeXX` prefixes dynamically via `kernel32.QueryDosDeviceW` across `A:`–`Z:`, with a `CommandLine` regex fallback, restoring exact path matching with Rule `R7`.

---

## Chapter 3: Baseline Data, Synthetic Labeling & Evaluation Scenarios

### 3.1 Real Baseline Workstation Recordings (`scenarios/baseline/`)
To ensure the LSTM autoencoder learns genuine user behavior rather than synthetic artifacts alone, four separate workstation sessions (`baseline_session_01.json` through `04.json`) were recorded through the endpoint agent on Windows 11 (`scripts/record_baseline.py`). Session 2 explicitly includes ordinary benign USB flash drive insertion, document access, and safe removal so routine removable-media usage is not flagged as anomalous.

### 3.2 Synthetic Generator Labeling & Isolation (`scenarios/generate_synthetic_events.py`)
Per the Plan v2 research-integrity contract, `make_event()` tags all generated fixtures with `details.is_synthetic = true` and `details.dataset_type = "synthetic"`. A new `generate_synthetic_normal()` generator produces `scenarios/fixtures/synthetic_normal.json` (12 routine workstation events labeled `normal`), kept strictly separated in `scenarios/fixtures/` from real recordings in `scenarios/baseline/`.

### 3.3 Scripted Attack & Noise Scenarios (`scenarios/` & `scenarios/ground_truth/`)
Five standalone replay scripts (`--output`, `--db`, `--ingest`) produce deterministic telemetry paired with ground-truth JSON specifications:

| Scenario | Script | Label | Expected Rules | Threat Level | Purpose |
|---|---|---|---|---|---|
| **Scenario A** | `scenarios/scenario_a.py` | `malicious` | `R1`, `R2`, `R7` | `CRITICAL` | Direct USB insertion $\rightarrow$ payload write $\rightarrow$ execution from `E:`. |
| **Scenario A′** | `scenarios/scenario_a_prime.py` | `malicious` | `R2` | `HIGH` | Staged evasion: USB arrival $\rightarrow$ copy to `C:\...\Temp\` $\rightarrow$ run from `C:` (evades `R7`). |
| **Scenario B** | `scenarios/scenario_b.py` | `malicious` | `R1`, `R2`, `R7` | `CRITICAL` | Staged attack: USB arrival $\rightarrow$ file write $\rightarrow$ modify $\rightarrow$ 180s delay $\rightarrow$ run. |
| **Scenario C** | `scenarios/scenario_c.py` | `malicious` | `R4`, `R5`, `R6` | `CRITICAL` | Anti-forensics: 6-file USB burst (`R4`), Security log clear `1102` (`R5`), 3900s timestomp (`R6`). |
| **Normal Noise** | `scenarios/normal_noise.py` | `normal` | `[]` (0 rules) | `LOW` | Everyday office work, browsing, and benign read-only USB PDF viewing (negative control). |

---

## Chapter 4: Agent Overhead Study & Human Experiment Design

### 4.1 Empirical Agent & Hybrid ML Overhead Study (`scripts/measure_overhead.py`)
Resource consumption was measured on Windows 11 (`Windows-11-10.0.26300-SP0`, 20 logical CPU cores, 15.71 GB RAM) using `psutil` across two phases: a 5.0s idle baseline and an active file-copy burst (50 `.txt` files totaling 9.77 MB) shipped to the FastAPI backend and scored by the PyTorch CPU LSTM autoencoder:

| Component | State | Avg CPU (%) | Peak CPU (%) | Avg Memory (MB) | Peak Memory (MB) |
|---|---|---:|---:|---:|---:|
| **Endpoint Agent** | Idle | 0.31 | 3.10 | 39.30 | 39.30 |
| **Endpoint Agent** | Active Copy + ML | 8.05 | 12.50 | 42.04 | 42.05 |
| **FastAPI Backend** | Idle | 0.00 | 0.00 | 57.96 | 57.96 |
| **FastAPI Backend** | Active Copy + ML | 2.92 | 5.90 | 58.42 | 58.59 |
| **ML Scorer + Engine (PyTorch CPU)** | Idle | 0.00 | 0.00 | 211.55 | 211.55 |
| **ML Scorer + Engine (PyTorch CPU)** | Active Copy + ML | 5.08 | 7.20 | 213.06 | 220.28 |

- **Agent Footprint:** Remains lightweight at **0.31% CPU / 39.30 MB RAM** while idle and **8.05% avg CPU / 42.04 MB RAM** during a 50-file burst.
- **Hybrid ML Scoring Latency:** Correlating and scoring all 50 captured events completed in **28.05 ms** on CPU.

### 4.2 Human Experiment Protocol (`scenarios/experiment/`)
To evaluate investigator efficiency and accuracy, a counterbalanced 2×2 within-subjects study compares **Windows Event Viewer** against **ForensiTrace** across matched scenarios **A** and **A′** (`scenarios/experiment/protocol_and_worksheet.md`):
- **Participants & Counterbalancing:** 8–10 classmates (unfamiliar with the dashboard), alternating both tool order and scenario order so no participant investigates the same attack chain twice.
- **Standardized 5 Questions:** (1) USB device used, (2) copied/created file path, (3) executing user account, (4) whether logs were cleared, and (5) chronological event order, scored against `scenarios/ground_truth/`.
- **Analysis Pipeline:** `scenarios/experiment/analyze_experiment.py` computes per-tool mean completion time and mean correct answers out of 5 from `results.csv` without claiming statistical significance due to the small sample size. *(Live participant results table to be inserted following classmate sessions.)*
