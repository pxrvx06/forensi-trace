# ForensiTrace Final Report Chapters — Correlation Engine, Rules, Hybrid ML Model & Limitations

> **Author:** Akash (Correlation Engine, Rules & ML Model Owner)  
> **Peer Reviewer:** Purva (Backend, Data Layer, PDF Reporting & ML Evaluation Owner)  
> **Reference Specification:** `ForensiTrace — Build & Execution Plan v2 (Hybrid ML)`  
> **Contracts Implemented:** `docs/rules.yaml`, `docs/ml.md`, `docs/ml_subsystem.md`  
> **Status:** Complete Draft Ready for Peer Review by Purva

---

## Positioning & Architectural Alignment Statement

ForensiTrace performs cross-source Windows endpoint forensic reconstruction without heavyweight ontology infrastructure, using a lightweight sequence-based anomaly detector that supports—but never replaces—explainable correlation rules (`R1`–`R7`). Every forensic conclusion remains traceable to unedited raw telemetry events through deterministic rule chains; the machine learning signal (`ml_anomaly_score`, a normalized LSTM autoencoder reconstruction error between `0.00` and `1.00`, never described as a percentage of risk) serves strictly as a complementary behavioral score displayed alongside rule confidence.

---

## Chapter 1: Deterministic Correlation Engine & Rule Suite (`R1`–`R7`)

### 1.1 YAML-Driven Correlation Architecture (`engine/correlator.py`, `docs/rules.yaml`)
All detection rules are declared in `docs/rules.yaml` and loaded at runtime by `engine/config.py`, keeping detection logic decoupled from code. `CorrelationEngine` evaluates normalized events across Windows Security/System Event Logs, USB PnP broadcasts, and filesystem notifications, generating deterministic `activity_id` hashes (`act_{rule_id}_{hash[:12]}`) and explicit `ActivityEventLink` provenance records.

### 1.2 Implemented Rule Suite (`R1`–`R7`) & Confidence Scoring (`engine/scoring.py`)
| Rule ID | Name | Window / Threshold | Base Confidence | Forensic Signal |
|---|---|---|---|---|
| **R1** | Device arrival followed by file activity | `300s` | `0.90` | `DEVICE_ARRIVED` followed by `FILE_CREATED`/`FILE_MODIFIED` on same drive |
| **R2** | File creation followed by process execution | `600s` | `0.90` | `FILE_CREATED` followed by `PROCESS_STARTED` at identical normalized path |
| **R3** | Process starts from removable drive without preceding write | `600s` | `0.80` | `PROCESS_STARTED` on confirmed removable drive with no prior write in window |
| **R4** | Bulk file creation on removable drive | `60s`, `min_count=5` | `0.85` | Rapid burst of distinct `FILE_CREATED` events on removable drive |
| **R5** | Log clearing near other activity | `600s` | `0.85` | `LOG_CLEARED` (`1102`/`104`) within 10 minutes of relevant host activity |
| **R6** | Timestamp disagreement | `> 120s` | `0.85` | Reported `ts_utc` differs from `details.ts_observed_utc` by `> 120s` |
| **R7** | Composite USB copy and execution chain | `900s` | `0.95` | Full 3-stage chain: USB arrival $\rightarrow$ file write on USB $\rightarrow$ execution from USB |

Deterministic confidence bonuses (`+0.02` to `+0.03`) reward confirmed user attribution, verified USB hardware serial/vendor IDs, tri-source corroboration, and rapid execution sequences, bounded strictly within `[0.0, 1.0]`.

---

## Chapter 2: Lightweight PyTorch LSTM Autoencoder (`engine/ml/`)

### 2.1 Model Architecture & CPU-First Execution (`engine/ml/model.py`, `engine/ml/config.py`)
To flag unusual telemetry sequences without GPU hardware requirements, `LSTMAutoencoder` implements a compact sequence-to-sequence reconstruction model running on CPU by default (with automatic CUDA fallback if available):
- **Input Representation:** Sliding windows of $N = 10$ consecutive events (stride $S = 1$), each encoded dynamically as a 12-dimensional vector (`len(ActionEnum) + 3 = 9 + 3`: 9 action one-hots, $\log(1 + \Delta t)$, `is_executable`, `is_removable`). Sequences shorter than 10 events are left-padded with zero vectors.
- **Encoder–Decoder:** Single-layer LSTM encoder (`input_dim=12`, `hidden_dim=16`) projected to an 8-dimensional bottleneck (`latent_dim=8`), decoded across 10 time steps back to $(10, 12)$ via a linear output head.
- **Training & Threshold Selection (`engine/ml/trainer.py`, `engine/ml/train.py`):** Trained for 30 epochs (`lr=0.005`, `seed=42`) strictly on real baseline recordings (`baseline_session_01` and `baseline_session_02`, 3 windows; `final_train_loss=0.1813`). Validation on `baseline_session_03` (1 window) established the 99th-percentile reconstruction MSE threshold $\tau = 0.289622$, persisted in `engine/ml/artifacts/threshold_metadata.json`.

---

## Chapter 3: Hybrid Scoring & Evidence-Grounded Narratives

### 3.1 Score Normalization & Hybrid Risk Index (`engine/ml/scoring.py`, `engine/ml/hybrid.py`)
Raw window MSE $E$ is normalized against $\tau$ into `ml_anomaly_score` $\in [0.0, 1.0]$:
- $E \le \tau \implies \text{score} = 0.5 \times (E / \tau)$ (maps $\tau \to 0.50$)
- $E > \tau \implies \text{score} = 0.5 + 0.5 \times \min((E - \tau) / \tau, 1.0)$ (maps $\ge 2\tau \to 1.00$)

Each correlated activity stores `confidence` and `ml_anomaly_score` separately. A 0.5 / 0.5 combined risk index (chosen by hand for triage sorting and `threat_level` badges: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) ranks incidents while falling back cleanly to rule confidence alone whenever `ml_anomaly_score` is `None`.

### 3.2 ML-Aware Incident Narratives (`engine/narratives.py`)
Every narrative sentence traces directly to observed raw event attributes (timestamps, device serials, normalized file paths, and process command lines). When `ml_anomaly_score` is available, an explicit behavioral assessment line reports the normalized reconstruction score and the contributing window characteristics (e.g., removable-media executable sequence or rapid event cadence) without using *"percentage of risk"* phrasing.

---

## Chapter 4: Limitations & Honest Evaluation Findings

1. **Small Real Baseline Dataset:** The LSTM autoencoder was trained on 2 real sessions (3 windows) and calibrated on 1 validation session (1 window). As measured in Purva's held-out evaluation (`backend/ml_evaluation_results.json`), while the model achieved **1.0000 Recall** across all attack scenarios (`0.91–1.00` normalized score), $\tau = 0.289622$ flagged both unseen benign sessions (`baseline_session_04` at `0.84` and `normal_noise` at `0.63`) due to zero-padding sensitivity on short sequences and limited normal USB variance.
2. **Rule-Anchored False-Positive Protection:** Because ForensiTrace only creates incident `Activity` records when deterministic rules (`R1`–`R7`) match raw telemetry, `baseline_session_04` and `normal_noise` still produced **0 false-positive incident cards**, demonstrating why ML is used strictly as a supporting signal beside explainable rules.
3. **Future Tuning Path:** Recording additional multi-minute real workstation sessions (including longer benign USB workflows) will raise validation window coverage and tighten $\tau$ without changing the frozen `docs/ml.md` contract.

---

## Peer Review Checklist (For Purva)
- [ ] Verify rule definitions (`R1`–`R7`) and confidence figures match `docs/rules.yaml` and `engine/scoring.py`.
- [ ] Verify `LSTMAutoencoder` dimensions (`12 -> 16 -> 8 -> 16 -> 12`) and threshold $\tau = 0.289622$ match `engine/ml/artifacts/model_config.json` and `threshold_metadata.json`.
- [ ] Confirm evaluation metrics in Chapter 4 align with `backend/ml_evaluation_results.json`.
