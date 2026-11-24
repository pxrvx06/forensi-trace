# ForensiTrace Machine Learning Technical Contract (Hybrid Architecture)

> **Status:** FROZEN CONTRACT — Phase 3 Specification  
> **Authors:** Purva (Backend & Data Layer Owner), Akash (Correlation Engine & ML Owner)  
> **Reviewers:** Daksh (Agent & Scenarios), Chetna (Collectors & UI)  
> **Rule:** This document is a strict technical contract. All components consuming or producing ML features, window scores, or threat assessments must conform strictly to this specification.

---

## 1. Architectural Philosophy: The Hybrid Model

ForensiTrace adheres to a hybrid architecture designed to satisfy both statistical anomaly detection and strict forensic explainability:

```
                            +--------------------------------+
                            |     Normalized Telemetry       |
                            |   (USB, FileSystem, Sysmon)    |
                            +---------------+----------------+
                                            |
                    +-----------------------+-----------------------+
                    |                                               |
                    v                                               v
     +------------------------------+               +------------------------------+
     |     Tier 1: ML Anomaly       |               |     Tier 2: Rule Engine      |
     |   LSTM Autoencoder on CPU    |               |    Deterministic R1 - R7     |
     +--------------+---------------+               +--------------+---------------+
                    |                                               |
                    | [0.0 - 1.0]                                   | [0.0 - 1.0]
                    v                                               v
          ml_anomaly_score                                   rule_confidence
                    |                                               |
                    +-----------------------+-----------------------+
                                            |
                                            v
                            +-------------------------------+
                            |   Reconstructed Activity      |
                            |   - ml_anomaly_score          |
                            |   - confidence (rule)         |
                            |   - threat_level              |
                            |   - narrative                 |
                            |   - raw evidence provenance   |
                            +-------------------------------+
```

1. **Role of Tier 1 (ML Anomaly Detector):** A lightweight LSTM Autoencoder processes sliding event windows to detect unusual behavioral sequences without requiring explicit attack signatures. It outputs a normalized `ml_anomaly_score` in $[0.0, 1.0]$.
2. **Role of Tier 2 (Deterministic Rule Engine):** Rules R1–R7 establish causal temporal links across telemetry sources, guaranteeing provenance, chain of custody, and explainability back to raw event IDs.
3. **Core Forensic Invariant:** The ML score **never** replaces rule confidence or raw telemetry evidence. Both signals are presented side-by-side in the API, the React dashboard, and the PDF forensic report.

---

## 2. Feature Vector Specification (Dynamically Sourced)

Per project rules, the input vector size is **never hard-coded**. It is computed dynamically from the schema action definitions plus 3 contextual flags:

$$\text{Vector Length} = |\text{ActionEnum}| + 3 = 9 + 3 = 12$$

### 2.1. Feature Layout

| Index | Feature Name | Source | Description | Type / Range |
|---|---|---|---|---|
| **0** | `ACTION_DEVICE_ARRIVED` | Schema (`ActionEnum.DEVICE_ARRIVED`) | USB volume mounted | Binary (`0.0` or `1.0`) |
| **1** | `ACTION_DEVICE_REMOVED` | Schema (`ActionEnum.DEVICE_REMOVED`) | USB volume disconnected | Binary (`0.0` or `1.0`) |
| **2** | `ACTION_FILE_CREATED` | Schema (`ActionEnum.FILE_CREATED`) | File creation event | Binary (`0.0` or `1.0`) |
| **3** | `ACTION_FILE_MODIFIED` | Schema (`ActionEnum.FILE_MODIFIED`) | File content/attribute modification | Binary (`0.0` or `1.0`) |
| **4** | `ACTION_FILE_DELETED` | Schema (`ActionEnum.FILE_DELETED`) | File deletion event | Binary (`0.0` or `1.0`) |
| **5** | `ACTION_FILE_MOVED` | Schema (`ActionEnum.FILE_MOVED`) | File renamed/moved | Binary (`0.0` or `1.0`) |
| **6** | `ACTION_PROCESS_STARTED` | Schema (`ActionEnum.PROCESS_STARTED`) | Process execution (Sysmon 1 / 4688) | Binary (`0.0` or `1.0`) |
| **7** | `ACTION_LOG_CLEARED` | Schema (`ActionEnum.LOG_CLEARED`) | Event log cleared (1102 / 104) | Binary (`0.0` or `1.0`) |
| **8** | `ACTION_LOGON` | Schema (`ActionEnum.LOGON`) | User logon event (4624) | Binary (`0.0` or `1.0`) |
| **9** | `DELTA_T_LOG` | Temporal Context | $\log_e(1 + \Delta t)$ where $\Delta t = \max(0.0, t_i - t_{i-1})$ in seconds | Continuous ($\ge 0.0$) |
| **10** | `IS_EXECUTABLE` | Entity Context | `1.0` if file/process path ends in executable extension (`.exe`, `.dll`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.sys`, `.scr`, `.msi`); else `0.0` | Binary (`0.0` or `1.0`) |
| **11** | `IS_REMOVABLE` | Entity & Details Context | `1.0` if drive letter is non-system (`!= C:`), e.g. `E:`, or `source == usb`; else `0.0` | Binary (`0.0` or `1.0`) |

### 2.2. Feature Extraction Rules
- If $t_{i-1}$ is unknown (first event in a session or stream), $\Delta t = 0.0 \implies \log(1 + 0) = 0.0$.
- Path inspection for `IS_EXECUTABLE` and `IS_REMOVABLE` must be case-insensitive.
- If an event belongs to an unrecognized action (schema violation), all action one-hot indices remain `0.0`.

---

## 3. Windowing & Sequence Formulation

The Autoencoder processes sequences of consecutive events:

- **Window Size ($N$):** $10$ consecutive events.
- **Stride ($S$):** $1$ event (sliding window for real-time telemetry streaming).
- **Matrix Dimension:** Each window is a 2D tensor of shape $(N, D) = (10, 12)$.
- **Padding Rule:** If an event sequence has fewer than $N$ events (e.g. at the start of a session), left-pad with zero vectors:
  $$\mathbf{W} \in \mathbb{R}^{10 \times 12}$$

---

## 4. Anomaly Scoring & Threshold Normalization

### 4.1. Autoencoder Reconstruction Loss
The PyTorch LSTM Autoencoder attempts to reconstruct the input window $\mathbf{W}$. The reconstruction error is the Mean Squared Error (MSE):

$$\text{MSE}(\mathbf{W}, \widehat{\mathbf{W}}) = \frac{1}{10 \times 12} \sum_{i=1}^{10} \sum_{j=1}^{12} (W_{ij} - \widehat{W}_{ij})^2$$

### 4.2. Normalization to $[0.0, 1.0]$
A baseline threshold $\tau$ is determined from the validation split of normal baseline activity (specifically, the 99th percentile of normal reconstruction loss, $\tau = P_{99}(\text{MSE}_{\text{val\_normal}})$).

To ensure intuitive interpretation across all user-facing components, raw reconstruction loss is normalized into `ml_anomaly_score` $\in [0.0, 1.0]$:

$$\text{ml\_anomaly\_score} = \min\left(1.0, \frac{\text{MSE}}{2 \times \tau}\right)$$

Under this mapping:
- $\text{MSE} = 0 \implies \text{score} = 0.00$ (completely routine pattern).
- $\text{MSE} = \tau \implies \text{score} = 0.50$ (baseline anomaly decision boundary).
- $\text{MSE} \ge 2\tau \implies \text{score} = 1.00$ (severe anomaly).

### 4.3. Mapping Window Scores to Activities
An activity spans multiple events $[e_{\text{start}}, \dots, e_{\text{end}}]$. An activity's `ml_anomaly_score` is defined as the **maximum** anomaly score of any sliding window that overlaps with the activity's supporting events:

$$\text{activity.ml\_anomaly\_score} = \max_{W_k \cap \text{Events}(\text{activity}) \neq \emptyset} \text{score}(W_k)$$

If no ML score is available (e.g. model not yet trained or ML offline), `ml_anomaly_score` is `None` / `null`.

---

## 5. Threat Level Classification & Hybrid Index

### 5.1. Combined Risk Index
For sorting and prioritization, a combined index $R_{\text{hybrid}}$ is calculated:

$$R_{\text{hybrid}} = 0.5 \times \text{rule\_confidence} + 0.5 \times \text{ml\_anomaly\_score}$$

*(Note: If `ml_anomaly_score` is missing or `None`, $R_{\text{hybrid}} = \text{rule\_confidence}$. Both component scores must always be displayed separately; the 0.5/0.5 weights are an empirical operational heuristic.)*

### 5.2. Threat Levels
Every activity is tagged with a discrete `threat_level`:

| Threat Level | Primary Criteria | Typical Scenarios |
|---|---|---|
| `CRITICAL` | $R_{\text{hybrid}} \ge 0.85$ OR rule `R6` (timestomp) / `R7` (complete exfiltration/staging) | Full USB exfiltration sequence, deliberate timestamp manipulation |
| `HIGH` | $0.70 \le R_{\text{hybrid}} < 0.85$ OR rule `R1` (unauthorized USB) / `R4` (file burst) / `R5` (log clear) | Rapid mass file copying, audit log tampering |
| `MEDIUM` | $0.40 \le R_{\text{hybrid}} < 0.70$ OR rule `R2` (file write + exec) / `R3` (untracked execution) | Unrecognized binary execution without preceding write, isolated write |
| `LOW` | $R_{\text{hybrid}} < 0.40$ AND no high-severity rule triggered | Routine background telemetry, benign USB read |

---

## 6. Data Splitting & Leakage Prevention Protocol

To ensure rigorous scientific validity and prevent temporal or session data leakage:

1. **Split Unit:** Data **MUST** be partitioned strictly by **recording session ID**, never by individual random events.
2. **Partitions:**
   - **Training Set (`train`):** Benign workstation sessions (normal daily workflow: web browsing, file edits, normal USB flash drive read/writes).
   - **Validation Set (`val`):** Independent benign sessions used exclusively for selecting hyper-parameters and calculating the 99th percentile baseline threshold $\tau$.
   - **Test Set (`test`):** Attack scenarios (A, A′, B, C), noise scripts, and separate held-out benign sessions.
3. **Disjointness Invariant:**
   $$\text{Sessions}(\text{train}) \cap \text{Sessions}(\text{val}) \cap \text{Sessions}(\text{test}) = \emptyset$$
4. **Privacy:** Real telemetry recordings containing hostnames, usernames, and file paths remain strictly inside the local repository/environment and must be anonymized before presentation.

---

## 7. API Endpoints Contract

### 7.1. `GET /timeline`
Merges normalized events and reconstructed activities into a single chronological stream for Chetna's React timeline.

- **Query Parameters:**
  - `limit`: int (default `100`, max `1000`)
  - `offset`: int (default `0`)
  - `source`: string (optional filter: `usb`, `fs`, `eventlog`)
- **Response Format:**
  ```json
  {
    "count": 2,
    "limit": 100,
    "offset": 0,
    "timeline": [
      {
        "type": "event",
        "ts_utc": "2026-10-23T10:00:00.120Z",
        "data": {
          "event_id": "8fdfc64e...",
          "source": "usb",
          "action": "DEVICE_ARRIVED",
          "entity": "E: (SanDisk Ultra)",
          "user": "SYSTEM"
        }
      },
      {
        "type": "activity",
        "ts_utc": "2026-10-23T10:02:30.800Z",
        "data": {
          "activity_id": "act_20261023_001",
          "rule_id": "R7",
          "rule_name": "Full USB Staging Chain",
          "confidence": 0.95,
          "ml_anomaly_score": 0.88,
          "threat_level": "CRITICAL",
          "narrative": "USB drive mounted followed by executable write and execution."
        }
      }
    ]
  }
  ```

### 7.2. `GET /report/{activity_id}`
Streams a formatted 3-page forensic PDF report (`application/pdf`) with `Content-Disposition: attachment; filename="ForensiTrace_Report_{activity_id}.pdf"`.

- **Page 1:** Case Header, Target Host/User details, Threat Badge, Activity Narrative & Metric Cards (`confidence`, `ml_anomaly_score`, `threat_level`).
- **Page 2:** Reconstructed Evidence Timeline and Correlated Events Table.
- **Page 3:** Raw Log Appendix (verbatim unedited JSON payloads for forensic explainability).

---

## 8. Handoff Verification Checklist

- [x] Feature vector formula dynamically references `ActionEnum` (`len(ActionEnum) + 3 = 12`).
- [x] Autoencoder reconstruction score normalized to $[0.0, 1.0]$ using validation baseline $\tau$.
- [x] `Activity` schema in `backend/schema.py` and DB table in `backend/db.py` extended with `ml_anomaly_score` and `threat_level`.
- [x] `GET /timeline` unified chronologically.
- [x] Session splitting code enforces disjoint session IDs across train/val/test.
- [x] `GET /report/{activity_id}` PDF generation ready.
