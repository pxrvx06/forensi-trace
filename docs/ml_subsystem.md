# ForensiTrace Phase III — Machine Learning Subsystem Specification & Handoff

> **Owner:** Akash (Correlation Engine & ML Owner)  
> **Repository:** `forensi-trace`  
> **Branch:** `akash`  
> **Status:** Fully Implemented, Trained on Baseline Data, and Verified (114 Engine & Backend Tests Passing)

---

## 1. Architectural Philosophy: The Two-Tier Hybrid Model

ForensiTrace adheres to a two-tier hybrid architecture uniting statistical sequence anomaly detection with deterministic forensic explainability:

```
                                  +------------------------------------+
                                  |       Normalized Telemetry         |
                                  |  (USB, FileSystem, Sysmon/Logon)   |
                                  +-----------------+------------------+
                                                    |
                         +--------------------------+--------------------------+
                         |                                                     |
                         v                                                     v
          +-------------------------------+                     +-------------------------------+
          |      Tier 1: ML Anomaly       |                     |     Tier 2: Rule Engine       |
          |    LSTM Autoencoder (CPU)     |                     |     Deterministic R1 - R7     |
          +---------------+---------------+                     +---------------+---------------+
                          |                                                     |
                          | [0.0 - 1.0]                                         | [0.0 - 1.0]
                          v                                                     v
                 ml_anomaly_score                                        rule_confidence
                          |                                                     |
                          +--------------------------+--------------------------+
                                                     |
                                                     v
                                     +-------------------------------+
                                     |    Reconstructed Activity     |
                                     |    - ml_anomaly_score         |
                                     |    - rule_confidence          |
                                     |    - R_hybrid combined score  |
                                     |    - threat_level             |
                                     |    - evidence provenance links|
                                     |    - ML-aware narrative       |
                                     +-------------------------------+
```

1. **Tier 1 (ML Anomaly Detector):** A lightweight PyTorch LSTM Autoencoder evaluates consecutive telemetry sequences to detect statistical anomalies without requiring prior signature definitions.
2. **Tier 2 (Deterministic Rule Engine):** Rules R1–R7 establish causal temporal links across telemetry sources, guaranteeing provenance, chain of custody, and explainability back to raw event IDs.
3. **Core Forensic Invariant:** The ML score **never** replaces rule confidence or raw telemetry evidence. An anomaly score indicates statistical divergence from baseline workstation behavior, not legal or factual proof of malicious intent.

---

## 2. Directory Structure

Akash's Phase III ML subsystem resides in `engine/ml/` with minimal necessary integration points in the existing engine:

```
engine/
├── ml/
│   ├── __init__.py            # Public module exports
│   ├── config.py              # MLModelConfig dataclass and serialization
│   ├── model.py               # Lightweight PyTorch LSTM Autoencoder (Encoder-Decoder)
│   ├── adapter.py             # EventFeatureAdapter and FeatureWindow sequence generator
│   ├── persistence.py         # Model weights (.pt), config, and threshold metadata persistence
│   ├── trainer.py             # Session-aware training, P99 threshold selection, and validation
│   ├── scoring.py             # AnomalyScorer, error normalization, and activity-level mapping
│   ├── hybrid.py              # HybridRiskEngine and discrete threat level classification
│   ├── train.py               # CLI entrypoint for model training on baseline sessions
│   └── artifacts/             # Trained model weights, metadata, and validation thresholds
│       ├── lstm_autoencoder.pt
│       ├── model_config.json
│       ├── feature_metadata.json
│       └── threshold_metadata.json
├── correlator.py              # CorrelationEngine integration with ML scoring
├── scoring.py                 # Confidence scoring + hybrid risk scoring exports
├── narratives.py              # Evidence-grounded narratives with ML context
└── tests/
    ├── test_ml_subsystem.py   # Comprehensive Phase III ML unit test suite (22 tests)
    ├── test_rules.py          # Phase II R1-R7 rules and regression suite (52 tests)
    └── test_fixtures.py       # Fixture integration tests (9 tests)
```

---

## 3. Feature Input Contract

Each event is mapped dynamically to a 12-dimensional vector ($\text{len}(\text{ActionEnum}) + 3 = 9 + 3 = 12$):

| Index | Feature Name | Description | Value Range |
|---|---|---|---|
| **0** | `ACTION_DEVICE_ARRIVED` | USB volume mounted (`ActionEnum.DEVICE_ARRIVED`) | `0.0` or `1.0` |
| **1** | `ACTION_DEVICE_REMOVED` | USB volume unmounted (`ActionEnum.DEVICE_REMOVED`) | `0.0` or `1.0` |
| **2** | `ACTION_FILE_CREATED` | File creation event (`ActionEnum.FILE_CREATED`) | `0.0` or `1.0` |
| **3** | `ACTION_FILE_MODIFIED` | File modification (`ActionEnum.FILE_MODIFIED`) | `0.0` or `1.0` |
| **4** | `ACTION_FILE_DELETED` | File deletion (`ActionEnum.FILE_DELETED`) | `0.0` or `1.0` |
| **5** | `ACTION_FILE_MOVED` | File move/rename (`ActionEnum.FILE_MOVED`) | `0.0` or `1.0` |
| **6** | `ACTION_PROCESS_STARTED` | Process execution (`ActionEnum.PROCESS_STARTED`) | `0.0` or `1.0` |
| **7** | `ACTION_LOG_CLEARED` | Security/System log cleared (`ActionEnum.LOG_CLEARED`) | `0.0` or `1.0` |
| **8** | `ACTION_LOGON` | Interactive user logon (`ActionEnum.LOGON`) | `0.0` or `1.0` |
| **9** | `DELTA_T_LOG` | Log-transformed time delta: $\log_e(1 + \max(0.0, \Delta t))$ in seconds | Continuous ($\ge 0.0$) |
| **10** | `IS_EXECUTABLE` | `1.0` if path ends in executable/script extension; else `0.0` | `0.0` or `1.0` |
| **11** | `IS_REMOVABLE` | `1.0` if non-system drive (`!= C:`) or USB source; else `0.0` | `0.0` or `1.0` |

### Sequencing & Session Boundaries:
- **Window Length ($N$):** 10 consecutive events.
- **Stride ($S$):** 1 event (sliding window).
- **Padding:** If a session has fewer than 10 events, it is left-padded with zero vectors of shape $(10, 12)$.
- **Session Boundary Invariant:** Windows **never** cross session boundaries. Events from separate recording sessions are partitioned before window generation.

---

## 4. LSTM Autoencoder Architecture

- **Encoder:** Stacked PyTorch LSTM (`input_size=12`, `hidden_size=16`, `num_layers=1`, `batch_first=True`) + Linear projection to bottleneck `latent_dim=8`.
- **Decoder:** Linear projection (`latent_dim=8 -> hidden_dim=16`) + repeat across time steps ($N=10$) + LSTM (`hidden_size=16`) + Linear output projection to `input_dim=12`.
- **Loss Function:** Reconstruction Mean Squared Error (MSE):
  $$\text{MSE}(\mathbf{W}, \widehat{\mathbf{W}}) = \frac{1}{10 \times 12} \sum_{i=1}^{10} \sum_{j=1}^{12} (W_{ij} - \widehat{W}_{ij})^2$$
- **Execution Target:** CPU-first execution (`device="cpu"` by default, auto-detects CUDA when present).
- **Sanitization:** Safely intercepts and cleans NaN, +/- Inf values (`torch.nan_to_num`) without crashing.

---

## 5. Anomaly Threshold Selection and Scoring Normalization

1. **Validation Threshold ($\tau$):** Derived from the 99th percentile of normal baseline validation reconstruction errors:
   $$\tau = P_{99}(\text{MSE}_{\text{val\_normal}})$$
2. **Score Normalization:**
   For reconstruction error $E$ and baseline threshold $T$:
   - If $E \le T$: $\text{score} = 0.5 \times \frac{E}{T}$
   - If $E > T$: $\text{score} = 0.5 + 0.5 \times \min\left(\frac{E - T}{T}, 1.0\right)$
3. **Activity-Level Anomaly Score Mapping:**
   Where an activity spans multiple supporting events and overlaps multiple sliding windows:
   $$\text{activity.ml\_anomaly\_score} = \max_{W_k \cap \text{Events}(\text{activity}) \neq \emptyset} \text{score}(W_k)$$

---

## 6. Hybrid Risk Scoring & Threat Levels

- **Combined Risk Formula:**
  $$R_{\text{hybrid}} = 0.5 \times \text{rule\_confidence} + 0.5 \times \text{ml\_anomaly\_score}$$
  *(If ML is unavailable, $R_{\text{hybrid}} = \text{rule\_confidence}$. The system explicitly records `ml_available=False` and never fabricates scores.)*
- **Discrete Threat Level Classification (docs/ml.md Section 5.2):**
  - `CRITICAL`: $R_{\text{hybrid}} \ge 0.85$ OR rule `R6` (timestomp) / `R7` (composite USB chain)
  - `HIGH`: $0.70 \le R_{\text{hybrid}} < 0.85$ OR rule `R1` (unauthorized USB) / `R4` (file burst) / `R5` (log clear)
  - `MEDIUM`: $0.40 \le R_{\text{hybrid}} < 0.70$ OR rule `R2` (file write + exec) / `R3` (untracked execution)
  - `LOW`: $R_{\text{hybrid}} < 0.40$ AND no high-severity rule

---

## 7. Execution Commands

### Training on Baseline Normal Sessions:
```bash
python -m engine.ml.train --data-dir scenarios/baseline --output-dir engine/ml/artifacts --epochs 30 --lr 0.005
```

### Running Test Suite:
```bash
# Run ML subsystem unit tests
python -m pytest engine/tests/test_ml_subsystem.py

# Run complete engine and backend test suite
python -m pytest backend/tests engine/tests
```

---

## 8. Completion State Matrix

| Component | State | Details |
|---|---|---|
| **1. Architecture Implementation** | **Complete** | All modules in `engine/ml/` implemented and modular. |
| **2. Successfully Tested Implementation** | **Complete** | 114 passing unit tests covering all architecture, boundaries, edge cases, and fallbacks. |
| **3. Actually Trained Model** | **Complete** | Trained on 4 real baseline sessions (`scenarios/baseline/`) over 30 epochs (final loss: 0.1813). |
| **4. Validated Threshold** | **Complete** | Baseline threshold $\tau = 0.289622$ derived from normal validation split ($P_{99}$). |
| **5. Verified End-to-End Inference** | **Complete** | Verified through `test_correlator_end_to_end_with_ml_scorer` and hybrid risk engine. |

---

## 9. Remaining Dependencies on Teammates

- **Purva (Backend & Data Layer):**
  - Features contract `backend/ml_features.py` is in sync with `engine/ml/adapter.py`.
  - Endpoint `GET /timeline` and `GET /report/{activity_id}` consume `activity.ml_anomaly_score` and `activity.threat_level`.
- **Daksh (Agent & Scenarios):**
  - Daksh's scenario scripts (`scenario_a.py`, `scenario_b.py`, `scenario_c.py`) and ground truth datasets run against the correlation engine.
  - As Daksh collects additional multi-day workstation baseline recordings, re-running `python -m engine.ml.train` will retrain the model and refine $\tau$.
