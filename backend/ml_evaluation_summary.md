# ForensiTrace Phase 3 — ML & Hybrid Evaluation Results

- **Evaluated At (UTC):** 2026-11-26T18:12:18.357716+00:00
- **Baseline Threshold (τ):** `0.289622` (99.0th percentile of normal validation loss)
- **ML Normalized Boundary:** `0.50` (where MSE = τ maps to `0.50`)
- **Excluded Splits (Leakage Prevention):** Train = `['baseline_session_01', 'baseline_session_02']`, Val = `['baseline_session_03']`

## 1. Rules Alone vs. ML Alone vs. Hybrid (Held-Out Test Set)

| Approach | TP | FP | TN | FN | Precision | Recall | F1 Score | False Positive Rate |
|---|---|---|---|---|---|---|---|---|
| **Rules Alone** | 4 | 0 | 2 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| **ML Alone** | 4 | 2 | 0 | 0 | 0.6667 | 1.0000 | 0.8000 | 1.0000 |
| **Hybrid (Rules + ML)** | 4 | 2 | 0 | 0 | 0.6667 | 1.0000 | 0.8000 | 1.0000 |

## 2. Per-Session Evaluation Breakdown

| Session ID | Source | Events | Ground Truth | Rules Triggered | Rules Hit | Max MSE | ML Score | ML Hit | Hybrid Hit | Threat Levels |
|---|---|---|---|---|---|---|---|---|---|---|
| `baseline_session_04` | real_baseline_held_out | 4 | normal | - | False | 0.4884 | 0.84 | True | True | - |
| `normal_noise` | ground_truth_scenario | 11 | normal | - | False | 0.3650 | 0.63 | True | True | - |
| `scenario_a` | ground_truth_scenario | 3 | malicious | R1, R2, R7 | True | 0.5777 | 1.00 | True | True | CRITICAL, CRITICAL, CRITICAL |
| `scenario_a_prime` | ground_truth_scenario | 3 | malicious | R2 | True | 0.5753 | 0.99 | True | True | CRITICAL |
| `scenario_b` | ground_truth_scenario | 4 | malicious | R1, R2, R7 | True | 0.5503 | 0.95 | True | True | CRITICAL, CRITICAL, CRITICAL, CRITICAL, CRITICAL |
| `scenario_c` | ground_truth_scenario | 9 | malicious | R1, R4, R5, R6 | True | 0.5293 | 0.91 | True | True | CRITICAL, CRITICAL, CRITICAL, CRITICAL, CRITICAL, CRITICAL, CRITICAL, CRITICAL, CRITICAL, CRITICAL, CRITICAL, CRITICAL, CRITICAL, CRITICAL, CRITICAL |

## 3. Observations: Where Each Approach Succeeds or Misses

- **Rules Alone:** Achieved 1.0000 precision and 0.0000 FPR on the held-out test set because rules R1–R7 only fire when exact causal preconditions match. However, rule-based detection cannot flag novel attack sequences that fall outside R1–R7.
- **ML Alone:** Achieved 1.0000 recall across all four attack scenarios (MSE 0.5293–0.5777, normalized scores 0.91–1.00), ranking every attack scenario strictly higher than both benign sessions (MSE 0.3650–0.4884). However, at the initial baseline threshold (τ = 0.289622 derived from 1 validation window), ML alone flagged `baseline_session_04` (short 4-event padded sequence) and `normal_noise` (unseen benign USB patterns) as false positives (FPR = 1.0000).
- **Hybrid (Rules + ML):** Combining Tier 1 ML with Tier 2 rules preserves rule-based evidence provenance while adding sequence anomaly scoring (0.91–1.00 on all attack chains). Under an OR-gated alerting policy (`Rules OR ML >= 0.50`), Hybrid inherits Tier 1's false positives until more multi-session normal baseline data is collected to tune τ; under ForensiTrace's rule-anchored `CorrelationEngine`, benign sessions generate 0 false-positive activities while confirmed rule matches are escalated to `CRITICAL` threat level.
