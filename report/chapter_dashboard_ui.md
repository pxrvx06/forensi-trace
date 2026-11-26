# ForensiTrace Final Report Chapter — React Investigation Dashboard & Explainability UI

> **Author:** Chetna Bothra (USB & File-System Collectors, React Dashboard Lead)  
> **Peer Reviewer:** Daksh Shaparia (Agent Core, Scenarios & Human Experiment Lead)  
> **Reference Specification:** `ForensiTrace — Build & Execution Plan v2 (Hybrid ML)`  
> **Contracts Implemented:** `docs/ml.md`, `backend/main.py`, `backend/reports.py`  
> **Status:** Draft Ready for Peer Review by Daksh

---

## 1. Positioning & Design Alignment

In alignment with ForensiTrace's hybrid architecture, the React dashboard is designed around explainability and raw-evidence traceability without heavyweight ontology infrastructure. Every correlated incident displays **Tier 2 deterministic rule confidence** side by side with the **Tier 1 ML anomaly score** (a normalized LSTM autoencoder reconstruction error between `0.00` and `1.00`, never presented as a percentage of risk). The ML signal supports triage and anomaly highlighting, while every conclusion remains directly traceable to unedited raw endpoint telemetry in the Evidence Drawer and exported Forensic Investigation Report PDF.

---

## 2. Dashboard Architecture (`dashboard/`)

Built strictly with React 18, Vite, and plain CSS (with zero additional UI or state frameworks per `.agent/rules/forensitrace.md`), the frontend is organized into modular layers:

| Module | Path | Responsibility |
|---|---|---|
| **API Client** | `dashboard/src/api/client.js` | Integrates with Purva's FastAPI endpoints (`GET /health`, `/events`, `/activities`, `/activities/{id}`, `/timeline`, `/report/{activity_id}`) with automatic mock fallback when offline. |
| **Validated Mock Bundle** | `dashboard/src/api/mockData.js` | Provides offline Scenario A / R5 / R1 mock telemetry, including missing-ML fallback (`ml_anomaly_score: null`). |
| **Header & Health Bar** | `dashboard/src/components/HeaderHealthBar.jsx` | Displays live/mock backend status, UTC health timestamp, mode/refresh controls, and three summary cards: **Events Ingested**, **Active Anomalies**, and **Correlated Activities**. |
| **Activity Feed** | `dashboard/src/components/ActivityFeed.jsx` | Renders correlated activities with title (`rule_name`), matched rule (`rule_id`), separate **Rule Confidence** and **ML Score (Norm. Error)** metrics, `threat_level` badge (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`), and incident narrative. |
| **Interactive Timeline** | `dashboard/src/components/InteractiveTimeline.jsx` | Consumes `GET /timeline` to render a unified chronological axis with colour-coded source badges (**USB**, **File System**, **Event Log**, and **Activity**), source filter pills, and inline event inspection. |
| **Evidence Drawer & PDF Export** | `dashboard/src/components/EvidenceDrawer.jsx` | Slide-over explainability drawer triggered for any rule-matched or ML-flagged activity; renders `evidence_chain` entries with rule, provenance role, metadata, syntax-highlighted `raw` / `details` JSON, and the **Export Forensic PDF** button calling `GET /report/{activity_id}`. |
| **Page Container** | `dashboard/src/pages/DashboardPage.jsx` | Coordinates data loading, live/mock fallback state, drawer selection, and labeled console logging (`[RECEIVED] ... -> [PRODUCED] ...`). |

---

## 3. Explainability & Hybrid Score Presentation

To satisfy both forensic rigor and the human-experiment workflow comparing ForensiTrace against Windows Event Viewer:
1. **Side-by-Side Dual Signals:** Each card in `ActivityFeed` and summary block in `EvidenceDrawer` renders `confidence` and `ml_anomaly_score` as distinct fields. If the ML subsystem is offline (`ml_anomaly_score: null`), the badge cleanly displays `Unavailable` without blocking rule-based investigation.
2. **Unified Cross-Source Chain:** `InteractiveTimeline` visualizes USB arrival, file-system mutations, Windows Event Log process executions, and correlated activities on one ordered axis so Scenario A appears as a single linked chain.
3. **Raw Evidence Provenance:** `EvidenceDrawer` maps each event in `evidence_chain` to its triggering `rule_id`, provenance `reason`/`Role`, and color-highlighted `raw` JSON payload, paired with one-click download of Purva's 3-page forensic investigation report PDF (`GET /report/{activity_id}`).

---

## 4. Verification Summary

- **Automated UI Tests (`dashboard/tests/Dashboard.test.jsx`):** Verified with Vitest (`5 passed` in `tests/Dashboard.test.jsx`), covering:
  1. Header health bar and all 3 summary cards in mock mode.
  2. Separate display of rule confidence and normalized ML score, graceful `Unavailable` fallback when ML is `null`, and absence of prohibited *"percentage of risk"* wording.
  3. Timeline colour-coded `USB`, `File System`, and `Event Log` badges and source filtering.
  4. Opening and closing the Evidence Drawer for rule-matched and ML-flagged activities with rule, role, and JSON highlighting.
  5. Triggering the **Export Forensic PDF** action and displaying download status.
- **Production Bundle (`npm run build`):** Verified cleanly with Vite (`38 modules transformed`, built in `1.60s`).
- **Pending Rehearsal Item:** Final live browser verification on the shared demo machine alongside Daksh's `scripts/run_demo.py` and the human experiment remains pending team rehearsal.
