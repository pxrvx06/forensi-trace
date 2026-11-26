# ForensiTrace React Dashboard

> **Owner:** Chetna Bothra (`dashboard/`)  
> **Contracts:** `docs/ml.md`, `backend/main.py`  
> **Scope Implemented:** Phase 3 Steps 1–5 (Stopped before Step 6 because `GET /report/{activity_id}` is not yet implemented in `backend/main.py`)

---

## Implemented Modules (Steps 1–5)

| Step | Module | Status |
|---|---|---|
| **Step 1** | `package.json`, `vite.config.js`, `index.html`, `src/api/client.js`, `src/api/mockData.js` | Done |
| **Step 2** | `src/components/HeaderHealthBar.jsx` (backend status + `Events Ingested`, `Active Anomalies`, `Correlated Activities`) | Done |
| **Step 3** | `src/components/ActivityFeed.jsx` (title, matched rule, rule confidence, ML anomaly badge, threat level, narrative) | Done |
| **Step 4** | `src/components/InteractiveTimeline.jsx` (merged `GET /timeline` axis with colour-coded `USB`, `File System`, `Event Log` badges) | Done |
| **Step 5** | `src/components/EvidenceDrawer.jsx` (raw supporting events with rule, role, and JSON syntax highlighting) | Done |
| **Step 6** | `"Export Forensic PDF"` button | **Blocked** — waiting on Purva (`backend/reports.py` + `GET /report/{activity_id}`) |
| **Step 7** | Polish, basic UI tests, demo machine browser check | Pending Steps 2–6 |
| **Step 8** | Final report chapter (dashboard and UI) | Pending Steps 1–7 + Daksh review |

---

## Running Locally

1. Ensure Node.js (v18+) and npm are installed.
2. Install dependencies and start the Vite dev server:
   ```bash
   cd dashboard
   npm install
   npm run dev
   ```
3. By default, the API client queries `http://127.0.0.1:8000` (override with `VITE_API_BASE_URL`). If the FastAPI backend is offline, the dashboard automatically falls back to validated mock data (`src/api/mockData.js`).
