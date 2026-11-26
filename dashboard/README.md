# ForensiTrace React Dashboard

> **Owner:** Chetna Bothra (`dashboard/`)  
> **Contracts:** `docs/ml.md`, `backend/main.py`  
> **Scope Implemented:** Phase 3 Steps 1–7 (UI complete + automated UI tests; demo-machine browser verification pending demo rehearsal)

---

## Implemented Modules (Steps 1–7)

| Step | Module | Status |
|---|---|---|
| **Step 1** | `package.json`, `vite.config.js`, `index.html`, `src/api/client.js`, `src/api/mockData.js` | Done |
| **Step 2** | `src/components/HeaderHealthBar.jsx` (backend status + `Events Ingested`, `Active Anomalies`, `Correlated Activities`) | Done |
| **Step 3** | `src/components/ActivityFeed.jsx` (title, matched rule, rule confidence, ML anomaly badge, threat level, narrative) | Done |
| **Step 4** | `src/components/InteractiveTimeline.jsx` (merged `GET /timeline` axis with colour-coded `USB`, `File System`, `Event Log` badges) | Done |
| **Step 5** | `src/components/EvidenceDrawer.jsx` (raw supporting events with rule, role, and JSON syntax highlighting) | Done |
| **Step 6** | `"Export Forensic PDF"` button in `EvidenceDrawer.jsx` wired to `GET /report/{activity_id}` | Done |
| **Step 7** | `tests/Dashboard.test.jsx` UI unit tests, drawer polish (`Escape` & backdrop close); demo-machine browser check pending rehearsal | In Progress (Local build & tests ready; demo machine check pending) |
| **Step 8** | `report/chapter_dashboard_ui.md` | Draft ready for Daksh review |

---

## Running Locally & Testing

1. Ensure Node.js (v18+) and npm are installed.
2. Install dependencies, run unit tests, and build:
   ```bash
   cd dashboard
   npm install
   npm test
   npm run build
   npm run dev
   ```
3. By default, the API client queries `http://127.0.0.1:8000` (override with `VITE_API_BASE_URL`). If the FastAPI backend is offline, the dashboard automatically falls back to validated mock data (`src/api/mockData.js`). Exporting a Forensic PDF requires the live FastAPI backend (`GET /report/{activity_id}`).
