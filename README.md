# ForensiTrace

**ForensiTrace** is a host-based digital forensics and event reconstruction tool designed to bridge the semantic gap in raw endpoint logs. It collects telemetry from three distinct sources (Windows Event Log, USB device events, and File System activity), normalizes them into a unified schema, and performs rule-based correlation to reconstruct human-understandable activity chains (e.g., USB drive insertion → file copy → process execution) with complete evidence provenance.

---

## Directory Structure & Ownership

Strict project structure per team agreement:

| Directory | Owner(s) | Description |
|---|---|---|
| `docs/` | Shared / Purva / Akash / Daksh / Chetna | Technical contracts: `schema.md` (Purva), `rules.yaml` (Akash), `api.md` (Akash + Purva), `agent_interface.md` (Daksh), sample/example JSONs, decisions log. Changes require team consensus. |
| `agent/` | Daksh & Chetna | Windows endpoint agent. Core agent, configuration, and HTTP sender (Daksh); Event Log collector (Daksh); USB and File System watchdog collectors (Chetna). |
| `backend/` | **Purva** | Ingestion and presentation backend: FastAPI application (`main.py`), Pydantic models (`schema.py`), source normalizers (`normalizers.py`), SQLite data-access layer (`db.py`), and ReportLab PDF reporting (`reports.py`). |
| `engine/` | Akash | Correlation engine: time-window event querying, rule evaluation from `rules.yaml`, activity building, evidence provenance linking, and narrative generator. |
| `dashboard/` | Chetna | React frontend: timeline visualization, activity feed, and evidence drawer showing raw supporting telemetry. |
| `scenarios/` | Daksh | Demonstration test scenarios (`scenario_a.py`, `scenario_b.py`, `scenario_c.py`), background noise script, ground truth fixtures, and evaluation experiment tasks. |
| `scripts/` | Daksh & Purva | Windows setup guide (`setup_windows.md` by Daksh) and one-command run/reset script (`run_demo.py` by Purva). |
| `report/` | All members | Final project report chapters, individually authored per component. |

---

## Shared Technical Contracts & Rules
All development adheres to [.agent/rules/forensitrace.md](file:///.agent/rules/forensitrace.md):
- **Tech Stack:** Python 3.x, FastAPI, SQLite, watchdog, pywin32, python-evtx; React (dashboard).
- **Contracts:** `docs/schema.md` is frozen first. Correlation rules live in `rules.yaml` (no machine learning).
- **Isolation:** Component boundaries are strictly maintained within their respective folders.
