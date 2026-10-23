# ForensiTrace Correlation Engine

**Owner:** Akash  
**Scope:** Correlation engine, detection rules (`rules.yaml`), evidence provenance linking, timestamp consistency checks, synthetic events, and test fixtures.

---

## Task Progress

- [x] **Task 1: Synthetic Event Generator & Fixtures**
  - Generator: [`scenarios/generate_synthetic_events.py`](../scenarios/generate_synthetic_events.py)
  - Fixtures: [`scenarios/fixtures/`](../scenarios/fixtures/) (`usb_copy_run.json`, `normal_noise.json`, `edge_cases.json`, `invalid_events.json`)
  - Tests: [`scenarios/test_synthetic_events.py`](../scenarios/test_synthetic_events.py) and [`engine/tests/test_fixtures.py`](./tests/test_fixtures.py)
- [x] **Task 2: Correlation Engine Core & Rules R1–R3**
  - Rules Technical Contract: [`docs/rules.yaml`](../docs/rules.yaml)
  - YAML Rules Loader: [`engine/config.py`](./config.py)
  - Correlation Engine: [`engine/correlator.py`](./correlator.py)
  - Comprehensive Tests: [`engine/tests/test_rules.py`](./tests/test_rules.py)
- [ ] **Task 3: Phase 3 Rules & Advanced Provenance** *(Upcoming)*
  - Bulk copy detection (R4), log clear correlation (R5), timestamp check (R6)
  - Combined USB copy-and-execute attack chain (R7) with confidence scoring
  - Full narrative generator citing event IDs

---

## 1. Implemented Correlation Rules (R1–R3)

All thresholds and filters are loaded dynamically from [`docs/rules.yaml`](../docs/rules.yaml) so tuning does not require code modifications.

| Rule ID | Rule Name | Time Window | Description & Matching Logic |
|---|---|---|---|
| **R1** | Device arrival followed by file activity | 5 min (300s) | Detects USB storage arrival (`source="usb"`, `action="DEVICE_ARRIVED"`), followed by file creation or modification (`source="fs"`, `action in ["FILE_CREATED", "FILE_MODIFIED"]`) on the same drive and host within $0 \le \Delta t \le 300\text{s}$. |
| **R2** | File creation followed by process execution | 10 min (600s) | Detects file creation (`source="fs"`, `action="FILE_CREATED"`), followed by a process launched from that identical file path (`source="eventlog"`, `action="PROCESS_STARTED"`). Compares canonicalized Windows paths case-insensitively within $0 \le \Delta t \le 600\text{s}$. |
| **R3** | Process starts from removable drive without preceding write | 10 min (600s) | Detects a process launched from a confirmed removable volume (`source="eventlog"`, `action="PROCESS_STARTED"`), where **no matching write event** was observed within the preceding 10-minute window ($t_{\text{proc}} - 600\text{s} \le t_{\text{write}} \le t_{\text{proc}}$). Indicates a pre-existing binary or unmonitored write. |

---

## 2. Key Architecture & Design Decisions

1. **Rule Configuration in YAML:**
   - Follows team rule: *“Correlation rules live in `rules.yaml`, not in code.”*
   - Located at [`docs/rules.yaml`](../docs/rules.yaml), loaded by [`engine/config.py`](./config.py).
2. **Inclusive Time-Window Boundaries:**
   - Window boundaries are inclusive: an event exactly on the threshold ($\Delta t = 300.0\text{s}$ for R1 or $\Delta t = 600.0\text{s}$ for R2/R3) matches. Events at $\Delta t = 301.0\text{s}$ or $\Delta t = 601.0\text{s}$ do not fire.
3. **Out-of-Order Telemetry Sorting:**
   - The engine automatically sorts events chronologically by `ts_utc` before evaluation, ensuring robustness even if collectors deliver events out of arrival sequence.
4. **Removability Verification (Rule R3):**
   - The engine never guesses that an arbitrary drive letter is removable. Drive removability is strictly established from confirmed USB arrival evidence (`DEVICE_ARRIVED`) or explicit metadata. Unverified drives (like `C:`) are ignored by R3.
   - R3 results are forensic indicators of an *absence of observed telemetry write evidence*, not proof that a write never occurred.
5. **Deterministic Activity IDs & Deduplication:**
   - Activity IDs are generated deterministically: `act_{rule_id}_{sha256(rule_id|host|event_ids)[:12]}`. Replaying identical events produces identical activity records, preventing duplicate rows in SQLite.
6. **Database Persistence Integration:**
   - Integrates cleanly with Purva's data-access layer [`backend/db.py`](../backend/db.py):
     - `get_events_in_window()` retrieves telemetry.
     - `insert_activity()` stores reconstructed activities and links their supporting events into `activity_events` (evidence provenance).

---

## 3. How to Run the Tests (Windows PowerShell)

Open Windows PowerShell in the project root (`d:\MINI PROJ`):

```powershell
# Run the Task 2 correlation rules test suite (25 tests)
python -m unittest engine/tests/test_rules.py -v

# Run the Task 1 fixture verification tests (8 tests)
python -m unittest engine/tests/test_fixtures.py -v

# Run all project tests across backend and engine (46 tests)
python -m pytest -v
```
