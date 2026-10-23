# ForensiTrace Correlation Engine

**Owner:** Akash  
**Scope:** Correlation engine, detection rules (`rules.yaml`), evidence provenance linking, timestamp consistency checks, synthetic events, and test fixtures.

---

## Task Progress

- [x] **Task 1: Synthetic Event Generator & Fixtures**
  - Generator: [`scenarios/generate_synthetic_events.py`](../scenarios/generate_synthetic_events.py)
  - Fixtures: [`scenarios/fixtures/`](../scenarios/fixtures/) (`usb_copy_run.json`, `normal_noise.json`, `edge_cases.json`, `invalid_events.json`)
  - Tests: [`scenarios/test_synthetic_events.py`](../scenarios/test_synthetic_events.py) and [`engine/tests/test_fixtures.py`](./tests/test_fixtures.py)
- [ ] **Task 2: Correlation Engine & Rules Implementation** *(Upcoming)*
  - Rule evaluation from `rules.yaml` (R1–R7)
  - Activity building & evidence provenance linking
  - Confidence scoring and narrative generation

---

## Running Fixture Tests

```powershell
python -m unittest engine/tests/test_fixtures.py -v
python -m pytest engine/tests/test_fixtures.py -v
```
