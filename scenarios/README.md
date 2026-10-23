# ForensiTrace Scenarios & Synthetic Telemetry

This directory contains test scenarios, synthetic event generation tools, and forensic evaluation datasets for ForensiTrace.

---

## 1. Synthetic Event Generator (`generate_synthetic_events.py`)

Authored by **Akash** (Task 1: Synthetic Event Generator & Fixtures).

### What it does
The generator deterministically produces normalized forensic event sequences that adhere strictly to the frozen technical contract in [`docs/schema.md`](../docs/schema.md) and [`backend/schema.py`](../backend/schema.py).

It produces repeatable, deterministic test fixtures covering:
- **Positive Attack Chains**: Removable USB drive insertion $\rightarrow$ file copy $\rightarrow$ process execution.
- **Normal Background Noise**: Everyday user activity (logon, text editor, web browsing, benign documents) designed to test false-positive resistance.
- **Forensic Edge Cases**: No-write USB arrivals, execution without write events, path/drive mismatches, duplicate events, out-of-order telemetry, and time-window boundary conditions.
- **Invalid Negative Test Cases**: Isolated schema-violating records used to ensure ingestion validators reject bad inputs with clear errors.

---

## 2. Generated Fixtures Directory (`scenarios/fixtures/`)

| Fixture File | Event Count | Schema Status | Description |
|---|---|---|---|
| [`scenarios/fixtures/usb_copy_run.json`](./fixtures/usb_copy_run.json) | 3 | Valid | Correlated attack chain: USB drive `E:` mounted, `payload.exe` written, and process started from `E:\reports\payload.exe`. |
| [`scenarios/fixtures/normal_noise.json`](./fixtures/normal_noise.json) | 9 | Valid | Ordinary workstation activity (winlogon, notepad, chrome, clean documents, non-executable USB backup). |
| [`scenarios/fixtures/edge_cases.json`](./fixtures/edge_cases.json) | 15 | Valid | Forensic boundary conditions: USB without write, execution without write, mismatched drive/file, duplicates, out-of-order, boundary timings (599s, 600s, 601s). |
| [`scenarios/fixtures/invalid_events.json`](./fixtures/invalid_events.json) | 9 | Invalid (Isolated) | Negative test suite testing rejection of missing fields, bad enums, malformed timestamps, lowercase drives, and hash mismatches. |

---

## 3. How to Run the Generator (Windows PowerShell)

Open Windows PowerShell in the project root (`d:\MINI PROJ`):

```powershell
# Generate all fixtures and automatically validate them against docs/schema.md
python scenarios/generate_synthetic_events.py

# Generate only a specific scenario fixture
python scenarios/generate_synthetic_events.py --scenario usb_copy_run
python scenarios/generate_synthetic_events.py --scenario normal_noise
python scenarios/generate_synthetic_events.py --scenario edge_cases
python scenarios/generate_synthetic_events.py --scenario invalid_events

# Output to a custom directory (e.g. engine/fixtures)
python scenarios/generate_synthetic_events.py --output-dir engine/fixtures --validate
```

---

## 4. How to Run the Tests

You can run the tests using either Python's standard `unittest` runner or `pytest`:

```powershell
# Using Python's standard library runner (no extra tools required)
python -m unittest scenarios/test_synthetic_events.py -v

# Or run from the engine test integration file
python -m unittest engine/tests/test_fixtures.py -v

# Using pytest (runs all test suites across the project)
python -m pytest -v
```

---

## 5. Approved Event Schema Assumptions & Dependencies

All generated events strictly adhere to Purva's frozen contract in [`docs/schema.md`](../docs/schema.md) and [`backend/schema.py`](../backend/schema.py):

1. **Deterministic `event_id` Hash Recipe:**
   $$\text{event\_id} = \text{SHA256}(\text{source} \parallel \text{raw\_record\_id} \parallel \text{ts\_utc})$$
   Calculated as 64 lowercase hexadecimal characters. Re-generating the same event always produces the exact same ID.
2. **Strict Allowed Sources & Actions:**
   - `usb`: `DEVICE_ARRIVED`, `DEVICE_REMOVED` (entity: device string with uppercase drive letter).
   - `fs`: `FILE_CREATED`, `FILE_MODIFIED`, `FILE_DELETED`, `FILE_MOVED` (entity: canonical Windows backslash path).
   - `eventlog`: `PROCESS_STARTED`, `LOG_CLEARED`, `LOGON` (entity: binary path).
3. **UTC Timestamps:**
   - Strictly ISO 8601 with millisecond precision and trailing `Z` (`YYYY-MM-DDTHH:MM:SS.mmmZ`).
4. **Path & Drive Conventions:**
   - Drive letters must always be uppercase (`E:`, `C:`).
   - All Windows paths must use backslashes (`\`), never forward slashes (`/`).
5. **Observation Time (Decision D-001):**
   - Per [`docs/decisions.md`](../docs/decisions.md), client observation timestamp is reserved for `details.ts_observed_utc` without mutating the top-level frozen schema.
