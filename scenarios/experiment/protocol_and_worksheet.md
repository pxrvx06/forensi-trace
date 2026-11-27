# ForensiTrace Human Evaluation Protocol & Worksheet (Phase 3 Step 6)

**Lead:** Daksh (with Chetna assisting if available)  
**Reference:** *ForensiTrace — Build & Execution Plan v2 (Hybrid ML)*, Page 12  

---

## 1. Study Design
- **Participants:** 8 to 10 classmates who have not previously seen the ForensiTrace dashboard.
- **Pilot:** Run once with a teammate first to verify question clarity and timing setup before collecting participant data.
- **Matched Scenarios:**
  - **Scenario A:** Direct USB copy & execution (`E:\reports\payload.exe` on `SanDisk Ultra`).
  - **Scenario A′:** Staged execution via local drive (`C:\Users\analyst\AppData\Local\Temp\staged_payload.exe` after `Kingston DataTraveler` arrival on `E:`).
- **Tools Compared:**
  1. **Windows Event Viewer** (baseline manual investigation)
  2. **ForensiTrace Dashboard** (timeline + hybrid scores + evidence drawer)
- **Counterbalancing Schedule (2×2 Latin Square):** Each participant investigates one scenario with each tool so nobody sees the same attack path twice, alternating tool order and scenario order:

| Participant | Run 1 (Tool / Scenario) | Run 2 (Tool / Scenario) |
|---|---|---|
| **P01, P05, P09** | Event Viewer / Scenario A | ForensiTrace / Scenario A′ |
| **P02, P06, P10** | ForensiTrace / Scenario A | Event Viewer / Scenario A′ |
| **P03, P07** | Event Viewer / Scenario A′ | ForensiTrace / Scenario A |
| **P04, P08** | ForensiTrace / Scenario A′ | Event Viewer / Scenario A |

---

## 2. Standardized 5 Questions (Asked on Every Run)
Start the stopwatch when the participant opens the tool and stop when they submit their answers to all 5 questions:

1. **Q1 (USB Device):** Which removable USB device (drive letter and device name) was connected?
2. **Q2 (Files Copied / Created):** Which executable file was created/copied, and at what full path?
3. **Q3 (User Account):** Which user account executed the payload process?
4. **Q4 (Log Clearing):** Were any Windows Security or System event logs cleared (`Yes` or `No`)?
5. **Q5 (Order of Events):** What was the exact chronological order of the 3 key events?

---

## 3. Ground-Truth Answer Key

### Scenario A (`scenarios/ground_truth/scenario_a.json`)
- **Q1:** `E:` — `SanDisk Ultra` (serial `4C53000123456789`)
- **Q2:** `E:\reports\payload.exe`
- **Q3:** `CONTOSO\analyst`
- **Q4:** `No`
- **Q5:** `DEVICE_ARRIVED (E:)` $\rightarrow$ `FILE_CREATED (E:\reports\payload.exe)` $\rightarrow$ `PROCESS_STARTED (E:\reports\payload.exe)`

### Scenario A′ (`scenarios/ground_truth/scenario_a_prime.json`)
- **Q1:** `E:` — `Kingston DataTraveler` (serial `80000000000123`)
- **Q2:** `C:\Users\analyst\AppData\Local\Temp\staged_payload.exe`
- **Q3:** `CONTOSO\analyst`
- **Q4:** `No`
- **Q5:** `DEVICE_ARRIVED (E:)` $\rightarrow$ `FILE_CREATED (C:\...\staged_payload.exe)` $\rightarrow$ `PROCESS_STARTED (C:\...\staged_payload.exe)`

---

## 4. Recording & Analysis Instructions
1. Copy `results_template.csv` to `results.csv` and record `1` (correct) or `0` (incorrect) for `q1`–`q5` along with `time_seconds`.
2. Run the analysis script:
   ```powershell
   python scenarios/experiment/analyze_experiment.py --csv scenarios/experiment/results.csv
   ```
3. **Reporting Rule (Plan v2, Page 12):** Report individual times, correct counts, and the mean per tool. With 8–10 participants, **do not claim statistical significance**.
