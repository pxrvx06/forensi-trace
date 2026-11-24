# ForensiTrace: A Lightweight Cross-Source Correlation Engine for Windows Endpoint Forensics

## Mini Project Phase-II Evaluation Report
**Department of Computer Science and Engineering (AI & ML)**  
**Siddaganga Institute of Technology, Tumakuru - 572103**  
**Academic Year:** 2026–27 (ODD Semester)  
**Batch No.:** B63 | **Panel No.:** 1  
**Under the Guidance of:** Ms. Rajeshwari K R  

---

### Student Details
* **Akash Nair** (`1SI24CI002`)
* **Chetna Bothra** (`1SI24CI008`)
* **Daksh Vimal Shaparia** (`1SI24CI009`)
* **Purva Anil Bharadiya** (`1SI24CI045`)

---

# Abstract

**ForensiTrace** is a lightweight digital forensic monitoring and investigation system designed to reconstruct and analyze activities on a Windows endpoint. It uses a Python-based background agent to continuously collect selected forensic events, including USB device activity, file-system changes, and Windows Event Logs.

Collected events are normalized into a common format and stored with timestamps and evidence-integrity information. A backend analysis engine correlates events based on time, users, files, and devices, while rule-based detection identifies potentially suspicious activity and distinguishes observed evidence from system-generated inferences.

The results are presented through a web-based dashboard where investigators can explore event details, reconstruct timelines, analyze correlated activities, review suspicious findings, and generate investigation reports.

The project demonstrates a practical approach to continuous endpoint monitoring, forensic evidence collection, timeline reconstruction, event correlation, and explainable digital forensic analysis within a lightweight mini-project scope.

---

# Table of Contents
- [Chapter 1: Introduction](#chapter-1-introduction)
  - [1.1 Overview of the project](#11-overview-of-the-project)
  - [1.2 Motivation](#12-motivation)
  - [1.3 Organization of the report](#13-organization-of-the-report)
- [Chapter 2: Literature Survey](#chapter-2-literature-survey)
  - [2.1 Limitations of Existing Work](#21-limitations-of-existing-work)
- [Chapter 3: Problem Statement and Objectives](#chapter-3-problem-statement-and-objectives)
  - [3.1 Problem Statement](#31-problem-statement)
  - [3.2 Objectives](#32-objectives)
- [Chapter 4: Requirements Specification](#chapter-4-requirements-specification)
  - [4.1 Functional Requirements](#41-functional-requirements)
  - [4.2 Non-Functional Requirements](#42-non-functional-requirements)
  - [4.3 Software and Hardware Requirements](#43-software-and-hardware-requirements)
- [Chapter 5: System Design & Methodology](#chapter-5-system-design--methodology)
  - [5.1 System Architecture](#51-system-architecture)
  - [5.2 Data Flow Diagrams](#52-data-flow-diagrams)
  - [5.3 Algorithms (Correlation Rules & Scoring)](#53-algorithms-correlation-rules--scoring)
  - [5.4 Database Design](#54-database-design)
- [Chapter 6: Implementation Details](#chapter-6-implementation-details)
  - [6.1 Programming Language/s Used](#61-programming-languages-used)
  - [6.2 Technologies / Tools Used](#62-technologies--tools-used)
  - [6.3 Datasets / Test Scenarios Details](#63-datasets--test-scenarios-details)
- [Chapter 7: Results](#chapter-7-results)
  - [7.1 Output and Reconstructed Example](#71-output-and-reconstructed-example)
  - [7.2 Comparison: Event Viewer vs. ForensiTrace](#72-comparison-event-viewer-vs-forensitrace)
  - [7.3 Testing Summary](#73-testing-summary)
- [Chapter 8: Conclusion](#chapter-8-conclusion)
  - [8.1 Conclusion](#81-conclusion)
  - [8.2 Limitations and Future Work](#82-limitations-and-future-work)
- [References](#references)

---

# Chapter 1: Introduction

## 1.1 Overview of the project
Digital forensics is the process of finding out what happened on a computer after a security incident by examining the traces left behind. On Windows computers, the primary tool available is the **Windows Event Viewer**, which shows system and security logs.

In real-world incidents (like someone plugging in a pendrive, copying confidential data, and running an unauthorized program), actions leave traces across multiple places:
1. **USB connection records** (when the device was plugged in).
2. **File-system activity** (which files were created, copied, or modified).
3. **Windows Event Logs** (which program was launched).

Currently, these events are stored separately as raw, unlinked lines. **ForensiTrace** is a lightweight tool built using Python that runs in the background on a Windows machine. It collects logs from these three sources, standardizes them into one simple format, and connects related events together into an easy-to-understand story (called an "activity") with clear proof.

## 1.2 Motivation
When investigating suspicious activity today, investigators face two problems:
1. **Manual cross-referencing is slow and error-prone:** In native Windows Event Viewer, logs are displayed as isolated lines without any link between a USB insertion, a file copy, and a program run. The investigator has to check multiple log screens and compare timestamps by hand.
2. **Existing enterprise tools are too heavy:** Large enterprise monitoring tools (like SIEM or EDR systems) and machine learning tools require high computing power, complex setups, and training data. Moreover, AI-based tools often act as "black boxes" that do not explain clearly *why* an alert was generated.

ForensiTrace is motivated by the need for a **simple, lightweight, and explainable tool** for single Windows laptops/PCs. It uses clear, transparent rules instead of black-box AI, so the investigator can see the exact raw logs behind every alert.

## 1.3 Organization of the report
This report is organized into the following chapters:
* **Chapter 2:** Discusses the literature survey of 12 published papers and outlines the limitations of existing systems.
* **Chapter 3:** States the problem statement and the five project objectives.
* **Chapter 4:** Details the functional, non-functional, hardware, and software requirements.
* **Chapter 5:** Explains the system architecture, data flow diagrams (Level 0 and Level 1), the 7 correlation rules, confidence scoring, and the 3 database tables.
* **Chapter 6:** Describes the implementation details, libraries used, and the test datasets.
* **Chapter 7:** Shows the results, a worked correlation example, a comparison table against Event Viewer, and test metrics.
* **Chapter 8:** Concludes the Phase 2 work and describes the future scope for Phase 3.
* **References:** Lists the 12 academic papers reviewed.

---

# Chapter 2: Literature Survey

To understand prior research, twelve papers covering evidence collection, timeline reconstruction, log analysis, and timestamp manipulation were reviewed.

| # | Paper & Author | Key Contribution | Gap / Limitation for ForensiTrace |
|---|---|---|---|
| 1 | **Raesa et al. (2026)** — *Velociraptor Methodology* | Large-scale artifact-backed evidence collection. | Requires a full platform; produces isolated alerts rather than a connected story. |
| 2 | **Oh, Lee & Hwang (2024)** — *Detection of Timestamp Manipulation* | Shows that dedicated filesystem tools often misclassify manipulated timestamps. | Built only for disk files; motivates our simpler check comparing file time against when the agent saw it. |
| 3 | **Dreier, Hargreaves & Breitinger (2024)** — *Implicit Timing in Timelines* | Improves event ordering in large timeline analysis tools. | Designed for offline full-disk image analysis rather than lightweight live monitoring. |
| 4 | **Palmbach & Breitinger (2020)** — *Detecting Timestamp Manipulation* | Tests how reliably Windows detects altered file timestamps. | Requires deep disk parsing; motivates our simple live timestamp comparison check. |
| 5 | **Bhandari & Jusas (2020)** — *Timeline Abstraction* | Groups low-level logs into simpler categories for investigators. | Uses heavy offline processing tools rather than a lightweight live agent. |
| 6 | **Studiawan & Sohel (2021)** — *Anomaly Detection with Autoencoders* | Uses deep learning autoencoders for timeline anomaly detection (94% accuracy). | Black-box model with low explainability; requires high compute unsuited for a lightweight agent. |
| 7 | **Soltani et al. (2019)** — *Temporal Pattern of FS Modification* | Infers which app ran from file-metadata patterns, even without logs. | Single-source; requires a long training phase to learn application patterns. |
| 8 | **Studiawan, Sohel & Payne (2019)** — *Survey on OS Log Forensics* | Confirms cross-source correlation remains an open research problem. | Survey only — builds no actual system. |
| 9 | **Arshad, Iqbal & Abbas (2018)** — *USB Storage Forensics on Windows 10* | Documents all registry and log traces left when a USB drive is connected. | Investigator must still check each trace manually; no automatic linking with file or program logs. |
| 10 | **Amato et al. (2017)** — *Semantic Correlation of Evidences* | Uses ontologies to correlate evidence across multiple sources. | Heavyweight; requires complex ontology servers not suited for lightweight endpoint deployment. |
| 11 | **Al Awawdeh et al. (2013)** — *CAT Record* | A real-time Windows agent logging computer activity including USBs. | Has no correlation engine — each logging module works independently without linking events. |
| 12 | **Hargreaves & Patterson (2012)** — *Automated Timeline Reconstruction* | First tool to summarize low-level file and registry events into high-level events using SQLite. | Single-source only; does not integrate live Windows Event Logs or live USB connections. |

## 2.1 Limitations of Existing Work
From the survey, the key limitations of existing work are:
1. **Event Viewer shows isolated entries:** There is no built-in linkage between related events like USB arrival, file copy, and program execution.
2. **Collection alone is not enough:** Real-time logging agents already exist (e.g., CAT Record, 2013), but they do not automatically connect the dots.
3. **Cross-source correlation is still a gap:** Prior attempts use heavyweight ontologies or machine learning, which are impractical for a lightweight, explainable student project.
4. **Single-source timestamps can be altered:** Attackers can alter file timestamps ("timestomping"), making single-source timestamps unreliable.
5. **Lack of explainability:** Machine learning models do not clearly show the raw logs that justify their alerts.

---

# Chapter 3: Problem Statement and Objectives

## 3.1 Problem Statement
> *Windows Event Logs record isolated, source-specific events, and Event Viewer only lets an investigator browse and filter them — it does not link related events from different evidence sources (e.g., a USB connection, a file copy, and a process launch). Prior research has advanced event reconstruction, real-time collection, and semantic/ML correlation independently, but a lightweight, explainable, cross-source correlation workflow — without heavyweight ontology or ML infrastructure — remains underexplored. ForensiTrace addresses this gap with a focused endpoint tool that correlates a small set of evidence sources into an explainable forensic timeline.*

## 3.2 Objectives
1. **Collect Endpoint Evidence:** Collect three Windows evidence sources — Windows Event Logs (process start and log cleared), USB plug-in/removal events, and file-system changes — using a lightweight Python background agent.
2. **Standardize into a Common Schema:** Convert logs from all three sources into a simple, common 10-field structure so they can be compared easily regardless of origin.
3. **Rule-Based Event Correlation:** Design and implement a rule-based correlation engine that connects related events across sources using time windows into single reconstructed activities.
4. **Provide Clear Evidence Provenance:** Link every reconstructed activity back to its raw, original logs in an SQLite database, so the investigator can see the exact proof behind each conclusion.
5. **Evaluate Effectiveness:** Test the system on controlled scenarios to show that correlated presentation makes understanding an incident faster and easier than browsing raw Event Viewer logs.

---

# Chapter 4: Requirements Specification

## 4.1 Functional Requirements
* **FR-1 (Collect Activity Logs):** Automatically record USB device plug-in and removal, file creation and modifications, and program launches on Windows.
* **FR-2 (Dynamic USB Drive Watching):** When a USB drive is plugged in (e.g., `E:`), the USB collector must instantly notify the file collector to start watching that drive.
* **FR-3 (Standardize Format):** Convert all logs into one common format with five key fields: Time, Source, Action, Path/Entity, and User.
* **FR-4 (No Duplicate Logs):** Give every event a unique ID based on a hash of its details and timestamp so that duplicate logs are ignored when saved to the database.
* **FR-5 (Connect Related Events):** Check time windows to link actions that happen close together (e.g., USB inserted $\rightarrow$ file created within 5 minutes $\rightarrow$ program executed).
* **FR-6 (Keep Proof for Every Alert):** Store a link between every high-level activity alert and the exact raw logs that triggered it.
* **FR-7 (Calculate Confidence Score):** Assign each alert a score between 0.00 and 1.00 based on how complete the evidence is.
* **FR-8 (View and Query):** Provide backend API endpoints so that an investigator or dashboard can view events, filter by source, and inspect alerts.

## 4.2 Non-Functional Requirements
* **NFR-1 (Lightweight & Fast):** Runs quietly in the background without slowing down the laptop (uses $< 2\%$ CPU and $< 50\text{ MB}$ RAM).
* **NFR-2 (Filters Out Noise):** Automatically ignores temporary Windows background files (like `.tmp`, `.crdownload`, browser locks) so only meaningful user actions are kept.
* **NFR-3 (Downtime Resilience):** If the backend server stops temporarily, the agent holds logs in memory and sends them once the server is back up.
* **NFR-4 (Clear & Explainable):** Uses transparent, human-readable rules instead of black-box AI.
* **NFR-5 (Data Integrity):** Uses SQLite with foreign key checks to make sure links between alerts and raw events stay consistent.

## 4.3 Software and Hardware Requirements

### Hardware Requirements
* **Endpoint PC / Laptop:** Any standard PC or VM running 64-bit Windows 10 or Windows 11 with at least 4 GB RAM.
* **USB Flash Drive:** A standard pen drive (FAT32 or NTFS) used for testing the live plug-in and run scenario.

### Software Requirements
* **Operating System:** Windows 10 or 11 with Administrator rights (needed to read Security Event Logs).
* **Programming Language:** Python 3.10+ (tested on Python 3.12).
* **Libraries:**
  * `fastapi` and `uvicorn` (backend server).
  * `pydantic` (format verification).
  * `watchdog` (monitors file and folder changes).
  * `pywin32` (reads Windows Event Logs and detects USB plug-in messages).
  * `python-evtx` (reads exported log files for offline tests).
  * `pyyaml` (reads correlation rules).
* **Database:** SQLite (comes built-in with Python).

---

# Chapter 5: System Design & Methodology

## 5.1 System Architecture
The system consists of four main parts:

```
[ Windows PC ] ──► [ Python Agent ] ──► [ Event Normalizer ] ──► [ FastAPI Backend ]
                       │ (USB, File, Logs)                                │
                       ▼                                                  ▼
                 [ Thread Queue ]                                [ SQLite Database ]
                       │                                                  │
                       ▼                                                  ▼
                 [ HTTP Sender ] ──────────────────────────────► [ Correlation Engine ]
                                                                          │
                                                                          ▼
                                                                [ Explainable Findings ]
                                                                          │
                                                                 (Dashboard / Report)
```

1. **Evidence Collection:** A Python background agent monitors USB connections, file changes, and Windows Event Logs.
2. **Common Formatting:** A normalizer converts the different raw logs into one clean, standard structure and sends them to the FastAPI backend.
3. **Storage & Linking:** An SQLite database saves the normalized events. The Correlation Engine queries the database to find events that happened close in time.
4. **Explainable Findings:** Connected events are grouped into an activity alert with a plain-English explanation and evidence links.

## 5.2 Data Flow Diagrams

### Level-0 DFD (Context Diagram)
The overall flow between the user, the computer, and ForensiTrace:
```
[ Windows PC Activity ] ──(Raw Logs)──► [ ForensiTrace System ] ──(Connected Story & Proof)──► [ Investigator ]
```

### Level-1 DFD (Step-by-Step Flow)
1. **Step 1: Collect Logs:** Watches USB plug-in/removal, watches new or modified files, reads Windows Event Viewer, and queues them.
2. **Step 2: Standardize:** Converts raw records into 5 simple fields: Time, Source, Action, Path/Entity, and User.
3. **Step 3: Correlate:** Checks time windows and matching paths against Rules R1 to R7, links related events together, and calculates a confidence score.
4. **Step 4: Show Results:** Saves findings into database tables so they can be viewed with raw proof on the dashboard and exported to PDF.

## 5.3 Algorithms (Correlation Rules & Scoring)

### 5.3.1 The 7 Correlation Rules (R1 to R7)
Rules live in a simple YAML configuration file (`docs/rules.yaml`), so thresholds can be changed without modifying any code:

| Rule | Rule Name | Time Window | First Event (Trigger) | What We Look For | Base Score |
|---|---|---|---|---|---|
| **R1** | USB Plug-in + File Activity | 5 mins (300s) | USB drive connected | File created or modified on that same drive | 0.80 |
| **R2** | New File + Program Launch | 10 mins (600s) | New file created | That exact file launched as a running program | 0.80 |
| **R3** | Direct Run from USB Drive | 10 mins (600s) | Program started from USB | Program runs directly from USB with no prior write seen | 0.75 |
| **R4** | Bulk File Copy on USB | 1 min (60s) | Rapid file creations | 5 or more files created on USB within 60 seconds | 0.85 |
| **R5** | Log Cleared Near Activity | 10 mins (600s) | Event Log cleared | Event log cleared shortly after USB, file, or program actions | 0.85 |
| **R6** | Timestamp Mismatch Check | 2 mins (120s) | File created/edited | File timestamp differs from actual observation time by $> 2$ mins | 0.85 |
| **R7** | Full USB Copy & Run Chain | 15 mins (900s) | 1. USB Connected | 2. File created on USB $\rightarrow$ 3. That file launched as program | 0.95 |

### 5.3.2 How Confidence Scoring Works
Every alert gets a score between **0.00 and 1.00**:
$$\text{Score} = \text{Starting Base Score} + \text{Bonus Points} - \text{Missing Info Penalty}$$

1. **Starting Base Score:** Starts between 0.75 and 0.95 depending on rule severity (e.g., R1 = 0.80, R7 = 0.95).
2. **Bonus for Details:** $+0.03$ if the Windows username is known; $+0.02$ if the USB serial number is recorded.
3. **Bonus for Multi-Source Match:** $+0.03$ when all 3 sources (USB, File, and Event Log) confirm the activity.
4. **Bonus for Speed:** $+0.02$ if the actions happened very quickly (e.g., within 30 seconds).
5. **Penalty:** $-0.10$ if key details like the file path are missing.

### 5.3.3 Plain-English Incident Story
The engine automatically builds a clear explanation. For example:
> *"USB drive (Serial: 4C530001) was plugged in as Drive E:\ at 10:14:02 AM [Step 1]. After 18 seconds, file E:\payload.exe was created [Step 2], and 9 seconds later it was launched as a program by user Alice [Step 3]. Confidence Score: 1.00 (High)."*

## 5.4 Database Design
The system uses **3 simple tables** in SQLite:

```
┌─────────────────────────────────┐           ┌─────────────────────────────────┐
│        TABLE 1: events          │           │       TABLE 2: activities       │
│  Stores all raw individual logs │           │ Stores correlated alert stories │
│  - event_id (Primary Key)       │           │  - activity_id (Primary Key)    │
│  - timestamp (UTC)              │           │  - rule_id (e.g., R1 to R7)     │
│  - source (usb / fs / eventlog) │           │  - title                        │
│  - action (e.g. FILE_CREATED)   │           │  - narrative (Plain English)    │
│  - entity (Drive or File path)  │           │  - confidence_score             │
│  - user (Windows username)      │           │  - ts_start_utc / ts_end_utc    │
│  - raw_json (Original log copy) │           └────────────────┬────────────────┘
└────────────────┬────────────────┘                            │
                 │                                             │
                 │          ┌───────────────────────┐          │
                 └─────────►│ TABLE 3: activity_events ◄────────┘
                            │ Bridge Table (Links Proof)   │
                            │ - activity_id                │
                            │ - event_id                   │
                            │ - reason / role in incident  │
                            └──────────────────────────────┘
```

* **Table 1 (`events`):** Stores all standardized individual logs. The `event_id` is a unique SHA-256 hash so the same event is never stored twice.
* **Table 2 (`activities`):** Stores high-level correlated alerts, the rule matched, the plain-English story, and the score.
* **Table 3 (`activity_events`):** A bridge table that links each alert to the exact raw events that proved it. When an investigator clicks an alert, this table immediately shows the raw proof.

---

# Chapter 6: Implementation Details

## 6.1 Programming Language/s Used
* **Python 3.12:** Used for the entire backend, collectors, and correlation engine because of its simple syntax and strong built-in Windows API support.
* **SQL (SQLite):** Used for lightweight local data storage without needing a separate database server.

## 6.2 Technologies / Tools Used
* **`pywin32`:** Intercepts Windows USB arrival messages (`DBT_DEVICEARRIVAL`) and reads Security Event Log entries.
* **`watchdog`:** Watches folders for file creation, edits, and renames in real time.
* **`FastAPI` & `Uvicorn`:** Provides the REST API server (`POST /events` to receive logs from the agent, `GET /events` and `GET /events/window` to query logs).
* **`Pydantic`:** Validates that incoming logs follow the common format.

## 6.3 Datasets / Test Scenarios Details
To test the pipeline reliably without manually plugging in USB drives every time, a synthetic event generator (`generate_synthetic_events.py`) was created to generate realistic test scenarios:

1. **Scenario A (`usb_copy_run.json`):** Simulates plugging in a USB drive (`E:`), copying `payload.exe` onto it, and launching it. Tests Rules R1, R2, and R7.
2. **Background Noise (`normal_noise.json`):** Simulates ordinary workstation activity (logging in, opening Notepad, editing a text document). Used to verify that normal work **does not** trigger false alerts.
3. **Scenario B (`bulk_file_creation.json`):** Simulates copying 6 files rapidly to a USB drive within 30 seconds. Tests Rule R4.
4. **Scenario C (`log_cleared.json`):** Simulates clearing the Security Event Log (Event ID 1102) right after a program runs. Tests Rule R5.
5. **Edge Cases (`edge_cases.json`):** Tests boundary situations, such as events arriving out of order, events at the exact edge of the time window (599s, 600s, 601s), and duplicate events.
6. **Invalid Events (`invalid_events.json`):** Negative test cases with missing fields or malformed timestamps to make sure the backend rejects bad data with clear errors.

---

# Chapter 7: Results

## 7.1 Output and Reconstructed Example
When the test scenario (USB plugged in $\rightarrow$ file copied $\rightarrow$ program run) is sent to the system, the pipeline processes it as follows:

* **Log 1 (10:14:02 AM - USB Collector):** USB drive connected as Drive `E:\` (Serial: `4C53000123456789`).
* **Log 2 (10:14:20 AM - File Collector):** File `E:\setup.exe` created on Drive `E:\` (18 seconds later).
* **Log 3 (10:14:29 AM - Event Log Collector):** Windows Event 4688 shows `E:\setup.exe` was launched as a program by user `analyst` (9 seconds later).

**How ForensiTrace Connects Them:**  
Because all three logs involve Drive `E:\` and happened within 27 seconds (well inside Rule R7's 15-minute window), the engine groups them into **one single activity alert**:

```json
{
  "activity_id": "act_R7_638891d4e0e5",
  "rule_id": "R7",
  "rule_name": "Composite USB copy and execution chain",
  "confidence": 1.00,
  "narrative": "Removable USB device was connected as drive E: at 10:14:02 AM. After 18s, file E:\\setup.exe was created, and 9s later it was launched as a program by user analyst.",
  "evidence_count": 3
}
```

## 7.2 Comparison: Event Viewer vs. ForensiTrace

| Feature | Windows Event Viewer (Native) | ForensiTrace |
|---|---|---|
| **Connecting multiple sources** | None. Shows one log channel at a time. | Automatically links USB, File, and Program logs together. |
| **Tracking USB drives** | Disabled by default; does not show drive letters or serial numbers easily. | Automatically records drive letter (e.g. `E:`) and device serial number on plug-in. |
| **File changes** | Generates too many noisy logs or requires heavy auditing. | Watches folders directly and filters out temporary background OS files. |
| **Time comparison** | Investigator must compare timestamps by hand. | Automatically calculates seconds between actions inside time windows. |
| **Explainability** | Shows raw XML text lines. | Gives a plain-English story explaining what happened. |
| **Proof tracking** | Disconnected; analyst must manually note down event numbers. | Bridge table (`activity_events`) links the alert directly to the exact raw logs. |
| **Duplicate prevention** | Re-sending or retrying creates duplicate logs. | Unique SHA-256 ID prevents storing the same event twice. |

## 7.3 Testing Summary
All implemented components were tested using automated unit tests:
* **Schema Validation Tests:** All sample JSON files strictly passed format checks.
* **Database Tests (`test_db.py`):** 5 tests passed (inserting, batching, ignoring duplicates, window queries).
* **Normalizer Tests (`test_normalizers.py`):** 9 tests passed (converting USB, File, and Event Log records).
* **Scenario & Noise Tests (`test_synthetic_events.py`):** 8 tests passed (positive attack chain fires; background noise produces no false alerts; invalid events are properly rejected).
* **Total:** **22 automated tests passing with 100% success rate.**

---

# Chapter 8: Conclusion

## 8.1 Conclusion
For Phase 2, the core pipeline of ForensiTrace has been successfully built and demonstrated:
1. **Full pipeline working:** The agent collects logs from USB, File System, and Event Logs; the normalizer standardizes them; SQLite stores them; and the correlation engine groups them into high-level activities.
2. **Clear explainability:** Every alert links back to its exact raw events in the database, avoiding black-box guessing.
3. **Tested against noise:** Background everyday activity does not trigger false alerts, while simulated attack chains fire correctly.

## 8.2 Limitations and Future Work

### Current Limitations in Phase 2
* Works only on Windows 10/11 computers.
* Uses a local SQLite database on one computer at a time.
* Reconstructed activities are currently verified via backend API endpoints and test runners; the visual web dashboard is a Phase 3 deliverable.

### Roadmap for Phase 3
1. **React Web Dashboard:** Build the browser dashboard with a timeline view, alert feed, and a side drawer showing raw logs.
2. **PDF Report Export:** Add one-click PDF report generation using ReportLab so investigators can print a case summary.
3. **One-Command Demo Runner:** Create a simple script (`run_demo.py`) to launch the entire demo with one command.
4. **Comprehension Experiment:** Run a test with 8–10 classmates comparing how fast and accurately they can solve a scenario using Event Viewer versus using ForensiTrace.

---

# References

1. Hargreaves, C., & Patterson, J. (2012). An automated timeline reconstruction approach for digital forensic investigations. *Digital Investigation*, 9, S69–S79.
2. Al Awawdeh, S., Baggili, I., Marrington, A., & Iqbal, F. (2013). Towards a unified agent-based approach for real time computer forensic evidence collection (CAT Record). *2013 IEEE/ACM International Conference on Advances in Social Networks Analysis and Mining (ASONAM)*, 1340–1345.
3. Studiawan, H., Sohel, F., & Payne, C. (2019). A survey on forensic investigation of operating system logs. *Digital Investigation*, 29, 1–20.
4. Soltani, S., Hosseini Seno, S. A., & Sadoghi Yazdi, H. (2019). Event reconstruction using temporal pattern of file system modification. *IET Information Security*, 13(3), 201–212.
5. Amato, F., Cozzolino, G., Mazzeo, A., & Mazzocca, N. (2017). Correlation of digital evidences in forensic investigation through semantic technologies. *2017 IEEE 31st International Conference on Advanced Information Networking and Applications (AINA)*, 668–673.
6. Studiawan, H., & Sohel, F. (2021). Anomaly detection in a forensic timeline with deep autoencoders. *Journal of Information Security and Applications*, 63, 103002.
7. Oh, J., Lee, S., & Hwang, H. (2024). Forensic detection of timestamp manipulation for digital forensic investigation. *IEEE Access*, 12, 72544–72565.
8. Raesa, A. A., Nambiar, A. S., Dawoonauth, V., Kumar, A., Cohen, M., & Singh, P. (2026). Extending detection engineering to digital forensics: The Velociraptor unified detection-forensics methodology. *DFRWS APAC 2026*.
9. Dreier, L. M., Hargreaves, C., & Breitinger, F. (2024). Integrating implicit timing information into digital forensic timelines. *Forensic Science International: Digital Investigation*, 49, 301755.
10. Palmbach, D., & Breitinger, F. (2020). Artifacts for detecting timestamp manipulation in NTFS on Windows and their reliability. *Forensic Science International: Digital Investigation*, 32, 300920.
11. Bhandari, S., & Jusas, V. (2020). An ontology based on the timeline of Log2timeline and Psort using abstraction approach in digital forensics. *Symmetry*, 12(4), 642.
12. Arshad, A., Iqbal, W., & Abbas, H. (2018). USB storage device forensics for Windows 10. *Journal of Forensic Sciences*, 63(3), 763–775.
