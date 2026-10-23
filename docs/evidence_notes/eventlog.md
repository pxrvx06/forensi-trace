# Windows Event Log Telemetry Evidence Notes

> **Notice:** This document is an empirical evidence template. It is filled in by running `python scenarios/probes/probe_eventlog.py` on a configured Windows 10/11 test machine with administrator privileges per `scripts/setup_windows.md`. **Do not invent or estimate values; populate solely from observed output.**

---

## 1. Test Environment Details

- **Test Machine Hostname:** *(To be filled from probe)*
- **OS Version & Build:** *(e.g., Windows 11 Pro 23H2 Build 22631.xxxx)*
- **Audit Policy Status:**
  - `Process Creation` subcategory: *(Enabled / Disabled)*
  - `CommandLine` in 4688: *(Enabled / Disabled)*
- **Probe Run Timestamp (UTC):** `YYYY-MM-DDTHH:MM:SSZ`

---

## 2. Event ID 4688: Process Creation (`PROCESS_STARTED`)

### Observed Channel
`Security`

### Sample System Header Properties
| Field Name | Observed Value / Format | Notes |
|---|---|---|
| `Provider[@Name]` | `Microsoft-Windows-Security-Auditing` | |
| `EventID` | `4688` | |
| `Version` | `2` | |
| `TimeCreated[@SystemTime]` | | ISO-8601 UTC timestamp format |
| `EventRecordID` | | Monotonically increasing record index |
| `Computer` | | FQDN or NetBIOS machine name |

### Sample EventData Fields
| Parameter Name | Example Observed Value | Mapping to ForensiTrace Schema |
|---|---|---|
| `SubjectUserSid` | | `details.subject_user_sid` |
| `SubjectUserName` | | `user` |
| `SubjectDomainName` | | `details.subject_domain` |
| `SubjectLogonId` | | `details.subject_logon_id` |
| `NewProcessId` | | `details.process_id` (Hex string e.g. `0x1a4`, convert to int) |
| `NewProcessName` | | `entity` (Full executable path, e.g. `C:\Windows\notepad.exe`) |
| `CommandLine` | | `details.command_line` (Null if policy disabled) |
| `ParentProcessName` | | `details.parent_process_name` |
| `MandatoryLabel` | | `details.integrity_level` |

### Observed Quirks & Parsing Considerations
- *Process IDs:* Observed whether `NewProcessId` is formatted in hexadecimal (e.g. `0x1a4`) or decimal.
- *Command Line:* Confirm whether arguments are preserved intact or truncated.
- *Raw XML Snippet:*
```xml
<!-- Paste raw XML from probe_eventlog.py output here -->
```

---

## 3. Event ID 1102: Audit Log Cleared (`LOG_CLEARED`)

### Observed Channel
`Security`

### Sample System Header Properties
| Field Name | Observed Value / Format | Notes |
|---|---|---|
| `Provider[@Name]` | `Microsoft-Windows-Security-Auditing` | |
| `EventID` | `1102` | |
| `TimeCreated[@SystemTime]` | | ISO-8601 UTC timestamp |
| `EventRecordID` | | |
| `Computer` | | |

### Sample EventData Fields
| Parameter Name | Example Observed Value | Mapping to ForensiTrace Schema |
|---|---|---|
| `SubjectUserSid` | | `details.subject_user_sid` |
| `SubjectUserName` | | `user` |
| `SubjectDomainName` | | `details.subject_domain` |
| `SubjectLogonId` | | `details.subject_logon_id` |

### Raw XML Snippet
```xml
<!-- Paste raw XML from probe_eventlog.py output here -->
```

---

## 4. Event ID 104: System Log Cleared (`LOG_CLEARED`)

### Observed Channel
`System`

### Sample System Header Properties
| Field Name | Observed Value / Format | Notes |
|---|---|---|
| `Provider[@Name]` | `Microsoft-Windows-Eventlog` | |
| `EventID` | `104` | |
| `TimeCreated[@SystemTime]` | | ISO-8601 UTC timestamp |
| `EventRecordID` | | |
| `Computer` | | |

### Sample EventData Fields / UserData
| Parameter Name | Example Observed Value | Mapping to ForensiTrace Schema |
|---|---|---|
| `SubjectUserName` | | `user` |
| `SubjectDomainName` | | `details.subject_domain` |
| `BackupPath` | | `details.backup_path` (if saved to evtx) |

### Raw XML Snippet
```xml
<!-- Paste raw XML from probe_eventlog.py output here -->
```

---

## 5. Collector Implementation Decisions Arising From Probe Findings

- [ ] Confirm UTC timezone conversion matches schema requirements (`ts_utc` with millisecond precision).
- [ ] Confirm `event_id` hash calculation format (`source + raw record id + timestamp`).
- [ ] Store complete original XML string intact under `raw`.
