# ForensiTrace Normalized Event Schema v1

> **Status:** FROZEN CONTRACT — Phase 1 / Phase 2 Baseline  
> **Author:** Purva (Backend & Data Layer Owner)  
> **Reviewers:** Daksh (Agent), Chetna (Collectors & UI), Akash (Correlation Engine)  
> **Rule:** This document is a strict technical contract. Do not edit directly; propose changes in comments/PRs with team agreement.

---

## 1. Field Specification Table

All collectors (`agent/collectors/`), database tables (`backend/db.py`), API payloads (`backend/main.py`), and the correlation engine (`engine/`) must strictly produce and consume events conforming to this schema.

| Field | Type | Required? | Description & Constraints |
|---|---|---|---|
| `event_id` | String (Hex 64) | **Required** | Deterministic SHA-256 hash of `"{source}\|{raw_record_id}\|{ts_utc}"`. Guarantees idempotency so re-sending or re-ingesting the same event is completely harmless. |
| `source` | String (Enum) | **Required** | Evidence source category. Must be strictly one of: `eventlog`, `usb`, `fs`. |
| `ts_utc` | String (ISO 8601) | **Required** | Event creation timestamp in UTC with millisecond precision and literal `Z` suffix. Example: `2026-10-23T10:00:00.120Z`. |
| `host` | String | **Required** | Hostname or NetBIOS machine name where telemetry originated. Example: `WIN-FORENSIC-01`. |
| `user` | String \| null | **Optional** | Account involved in the event (format: `DOMAIN\username` or `username`). `null` when user identity cannot be reliably attributed (e.g., raw file system notifications). |
| `action` | String (Enum) | **Required** | Standardized action descriptor drawn from the fixed allowed actions table below. |
| `entity_type` | String (Enum) | **Required** | Target entity classification. Must be strictly one of: `device`, `file`, `process`. |
| `entity` | String | **Required** | Primary identifier of the affected entity: Device (drive letter + serial/name), File (canonical absolute path), or Process (binary image path). |
| `details` | Object (JSON) | **Required** | Structured dictionary containing source-specific metadata, parameters, and the `raw_record_id` used in hash generation. |
| `raw` | Object \| String | **Required** | The untouched, original record from the source. Displayed verbatim in the dashboard evidence drawer for forensic explainability. |

---

## 2. Fixed Allowed Actions by Source

Actions are strictly bounded by telemetry source:

| Source | Allowed `action` Values | Target `entity_type` | Trigger Description |
|---|---|---|---|
| `usb` | `DEVICE_ARRIVED` | `device` | USB storage volume mounted or arrival event detected in device management. |
| `usb` | `DEVICE_REMOVED` | `device` | USB storage device safely removed or disconnected. |
| `fs` | `FILE_CREATED` | `file` | File created on monitored volume (e.g. removable drive). |
| `fs` | `FILE_MODIFIED` | `file` | Existing file content or attributes altered. |
| `fs` | `FILE_DELETED` | `file` | Monitored file deleted from volume. |
| `fs` | `FILE_MOVED` | `file` | Monitored file renamed or moved to/from path. |
| `eventlog` | `PROCESS_STARTED` | `process` | Process created (Event ID 4688 / Sysmon 1). |
| `eventlog` | `LOG_CLEARED` | `file` \| `process` | Audit/Security log cleared (Event ID 1102 / System 104). |
| `eventlog` | `LOGON` | `process` | User interactive or network logon (Event ID 4624). |

---

## 3. Formatting & Serialization Rules

1. **Timestamps (`ts_utc`):**
   * Must always be in UTC ISO 8601 format with millisecond precision and trailing `Z`.
   * Format: `YYYY-MM-DDTHH:MM:SS.mmmZ` (regex: `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`).
   * Collectors must convert local Windows file times/system times to UTC before emitting.

2. **Drive Letters & File Paths:**
   * Drive letters must always be uppercase (e.g., `E:`, `C:`).
   * All Windows filesystem and process paths must use standard Windows backslashes (`\`), not forward slashes (`/`).
   * Canonical path example: `E:\reports\payload.exe`.

3. **Deterministic `event_id` Recipe:**
   * Compute standard SHA-256 hash (64 lowercase hexadecimal characters):
     ```python
     event_id = hashlib.sha256(f"{source}|{raw_record_id}|{ts_utc}".encode("utf-8")).hexdigest()
     ```
   * **`raw_record_id` extraction rules:**
     * `eventlog`: Channel and EventRecordID (e.g., `Security:9482104`).
     * `usb`: Device instance identifier or serial number (e.g., `USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA\4C53000123456789`).
     * `fs`: Because filesystem watchdog notifications lack native OS sequence numbers, use `"{action}|{entity}"` (e.g., `FILE_CREATED|E:\reports\payload.exe`).
   * Every event's `details` dictionary must include `"raw_record_id"` for verification.

---

## 4. End-to-End Scenario Sample Events

The following three sample events illustrate the baseline investigation scenario:
1. **USB Drive Inserted (`E:`)**
2. **Payload Copied (`payload.exe` written to `E:\reports\`)**
3. **Payload Executed (`payload.exe` executed from `E:\reports\`)**

### 4.1. USB Event (`usb`) — Drive E: Inserted
*File: `docs/examples/usb_event.json`*
```json
{
  "event_id": "8fdfc64e74cc0d33ca188bff14a86a57ec8ac88f9569ea731ad171d9c67213e6",
  "source": "usb",
  "ts_utc": "2026-10-23T10:00:00.120Z",
  "host": "WIN-FORENSIC-01",
  "user": "SYSTEM",
  "action": "DEVICE_ARRIVED",
  "entity_type": "device",
  "entity": "E: (SanDisk Ultra 4C53000123456789)",
  "details": {
    "raw_record_id": "USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA\\4C53000123456789",
    "drive_letter": "E:",
    "device_name": "SanDisk Ultra",
    "serial_number": "4C53000123456789",
    "vendor_id": "0781",
    "product_id": "5581"
  },
  "raw": {
    "DeviceInstanceId": "USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA\\4C53000123456789&0",
    "Class": "DiskDrive",
    "FriendlyName": "SanDisk Ultra USB Device",
    "DriveLetter": "E:",
    "EventType": "DBT_DEVICEARRIVAL"
  }
}
```

### 4.2. File System Event (`fs`) — Payload Copied to E:\reports\
*File: `docs/examples/fs_event.json`*
```json
{
  "event_id": "8376a88fcb952b02739e8f45c59bfba2c381de2b6140e44551b03832d5d149a7",
  "source": "fs",
  "ts_utc": "2026-10-23T10:01:15.450Z",
  "host": "WIN-FORENSIC-01",
  "user": null,
  "action": "FILE_CREATED",
  "entity_type": "file",
  "entity": "E:\\reports\\payload.exe",
  "details": {
    "raw_record_id": "FILE_CREATED|E:\\reports\\payload.exe",
    "drive_letter": "E:",
    "file_path": "E:\\reports\\payload.exe",
    "file_name": "payload.exe",
    "extension": ".exe",
    "file_size_bytes": 65536,
    "is_directory": false
  },
  "raw": {
    "event_type": "created",
    "src_path": "E:\\reports\\payload.exe",
    "is_directory": false
  }
}
```

### 4.3. Event Log Event (`eventlog`) — Process Started from Removable Drive
*File: `docs/examples/eventlog_event.json`*
```json
{
  "event_id": "d8d4e6d93a6d82f72cf368ba8a0daa8f3ea55558116c3d67637c0736fa487dd7",
  "source": "eventlog",
  "ts_utc": "2026-10-23T10:02:30.800Z",
  "host": "WIN-FORENSIC-01",
  "user": "CONTOSO\\analyst",
  "action": "PROCESS_STARTED",
  "entity_type": "process",
  "entity": "E:\\reports\\payload.exe",
  "details": {
    "raw_record_id": "Security:9482104",
    "event_record_id": 9482104,
    "channel": "Security",
    "event_code": 4688,
    "process_id": "0x1a4c",
    "process_name": "E:\\reports\\payload.exe",
    "parent_process_id": "0x0e20",
    "parent_process_name": "C:\\Windows\\explorer.exe",
    "command_line": "\"E:\\reports\\payload.exe\" --silent"
  },
  "raw": {
    "Event": {
      "System": {
        "Provider": {
          "Name": "Microsoft-Windows-Security-Auditing"
        },
        "EventID": 4688,
        "EventRecordID": 9482104,
        "Channel": "Security",
        "Computer": "WIN-FORENSIC-01",
        "TimeCreated": {
          "SystemTime": "2026-10-23T10:02:30.800Z"
        }
      },
      "EventData": {
        "NewProcessName": "E:\\reports\\payload.exe",
        "ProcessId": "0x1a4c",
        "ParentProcessName": "C:\\Windows\\explorer.exe",
        "CommandLine": "\"E:\\reports\\payload.exe\" --silent",
        "SubjectUserName": "analyst",
        "SubjectDomainName": "CONTOSO"
      }
    }
  }
}
```

---

## 5. Open Questions for Team Review

1. **Watchdog `raw_record_id` Fallback (Chetna):**  
   The Windows `watchdog` file-system library notifies file mutations as asynchronous filesystem events without an OS-level serial record ID. We formulated the fallback as `"{action}|{entity}"` combined with millisecond timestamp for the `event_id` hash. Does Chetna's FS collector have access to NTFS USN Journal sequence numbers, or should we keep this `"{action}|{entity}"` convention as standard?

2. **User Attribution on File System Events (Chetna & Daksh):**  
   File system events observed via filesystem change notifications typically do not expose the originating Windows User SID/account without heavy file handle auditing. In this schema, `user` is set to `null` for `fs` events unless actively enriched. The team should confirm this is acceptable for correlation rules.

3. **`raw` Structure Formatting (Akash & Chetna):**  
   `raw` is modeled as a JSON object (or stringified payload) representing the exact unmodified dictionary received from the collector. Chetna's React evidence drawer can render this with JSON pretty-printing.

4. **`FILE_MOVED` Renaming Details (Chetna & Akash):**  
   When a file is moved or renamed, should `entity` always represent the destination path, with `details.src_path` containing the source path? Current recommendation: `entity` = destination path, `details.src_path` = original path.
