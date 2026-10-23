# Windows File-System Telemetry Evidence Notes

> **Source:** Chetna (USB and File-System Collectors Owner)  
> **Related Contracts:** [`docs/schema.md`](../schema.md), [`agent/collectors/fs_collector.py`](../../agent/collectors/fs_collector.py)  
> **Related Samples:** [`docs/samples/fs_created.json`](../samples/fs_created.json), [`docs/samples/fs_modified.json`](../samples/fs_modified.json), [`docs/samples/fs_moved.json`](../samples/fs_moved.json), [`docs/samples/fs_deleted.json`](../samples/fs_deleted.json)

---

## 1. Evidence Extraction Methodology

File mutations on removable drives are monitored using Python's `watchdog` library (`ReadDirectoryChangesW` underneath on Windows):
1. **Dynamic Scheduling:**
   - Watcher is scheduled dynamically on the removable drive root (e.g. `E:\`) only when the USB collector announces drive arrival.
   - Prevents disk I/O exhaustion from watching noisy fixed volumes like `C:\`.
2. **Noise Suppression:**
   - Filters out temporary office locks (`~$`), partial downloads (`.crdownload`, `.part`), editor swap files (`.swp`), and system volume metadata (`$RECYCLE.BIN`, `System Volume Information`).
3. **Burst Debouncing:**
   - When a payload file is copied in Windows, file creation triggers an initial `created` notification followed by a rapid burst of `modified` events as byte chunks are flushed.
   - The burst debouncer suppresses immediate `modified` events within $1.5\text{ s}$ of `created`, guaranteeing that copying a file produces a single clean `FILE_CREATED` event without flood.

---

## 2. Field Mapping to ForensiTrace Schema

| File System Action | Watchdog Trigger | ForensiTrace Normalized Field |
|---|---|---|
| File Created | `on_created` | `action: "FILE_CREATED"` |
| File Modified | `on_modified` | `action: "FILE_MODIFIED"` |
| File Moved / Renamed | `on_moved` | `action: "FILE_MOVED"` |
| File Deleted | `on_deleted` | `action: "FILE_DELETED"` |
| Canonical Path | Windows backslash path | `entity` (e.g. `E:\reports\payload.exe`) |
| Drive Letter | Uppercase drive prefix | `details.drive_letter` (e.g. `E:`) |
| File Name | Base file name | `details.file_name` |
| Extension | Lowercase extension | `details.extension` (e.g. `.exe`) |
| File Size | `os.path.getsize()` | `details.file_size_bytes` |
| Raw Record ID | Action + Entity | `raw_record_id: "{action}|{entity}"` |
| Deterministic Hash | SHA-256 Recipe | `SHA256("fs|" + raw_record_id + "|" + ts_utc)` |

---

## 3. Forensic Value in Attack Scenarios

In Scenario A:
- Records the delivery of malicious executables or staging of exfiltrated data.
- Bridges the timeline between USB device connection ($T_0$) and eventual process execution ($T_2$).
- Provides evidence provenance linking file attributes and byte counts to the correlated activity.
