# Real Recorded Telemetry Samples

> **Source:** Chetna (USB and File-System Collectors Owner) & Daksh (Event Log Collector Owner)  
> **Receivers:** Purva (Backend Normalizer Tests) & Akash (Correlation Engine Tests)  
> **Contract:** [`docs/schema.md`](../schema.md) & [`backend/schema.py`](../../backend/schema.py)

---

## 1. Overview & Purpose

This directory contains real sample event recordings produced by the ForensiTrace telemetry collectors:
1. **USB Collector (`source: "usb"`)** — Captured device arrival and safe removal.
2. **File-System Collector (`source: "fs"`)** — Captured filesystem mutations (`created`, `modified`, `moved`, `deleted`) on monitored removable storage volumes.

These sample recordings serve two technical contracts:
- **For Purva (Backend Normalizers):** Feeds input data to normalizer functions to verify raw Windows structures map correctly to the schema.
- **For Akash (Correlation Engine):** Allows correlation engine tests to transition from synthetic fixtures to real-world collector telemetry.

---

## 2. Sample Files Index

| Telemetry Source | Action | File Path | Description |
|---|---|---|---|
| `usb` | `DEVICE_ARRIVED` | [`docs/samples/usb_arrival.json`](usb_arrival.json) | Insertion of SanDisk Ultra USB drive mounting as drive `E:`. |
| `usb` | `DEVICE_REMOVED` | [`docs/samples/usb_removal.json`](usb_removal.json) | Disconnection of SanDisk Ultra USB drive. |
| `usb` (Batch) | `ARRIVED` + `REMOVED` | [`docs/samples/usb_samples.json`](usb_samples.json) | Transmittable `EventBatch` containing both USB lifecycle events. |
| `fs` | `FILE_CREATED` | [`docs/samples/fs_created.json`](fs_created.json) | Payload `E:\reports\payload.exe` copied to removable drive. |
| `fs` | `FILE_MODIFIED` | [`docs/samples/fs_modified.json`](fs_modified.json) | Payload content altered or attributes written. |
| `fs` | `FILE_MOVED` | [`docs/samples/fs_moved.json`](fs_moved.json) | Payload renamed from `payload.exe` to `payload_backup.exe`. |
| `fs` | `FILE_DELETED` | [`docs/samples/fs_deleted.json`](fs_deleted.json) | Payload removed from removable volume. |
| `fs` (Batch) | All FS Actions | [`docs/samples/fs_samples.json`](fs_samples.json) | Transmittable `EventBatch` containing complete file lifecycle. |

---

## 3. Schema & Validation Contract

Every sample event strictly adheres to the frozen specification:
1. **Deterministic `event_id` Recipe:**
   $$\text{event\_id} = \text{SHA256}(\text{source} \parallel \text{raw\_record\_id} \parallel \text{ts\_utc})$$
2. **Millisecond UTC Timestamps (`ts_utc`):**
   Format: `YYYY-MM-DDTHH:MM:SS.mmmZ` (regex: `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`).
3. **Canonical Windows Paths:**
   Uppercase drive letters (e.g. `E:`) and standard Windows backslashes (`\`).

All files pass automated validation via `python docs/validate_examples.py`.
