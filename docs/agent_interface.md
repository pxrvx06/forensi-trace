# ForensiTrace Agent Interface Contract

> **Document Status:** DRAFT — Awaiting Review & Confirmation  
> **Author:** Daksh (Agent Core & Event Log Collector Owner)  
> **Reviewers:** Chetna (USB & File-System Collectors Owner), Purva (Backend Ingestion & Database Owner)  
> **Related Contracts:** [`docs/schema.md`](schema.md), [`backend/schema.py`](../backend/schema.py)

---

## 1. Overview & Purpose

The ForensiTrace endpoint agent runs as a unified background service on Windows endpoints. It manages three pluggable telemetry collectors:
1. **Event Log Collector** (Security 4688, 1102, System 104) — Owned by Daksh
2. **USB Device Collector** (Drive arrival/removal, device serial/name) — Owned by Chetna
3. **File-System Collector** (Watchdog file mutation watcher) — Owned by Chetna

This document establishes:
1. The **Collector Lifecycle & Emission Interface** that all collectors must implement.
2. The **Inter-Collector Hand-off Hook** by which the USB collector informs the File-System collector to start/stop watching removable drives.
3. The **Agent-to-Backend Batch Transmission Contract** for shipping telemetry to `POST /events`.

---

## 2. Collector Interface Specification

Every collector module in `agent/collectors/` must inherit from `BaseCollector` (defined in `agent/collectors/base.py`) and adhere to the standard lifecycle interface:

```python
from abc import ABC, abstractmethod
import queue
from typing import Any, Dict

class BaseCollector(ABC):
    """
    Abstract Base Class for all ForensiTrace telemetry collectors.
    """
    def __init__(self, event_queue: queue.Queue[Dict[str, Any]], config: Dict[str, Any]) -> None:
        self.event_queue = event_queue
        self.config = config
        self._running = False

    @abstractmethod
    def start(self) -> None:
        """
        Initializes collector resources and begins telemetry ingestion in a background thread.
        Must be non-blocking (spawns its own worker/monitoring thread).
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """
        Gracefully terminates collector threads, unhooks OS callbacks, and releases handles.
        Must be idempotent and safe to call multiple times.
        """
        pass

    @property
    def is_alive(self) -> bool:
        """Returns True if the collector worker thread is currently active."""
        return self._running

    def emit(self, event_dict: Dict[str, Any]) -> None:
        """
        Emits a normalized event dictionary onto the agent's central thread-safe queue.
        Guaranteed non-blocking.
        """
        try:
            self.event_queue.put_nowait(event_dict)
        except queue.Full:
            # Local queue limit hit; log dropped telemetry warning with source name
            pass
```

### Event Emission Protocol
- When a collector captures telemetry, it normalizes the record according to [`docs/schema.md`](schema.md) and calls `self.emit(event_dict)`.
- Emission is thread-safe and non-blocking via `queue.Queue[dict]`.
- Collectors do **not** perform network requests or write to SQLite directly. All transmission is delegated to the agent core's HTTP sender.

---

## 3. USB-to-FileSystem Collector Hand-off Hook

### Problem Context
Monitoring the entire `C:\` drive with `watchdog` generates overwhelming disk I/O noise (thousands of temporary file mutations per minute). To keep overhead minimal while satisfying Scenario A:
- The **File-System Collector** watches specific user folders (`Documents`, `Downloads`, `Desktop`, `Temp`).
- The moment a user inserts a removable USB drive (e.g., `E:`), the **USB Collector** must notify the **File-System Collector** immediately so that `watchdog` can dynamically schedule an observer on the new root path (e.g. `E:\`).
- When the USB drive is removed, the File-System collector unschedules the observer for that drive letter.

### Architecture Options Evaluated

| Architecture Option | Description | Latency | Complexity | Threading |
|---|---|---|---|---|
| **Option A: Direct Callback Hook** *(Recommended)* | The USB collector accepts a registered callback function `on_drive_event(drive_letter: str, action: str)` invoked synchronously upon arrival/removal. | Immediate (0 ms delay) | Low (Single function invocation) | Direct invocation from USB event thread to thread-safe `watchdog.Observer.schedule()` |
| **Option B: Shared Inter-Collector Queue** | The agent core maintains a `drive_events_queue = queue.Queue()`. The USB collector pushes drive letters; the FS collector runs a dedicated worker thread polling the queue. | Polling-dependent (100–500 ms delay) | Medium (Requires dedicated polling thread and loop) | Extra thread and queue management required |

### Recommendation: Option A (Direct Callback Hook)

**Why Option A is recommended:**
1. **Zero Latency:** In forensic scenarios, an attacker or script may write a payload immediately upon drive connection. Option A attaches the file watcher in `< 1ms`, eliminating race conditions where files are copied before the watcher starts.
2. **Resource Efficiency:** Avoids creating an additional polling thread running an idle loop inside the File-System collector.
3. **Thread Safety:** Python's `watchdog.observers.Observer.schedule()` is inherently thread-safe and can be invoked directly from the USB collector's notification thread.
4. **Clean Decoupling:** The USB collector does not need to know about the File-System collector; it simply executes any registered listener:

```python
# In agent/main.py (Agent Core orchestration):
fs_collector = FileSystemCollector(event_queue, config)
usb_collector = USBCollector(event_queue, config)

# Wire the callback hook:
usb_collector.register_drive_listener(fs_collector.handle_drive_event)
```

### Callback Signature Contract
```python
def handle_drive_event(drive_letter: str, event_type: str) -> None:
    """
    Hook invoked when a removable drive is attached or removed.
    
    :param drive_letter: Uppercase Windows drive string with trailing colon, e.g. "E:"
    :param event_type: "ATTACHED" | "REMOVED"
    """
```

---

## 4. Agent-to-Backend Batch Transmission Contract (`POST /events`)

The agent core (`agent/sender.py`) flushes queued telemetry to the FastAPI backend ingestion service.

### Endpoint Details
- **Method:** `POST`
- **Path:** `/events`
- **Headers:** `Content-Type: application/json`

### Payload Schema (`EventBatch`)
The request body must be a JSON object strictly matching `backend/schema.py` (`EventBatch`):

```json
{
  "events": [
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
        "serial_number": "4C53000123456789"
      },
      "raw": {
        "EventType": "DBT_DEVICEARRIVAL",
        "DriveLetter": "E:"
      }
    }
  ],
  "batch_size": 1
}
```

### Ingestion Response Specification

| HTTP Status | Condition | Example Response Body | Agent Action |
|---|---|---|---|
| `200 OK` | Batch accepted and written to database. Duplicates ignored via `INSERT OR IGNORE`. | `{"status": "ok", "ingested": 1, "duplicates": 0}` | Drain committed events from local memory buffer. |
| `422 Unprocessable Entity` | Schema validation error (invalid field, timestamp format, or disallowed action). | `{"detail": [{"loc": ["body", "events", 0, "ts_utc"], "msg": "invalid timestamp", "type": "value_error"}]}` | Log error with offending event ID; drop invalid record to avoid blocking the queue. |
| `500 / 502 / 503 / 504` | Backend server error or temporary unavailability. | `{"status": "error", "message": "database locked"}` | Retain events in buffer; trigger exponential backoff retry. |
| **Connection Refused** | Backend process offline or unreachable. | N/A (Socket error) | Retain events in memory buffer; retry with backoff. Do **not** discard events. |

### Idempotency & Deduplication
Every event possesses a deterministic `event_id = SHA256(source|raw_record_id|ts_utc)`. In the event of network dropouts or backend restarts during a transmission, the agent resends the unacknowledged batch. SQLite's primary key uniqueness ensures that repeated deliveries are completely harmless.

---

## 5. Review & Confirmation Sign-off

- [ ] **Chetna (USB & FS Collector):** Review collector lifecycle methods (`start`/`stop`) and confirm acceptance of Option A (callback hook `handle_drive_event`).
- [ ] **Purva (Backend Ingestion):** Review `POST /events` batch JSON format and HTTP response codes.
