# Windows USB Storage Telemetry Evidence Notes

> **Source:** Chetna (USB and File-System Collectors Owner)  
> **Related Contracts:** [`docs/schema.md`](../schema.md), [`agent/collectors/usb_collector.py`](../../agent/collectors/usb_collector.py)  
> **Related Samples:** [`docs/samples/usb_arrival.json`](../samples/usb_arrival.json), [`docs/samples/usb_removal.json`](../samples/usb_removal.json)

---

## 1. Evidence Extraction Methodology

USB storage arrival and removal is detected via two complementary Windows mechanisms:
1. **Real-time Win32 Broadcasts (`WM_DEVICECHANGE`):**
   - Notification messages `DBT_DEVICEARRIVAL` (`0x8000`) and `DBT_DEVICEREMOVECOMPLETE` (`0x8004`).
   - Parsed using `DEV_BROADCAST_VOLUME` with bitmask extraction (`dbcv_unitmask`) to identify the assigned drive letter (e.g. `16` $\rightarrow$ `E:`).
2. **Registry Artifacts:**
   - `HKLM\SYSTEM\MountedDevices`: Maps `\DosDevices\<DriveLetter>` to device hardware instance IDs (`\??\USBSTOR#Disk&Ven_...#<Serial>#{GUID}`).
   - `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: Stores device friendly name (`FriendlyName`), hardware descriptors, and manufacturer info.
   - `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: Maps serial numbers to parent USB root devices to resolve `vendor_id` and `product_id`.

---

## 2. Field Mapping to ForensiTrace Schema

| Windows Source Artifact | Extracted Value | ForensiTrace Normalized Field |
|---|---|---|
| `WM_DEVICECHANGE (wparam=0x8000)` | `DEVICE_ARRIVED` | `action` |
| `WM_DEVICECHANGE (wparam=0x8004)` | `DEVICE_REMOVED` | `action` |
| `DEV_BROADCAST_VOLUME.dbcv_unitmask` | `E:` (Bit 4) | `details.drive_letter` |
| `MountedDevices \DosDevices\E:` | `USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA\4C53000123456789` | `details.raw_record_id` |
| `Enum\USBSTOR FriendlyName` | `SanDisk Ultra` | `details.device_name` |
| `Enum\USBSTOR Instance ID` | `4C53000123456789` | `details.serial_number` |
| `Enum\USB Hardware ID` | `0781` / `5581` | `details.vendor_id` / `details.product_id` |
| Formatted Entity | `E: (SanDisk Ultra 4C53000123456789)` | `entity` |
| Timestamp Recipe | ISO 8601 UTC with milliseconds | `ts_utc` |
| Hash Recipe | `SHA256("usb|" + raw_record_id + "|" + ts_utc)` | `event_id` |

---

## 3. Forensic Value in Attack Scenarios

In Scenario A:
- Provides the physical anchoring timestamp $T_0$ when an attacker connects an untrusted storage volume.
- Associates the drive letter (`E:`) that subsequent file mutations and process executions will reference.
- Serial number and device name establish device provenance for incident attribution.
