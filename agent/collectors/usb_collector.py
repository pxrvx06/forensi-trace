"""
ForensiTrace USB Telemetry Collector
Author: Chetna (USB and File-System Collectors Owner)
Contract: docs/schema.md & docs/agent_interface.md
Scope: Step 1 (Page 6) - USB arrival and removal, drive letter, serial number, device name.
"""

from __future__ import annotations

import os
import re
import time
import queue
import ctypes
import hashlib
import logging
import threading
from ctypes import wintypes
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from agent.collectors.base import BaseCollector

# Configure labeled logger per project rules
logger = logging.getLogger("forensitrace.agent.collector.usb")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Win32 Constants
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3

WM_DEVICECHANGE = 0x0219
WM_DESTROY = 0x0002

DBT_DEVICEARRIVAL = 0x8000
DBT_DEVICEREMOVECOMPLETE = 0x8004
DBT_DEVNODES_CHANGED = 0x0007

DBT_DEVTYP_VOLUME = 0x00000002


# Win32 Broadcast Structures for Device Notifications
class DEV_BROADCAST_HDR(ctypes.Structure):
    _fields_ = [
        ("dbch_size", wintypes.DWORD),
        ("dbch_devicetype", wintypes.DWORD),
        ("dbch_reserved", wintypes.DWORD),
    ]


class DEV_BROADCAST_VOLUME(ctypes.Structure):
    _fields_ = [
        ("dbcv_size", wintypes.DWORD),
        ("dbcv_devicetype", wintypes.DWORD),
        ("dbcv_reserved", wintypes.DWORD),
        ("dbcv_unitmask", wintypes.DWORD),
        ("dbcv_flags", wintypes.WORD),
    ]


def get_iso_utc_timestamp() -> str:
    """Returns current UTC timestamp in ISO 8601 format with millisecond precision and 'Z'."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def get_drive_letters_from_mask(unitmask: int) -> List[str]:
    """Converts a Win32 volume bitmask into a list of uppercase drive letters (e.g. ['E:'])."""
    letters: List[str] = []
    for i in range(26):
        if unitmask & (1 << i):
            letters.append(f"{chr(65 + i)}:")
    return letters


def parse_mounted_device_binary(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Parses Windows HKLM\\SYSTEM\\MountedDevices binary entry for USBSTOR device info.
    Example payload structure:
    \\??\\USBSTOR#Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00#4C53000123456789#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
    """
    res: Dict[str, Any] = {}
    try:
        decoded = raw_bytes.decode("utf-16le", errors="ignore")
    except Exception:
        return res

    if "USBSTOR" not in decoded and "STORAGE#Volume" not in decoded:
        return res

    ven_match = re.search(r"Ven_([^&#]+)", decoded, re.IGNORECASE)
    if ven_match:
        res["vendor"] = ven_match.group(1).replace("_", " ").strip()

    prod_match = re.search(r"Prod_([^&#]+)", decoded, re.IGNORECASE)
    if prod_match:
        res["product"] = prod_match.group(1).replace("_", " ").strip()

    rev_match = re.search(r"Rev_([^&#]+)", decoded, re.IGNORECASE)
    if rev_match:
        res["revision"] = rev_match.group(1).strip()

    # Serial number between '#' delimiters
    serial_match = re.search(r"#([^#&]+)(?:&[0-9]+)?#\{[0-9a-fA-F\-]{36}\}", decoded)
    if serial_match:
        res["serial_number"] = serial_match.group(1).strip()

    if res.get("vendor") and res.get("product"):
        res["device_name"] = f"{res['vendor']} {res['product']}"
        raw_rec = f"USBSTOR\\DISK&VEN_{res['vendor'].upper()}&PROD_{res['product'].upper()}"
        if res.get("serial_number"):
            raw_rec += f"\\{res['serial_number']}"
        res["raw_record_id"] = raw_rec

    return res


def query_registry_device_info(drive_letter: str) -> Dict[str, Any]:
    """
    Queries the Windows registry (HKLM\\SYSTEM\\MountedDevices, Enum\\USBSTOR, Enum\\USB)
    to retrieve USB hardware identifiers, device name, and serial number.
    """
    info: Dict[str, Any] = {
        "drive_letter": drive_letter.upper(),
        "device_name": None,
        "serial_number": None,
        "vendor_id": None,
        "product_id": None,
        "raw_record_id": None,
        "friendly_name": None,
    }

    try:
        import winreg
    except ImportError:
        return info

    # 1. Query HKLM\SYSTEM\MountedDevices
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices") as mkey:
            dos_name = f"\\DosDevices\\{drive_letter.upper()}"
            raw_bytes, _ = winreg.QueryValueEx(mkey, dos_name)
            parsed = parse_mounted_device_binary(raw_bytes)
            if parsed:
                info.update(parsed)
    except Exception as exc:
        logger.debug("[query_registry_device_info] MountedDevices query failed for %s: %s", drive_letter, exc)

    serial = info.get("serial_number")

    # 2. Query HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR") as usbstor_key:
            sub_count, _, _ = winreg.QueryInfoKey(usbstor_key)
            for i in range(sub_count):
                subkey_name = winreg.EnumKey(usbstor_key, i)
                try:
                    with winreg.OpenKey(usbstor_key, subkey_name) as dev_key:
                        inst_count, _, _ = winreg.QueryInfoKey(dev_key)
                        for j in range(inst_count):
                            inst_name = winreg.EnumKey(dev_key, j)
                            # Check if instance matches our serial number
                            matched = False
                            if serial and serial.lower() in inst_name.lower():
                                matched = True
                            elif not serial:
                                matched = True

                            if matched:
                                with winreg.OpenKey(dev_key, inst_name) as inst_key:
                                    try:
                                        fname, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                                        info["friendly_name"] = fname
                                        if not info.get("device_name"):
                                            # Strip trailing ' USB Device' if present for clean name
                                            clean_name = re.sub(r"\s+USB\s+Device$", "", fname, flags=re.IGNORECASE)
                                            info["device_name"] = clean_name
                                    except OSError:
                                        pass

                                    if not info.get("raw_record_id"):
                                        clean_inst = inst_name.split("&")[0] if "&" in inst_name else inst_name
                                        info["raw_record_id"] = f"USBSTOR\\{subkey_name}\\{clean_inst}"
                                    if not info.get("serial_number"):
                                        info["serial_number"] = inst_name.split("&")[0]
                                break
                except OSError:
                    continue
    except Exception as exc:
        logger.debug("[query_registry_device_info] USBSTOR query failed: %s", exc)

    # 3. Query HKLM\SYSTEM\CurrentControlSet\Enum\USB to resolve VID and PID
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USB") as usb_key:
            sub_count, _, _ = winreg.QueryInfoKey(usb_key)
            for i in range(sub_count):
                vid_pid_key = winreg.EnumKey(usb_key, i)
                vid_match = re.search(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", vid_pid_key)
                if vid_match:
                    vid, pid = vid_match.group(1), vid_match.group(2)
                    try:
                        with winreg.OpenKey(usb_key, vid_pid_key) as vp_key:
                            inst_count, _, _ = winreg.QueryInfoKey(vp_key)
                            for j in range(inst_count):
                                inst_name = winreg.EnumKey(vp_key, j)
                                if serial and serial.lower() in inst_name.lower():
                                    info["vendor_id"] = vid.lower()
                                    info["product_id"] = pid.lower()
                                    break
                    except OSError:
                        pass
                if info.get("vendor_id") and info.get("product_id"):
                    break
    except Exception as exc:
        logger.debug("[query_registry_device_info] USB VID/PID query failed: %s", exc)

    return info


def query_volume_metadata(drive_letter: str) -> Dict[str, Any]:
    """Queries volume label, filesystem type, and volume serial number using GetVolumeInformationW."""
    meta = {
        "volume_label": "",
        "file_system": "",
        "volume_serial": "",
    }
    try:
        kernel32 = ctypes.windll.kernel32
        vol_buf = ctypes.create_unicode_buffer(261)
        fs_buf = ctypes.create_unicode_buffer(261)
        serial_num = ctypes.c_ulong()
        max_component_len = ctypes.c_ulong()
        flags = ctypes.c_ulong()

        root_path = f"{drive_letter.upper()}\\"
        success = kernel32.GetVolumeInformationW(
            root_path,
            vol_buf,
            261,
            ctypes.byref(serial_num),
            ctypes.byref(max_component_len),
            ctypes.byref(flags),
            fs_buf,
            261,
        )
        if success:
            meta["volume_label"] = vol_buf.value
            meta["file_system"] = fs_buf.value
            if serial_num.value:
                meta["volume_serial"] = f"{serial_num.value:08X}"
    except Exception as exc:
        logger.debug("[query_volume_metadata] GetVolumeInformationW failed for %s: %s", drive_letter, exc)
    return meta


def resolve_usb_device_info(drive_letter: str) -> Dict[str, Any]:
    """
    Orchestrates registry lookups and volume inspection to resolve complete USB device identity.
    Provides robust fallbacks so it never fails even on virtualized or generic USB devices.
    """
    letter = drive_letter.upper()
    if not letter.endswith(":"):
        letter = f"{letter}:"

    logger.debug("[resolve_usb_device_info] [RECEIVED] Resolving device info for '%s'", letter)

    reg_info = query_registry_device_info(letter)
    vol_info = query_volume_metadata(letter)

    # Resolve Serial Number
    serial = reg_info.get("serial_number") or vol_info.get("volume_serial") or "000000000000"

    # Resolve Device Name
    device_name = reg_info.get("device_name")
    if not device_name and reg_info.get("friendly_name"):
        device_name = re.sub(r"\s+USB\s+Device$", "", reg_info["friendly_name"], flags=re.IGNORECASE)
    if not device_name and vol_info.get("volume_label"):
        device_name = vol_info["volume_label"]
    if not device_name:
        device_name = "USB Flash Disk"

    # Resolve Raw Record ID
    raw_rec = reg_info.get("raw_record_id")
    if not raw_rec:
        raw_rec = f"USBSTOR\\DISK&VEN_GENERIC&PROD_USB\\{serial}"

    friendly_name = reg_info.get("friendly_name") or f"{device_name} USB Device"
    device_inst_id = f"{raw_rec}&0" if not raw_rec.endswith("&0") else raw_rec

    final_info = {
        "drive_letter": letter,
        "device_name": device_name,
        "serial_number": serial,
        "vendor_id": reg_info.get("vendor_id"),
        "product_id": reg_info.get("product_id"),
        "raw_record_id": raw_rec,
        "volume_label": vol_info.get("volume_label", ""),
        "file_system": vol_info.get("file_system", ""),
        "friendly_name": friendly_name,
        "device_instance_id": device_inst_id,
    }

    logger.debug("[resolve_usb_device_info] [PRODUCED] Resolved identity for '%s': name='%s', serial='%s'", letter, device_name, serial)
    return final_info


def build_usb_event(
    drive_letter: str,
    action: str,
    device_info: Dict[str, Any],
    host: str,
    user: Optional[str] = "SYSTEM",
) -> Dict[str, Any]:
    """
    Constructs a normalized USB telemetry event dictionary adhering strictly to docs/schema.md contract.
    """
    source = "usb"
    ts_utc = get_iso_utc_timestamp()
    raw_record_id = device_info.get("raw_record_id", f"USBSTOR\\DISK\\{drive_letter}")

    # Deterministic SHA-256 event_id = sha256("{source}|{raw_record_id}|{ts_utc}")
    seed = f"{source}|{raw_record_id}|{ts_utc}"
    event_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()

    # Format entity string: e.g. "E: (SanDisk Ultra 4C53000123456789)"
    device_name = device_info.get("device_name", "USB Drive")
    serial_number = device_info.get("serial_number", "")
    if device_name and serial_number:
        entity = f"{drive_letter} ({device_name} {serial_number})"
    elif device_name:
        entity = f"{drive_letter} ({device_name})"
    else:
        entity = f"{drive_letter} (Removable Disk)"

    # Details payload conforming to schema.md
    details: Dict[str, Any] = {
        "raw_record_id": raw_record_id,
        "drive_letter": drive_letter,
        "device_name": device_name,
        "serial_number": serial_number,
    }
    if device_info.get("vendor_id"):
        details["vendor_id"] = device_info["vendor_id"]
    if device_info.get("product_id"):
        details["product_id"] = device_info["product_id"]
    if device_info.get("volume_label"):
        details["volume_label"] = device_info["volume_label"]
    if device_info.get("file_system"):
        details["file_system"] = device_info["file_system"]

    # Raw telemetry snapshot for explainability in evidence drawer
    raw_event_type = "DBT_DEVICEARRIVAL" if action == "DEVICE_ARRIVED" else "DBT_DEVICEREMOVECOMPLETE"
    raw_payload: Dict[str, Any] = {
        "DeviceInstanceId": device_info.get("device_instance_id", f"{raw_record_id}&0"),
        "Class": "DiskDrive",
        "FriendlyName": device_info.get("friendly_name", f"{device_name} USB Device"),
        "DriveLetter": drive_letter,
        "EventType": raw_event_type,
    }

    event = {
        "event_id": event_id,
        "source": source,
        "ts_utc": ts_utc,
        "host": host,
        "user": user,
        "action": action,
        "entity_type": "device",
        "entity": entity,
        "details": details,
        "raw": raw_payload,
    }

    logger.debug("[build_usb_event] [PRODUCED] Built %s event_id='%s' for drive='%s'", action, event_id, drive_letter)
    return event


def get_removable_drives() -> List[str]:
    """
    Returns a list of uppercase drive letters (e.g. ['E:']) for all currently mounted removable volumes.
    Uses GetLogicalDrives and GetDriveTypeW.
    """
    removable: List[str] = []
    try:
        kernel32 = ctypes.windll.kernel32
        drives_mask = kernel32.GetLogicalDrives()
        for i in range(26):
            if drives_mask & (1 << i):
                letter = f"{chr(65 + i)}:"
                root_path = f"{letter}\\"
                dtype = kernel32.GetDriveTypeW(root_path)
                if dtype == DRIVE_REMOVABLE:
                    removable.append(letter)
    except Exception as exc:
        logger.error("[get_removable_drives] Error inspecting logical drives: %s", exc)
    return removable


class USBCollector(BaseCollector):
    """
    ForensiTrace USB Telemetry Collector.
    Detects USB mass-storage arrival and removal, resolves drive letters, device names,
    serial numbers, and emits normalized schema events. Notifies downstream collectors
    (such as FileSystemCollector) via drive listener callbacks.
    """

    def __init__(
        self,
        event_queue: queue.Queue[Dict[str, Any]],
        config: Optional[Any] = None,
        poll_interval_seconds: float = 1.0,
    ) -> None:
        super().__init__(event_queue, config, name="USBCollector")
        self.poll_interval_seconds = poll_interval_seconds
        self.host = getattr(config, "host", os.environ.get("COMPUTERNAME", "WIN-FORENSIC-01")) if config else "WIN-FORENSIC-01"

        # User identification
        current_user = os.environ.get("USERNAME", "SYSTEM")
        domain = os.environ.get("USERDOMAIN")
        self.user = f"{domain}\\{current_user}" if domain and current_user != "SYSTEM" else current_user

        self._known_devices: Dict[str, Dict[str, Any]] = {}
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._hwnd: Optional[int] = None
        self._class_atom: Optional[Any] = None
        self._lock = threading.Lock()

        logger.info("[%s] [RECEIVED] Initialized USBCollector on host='%s', user='%s'", self.name, self.host, self.user)

    def start(self) -> None:
        """
        Starts the USB collector background monitoring worker.
        Non-blocking: runs message pumping and drive reconciliation in a dedicated daemon thread.
        """
        with self._lock:
            if self._running:
                logger.warning("[%s] start() called but collector is already running.", self.name)
                return

            self._running = True
            self._stop_event.clear()

            # Record currently connected removable drives at startup so we don't flood on boot
            # but can accurately detect removal or newly plugged drives.
            existing_drives = get_removable_drives()
            for d in existing_drives:
                self._known_devices[d] = resolve_usb_device_info(d)

            logger.info(
                "[%s] [START] Initialized with %d existing removable drive(s): %s",
                self.name,
                len(existing_drives),
                list(self._known_devices.keys()),
            )

            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="ForensiTrace-USBCollector-Worker",
                daemon=True,
            )
            self._worker_thread.start()
            logger.info("[%s] [PRODUCED] Background monitoring thread active.", self.name)

    def stop(self) -> None:
        """
        Gracefully terminates the USB collector and releases Win32 resources.
        Idempotent and safe to call multiple times.
        """
        with self._lock:
            if not self._running:
                return

            logger.info("[%s] [STOP] Stopping USB collector...", self.name)
            self._running = False
            self._stop_event.set()

            # Signal message window to destroy if active
            if self._hwnd:
                try:
                    import win32gui
                    import win32con
                    win32gui.PostMessage(self._hwnd, win32con.WM_DESTROY, 0, 0)
                except Exception as exc:
                    logger.debug("[%s] PostMessage WM_DESTROY: %s", self.name, exc)

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=3.0)

        logger.info("[%s] [PRODUCED] USB collector stopped.", self.name)

    @property
    def is_alive(self) -> bool:
        """Returns True if the collector worker thread is currently running."""
        return self._running and (self._worker_thread is not None and self._worker_thread.is_alive())

    def _worker_loop(self) -> None:
        """
        Main worker execution thread:
        Creates a hidden message-handling window for WM_DEVICECHANGE and runs periodic drive reconciliation.
        """
        has_win32 = False
        try:
            import win32gui
            import win32con
            has_win32 = True
        except ImportError:
            logger.warning("[%s] pywin32 not present; relying solely on polling reconciler.", self.name)

        if has_win32:
            self._setup_message_window()

        while not self._stop_event.is_set():
            try:
                if has_win32 and self._hwnd:
                    win32gui.PumpWaitingMessages()

                # Reconcile drives periodically
                self.reconcile_drives()
            except Exception as exc:
                logger.error("[%s] Error in worker loop: %s", self.name, exc, exc_info=True)

            self._stop_event.wait(self.poll_interval_seconds)

        # Cleanup Win32 window resources
        if has_win32 and self._hwnd:
            try:
                win32gui.DestroyWindow(self._hwnd)
                self._hwnd = None
                if self._class_atom:
                    hinst = win32gui.GetModuleHandle(None)
                    win32gui.UnregisterClass(self._class_atom, hinst)
                    self._class_atom = None
            except Exception as exc:
                logger.debug("[%s] Win32 cleanup error: %s", self.name, exc)

    def _setup_message_window(self) -> None:
        """Registers and instantiates the hidden Win32 window for WM_DEVICECHANGE broadcast."""
        try:
            import win32gui
            import win32con

            def _wnd_proc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
                if msg == win32con.WM_DEVICECHANGE:
                    logger.debug("[%s] [RECEIVED] WM_DEVICECHANGE wparam=0x%X", self.name, wparam)
                    self._handle_wm_devicechange(wparam, lparam)
                    return 1
                elif msg == win32con.WM_DESTROY:
                    win32gui.PostQuitMessage(0)
                    return 0
                return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

            wc = win32gui.WNDCLASS()
            wc.lpfnWndProc = _wnd_proc
            wc.lpszClassName = f"ForensiTraceUSBWatcher_{os.getpid()}_{id(self)}"
            wc.hInstance = win32gui.GetModuleHandle(None)

            try:
                self._class_atom = win32gui.RegisterClass(wc)
            except Exception:
                self._class_atom = wc.lpszClassName

            self._hwnd = win32gui.CreateWindow(
                self._class_atom,
                "ForensiTraceUSBWatcherWindow",
                0, 0, 0, 0, 0,
                0, 0, wc.hInstance, None
            )
            logger.info("[%s] [PRODUCED] Registered WM_DEVICECHANGE listener (HWND=%s)", self.name, self._hwnd)
        except Exception as exc:
            logger.warning("[%s] Failed to setup Win32 message window: %s. Using polling reconciler.", self.name, exc)

    def _handle_wm_devicechange(self, wparam: int, lparam: int) -> None:
        """Processes WM_DEVICECHANGE parameters for DBT_DEVICEARRIVAL and DBT_DEVICEREMOVECOMPLETE."""
        if wparam in (DBT_DEVICEARRIVAL, DBT_DEVICEREMOVECOMPLETE):
            if lparam != 0:
                try:
                    hdr = DEV_BROADCAST_HDR.from_address(lparam)
                    if hdr.dbch_devicetype == DBT_DEVTYP_VOLUME:
                        vol = DEV_BROADCAST_VOLUME.from_address(lparam)
                        letters = get_drive_letters_from_mask(vol.dbcv_unitmask)
                        logger.info("[%s] [RECEIVED] Volume broadcast for drives: %s (wparam=0x%X)", self.name, letters, wparam)
                        for letter in letters:
                            if wparam == DBT_DEVICEARRIVAL:
                                self._on_device_arrival(letter)
                            else:
                                self._on_device_removal(letter)
                        return
                except Exception as exc:
                    logger.debug("[%s] DEV_BROADCAST_VOLUME parse error: %s", self.name, exc)

            # Fall back to reconciliation if volume struct not parsed
            self.reconcile_drives()
        elif wparam == DBT_DEVNODES_CHANGED:
            self.reconcile_drives()

    def reconcile_drives(self) -> None:
        """
        Inspects logical drives and compares mounted removable drives against known devices.
        Detects arrival of newly plugged drives and removal of disconnected drives.
        """
        current_removable = set(get_removable_drives())
        known_drives = set(self._known_devices.keys())

        # Newly attached drives
        new_arrivals = current_removable - known_drives
        for drive_letter in new_arrivals:
            self._on_device_arrival(drive_letter)

        # Removed drives
        removals = known_drives - current_removable
        for drive_letter in removals:
            self._on_device_removal(drive_letter)

    def _on_device_arrival(self, drive_letter: str, custom_info: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Handles arrival of a USB drive:
        1. Resolves device identity (name, serial, IDs).
        2. Emits normalized DEVICE_ARRIVED event to agent queue.
        3. Invokes inter-collector drive listeners (e.g. for FS Collector).
        """
        letter = drive_letter.upper()
        if not letter.endswith(":"):
            letter = f"{letter}:"

        with self._lock:
            if letter in self._known_devices and not custom_info:
                # Already processed and active
                return None

            device_info = custom_info if custom_info else resolve_usb_device_info(letter)
            self._known_devices[letter] = device_info

        logger.info(
            "[%s] [RECEIVED] USB Drive Arrived: drive='%s', name='%s', serial='%s'",
            self.name,
            letter,
            device_info.get("device_name"),
            device_info.get("serial_number"),
        )

        event = build_usb_event(
            drive_letter=letter,
            action="DEVICE_ARRIVED",
            device_info=device_info,
            host=self.host,
            user=self.user,
        )

        self.emit(event)
        logger.info("[%s] [PRODUCED] Emitted DEVICE_ARRIVED event_id='%s' for '%s'", self.name, event["event_id"], letter)

        # Inter-collector hook notification (Section 3 of docs/agent_interface.md)
        self.notify_drive_listeners(letter, "ATTACHED")
        return event

    def _on_device_removal(self, drive_letter: str) -> Optional[Dict[str, Any]]:
        """
        Handles removal of a USB drive:
        1. Emits normalized DEVICE_REMOVED event with cached identity.
        2. Invokes inter-collector drive listeners to detach file watcher.
        """
        letter = drive_letter.upper()
        if not letter.endswith(":"):
            letter = f"{letter}:"

        with self._lock:
            device_info = self._known_devices.pop(letter, None)
            if not device_info:
                device_info = {
                    "drive_letter": letter,
                    "device_name": "USB Flash Disk",
                    "serial_number": "UNKNOWN",
                    "raw_record_id": f"USBSTOR\\DISK\\{letter}",
                }

        logger.info("[%s] [RECEIVED] USB Drive Removed: drive='%s'", self.name, letter)

        event = build_usb_event(
            drive_letter=letter,
            action="DEVICE_REMOVED",
            device_info=device_info,
            host=self.host,
            user=self.user,
        )

        self.emit(event)
        logger.info("[%s] [PRODUCED] Emitted DEVICE_REMOVED event_id='%s' for '%s'", self.name, event["event_id"], letter)

        # Inter-collector hook notification
        self.notify_drive_listeners(letter, "REMOVED")
        return event

    # ------------------------------------------------------------------
    # Simulation & Verification Interface (For Automated Tests & Demos)
    # ------------------------------------------------------------------

    def simulate_arrival(self, drive_letter: str, custom_info: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Simulates a USB drive arrival event (used in tests and synthetic verification)."""
        return self._on_device_arrival(drive_letter, custom_info=custom_info)

    def simulate_removal(self, drive_letter: str) -> Optional[Dict[str, Any]]:
        """Simulates a USB drive removal event (used in tests and synthetic verification)."""
        return self._on_device_removal(drive_letter)
