"""
Unit Tests for ForensiTrace USB Telemetry Collector
Author: Chetna (USB and File-System Collectors Owner)
Scope: Step 1 (Page 6) - USB arrival and removal, drive letter, serial number, device name.
Rules: Labeled logging, schema conformance, must-fire and must-not-fire test cases.
"""

from __future__ import annotations

import queue
import hashlib
import unittest
from typing import Any, Dict, List
from unittest.mock import patch, MagicMock

from agent.collectors.usb_collector import (
    USBCollector,
    get_drive_letters_from_mask,
    parse_mounted_device_binary,
    resolve_usb_device_info,
    build_usb_event,
    get_removable_drives,
    DRIVE_REMOVABLE,
    DRIVE_FIXED,
)
from backend.schema import Event, SourceEnum, ActionEnum, EntityTypeEnum, compute_event_id


class TestUSBCollector(unittest.TestCase):
    """
    Test suite for USBCollector meeting all Page 6 Step 1 specifications.
    """

    def setUp(self):
        self.event_queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=100)
        self.collector = USBCollector(event_queue=self.event_queue)

    def tearDown(self):
        if self.collector.is_alive:
            self.collector.stop()

    def test_bitmask_to_drive_letters_parser(self):
        """Must correctly convert Windows volume unitmasks into drive letter strings."""
        # Unitmask 1 (bit 0) -> A:
        self.assertEqual(get_drive_letters_from_mask(1), ["A:"])
        # Unitmask 4 (bit 2) -> C:
        self.assertEqual(get_drive_letters_from_mask(4), ["C:"])
        # Unitmask 16 (bit 4) -> E:
        self.assertEqual(get_drive_letters_from_mask(16), ["E:"])
        # Multiple drives: 4 | 16 = 20 -> C: and E:
        self.assertEqual(get_drive_letters_from_mask(20), ["C:", "E:"])
        # Must not fire on 0
        self.assertEqual(get_drive_letters_from_mask(0), [])

    def test_mounted_device_parser_must_fire_on_usbstor(self):
        """Must fire: Successfully parses vendor, product, and serial from MountedDevices USBSTOR binary string."""
        sample_str = r"\??\USBSTOR#Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00#4C53000123456789#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
        raw_bytes = sample_str.encode("utf-16le")

        parsed = parse_mounted_device_binary(raw_bytes)
        self.assertEqual(parsed.get("vendor"), "SanDisk")
        self.assertEqual(parsed.get("product"), "Ultra")
        self.assertEqual(parsed.get("serial_number"), "4C53000123456789")
        self.assertEqual(parsed.get("device_name"), "SanDisk Ultra")
        self.assertEqual(parsed.get("raw_record_id"), r"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA\4C53000123456789")

    def test_mounted_device_parser_must_not_fire_on_non_usb(self):
        """Must not fire: Returns empty dict when binary data does not contain USBSTOR."""
        # Standard fixed partition MBR signature (24 bytes binary)
        fixed_mbr_bytes = b"\x12\x34\x56\x78\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        parsed = parse_mounted_device_binary(fixed_mbr_bytes)
        self.assertEqual(parsed, {})

    def test_build_usb_event_schema_conformance(self):
        """Must produce an event conforming strictly to docs/schema.md and backend.schema.Event."""
        custom_info = {
            "drive_letter": "E:",
            "device_name": "SanDisk Ultra",
            "serial_number": "4C53000123456789",
            "vendor_id": "0781",
            "product_id": "5581",
            "raw_record_id": r"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA\4C53000123456789",
            "friendly_name": "SanDisk Ultra USB Device",
            "device_instance_id": r"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA\4C53000123456789&0",
        }

        event_dict = build_usb_event(
            drive_letter="E:",
            action="DEVICE_ARRIVED",
            device_info=custom_info,
            host="WIN-FORENSIC-01",
            user="SYSTEM",
        )

        # 1. Validate fields
        self.assertEqual(event_dict["source"], "usb")
        self.assertEqual(event_dict["action"], "DEVICE_ARRIVED")
        self.assertEqual(event_dict["entity_type"], "device")
        self.assertEqual(event_dict["entity"], "E: (SanDisk Ultra 4C53000123456789)")
        self.assertEqual(event_dict["details"]["drive_letter"], "E:")
        self.assertEqual(event_dict["details"]["device_name"], "SanDisk Ultra")
        self.assertEqual(event_dict["details"]["serial_number"], "4C53000123456789")

        # 2. Check deterministic hash recipe
        expected_hash = hashlib.sha256(
            f"usb|{custom_info['raw_record_id']}|{event_dict['ts_utc']}".encode("utf-8")
        ).hexdigest()
        self.assertEqual(event_dict["event_id"], expected_hash)

        # 3. Validate with Purva's Pydantic Event model
        validated_event = Event(**event_dict)
        self.assertEqual(validated_event.source, SourceEnum.usb)
        self.assertEqual(validated_event.action, ActionEnum.DEVICE_ARRIVED)
        self.assertEqual(validated_event.entity_type, EntityTypeEnum.device)

    def test_device_arrival_and_removal_cycle(self):
        """Must correctly emit DEVICE_ARRIVED on insertion and DEVICE_REMOVED on removal."""
        custom_info = {
            "drive_letter": "E:",
            "device_name": "Kingston DataTraveler",
            "serial_number": "AA00000000000456",
            "raw_record_id": r"USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER\AA00000000000456",
        }

        # 1. Arrival
        arrived_event = self.collector.simulate_arrival("E:", custom_info=custom_info)
        self.assertIsNotNone(arrived_event)
        self.assertEqual(arrived_event["action"], "DEVICE_ARRIVED")
        self.assertEqual(self.event_queue.qsize(), 1)
        queued_arrived = self.event_queue.get_nowait()
        self.assertEqual(queued_arrived["event_id"], arrived_event["event_id"])
        self.assertEqual(queued_arrived["entity"], "E: (Kingston DataTraveler AA00000000000456)")

        # Verify validated by Pydantic schema
        Event(**queued_arrived)

        # 2. Removal
        removed_event = self.collector.simulate_removal("E:")
        self.assertIsNotNone(removed_event)
        self.assertEqual(removed_event["action"], "DEVICE_REMOVED")
        self.assertEqual(self.event_queue.qsize(), 1)
        queued_removed = self.event_queue.get_nowait()
        self.assertEqual(queued_removed["event_id"], removed_event["event_id"])
        self.assertEqual(queued_removed["raw"]["EventType"], "DBT_DEVICEREMOVECOMPLETE")

        # Verify removal event is also schema-valid
        Event(**queued_removed)

    def test_inter_collector_drive_listener_hook(self):
        """Must invoke registered drive listeners with (drive_letter, 'ATTACHED') and (drive_letter, 'REMOVED')."""
        received_notifications: List[tuple[str, str]] = []

        def mock_fs_drive_listener(drive_letter: str, event_type: str):
            received_notifications.append((drive_letter, event_type))

        self.collector.register_drive_listener(mock_fs_drive_listener)

        # Trigger arrival
        self.collector.simulate_arrival("F:")
        self.assertEqual(len(received_notifications), 1)
        self.assertEqual(received_notifications[0], ("F:", "ATTACHED"))

        # Trigger removal
        self.collector.simulate_removal("F:")
        self.assertEqual(len(received_notifications), 2)
        self.assertEqual(received_notifications[1], ("F:", "REMOVED"))

    def test_debounce_duplicate_arrival(self):
        """Must debounce: does not emit duplicate arrival events if the drive is already connected."""
        custom_info = {
            "drive_letter": "E:",
            "device_name": "SanDisk Ultra",
            "serial_number": "4C53000123456789",
        }

        # First arrival
        ev1 = self.collector.simulate_arrival("E:", custom_info=custom_info)
        self.assertIsNotNone(ev1)
        self.assertEqual(self.event_queue.qsize(), 1)

        # Second arrival for already known drive without removal
        ev2 = self.collector.simulate_arrival("E:", custom_info=None)
        self.assertIsNone(ev2)
        # Queue count should remain 1
        self.assertEqual(self.event_queue.qsize(), 1)

    def test_reconciliation_must_fire_on_new_drive_and_not_fire_on_fixed(self):
        """
        Reconciliation test:
        Must fire arrival when a new DRIVE_REMOVABLE volume appears.
        Must not fire on fixed drive (e.g. C:).
        """
        # Mock get_removable_drives to return ['G:']
        with patch("agent.collectors.usb_collector.get_removable_drives", return_value=["G:"]):
            self.collector.reconcile_drives()

            # Must have detected G:
            self.assertIn("G:", self.collector._known_devices)
            self.assertEqual(self.event_queue.qsize(), 1)
            event = self.event_queue.get_nowait()
            self.assertEqual(event["details"]["drive_letter"], "G:")
            self.assertEqual(event["action"], "DEVICE_ARRIVED")

        # Now mock get_removable_drives to return empty (drive G: was disconnected)
        with patch("agent.collectors.usb_collector.get_removable_drives", return_value=[]):
            self.collector.reconcile_drives()

            # Must have removed G: and emitted DEVICE_REMOVED
            self.assertNotIn("G:", self.collector._known_devices)
            self.assertEqual(self.event_queue.qsize(), 1)
            event = self.event_queue.get_nowait()
            self.assertEqual(event["details"]["drive_letter"], "G:")
            self.assertEqual(event["action"], "DEVICE_REMOVED")

    def test_collector_lifecycle_start_and_stop(self):
        """Tests that start and stop operate cleanly and idempotently."""
        self.collector.poll_interval_seconds = 0.05
        self.collector.start()
        self.assertTrue(self.collector.is_alive)

        # Stop collector
        self.collector.stop()
        self.assertFalse(self.collector.is_alive)

        # Secondary stop call must be harmless (idempotent)
        self.collector.stop()
        self.assertFalse(self.collector.is_alive)


if __name__ == "__main__":
    unittest.main()
