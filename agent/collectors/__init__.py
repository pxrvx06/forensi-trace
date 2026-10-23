"""ForensiTrace Telemetry Collectors Package."""

from agent.collectors.base import BaseCollector
from agent.collectors.usb_collector import USBCollector

__all__ = ["BaseCollector", "USBCollector"]
