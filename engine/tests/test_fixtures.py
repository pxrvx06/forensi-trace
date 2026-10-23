#!/usr/bin/env python3
"""
test_fixtures.py - Engine test integration for synthetic event fixtures.

Author: Akash (Correlation Engine & Fixtures Owner)
Task 1: Synthetic Event Generator and Fixtures
Team Contract: docs/schema.md, backend/schema.py
"""

from __future__ import annotations

import unittest
from scenarios.test_synthetic_events import TestSyntheticEventGenerator

__all__ = ["TestSyntheticEventGenerator"]

if __name__ == "__main__":
    unittest.main()
