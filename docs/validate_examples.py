#!/usr/bin/env python3
"""
ForensiTrace Schema Validator for Example Events
Author: Purva
Validates JSON event files in docs/examples/ against docs/schema.md contract.
"""

import sys
import json
import re
import hashlib
from pathlib import Path

# Contract rules from docs/schema.md
REQUIRED_FIELDS = {
    "event_id",
    "source",
    "ts_utc",
    "host",
    "action",
    "entity_type",
    "entity",
    "details",
    "raw"
}

ALLOWED_SOURCES = {"usb", "fs", "eventlog"}

ALLOWED_ACTIONS = {
    "usb": {"DEVICE_ARRIVED", "DEVICE_REMOVED"},
    "fs": {"FILE_CREATED", "FILE_MODIFIED", "FILE_DELETED", "FILE_MOVED"},
    "eventlog": {"PROCESS_STARTED", "LOG_CLEARED", "LOGON"}
}

ALLOWED_ENTITY_TYPES = {"device", "file", "process"}

TIMESTAMP_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
HEX64_REGEX = re.compile(r"^[0-9a-f]{64}$")
DRIVE_LETTER_REGEX = re.compile(r"^[A-Z]:")


def validate_event(filepath: Path) -> tuple[bool, list[str]]:
    """Validate a single JSON event file against schema rules. Returns (is_valid, errors)."""
    errors = []
    
    # 1. Parse JSON
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return False, [f"JSON Parse Error: {e}"]

    # 2. Check required fields
    missing_fields = REQUIRED_FIELDS - set(data.keys())
    if missing_fields:
        errors.append(f"Missing required fields: {sorted(missing_fields)}")

    # 3. Validate source
    source = data.get("source")
    if source not in ALLOWED_SOURCES:
        errors.append(f"Invalid source '{source}'; allowed: {sorted(ALLOWED_SOURCES)}")

    # 4. Validate action for source
    action = data.get("action")
    if source in ALLOWED_ACTIONS:
        allowed = ALLOWED_ACTIONS[source]
        if action not in allowed:
            errors.append(f"Action '{action}' is not allowed for source '{source}'; allowed: {sorted(allowed)}")

    # 5. Validate entity_type
    entity_type = data.get("entity_type")
    if entity_type not in ALLOWED_ENTITY_TYPES:
        errors.append(f"Invalid entity_type '{entity_type}'; allowed: {sorted(ALLOWED_ENTITY_TYPES)}")

    # 6. Validate timestamp format (UTC ISO 8601 with milliseconds and trailing Z)
    ts_utc = data.get("ts_utc")
    if not isinstance(ts_utc, str) or not TIMESTAMP_REGEX.match(ts_utc):
        errors.append(f"Invalid ts_utc format '{ts_utc}'; expected YYYY-MM-DDTHH:MM:SS.mmmZ")

    # 7. Validate entity and path formatting (uppercase drive letters, backslashes)
    entity = data.get("entity")
    if not isinstance(entity, str) or not entity.strip():
        errors.append("Field 'entity' must be a non-empty string")
    else:
        # Check if entity contains Windows path with forward slash
        if "/" in entity and ("\\" in entity or ":" in entity):
            errors.append(f"Entity path '{entity}' must use Windows backslashes '\\', not forward slashes")
        # Check uppercase drive letter if present at start of path
        if len(entity) >= 2 and entity[1] == ":" and not entity[0].isupper():
            errors.append(f"Drive letter in entity '{entity}' must be uppercase")

    # 8. Validate details
    details = data.get("details")
    if not isinstance(details, dict):
        errors.append("Field 'details' must be a JSON object (dict)")
    else:
        raw_record_id = details.get("raw_record_id")
        if not raw_record_id:
            errors.append("details.raw_record_id is required for event_id recipe verification")
        else:
            # Check event_id computation recipe
            if source and ts_utc:
                expected_hash_input = f"{source}|{raw_record_id}|{ts_utc}"
                computed_hash = hashlib.sha256(expected_hash_input.encode("utf-8")).hexdigest()
                event_id = data.get("event_id")
                if event_id != computed_hash:
                    errors.append(
                        f"event_id mismatch! Expected sha256('{expected_hash_input}') = {computed_hash}, got {event_id}"
                    )

    # 9. Validate event_id format
    event_id = data.get("event_id")
    if not isinstance(event_id, str) or not HEX64_REGEX.match(event_id):
        errors.append(f"Invalid event_id '{event_id}'; must be a 64-character lowercase SHA-256 hex string")

    # 10. Validate raw field presence
    raw = data.get("raw")
    if raw is None:
        errors.append("Field 'raw' cannot be null; must contain untouched original record")

    return (len(errors) == 0), errors


def main():
    print("[ForensiTrace] Starting Schema Validation on Example Files...")
    base_dir = Path(__file__).resolve().parent
    examples_dir = base_dir / "examples"

    example_files = [
        examples_dir / "usb_event.json",
        examples_dir / "fs_event.json",
        examples_dir / "eventlog_event.json"
    ]

    all_passed = True

    for file_path in example_files:
        print(f"\n[RECEIVED] Validating: {file_path.name} ({file_path})")
        if not file_path.exists():
            print(f"[PRODUCED] [FAIL] File does not exist: {file_path}")
            all_passed = False
            continue

        is_valid, errors = validate_event(file_path)
        if is_valid:
            print(f"[PRODUCED] [PASS] {file_path.name} conforms to docs/schema.md contract")
        else:
            print(f"[PRODUCED] [FAIL] {file_path.name} failed validation:")
            for err in errors:
                print(f"  - ERROR: {err}")
            all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("[SUMMARY] ALL EXAMPLE FILES PASSED VALIDATION.")
        print("=" * 60)
        sys.exit(0)
    else:
        print("[SUMMARY] VALIDATION FAILED FOR ONE OR MORE FILES.")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    main()
