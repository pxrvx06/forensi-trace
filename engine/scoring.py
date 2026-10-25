"""
engine/scoring.py - Deterministic, Explainable Confidence Scoring for ForensiTrace.

Author: Akash (Correlation Engine & Rules Owner)
Contract: docs/schema.md, docs/rules.yaml, backend/schema.py
Scope: Task 3 - Confidence Scoring Architecture

Forensic Principle:
Confidence represents the degree of evidence completeness, signal fidelity, and
telemetry agreement supporting an activity reconstruction. It is explicitly
DISTINGUISHED from statistical certainty or legal proof of malicious intent.
All scores are deterministic, bounded strictly between 0.0 and 1.0, and explainable
via concrete observed factors.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("forensitrace.engine.scoring")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# Base confidence scores per rule baseline
BASE_CONFIDENCE_BY_RULE: Dict[str, float] = {
    "R1": 0.90,  # Device arrival followed by file activity (strong causal link)
    "R2": 0.90,  # File creation followed by process execution (strong path match)
    "R3": 0.80,  # Process without preceding write (negative-evidence signal)
    "R4": 0.85,  # Bulk file creation burst (statistical threshold)
    "R5": 0.85,  # Log clearing near activity (dual-evidence proximity)
    "R6": 0.85,  # Timestamp disagreement / timestomping (direct telemetry conflict)
    "R7": 0.95,  # Full 3-stage composite chain (USB -> Write -> Exec)
}


def compute_confidence(
    rule_id: str,
    events: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
) -> Tuple[float, List[str]]:
    """
    Computes a deterministic, explainable confidence score in [0.0, 1.0].
    
    Returns:
        (confidence_score, list_of_contributing_factors)
    """
    ctx = context or {}
    factors: List[str] = []
    
    # 1. Start with base confidence
    base = BASE_CONFIDENCE_BY_RULE.get(rule_id, 0.75)
    score = base
    factors.append(f"Base confidence for rule {rule_id}: {base:.2f}")

    # 2. Factor: User attribution presence
    users = [e.get("user") for e in events if e.get("user") not in (None, "", "-", "SYSTEM")]
    if users:
        score += 0.03
        factors.append(f"User identity confirmed ({users[0]}): +0.03")

    # 3. Factor: Hardware evidence specificity (e.g. USB serial / vendor ID)
    has_hardware_serial = any(
        e.get("details", {}).get("serial_number") or e.get("details", {}).get("vendor_id")
        for e in events
    )
    if has_hardware_serial:
        score += 0.02
        factors.append("Hardware device serial number verified: +0.02")

    # 4. Factor: Rule-specific evidentiary adjustments
    if rule_id == "R7":
        # All 3 stages present and matched
        stages_count = len({e.get("source") for e in events})
        if stages_count >= 3:
            score += 0.03
            factors.append("Tri-source corroboration (usb, fs, eventlog): +0.03")
        
        # Temporal tightness (< 300s of 900s allowed)
        elapsed_sec = ctx.get("elapsed_seconds")
        if elapsed_sec is not None and elapsed_sec <= 300.0:
            score += 0.02
            factors.append(f"Rapid sequence execution ({int(elapsed_sec)}s <= 300s): +0.02")

    elif rule_id == "R4":
        # Scale with burst volume
        file_count = ctx.get("file_count", len(events))
        if file_count >= 20:
            score += 0.10
            factors.append(f"High-volume file burst ({file_count} files >= 20): +0.10")
        elif file_count >= 10:
            score += 0.05
            factors.append(f"Elevated file burst ({file_count} files >= 10): +0.05")

    elif rule_id == "R5":
        # Proximity of log clearing to activity
        delta_sec = ctx.get("delta_seconds")
        if delta_sec is not None and abs(delta_sec) <= 60.0:
            score += 0.05
            factors.append(f"Immediate proximity to activity ({int(abs(delta_sec))}s <= 60s): +0.05")

    elif rule_id == "R6":
        # Magnitude of discrepancy (e.g. hours or days vs minutes)
        diff_sec = ctx.get("discrepancy_seconds")
        if diff_sec is not None:
            if abs(diff_sec) >= 3600.0:
                score += 0.10
                factors.append(f"Severe timestamp discrepancy ({int(abs(diff_sec))}s >= 1 hour): +0.10")
            elif abs(diff_sec) >= 600.0:
                score += 0.05
                factors.append(f"Substantial timestamp discrepancy ({int(abs(diff_sec))}s >= 10 min): +0.05")

    # 5. Penalties for missing fields
    if any(not e.get("entity") for e in events):
        score -= 0.10
        factors.append("Entity identifier missing on one or more events: -0.10")

    # 6. Strict clamp to [0.0, 1.0] and round to 2 decimal places
    final_score = round(max(0.0, min(1.0, score)), 2)
    logger.debug("[compute_confidence] Rule %s -> score=%.2f, factors=%s", rule_id, final_score, factors)
    return final_score, factors
