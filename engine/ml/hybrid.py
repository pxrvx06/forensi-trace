"""
engine/ml/hybrid.py - Hybrid Scoring and Threat Level Classification Integration.

Author: Akash (Correlation Engine & ML Owner)
Contract: docs/ml.md (Section 1, 5)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("forensitrace.engine.ml.hybrid")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


@dataclass
class HybridScoringResult:
    """Consolidated outcome of rule-based and ML hybrid scoring."""
    rule_id: str
    rule_confidence: float
    ml_anomaly_score: Optional[float]
    combined_score: float
    threat_level: str
    ml_available: bool
    explanation: str
    contributing_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_confidence": self.rule_confidence,
            "ml_anomaly_score": self.ml_anomaly_score,
            "combined_score": self.combined_score,
            "threat_level": self.threat_level,
            "ml_available": self.ml_available,
            "explanation": self.explanation,
            "contributing_factors": self.contributing_factors,
        }


def compute_hybrid_score(
    rule_confidence: float,
    ml_anomaly_score: Optional[float],
    rule_weight: float = 0.5,
    ml_weight: float = 0.5,
) -> Tuple[float, bool]:
    """
    CRITICAL FORENSIC FORMULA:
    Computes combined hybrid risk score R_hybrid:
    - If ML available: R_hybrid = rule_weight * rule_confidence + ml_weight * ml_anomaly_score
    - If ML unavailable (None): R_hybrid = rule_confidence (safe fallback)
    Returns:
        (combined_score, ml_available)
    """
    conf = max(0.0, min(1.0, float(rule_confidence)))

    if ml_anomaly_score is None:
        # Fallback when ML is offline or model artifacts missing
        return round(conf, 4), False

    anom = max(0.0, min(1.0, float(ml_anomaly_score)))
    combined = (rule_weight * conf) + (ml_weight * anom)
    return round(max(0.0, min(1.0, combined)), 4), True


def classify_threat_level(
    rule_id: str,
    combined_score: float,
) -> str:
    """
    Categorizes threat level strictly following docs/ml.md Section 5.2 criteria:

    | Threat Level | Primary Criteria | Typical Scenarios |
    |---|---|---|
    | CRITICAL | R_hybrid >= 0.85 OR rule R6 (timestomp) / R7 (composite USB chain) |
    | HIGH     | 0.70 <= R_hybrid < 0.85 OR rule R1 (USB file act) / R4 (burst) / R5 (log clear) |
    | MEDIUM   | 0.40 <= R_hybrid < 0.70 OR rule R2 (write+exec) / R3 (untracked exec) |
    | LOW      | R_hybrid < 0.40 AND no high-severity rule triggered |
    """
    rid = (rule_id or "").upper().strip()
    score = float(combined_score)

    # 1. CRITICAL: Score >= 0.85 OR Composite Chains / Anti-forensics (R6, R7)
    if score >= 0.85 or rid in ("R6", "R7"):
        return "CRITICAL"

    # 2. HIGH: 0.70 <= Score < 0.85 OR High-Severity Rules (R1, R4, R5)
    if score >= 0.70 or rid in ("R1", "R4", "R5"):
        return "HIGH"

    # 3. MEDIUM: 0.40 <= Score < 0.70 OR Mid-Severity Rules (R2, R3)
    if score >= 0.40 or rid in ("R2", "R3"):
        return "MEDIUM"

    # 4. LOW: Score < 0.40 and no high/medium rule
    return "LOW"


class HybridRiskEngine:
    """
    Hybrid scoring engine uniting Tier 1 (ML anomaly) and Tier 2 (Rule engine).
    Preserves rule determinism, generates combined scores, and assigns discrete threat levels.
    """

    def __init__(self, rule_weight: float = 0.5, ml_weight: float = 0.5):
        self.rule_weight = rule_weight
        self.ml_weight = ml_weight

    def evaluate(
        self,
        rule_id: str,
        rule_confidence: float,
        ml_anomaly_score: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> HybridScoringResult:
        """
        Calculates hybrid score and threat level, producing an explainable audit summary.
        """
        combined, ml_available = compute_hybrid_score(
            rule_confidence=rule_confidence,
            ml_anomaly_score=ml_anomaly_score,
            rule_weight=self.rule_weight,
            ml_weight=self.ml_weight,
        )

        threat_level = classify_threat_level(
            rule_id=rule_id,
            combined_score=combined,
        )

        factors: List[str] = [
            f"Rule confidence ({rule_id}): {rule_confidence:.2f}",
        ]

        if ml_available and ml_anomaly_score is not None:
            factors.append(f"ML sequence anomaly score: {ml_anomaly_score:.2f}")
            factors.append(
                f"Combined risk index ({self.rule_weight:.1f}*rule + {self.ml_weight:.1f}*ml): {combined:.2f}"
            )
            explanation = (
                f"Evaluated with hybrid risk index {combined:.2f} (threat level: {threat_level}). "
                f"Rule {rule_id} contributed {rule_confidence:.2f} confidence; "
                f"ML autoencoder detected sequence anomaly of {ml_anomaly_score:.2f}."
            )
        else:
            factors.append("ML anomaly detection offline; combined score equals rule confidence.")
            explanation = (
                f"Evaluated with rule-only confidence {rule_confidence:.2f} (threat level: {threat_level}). "
                f"ML analysis was unavailable for this sequence."
            )

        return HybridScoringResult(
            rule_id=rule_id,
            rule_confidence=rule_confidence,
            ml_anomaly_score=ml_anomaly_score,
            combined_score=combined,
            threat_level=threat_level,
            ml_available=ml_available,
            explanation=explanation,
            contributing_factors=factors,
        )
