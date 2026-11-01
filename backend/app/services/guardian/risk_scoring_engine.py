"""Deterministic Risk Scoring Engine for Blue Guardian.

Implements multi-dimensional risk quantification bounded between 0.0 and 10.0:
Risk = 10 * (0.30*Severity + 0.25*Criticality + 0.20*DirectImpact + 0.10*BlastRadius + 0.10*AttackStage + 0.05*EvidenceConfidence)

Guarantees:
- Confidence is decoupled from impact and cannot independently create Critical risk.
- Inferred exposure is never scored as confirmed compromise.
- Result is deterministic and fully explainable.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Dict, List, Optional
import uuid

from app.agents.blue_guardian.schemas import RiskCategory
from app.models.guardian import ThreatDetection
from app.models.synthetic_asset import SyntheticAsset
from app.services.guardian.asset_impact_analyzer import EvaluatedAssetImpact

logger = logging.getLogger("aegismesh.guardian.risk_scoring")

SCORING_FORMULA_VERSION = "1.0.0"

# Normalization constants
SEVERITY_WEIGHTS = {
    "low": 0.25,
    "medium": 0.50,
    "high": 0.75,
    "critical": 1.00,
}

CRITICALITY_WEIGHTS = {
    "low": 0.25,
    "medium": 0.50,
    "high": 0.75,
    "critical": 1.00,
}

STAGE_WEIGHTS = {
    "reconnaissance": 0.20,
    "discovery": 0.20,
    "initial_access": 0.40,
    "persistence": 0.60,
    "privilege_escalation": 0.75,
    "credential_access": 0.85,
    "lateral_movement": 0.85,
    "exfiltration": 1.00,
    "suspicious_configuration": 0.35,
}


@dataclass(frozen=True)
class RiskScoringResult:
    """Calculated risk metrics and dimension breakdown."""
    risk_score: float
    risk_category: RiskCategory
    severity_normalized: float
    asset_criticality_normalized: float
    direct_impact_normalized: float
    blast_radius_normalized: float
    attack_stage_normalized: float
    evidence_confidence_normalized: float
    formula_version: str
    rationale: str


class RiskScoringEngine:
    """Computes explainable, multi-dimensional security risk scores for threat detections."""

    @classmethod
    def calculate_category(cls, score: float) -> RiskCategory:
        """Maps continuous risk score to categorical risk tier."""
        if score <= 2.0:
            return RiskCategory.INFORMATIONAL
        elif score <= 4.0:
            return RiskCategory.LOW
        elif score <= 6.0:
            return RiskCategory.MEDIUM
        elif score <= 8.0:
            return RiskCategory.HIGH
        else:
            return RiskCategory.CRITICAL

    @classmethod
    def calculate_risk_score(
        cls,
        severity: str,
        confidence: float,
        impact_analysis: Dict[str, Any],
        mitre_tactics: Optional[List[str]] = None,
        total_sandbox_assets: int = 10,
    ) -> Tuple[float, RiskCategory, Dict[str, Any]]:
        """
        Calculates multi-dimensional risk score from decoupled components.
        Returns (final_score, category, rationale_dict).
        """
        # 1. Severity Dimension (0.30 weight)
        sev_key = str(severity).lower()
        w_sev = SEVERITY_WEIGHTS.get(sev_key, 0.50)

        # 2. Asset Criticality Dimension (0.25 weight)
        direct_items = impact_analysis.get("directly_affected", [])
        has_critical = impact_analysis.get("has_critical_exposure", False)
        direct_crit = any(d.get("is_critical", False) for d in direct_items)
        if direct_crit:
            w_crit = 1.00
        elif has_critical:
            w_crit = 0.75
        elif direct_items:
            w_crit = 0.50
        else:
            w_crit = 0.25

        # 3. Direct Impact Dimension (0.20 weight)
        direct_count = len(direct_items)
        if direct_count == 0:
            w_direct = 0.10
        else:
            w_direct = min(1.00, round(0.40 + (0.20 * direct_count), 2))

        # 4. Blast Radius Dimension (0.10 weight)
        exposed_count = len(impact_analysis.get("potentially_exposed", []))
        total_impacted = direct_count + exposed_count
        w_blast = min(1.00, round(total_impacted / max(1, total_sandbox_assets), 2))

        # 5. Attack Stage Dimension (0.10 weight)
        stage_weights = []
        if mitre_tactics:
            for t in mitre_tactics:
                tk = str(t).lower().replace(" ", "_").replace("-", "_")
                stage_weights.append(STAGE_WEIGHTS.get(tk, 0.50))
        w_stage = max(stage_weights) if stage_weights else 0.50

        # 6. Evidence Confidence Dimension (0.05 weight)
        # Note: 5% weight prevents high confidence from independently driving Critical risk
        w_conf = max(0.00, min(1.00, float(confidence or 0.0)))

        # Multi-dimensional calculation
        raw_score = 10.0 * (
            (0.30 * w_sev) +
            (0.25 * w_crit) +
            (0.20 * w_direct) +
            (0.10 * w_blast) +
            (0.10 * w_stage) +
            (0.05 * w_conf)
        )

        final_score = round(max(0.0, min(10.0, raw_score)), 2)
        category = cls.calculate_category(final_score)

        rationale = {
            "formula_version": SCORING_FORMULA_VERSION,
            "weights": {
                "severity": round(w_sev, 2),
                "criticality": round(w_crit, 2),
                "direct_impact": round(w_direct, 2),
                "blast_radius": round(w_blast, 2),
                "attack_stage": round(w_stage, 2),
                "confidence": round(w_conf, 2),
            },
            "raw_score": raw_score,
            "final_score": final_score,
            "category": category.value,
            "summary": (
                f"Formula v{SCORING_FORMULA_VERSION}: "
                f"10*(0.30*Sev[{w_sev:.2f}] + 0.25*Crit[{w_crit:.2f}] + 0.20*Direct[{w_direct:.2f}] + "
                f"0.10*Blast[{w_blast:.2f}] + 0.10*Stage[{w_stage:.2f}] + 0.05*Conf[{w_conf:.2f}]) = {final_score:.2f} "
                f"({category.value})."
            ),
        }

        return final_score, category, rationale

    @classmethod
    def evaluate_risk(
        cls,
        detection: ThreatDetection,
        impacted_assets: List[EvaluatedAssetImpact],
        sandbox_assets_by_id: Dict[uuid.UUID, SyntheticAsset],
        total_sandbox_assets_count: int,
    ) -> RiskScoringResult:
        """Evaluates 6 normalized dimensions and computes final deterministic risk score."""
        # 1. Severity Dimension (0.30 weight)
        sev_key = str(detection.severity).lower()
        w_sev = SEVERITY_WEIGHTS.get(sev_key, 0.50)

        # 2. Asset Criticality Dimension (0.25 weight)
        direct_asset_ids = [
            imp.asset_id for imp in impacted_assets
            if imp.impact_type.value == "DIRECTLY_AFFECTED"
        ]
        highest_crit_score = 0.20  # conservative baseline
        highest_crit_label = "none"

        for aid in direct_asset_ids:
            asset = sandbox_assets_by_id.get(aid)
            if asset:
                crit_label = getattr(asset, "risk_level", "low") or "low"
                crit_val = CRITICALITY_WEIGHTS.get(crit_label.lower(), 0.25)
                if crit_val > highest_crit_score:
                    highest_crit_score = crit_val
                    highest_crit_label = crit_label

        w_crit = highest_crit_score

        # 3. Direct Impact Dimension (0.20 weight)
        direct_count = len(direct_asset_ids)
        if direct_count == 0:
            w_direct = 0.10
        else:
            w_direct = min(1.00, round(0.40 + (0.20 * direct_count), 2))

        # 4. Blast Radius Dimension (0.10 weight)
        total_impacted = len(impacted_assets)
        total_sb = max(1, total_sandbox_assets_count)
        w_blast = min(1.00, round(total_impacted / total_sb, 2))

        # 5. Attack Stage Dimension (0.10 weight)
        cls_key = str(detection.classification).lower().replace(" ", "_")
        w_stage = STAGE_WEIGHTS.get(cls_key, 0.50)

        # 6. Evidence Confidence Dimension (0.05 weight)
        # Note: 5% weight prevents high confidence from independently driving Critical risk
        w_conf = max(0.00, min(1.00, float(detection.confidence_score)))

        # Multi-dimensional calculation
        raw_score = 10.0 * (
            (0.30 * w_sev) +
            (0.25 * w_crit) +
            (0.20 * w_direct) +
            (0.10 * w_blast) +
            (0.10 * w_stage) +
            (0.05 * w_conf)
        )

        final_score = round(max(0.0, min(10.0, raw_score)), 2)
        category = cls.calculate_category(final_score)

        rationale = (
            f"Formula v{SCORING_FORMULA_VERSION}: "
            f"10*(0.30*Sev[{w_sev:.2f}] + 0.25*Crit[{w_crit:.2f}] + 0.20*Direct[{w_direct:.2f}] + "
            f"0.10*Blast[{w_blast:.2f}] + 0.10*Stage[{w_stage:.2f}] + 0.05*Conf[{w_conf:.2f}]) = {final_score:.2f} "
            f"({category.value}). Direct assets: {direct_count}, Exposed: {total_impacted - direct_count}, "
            f"Target criticality: '{highest_crit_label}'."
        )

        return RiskScoringResult(
            risk_score=final_score,
            risk_category=category,
            severity_normalized=w_sev,
            asset_criticality_normalized=w_crit,
            direct_impact_normalized=w_direct,
            blast_radius_normalized=w_blast,
            attack_stage_normalized=w_stage,
            evidence_confidence_normalized=w_conf,
            formula_version=SCORING_FORMULA_VERSION,
            rationale=rationale,
        )
