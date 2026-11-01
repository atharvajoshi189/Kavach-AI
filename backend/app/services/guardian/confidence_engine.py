"""Deterministic Confidence Engine for Blue Guardian Threat Detections.

Computes a bounded evidence-quality score (0.0 to 1.0) reflecting observational fidelity,
event volume, payload completeness, and correlation reliability.
Strictly decoupled from threat severity.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger("aegismesh.guardian.confidence")


class ConfidenceEngine:
    """Evaluates supporting forensic evidence strength to calculate confidence score."""

    @classmethod
    def evaluate_confidence(
        cls,
        base_confidence: float,
        event_count: int,
        min_required_events: int,
        correlation_confidence: float = 1.0,
        correlation_basis: str = "DIRECT",
        has_rich_payload: bool = False,
        asset_resolution_verified: bool = False,
    ) -> tuple[float, str]:
        """Calculates bounded confidence score and returns (score, rationale).
        
        Scoring logic:
        1. Starts at base_confidence (e.g. 0.70).
        2. Corroborating event volume: +0.05 per event beyond min_required_events (max +0.15).
        3. Correlation confidence multiplier: weights the score by cluster tightness.
        4. Rich payload evidence (IOCs, endpoints, commands present): +0.05.
        5. Asset resolution verified in sandbox topology: +0.05.
        6. Clamped to [0.10, 1.00], rounded to 2 decimal places.
        """
        score = base_confidence
        factors: List[str] = [f"Base rule confidence: {base_confidence:.2f}"]

        # 1. Corroborating volume
        extra_events = max(0, event_count - min_required_events)
        if extra_events > 0:
            volume_bonus = min(0.15, extra_events * 0.05)
            score += volume_bonus
            factors.append(f"+{volume_bonus:.2f} for {extra_events} corroborating event(s)")

        # 2. Rich payload indicators
        if has_rich_payload:
            score += 0.05
            factors.append("+0.05 for rich forensic payload indicators")

        # 3. Asset topological verification
        if asset_resolution_verified:
            score += 0.05
            factors.append("+0.05 for verified sandbox asset topology")

        # 4. Correlation basis adjustment
        if correlation_basis.upper() == "DIRECT":
            score += 0.05
            factors.append("+0.05 for direct deterministic campaign/run lineage")
        elif correlation_basis.upper() == "TEMPORAL":
            # Slightly lower certainty on pure temporal windowing
            score -= 0.05
            factors.append("-0.05 for sliding temporal correlation window")

        # 5. Apply correlation cluster confidence scale
        clamped_cluster_conf = max(0.5, min(1.0, correlation_confidence))
        score = score * clamped_cluster_conf
        if clamped_cluster_conf < 1.0:
            factors.append(f"Scaled by correlation confidence factor ({clamped_cluster_conf:.2f})")

        # Final bounding and rounding
        final_score = round(max(0.10, min(1.00, score)), 2)
        rationale = "; ".join(factors) + f" => Final Confidence: {final_score:.2f}."

        return final_score, rationale

