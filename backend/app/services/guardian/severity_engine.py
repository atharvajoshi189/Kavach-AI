"""Deterministic Severity Engine for Blue Guardian Threat Detections.

Computes threat severity strictly from potential security impact and asset criticality,
guaranteeing complete independence from detection confidence scores.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import enum
import logging

logger = logging.getLogger("aegismesh.guardian.severity")


class SeverityLevel(str, enum.Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


_SEVERITY_ORDER = {
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4,
}

_ORDER_TO_SEVERITY = {v: k for k, v in _SEVERITY_ORDER.items()}


class SeverityEngine:
    """Evaluates potential operational impact to assign deterministic severity levels."""

    @classmethod
    def evaluate_severity(
        cls,
        base_severity: str,
        affected_assets: Optional[List[Dict[str, Any]]] = None,
        is_compromised: bool = False,
        multi_host_scope: bool = False,
        context_notes: Optional[List[str]] = None,
    ) -> tuple[str, str]:
        """Calculates final severity and returns (severity_level, rationale).
        
        Rules:
        1. Base severity establishes initial impact level.
        2. If any affected asset is marked 'critical', severity is escalated by 1 tier.
        3. If evidence confirms successful compromise (e.g. root privilege gained, data egressed),
           severity is escalated by 1 tier.
        4. If multi_host_scope is True (lateral movement), severity cannot be below 'High'.
        """
        # Normalize base severity
        normalized_base = base_severity.capitalize()
        try:
            current_level = SeverityLevel(normalized_base)
        except ValueError:
            current_level = SeverityLevel.MEDIUM

        current_rank = _SEVERITY_ORDER[current_level]
        escalations: List[str] = [f"Base rule severity assigned as '{current_level.value}'"]

        # Asset criticality check
        assets = affected_assets or []
        has_critical_asset = any(
            str(a.get("criticality", "")).lower() in ["critical", "high"]
            for a in assets
        )
        if has_critical_asset and current_rank < 4:
            current_rank = min(4, current_rank + 1)
            escalations.append("Elevated due to critical target infrastructure")

        # Attack stage compromise check
        if is_compromised and current_rank < 4:
            current_rank = min(4, current_rank + 1)
            escalations.append("Elevated due to confirmed stage compromise in event payload")

        # Multi-host / lateral movement floor
        if multi_host_scope and current_rank < 3:
            current_rank = 3
            escalations.append("Enforced 'High' floor for multi-host lateral traversal")

        final_level = _ORDER_TO_SEVERITY[current_rank].value
        rationale = "; ".join(escalations) + "."
        if context_notes:
            rationale += " Notes: " + "; ".join(context_notes) + "."

        return final_level, rationale

