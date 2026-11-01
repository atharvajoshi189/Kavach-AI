"""Evidence grounding and factual verification guard for AI responses."""

import logging
from typing import Any, Optional, Set
from pydantic import BaseModel
from app.ai.providers.base import AIValidationError

logger = logging.getLogger(__name__)


class EvidenceGuard:
    """Verifies that generative AI outputs are strictly grounded in persisted evidence."""

    @staticmethod
    def verify_evidence_references(
        response_data: dict[str, Any],
        known_valid_ids: Set[str],
        strict: bool = False,
    ) -> dict[str, Any]:
        """Validates that all cited evidence IDs exist in the provided persisted context.

        Args:
            response_data: The dictionary output from model generation.
            known_valid_ids: Set of valid UUID strings passed as evidence.
            strict: If True, raises AIValidationError when unknown IDs appear.
                    If False, filters out hallucinated IDs and adds an uncertainty.
        """
        cited_ids = response_data.get("supporting_evidence_ids", [])
        if not isinstance(cited_ids, list):
            cited_ids = []

        valid_cited_ids: list[str] = []
        hallucinated_ids: list[str] = []

        for item_id in cited_ids:
            str_id = str(item_id).strip()
            if str_id in known_valid_ids:
                valid_cited_ids.append(str_id)
            else:
                hallucinated_ids.append(str_id)

        if hallucinated_ids:
            msg = f"EvidenceGuard detected hallucinated evidence IDs: {hallucinated_ids}"
            logger.warning(msg)
            if strict:
                raise AIValidationError(msg, provider="evidence_guard")

            # Prune invalid IDs and record explicit uncertainty
            response_data["supporting_evidence_ids"] = valid_cited_ids
            uncertainties = response_data.setdefault("uncertainties", [])
            uncertainties.append(
                f"EvidenceGuard filtered {len(hallucinated_ids)} unverified evidence references not found in persisted telemetry."
            )
        else:
            response_data["supporting_evidence_ids"] = valid_cited_ids

        return response_data

    @staticmethod
    def verify_risk_score_immutability(
        response_data: dict[str, Any],
        expected_score: float,
    ) -> dict[str, Any]:
        """Guarantees that the AI did not alter or recalculate the authoritative risk score."""
        reported_score = response_data.get("authoritative_risk_score")
        if reported_score is not None:
            # Allow minor floating point tolerance
            if abs(float(reported_score) - float(expected_score)) > 0.001:
                logger.warning(
                    "AI response attempted to modify risk score from %s to %s. Restoring authoritative score.",
                    expected_score,
                    reported_score,
                )
                response_data["authoritative_risk_score"] = float(expected_score)
                uncertainties = response_data.setdefault("uncertainties", [])
                uncertainties.append(
                    "AI score adjustment rejected: Deterministic risk score restored by EvidenceGuard."
                )
        else:
            response_data["authoritative_risk_score"] = float(expected_score)

        return response_data

    @staticmethod
    def enforce_synthetic_boundary(response_data: dict[str, Any]) -> dict[str, Any]:
        """Ensures that the response is explicitly tagged as synthetic simulation."""
        response_data["is_ai_generated"] = True
        if "is_simulated" in response_data:
            response_data["is_simulated"] = True
        return response_data

