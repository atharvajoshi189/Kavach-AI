"""Deterministic Defensive Recommendation Engine for Blue Guardian.

Maps ThreatDetection, ThreatRiskAssessment, and ThreatAssetImpact evidence into
actionable, prioritized, and evidence-backed DefensiveRecommendation records.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.agents.blue_guardian.schemas import (
    RecommendationPriority,
    RecommendationStatus,
    RecommendationType,
)
from app.models.guardian import (
    DefensiveRecommendation,
    GuardianExecution,
    ThreatAssetImpact,
    ThreatDetection,
    ThreatRiskAssessment,
)
from app.models.synthetic_asset import SyntheticAsset
from app.services.guardian.playbook_library import Playbook, PlaybookLibrary

logger = logging.getLogger("aegismesh.guardian.recommendations")


class RecommendationEngine:
    """Async engine for generating deterministic, evidence-backed defensive recommendations."""

    def __init__(
        self,
        session: AsyncSession,
        playbook_library: Optional[PlaybookLibrary] = None,
    ):
        self.session = session
        self.playbook_library = playbook_library or PlaybookLibrary()

    def calculate_priority(
        self,
        detection: ThreatDetection,
        risk_assessment: ThreatRiskAssessment,
        playbook: Playbook,
    ) -> RecommendationPriority:
        """Deterministically evaluates priority (P0, P1, P2, P3) based on risk and asset impact."""
        risk_score = float(risk_assessment.risk_score or 0.0)
        sev = (detection.severity or "").lower()
        critical_exposed = risk_assessment.critical_asset_exposed

        # P0: Immediate containment required
        if risk_score >= 8.0 or (sev == "critical" and critical_exposed):
            return RecommendationPriority.P0
        # If playbook is intrinsically P0 and severity is at least high/critical
        if playbook.default_priority == RecommendationPriority.P0 and sev in ("critical", "high"):
            return RecommendationPriority.P0

        # P1: High priority
        if risk_score >= 6.0 or sev in ("critical", "high"):
            return RecommendationPriority.P1
        if playbook.default_priority in (RecommendationPriority.P0, RecommendationPriority.P1):
            return RecommendationPriority.P1

        # P2: Medium priority
        if risk_score >= 4.0 or sev == "medium":
            return RecommendationPriority.P2

        # P3: Low / Informational
        return RecommendationPriority.P3

    async def generate_recommendations_for_execution(
        self,
        execution: GuardianExecution,
    ) -> List[DefensiveRecommendation]:
        """Generates and persists defensive recommendations for all detections in an execution.
        
        Strictly enforces:
        1. Sandbox boundary isolation
        2. Evidence-backed requirement (must have observed/derived detection evidence)
        3. Deterministic matching and priority calculation
        4. Idempotency across execution re-runs
        """
        execution_id = execution.id
        sandbox_id = execution.sandbox_id

        # 1. Fetch risk assessments with their detections and asset impacts
        ass_query = (
            select(ThreatRiskAssessment)
            .where(ThreatRiskAssessment.guardian_execution_id == execution_id)
            .where(ThreatRiskAssessment.sandbox_id == sandbox_id)
            .options(
                selectinload(ThreatRiskAssessment.threat_detection),
                selectinload(ThreatRiskAssessment.asset_impacts),
            )
            .order_by(ThreatRiskAssessment.risk_score.desc())
        )
        ass_res = await self.session.execute(ass_query)
        assessments = list(ass_res.scalars().all())

        if not assessments:
            logger.info("No threat risk assessments found for execution %s", execution_id)
            return []

        # 2. Fetch existing recommendations for idempotency
        rec_query = (
            select(DefensiveRecommendation)
            .where(DefensiveRecommendation.guardian_execution_id == execution_id)
            .where(DefensiveRecommendation.sandbox_id == sandbox_id)
        )
        rec_res = await self.session.execute(rec_query)
        existing_recs_map: Dict[tuple[UUID, str], DefensiveRecommendation] = {
            (rec.threat_detection_id, rec.playbook_id): rec
            for rec in rec_res.scalars().all()
        }

        generated_recommendations: List[DefensiveRecommendation] = []

        for ass in assessments:
            det = ass.threat_detection
            if not det:
                continue

            # Evidence-backed validation: Detection must have supporting evidence
            has_evidence = bool(
                det.evidence_references
                or det.affected_asset_ids
                or (det.mitre_techniques and len(det.mitre_techniques) > 0)
            )
            if not has_evidence:
                logger.warning(
                    "Skipping recommendation generation for detection %s due to absence of supporting evidence",
                    det.id,
                )
                continue

            # Extract MITRE technique IDs
            tech_ids: List[str] = []
            if det.mitre_techniques and isinstance(det.mitre_techniques, list):
                for tech in det.mitre_techniques:
                    if isinstance(tech, dict) and "technique_id" in tech:
                        tech_ids.append(str(tech["technique_id"]))
                    elif isinstance(tech, str):
                        tech_ids.append(tech)

            # Match playbooks
            matched_playbooks = self.playbook_library.find_playbooks_for_detection(
                classification=det.classification,
                mitre_technique_ids=tech_ids,
            )

            # Determine affected assets: direct assets from detection + directly affected impacts
            affected_asset_ids = list(det.affected_asset_ids or [])
            for imp in ass.asset_impacts:
                if imp.impact_type == "DIRECTLY_AFFECTED":
                    str_id = str(imp.asset_id)
                    if str_id not in affected_asset_ids:
                        affected_asset_ids.append(str_id)

            for playbook in matched_playbooks:
                priority = self.calculate_priority(det, ass, playbook)
                unique_key = (det.id, playbook.playbook_id)

                # Formulate evidence-backed rationale
                rationale = (
                    f"Generated for Detection '{det.title}' [{det.detection_code}] "
                    f"with Risk Score {ass.risk_score:.2f} ({ass.risk_category}). "
                    f"{playbook.rationale} Directly affects {len(affected_asset_ids)} asset(s)."
                )

                # Formulate expected outcome
                expected_outcome = (
                    f"{playbook.expected_outcome} Specifically shields identified assets: "
                    f"{', '.join(affected_asset_ids[:3]) if affected_asset_ids else 'designated cluster'}."
                )

                # Asset-specific verification criteria
                verification_criteria = list(playbook.verification_criteria)
                if affected_asset_ids:
                    verification_criteria.append(
                        f"Validate healthy operational status on asset(s): {', '.join(affected_asset_ids[:2])}"
                    )

                rec_code = f"REC-{execution_id.hex[:6].upper()}-{playbook.playbook_id.replace('BGD-PB-', 'PB')}"

                if unique_key in existing_recs_map:
                    # Update existing record
                    rec = existing_recs_map[unique_key]
                    rec.title = f"Remediate {det.title}: {playbook.title}"
                    rec.description = playbook.description
                    rec.priority = priority.value
                    rec.recommendation_type = playbook.recommendation_type.value
                    rec.playbook_version = playbook.playbook_version
                    rec.affected_asset_ids = affected_asset_ids
                    rec.evidence_references = {
                        "detection_id": str(det.id),
                        "detection_code": det.detection_code,
                        "risk_score": ass.risk_score,
                        "risk_category": ass.risk_category,
                        "severity": det.severity,
                        "mitre_techniques": tech_ids,
                        "evidence_keys": list(det.evidence_references.keys()) if isinstance(det.evidence_references, dict) else [],
                    }
                    rec.rationale = rationale
                    rec.expected_outcome = expected_outcome
                    rec.verification_criteria = verification_criteria
                    rec.implementation_complexity = playbook.complexity
                    rec.updated_at = datetime.now(timezone.utc)
                else:
                    # Create new recommendation
                    rec = DefensiveRecommendation(
                        id=uuid.uuid4(),
                        guardian_execution_id=execution_id,
                        threat_detection_id=det.id,
                        risk_assessment_id=ass.id,
                        sandbox_id=sandbox_id,
                        recommendation_code=rec_code,
                        title=f"Remediate {det.title}: {playbook.title}",
                        description=playbook.description,
                        priority=priority.value,
                        recommendation_type=playbook.recommendation_type.value,
                        playbook_id=playbook.playbook_id,
                        playbook_version=playbook.playbook_version,
                        affected_asset_ids=affected_asset_ids,
                        evidence_references={
                            "detection_id": str(det.id),
                            "detection_code": det.detection_code,
                            "risk_score": ass.risk_score,
                            "risk_category": ass.risk_category,
                            "severity": det.severity,
                            "mitre_techniques": tech_ids,
                            "evidence_keys": list(det.evidence_references.keys()) if isinstance(det.evidence_references, dict) else [],
                        },
                        rationale=rationale,
                        expected_outcome=expected_outcome,
                        verification_criteria=verification_criteria,
                        implementation_complexity=playbook.complexity,
                        status=RecommendationStatus.PROPOSED.value,
                        created_at=datetime.now(timezone.utc),
                        updated_at=datetime.now(timezone.utc),
                        is_simulated=True,
                        simulation_only=True,
                    )
                    self.session.add(rec)
                    existing_recs_map[unique_key] = rec

                generated_recommendations.append(rec)

        await self.session.flush()

        # Update guardian_execution count metric
        execution.recommendations_count = len(generated_recommendations)
        await self.session.flush()

        return generated_recommendations

