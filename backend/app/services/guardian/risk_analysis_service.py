"""
AEGIS Vulnerability & Risk Management Subsystem
Step 09.2.3.4 - Risk Analysis Service

Coordinates asset impact analysis, blast radius traversal, multi-dimensional risk scoring,
and risk prioritization for Blue Guardian threat detections.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.agents.blue_guardian.schemas import (
    AssetImpactType,
    RiskCategory,
)
from app.models.guardian import (
    GuardianExecution,
    ThreatAssetImpact,
    ThreatDetection,
    ThreatRiskAssessment,
)
from app.models.synthetic_asset import SyntheticAsset
from app.services.guardian.asset_impact_analyzer import AssetImpactAnalyzer
from app.services.guardian.blast_radius_analyzer import BlastRadiusAnalyzer
from app.services.guardian.risk_prioritization import RiskPrioritizer
from app.services.guardian.risk_scoring_engine import RiskScoringEngine

logger = logging.getLogger("aegismesh.guardian.risk_analysis")


class RiskAnalysisService:
    """
    Async service responsible for orchestrating risk assessments across detections within an execution.
    Enforces strict sandbox boundary isolation, idempotency, and deterministic risk scoring.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def run_risk_analysis_for_execution(
        self,
        execution: GuardianExecution,
        detections: Optional[List[ThreatDetection]] = None,
    ) -> List[ThreatRiskAssessment]:
        """
        Runs asset impact analysis, blast radius calculation, and risk scoring
        for all ThreatDetection records associated with the given execution.
        """
        sandbox_id = execution.sandbox_id
        execution_id = execution.id

        # 1. Strict sandbox isolation: query only assets registered to this sandbox
        asset_query = select(SyntheticAsset).where(SyntheticAsset.sandbox_id == sandbox_id)
        asset_res = await self.session.execute(asset_query)
        assets = list(asset_res.scalars().all())

        sandbox_assets_by_id: Dict[UUID, SyntheticAsset] = {asset.id: asset for asset in assets}
        adjacency_map: Dict[UUID, Set[UUID]] = {}

        for asset in assets:
            connected = set()
            if asset.connected_asset_ids and isinstance(asset.connected_asset_ids, list):
                for cid in asset.connected_asset_ids:
                    try:
                        connected.add(UUID(str(cid)))
                    except (ValueError, TypeError):
                        pass

            adjacency_map[asset.id] = connected

        impact_analyzer = AssetImpactAnalyzer()

        # 2. Query threat detections if not provided
        if detections is None:
            det_query = (
                select(ThreatDetection)
                .where(ThreatDetection.guardian_execution_id == execution_id)
                .order_by(ThreatDetection.created_at, ThreatDetection.id)
            )
            det_res = await self.session.execute(det_query)
            detections = list(det_res.scalars().all())

        # 3. Retrieve existing assessments to guarantee idempotency on retry
        existing_ass_query = (
            select(ThreatRiskAssessment)
            .where(ThreatRiskAssessment.guardian_execution_id == execution_id)
            .options(selectinload(ThreatRiskAssessment.asset_impacts))
        )
        existing_ass_res = await self.session.execute(existing_ass_query)
        existing_assessments_map = {
            ass.threat_detection_id: ass for ass in existing_ass_res.scalars().all()
        }

        created_assessments: List[ThreatRiskAssessment] = []

        for detection in detections:
            # Run deterministic impact analysis (Direct + Potentially Exposed via blast radius)
            impacts = impact_analyzer.analyze_impact(
                detection=detection,
                sandbox_assets_by_id=sandbox_assets_by_id,
                adjacency_map=adjacency_map,
            )

            # Calculate deterministic risk score
            scoring_result = RiskScoringEngine.evaluate_risk(
                detection=detection,
                impacted_assets=impacts,
                sandbox_assets_by_id=sandbox_assets_by_id,
                total_sandbox_assets_count=len(assets),
            )

            existing = existing_assessments_map.get(detection.id)
            cat_str = scoring_result.risk_category.value

            if existing:
                # Remove child impacts for this assessment cleanly before re-adding
                for old_imp in list(existing.asset_impacts):
                    await self.session.delete(old_imp)
                await self.session.flush()
                assessment = existing
                assessment.risk_score = scoring_result.risk_score
                assessment.risk_category = cat_str
                assessment.severity = detection.severity
                assessment.asset_criticality_score = scoring_result.asset_criticality_normalized
                assessment.direct_impact_score = scoring_result.direct_impact_normalized
                assessment.blast_radius_score = scoring_result.blast_radius_normalized
                assessment.attack_stage_score = scoring_result.attack_stage_normalized
                assessment.evidence_confidence_score = scoring_result.evidence_confidence_normalized
                assessment.scoring_formula_version = scoring_result.formula_version
                assessment.assessment_rationale = scoring_result.rationale
                assessment.assessment_status = "completed"
                assessment.assessed_at = datetime.now(timezone.utc)
            else:
                assessment = ThreatRiskAssessment(
                    id=uuid.uuid4(),
                    guardian_execution_id=execution_id,
                    threat_detection_id=detection.id,
                    sandbox_id=sandbox_id,
                    risk_score=scoring_result.risk_score,
                    risk_category=cat_str,
                    severity=detection.severity,
                    asset_criticality_score=scoring_result.asset_criticality_normalized,
                    direct_impact_score=scoring_result.direct_impact_normalized,
                    blast_radius_score=scoring_result.blast_radius_normalized,
                    attack_stage_score=scoring_result.attack_stage_normalized,
                    evidence_confidence_score=scoring_result.evidence_confidence_normalized,
                    scoring_formula_version=scoring_result.formula_version,
                    assessment_rationale=scoring_result.rationale,
                    assessment_status="completed",
                    assessed_at=datetime.now(timezone.utc),
                    is_simulated=True,
                    simulation_only=True,
                )
                self.session.add(assessment)
                await self.session.flush()

            assessment._directly_affected_count = len(
                [i for i in impacts if i.impact_type.value == "DIRECTLY_AFFECTED"]
            )
            assessment._blast_radius_size = len(
                [i for i in impacts if i.impact_type.value == "POTENTIALLY_EXPOSED"]
            )
            assessment._critical_asset_exposed = any(
                (getattr(sandbox_assets_by_id.get(i.asset_id), "risk_level", None) or "").lower() == "critical"
                for i in impacts
            )

            # Create ThreatAssetImpact records for each categorized asset
            for imp in impacts:
                target_asset = sandbox_assets_by_id.get(imp.asset_id)
                impact_record = ThreatAssetImpact(
                    id=uuid.uuid4(),
                    risk_assessment_id=assessment.id,
                    asset_id=imp.asset_id,
                    sandbox_id=sandbox_id,
                    impact_type=imp.impact_type.value,
                    impact_score=imp.impact_score,
                    traversal_depth=imp.traversal_depth,
                    relationship_path=list(imp.relationship_path or []),
                    impact_rationale=imp.impact_rationale,
                    evidence_references=dict(imp.evidence_references or {}),
                )
                impact_record._asset_name_cached = target_asset.name if target_asset else "Unknown"
                impact_record._asset_type_cached = target_asset.asset_type if target_asset else "Unknown"
                impact_record._is_critical_cached = (
                    getattr(target_asset, "risk_level", None) or ""
                ).lower() == "critical" if target_asset else False
                self.session.add(impact_record)

            created_assessments.append(assessment)

        await self.session.flush()

        # Update execution summary metrics
        total_assessments = len(created_assessments)
        max_score = 0.0
        if created_assessments:
            max_score = max(float(a.risk_score or 0.0) for a in created_assessments)

        execution.risk_assessments_count = total_assessments
        execution.max_risk_score = round(max_score, 2)
        await self.session.flush()

        # Re-fetch assessments with full relationships loaded
        ass_ids = [a.id for a in created_assessments]
        if ass_ids:
            full_query = (
                select(ThreatRiskAssessment)
                .where(ThreatRiskAssessment.id.in_(ass_ids))
                .options(
                    selectinload(ThreatRiskAssessment.asset_impacts).selectinload(ThreatAssetImpact.asset),
                    selectinload(ThreatRiskAssessment.threat_detection),
                )
                .order_by(desc(ThreatRiskAssessment.risk_score))
            )
            full_res = await self.session.execute(full_query)
            return list(full_res.scalars().all())

        return []

    async def get_assessments_for_execution(
        self,
        execution_id: UUID,
        skip: int = 0,
        limit: int = 50,
        risk_category: Optional[str] = None,
        min_score: Optional[float] = None,
    ) -> Tuple[List[ThreatRiskAssessment], int]:
        """
        Retrieves paginated risk assessments for an execution with optional filtering.
        """
        base_query = select(ThreatRiskAssessment).where(
            ThreatRiskAssessment.guardian_execution_id == execution_id
        )

        if risk_category:
            base_query = base_query.where(ThreatRiskAssessment.risk_category == risk_category)

        if min_score is not None:
            base_query = base_query.where(ThreatRiskAssessment.risk_score >= min_score)

        count_query = select(func.count()).select_from(base_query.subquery())
        count_res = await self.session.execute(count_query)
        total = count_res.scalar_one()

        paged_query = (
            base_query.options(
                selectinload(ThreatRiskAssessment.asset_impacts).selectinload(ThreatAssetImpact.asset),
                selectinload(ThreatRiskAssessment.threat_detection),
            )
            .order_by(desc(ThreatRiskAssessment.risk_score), desc(ThreatRiskAssessment.created_at))
            .offset(skip)
            .limit(limit)
        )
        paged_res = await self.session.execute(paged_query)
        records = list(paged_res.scalars().all())

        return records, total

    async def get_assessment_by_id(self, assessment_id: UUID) -> Optional[ThreatRiskAssessment]:
        """Retrieves a single ThreatRiskAssessment by ID with impacts and detection."""
        query = (
            select(ThreatRiskAssessment)
            .where(ThreatRiskAssessment.id == assessment_id)
            .options(
                selectinload(ThreatRiskAssessment.asset_impacts).selectinload(ThreatAssetImpact.asset),
                selectinload(ThreatRiskAssessment.threat_detection),
            )
        )
        res = await self.session.execute(query)
        return res.scalar_one_or_none()

    async def get_risk_summary(self, sandbox_id: Optional[UUID] = None) -> Dict[str, Any]:
        """
        Aggregates global or sandbox-scoped risk assessment metrics across all executions.
        """
        query = (
            select(ThreatRiskAssessment)
            .join(GuardianExecution, ThreatRiskAssessment.guardian_execution_id == GuardianExecution.id)
            .options(
                selectinload(ThreatRiskAssessment.threat_detection),
                selectinload(ThreatRiskAssessment.asset_impacts),
            )
        )

        if sandbox_id:
            query = query.where(GuardianExecution.sandbox_id == sandbox_id)

        res = await self.session.execute(query)
        assessments = list(res.scalars().all())

        total = len(assessments)
        by_category = {cat.value: 0 for cat in RiskCategory}
        by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        max_score = 0.0
        sum_score = 0.0

        for a in assessments:
            cat_str = a.risk_category.value if hasattr(a.risk_category, "value") else str(a.risk_category)
            if cat_str in by_category:
                by_category[cat_str] += 1
            sev = a.severity.capitalize() if a.severity else "Low"
            by_severity[sev] = by_severity.get(sev, 0) + 1
            score = float(a.risk_score or 0.0)
            if score > max_score:
                max_score = score
            sum_score += score

        # Count affected assets
        imp_query = (
            select(ThreatAssetImpact)
            .join(ThreatRiskAssessment, ThreatAssetImpact.risk_assessment_id == ThreatRiskAssessment.id)
            .join(GuardianExecution, ThreatRiskAssessment.guardian_execution_id == GuardianExecution.id)
        )

        if sandbox_id:
            imp_query = imp_query.where(GuardianExecution.sandbox_id == sandbox_id)

        imp_res = await self.session.execute(imp_query)
        impacts = list(imp_res.scalars().all())

        direct_asset_ids = {imp.asset_id for imp in impacts if imp.impact_type == "DIRECTLY_AFFECTED"}
        exposed_asset_ids = {imp.asset_id for imp in impacts if imp.impact_type == "POTENTIALLY_EXPOSED"}

        return {
            "total_assessments": total,
            "max_risk_score": round(max_score, 2),
            "average_risk_score": round(sum_score / total, 2) if total > 0 else 0.0,
            "by_category": by_category,
            "by_severity": by_severity,
            "directly_affected_assets_count": len(direct_asset_ids),
            "potentially_exposed_assets_count": len(exposed_asset_ids),
        }

    async def get_risk_priorities(
        self, sandbox_id: Optional[UUID] = None, limit: int = 10
    ) -> Dict[str, Any]:
        """
        Computes prioritized lists of threat assessments and asset risk profiles.
        """
        query = (
            select(ThreatRiskAssessment)
            .join(GuardianExecution, ThreatRiskAssessment.guardian_execution_id == GuardianExecution.id)
            .options(
                selectinload(ThreatRiskAssessment.threat_detection),
                selectinload(ThreatRiskAssessment.asset_impacts),
            )
        )

        if sandbox_id:
            query = query.where(GuardianExecution.sandbox_id == sandbox_id)

        res = await self.session.execute(query)
        assessments = list(res.scalars().all())
        ranked_assessments = RiskPrioritizer.rank_threats(assessments)

        items = []
        highest_det_id = None
        for idx, ass in enumerate(ranked_assessments[:limit]):
            det = ass.threat_detection
            if idx == 0 and det:
                highest_det_id = det.id
            cat = RiskCategory(ass.risk_category) if isinstance(ass.risk_category, str) else ass.risk_category
            items.append({
                "rank": idx + 1,
                "risk_assessment_id": ass.id,
                "threat_detection_id": ass.threat_detection_id,
                "detection_code": det.detection_code if det else "DET-UNKNOWN",
                "title": det.rule_name if det else "Unknown",
                "classification": det.classification if det else "Unknown",
                "severity": ass.severity,
                "risk_score": round(float(ass.risk_score or 0.0), 2),
                "risk_category": cat,
                "critical_asset_exposed": ass.critical_asset_exposed,
                "directly_affected_asset_count": ass.directly_affected_count,
                "detected_at": det.created_at if det else ass.assessed_at,
            })

        # Highest risk asset
        highest_asset_id = None
        if ranked_assessments and ranked_assessments[0].asset_impacts:
            highest_asset_id = ranked_assessments[0].asset_impacts[0].asset_id

        return {
            "items": items,
            "total": len(ranked_assessments),
            "highest_risk_detection_id": highest_det_id,
            "highest_risk_asset_id": highest_asset_id,
        }

    async def get_asset_risk_profile(self, asset_id: UUID) -> Optional[Dict[str, Any]]:
        """
        Calculates and returns the aggregated risk profile for a specific asset.
        """
        asset_res = await self.session.execute(select(SyntheticAsset).where(SyntheticAsset.id == asset_id))
        asset = asset_res.scalar_one_or_none()
        if not asset:
            return None

        imp_query = (
            select(ThreatAssetImpact)
            .where(ThreatAssetImpact.asset_id == asset_id)
            .options(
                selectinload(ThreatAssetImpact.risk_assessment),
            )
        )
        imp_res = await self.session.execute(imp_query)
        impacts = list(imp_res.scalars().all())

        direct_count = sum(1 for imp in impacts if imp.impact_type == "DIRECTLY_AFFECTED")
        indirect_count = sum(1 for imp in impacts if imp.impact_type != "DIRECTLY_AFFECTED")
        max_score = 0.0
        max_cat = RiskCategory.INFORMATIONAL

        for imp in impacts:
            if imp.risk_assessment:
                s = float(imp.risk_assessment.risk_score or 0.0)
                if s > max_score:
                    max_score = s
                    cat_val = imp.risk_assessment.risk_category
                    max_cat = RiskCategory(cat_val) if isinstance(cat_val, str) else cat_val

        return {
            "asset_id": asset.id,
            "sandbox_id": asset.sandbox_id,
            "asset_name": asset.name,
            "asset_type": asset.asset_type,
            "criticality": getattr(asset, "risk_level", "low") or "low",
            "highest_risk_score": round(max_score, 2),
            "highest_risk_category": max_cat,
            "direct_detections_count": direct_count,
            "indirect_exposure_count": indirect_count,
            "total_assessments_count": len(impacts),
        }
