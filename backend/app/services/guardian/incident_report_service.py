"""Deterministic Incident Report Service for Blue Guardian.

Synthesizes immutable, versioned, evidence-backed security incident reports and
executive security posture summaries distinguishing observed facts, derived conclusions,
inferred exposure, and advisory recommendations.
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
    ExecutiveSummaryResponse,
    IncidentReportStatus,
    RecommendationPriority,
)
from app.models.guardian import (
    DefensiveEventRecord,
    DefensiveRecommendation,
    GuardianExecution,
    IncidentReport,
    RemediationPlan,
    ThreatAssetImpact,
    ThreatDetection,
    ThreatRiskAssessment,
)
from app.services.guardian.ai_enrichment import AIEnrichmentProvider

logger = logging.getLogger("aegismesh.guardian.incident_report")


class IncidentReportService:
    """Async service responsible for generating structured incident reports and executive summaries."""

    def __init__(
        self,
        session: AsyncSession,
        ai_provider: Optional[AIEnrichmentProvider] = None,
    ):
        self.session = session
        self.ai_provider = ai_provider or AIEnrichmentProvider()

    def _determine_posture_rating(self, max_risk_score: float, p0_count: int) -> str:
        """Determines executive posture rating from risk score and critical actions."""
        if max_risk_score >= 8.0 or p0_count > 0:
            return "Critical Risk"
        if max_risk_score >= 6.0:
            return "High Risk"
        if max_risk_score >= 4.0:
            return "Moderate Risk"
        return "Low Risk / Hardened"

    async def generate_incident_report(
        self,
        execution: GuardianExecution,
        report_version: Optional[int] = None,
        custom_title: Optional[str] = None,
        include_ai_narrative: bool = True,
    ) -> IncidentReport:
        """Generates a structured, evidence-backed IncidentReport.
        
        Strictly enforces:
        1. Epistemic boundary segregation:
           - Observed Facts: Ingested events, timestamps, raw telemetry hashes
           - Derived Conclusions: Detections, risk scores, MITRE techniques
           - Inferred Exposure: Downstream blast radius assets (marked POTENTIALLY_EXPOSED)
           - Advisory Recommendations: Action plans and mitigation playbooks
        2. Versioning & Idempotency: Supports version incrementing or target version update
        3. Traceability: Immutable references to detections and recommendations
        """
        execution_id = execution.id
        sandbox_id = execution.sandbox_id

        # 1. Gather all execution artifacts
        # Ingested events (Observed Facts)
        ev_query = (
            select(DefensiveEventRecord)
            .where(DefensiveEventRecord.guardian_execution_id == execution_id)
            .where(DefensiveEventRecord.sandbox_id == sandbox_id)
            .order_by(DefensiveEventRecord.original_timestamp)
        )
        ev_res = await self.session.execute(ev_query)
        events = list(ev_res.scalars().all())

        # Risk assessments with detections and asset impacts (Derived Conclusions & Inferred Exposure)
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

        # Recommendations (Advisory)
        rec_query = (
            select(DefensiveRecommendation)
            .where(DefensiveRecommendation.guardian_execution_id == execution_id)
            .where(DefensiveRecommendation.sandbox_id == sandbox_id)
            .order_by(DefensiveRecommendation.priority, DefensiveRecommendation.created_at)
        )
        rec_res = await self.session.execute(rec_query)
        recommendations = list(rec_res.scalars().all())

        # Remediation Plan if any
        plan_query = (
            select(RemediationPlan)
            .where(RemediationPlan.guardian_execution_id == execution_id)
            .where(RemediationPlan.sandbox_id == sandbox_id)
            .order_by(RemediationPlan.created_at.desc())
        )
        plan_res = await self.session.execute(plan_query)
        remediation_plan = plan_res.scalars().first()

        # 2. Compute metrics and aggregations
        max_risk_score = 0.0
        risk_category = "Minimal"
        overall_severity = "Low"
        severities = [ass.threat_detection.severity for ass in assessments if ass.threat_detection]
        if "Critical" in severities:
            overall_severity = "Critical"
        elif "High" in severities:
            overall_severity = "High"
        elif "Medium" in severities:
            overall_severity = "Medium"

        if assessments:
            top_ass = assessments[0]
            max_risk_score = float(top_ass.risk_score)
            risk_category = top_ass.risk_category

        threat_classifications = list({
            ass.threat_detection.classification
            for ass in assessments
            if ass.threat_detection and ass.threat_detection.classification
        })

        # Directly affected vs potentially exposed assets
        directly_affected_assets: set[str] = set()
        potentially_exposed_assets: set[str] = set()

        all_mitre_techniques: List[Dict[str, Any]] = []
        seen_mitre_ids: set[str] = set()

        for ass in assessments:
            det = ass.threat_detection
            if det:
                if det.affected_asset_ids:
                    for aid in det.affected_asset_ids:
                        directly_affected_assets.add(str(aid))

                if det.mitre_techniques and isinstance(det.mitre_techniques, list):
                    for tech in det.mitre_techniques:
                        tid = tech.get("technique_id") if isinstance(tech, dict) else str(tech)
                        if tid and tid not in seen_mitre_ids:
                            seen_mitre_ids.add(tid)
                            all_mitre_techniques.append(tech if isinstance(tech, dict) else {"technique_id": tid})

            for imp in ass.asset_impacts:
                if imp.impact_type == "DIRECTLY_AFFECTED":
                    directly_affected_assets.add(str(imp.asset_id))
                elif imp.impact_type == "POTENTIALLY_EXPOSED":
                    potentially_exposed_assets.add(str(imp.asset_id))

        # Ensure blast radius assets are not in directly affected set
        potentially_exposed_assets -= directly_affected_assets

        # Build timeline (Observed Facts)
        event_timeline = [
            {
                "event_id": str(ev.id),
                "event_type": ev.event_type,
                "timestamp": ev.original_timestamp.isoformat(),
                "severity": ev.severity,
                "sha256_hash": ev.sha256_hash,
                "source_asset_id": str(ev.source_asset_id) if ev.source_asset_id else None,
                "destination_asset_id": str(ev.destination_asset_id) if ev.destination_asset_id else None,
            }
            for ev in events
        ]

        # Build detection summaries (Derived Conclusions)
        detection_summaries = [
            {
                "detection_id": str(ass.threat_detection.id),
                "detection_code": ass.threat_detection.detection_code,
                "title": ass.threat_detection.title,
                "classification": ass.threat_detection.classification,
                "severity": ass.threat_detection.severity,
                "risk_score": ass.risk_score,
                "risk_category": ass.risk_category,
                "confidence_score": ass.threat_detection.confidence_score,
                "mitre_tactics": ass.threat_detection.mitre_tactics,
            }
            for ass in assessments
            if ass.threat_detection
        ]

        # Build recommendation summaries (Advisory)
        recommendation_summaries = [
            {
                "recommendation_id": str(rec.id),
                "recommendation_code": rec.recommendation_code,
                "title": rec.title,
                "priority": rec.priority,
                "recommendation_type": rec.recommendation_type,
                "playbook_id": rec.playbook_id,
                "complexity": rec.implementation_complexity,
                "status": rec.status,
            }
            for rec in recommendations
        ]

        p0_count = sum(1 for rec in recommendations if rec.priority.upper() == "P0")
        posture_rating = self._determine_posture_rating(max_risk_score, p0_count)

        # 3. Generate narrative (Executive Summary) via AI or Deterministic Fallback
        top_threats = [
            {
                "title": ass.threat_detection.title,
                "classification": ass.threat_detection.classification,
                "risk_score": ass.risk_score,
            }
            for ass in assessments[:3]
            if ass.threat_detection
        ]

        narrative_data = await self.ai_provider.generate_executive_narrative(
            posture_rating=posture_rating,
            max_risk_score=max_risk_score,
            risk_category=risk_category,
            total_detections=len(assessments),
            p0_count=p0_count,
            affected_asset_count=len(directly_affected_assets),
            exposed_asset_count=len(potentially_exposed_assets),
            threat_classes=threat_classifications,
            top_threats=top_threats,
        )

        executive_summary = narrative_data["executive_summary"]

        # 4. Determine report version
        if report_version is None:
            max_v_query = select(func.max(IncidentReport.report_version)).where(
                IncidentReport.guardian_execution_id == execution_id
            )
            max_v_res = await self.session.execute(max_v_query)
            current_max_v = max_v_res.scalar() or 0
            target_version = current_max_v + 1
        else:
            target_version = report_version

        # Title
        report_title = custom_title or f"Security Incident Report v{target_version} — Execution {execution_id.hex[:8].upper()}"

        # 5. Build full epistemic report content dictionary
        report_content = {
            "metadata": {
                "report_version": target_version,
                "execution_id": str(execution_id),
                "sandbox_id": str(sandbox_id),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "posture_rating": posture_rating,
                "ai_enriched": narrative_data.get("ai_enriched", False),
            },
            "epistemic_sections": {
                "observed_facts": {
                    "total_events_ingested": len(events),
                    "event_timeline": event_timeline,
                    "event_types_observed": list({ev.event_type for ev in events}),
                },
                "derived_conclusions": {
                    "total_threat_detections": len(assessments),
                    "max_risk_score": max_risk_score,
                    "peak_risk_category": risk_category,
                    "overall_severity": overall_severity,
                    "threat_classifications": threat_classifications,
                    "mitre_techniques": all_mitre_techniques,
                    "detection_details": detection_summaries,
                },
                "inferred_exposure": {
                    "directly_affected_asset_ids": sorted(list(directly_affected_assets)),
                    "potentially_exposed_asset_ids": sorted(list(potentially_exposed_assets)),
                    "blast_radius_nodes_count": len(potentially_exposed_assets),
                    "exposure_caveat": "Downstream blast radius assets are classified as POTENTIALLY_EXPOSED based on graph proximity and require active credential validation before confirmation.",
                },
                "advisory_recommendations": {
                    "total_recommendations": len(recommendations),
                    "p0_count": p0_count,
                    "recommendations": recommendation_summaries,
                    "immediate_priorities": narrative_data.get("immediate_priorities", []),
                    "residual_risks_and_uncertainties": narrative_data.get("residual_risks_and_uncertainties", []),
                    "remediation_plan_id": str(remediation_plan.id) if remediation_plan else None,
                },
            },
        }

        # 6. Check existing report with target version for idempotency
        existing_report_query = (
            select(IncidentReport)
            .where(IncidentReport.guardian_execution_id == execution_id)
            .where(IncidentReport.report_version == target_version)
        )
        existing_report_res = await self.session.execute(existing_report_query)
        existing_report = existing_report_res.scalars().first()

        if existing_report:
            report = existing_report
            report.title = report_title
            report.executive_summary = executive_summary
            report.threat_classifications = threat_classifications
            report.severity = overall_severity
            report.max_risk_score = max_risk_score
            report.risk_category = risk_category
            report.affected_asset_ids = sorted(list(directly_affected_assets))
            report.potentially_exposed_asset_ids = sorted(list(potentially_exposed_assets))
            report.blast_radius_nodes_count = len(potentially_exposed_assets)
            report.mitre_techniques = all_mitre_techniques
            report.event_timeline = event_timeline
            report.detection_summaries = detection_summaries
            report.recommendation_summaries = recommendation_summaries
            report.remediation_plan_id = remediation_plan.id if remediation_plan else None
            report.report_content = report_content
            report.generated_at = datetime.now(timezone.utc)
        else:
            report = IncidentReport(
                id=uuid.uuid4(),
                guardian_execution_id=execution_id,
                sandbox_id=sandbox_id,
                report_version=target_version,
                title=report_title,
                executive_summary=executive_summary,
                threat_classifications=threat_classifications,
                severity=overall_severity,
                max_risk_score=max_risk_score,
                risk_category=risk_category,
                affected_asset_ids=sorted(list(directly_affected_assets)),
                potentially_exposed_asset_ids=sorted(list(potentially_exposed_assets)),
                blast_radius_nodes_count=len(potentially_exposed_assets),
                mitre_techniques=all_mitre_techniques,
                event_timeline=event_timeline,
                detection_summaries=detection_summaries,
                recommendation_summaries=recommendation_summaries,
                remediation_plan_id=remediation_plan.id if remediation_plan else None,
                report_content=report_content,
                report_status=IncidentReportStatus.PUBLISHED.value,
                generated_at=datetime.now(timezone.utc),
                created_at=datetime.now(timezone.utc),
            )
            self.session.add(report)

        await self.session.flush()

        # Update guardian_execution count metric
        count_query = select(func.count(IncidentReport.id)).where(
            IncidentReport.guardian_execution_id == execution_id
        )
        count_res = await self.session.execute(count_query)
        execution.incident_reports_count = count_res.scalar() or 1
        await self.session.flush()

        return report

    async def generate_executive_summary(
        self,
        execution_id: UUID,
        sandbox_id: UUID,
    ) -> ExecutiveSummaryResponse:
        """Retrieves and computes an executive security posture summary for an execution."""
        # 1. Fetch assessments
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

        # 2. Fetch recommendations
        rec_query = (
            select(DefensiveRecommendation)
            .where(DefensiveRecommendation.guardian_execution_id == execution_id)
            .where(DefensiveRecommendation.sandbox_id == sandbox_id)
        )
        rec_res = await self.session.execute(rec_query)
        recommendations = list(rec_res.scalars().all())

        max_risk_score = 0.0
        risk_category = "Minimal"
        if assessments:
            max_risk_score = float(assessments[0].risk_score)
            risk_category = assessments[0].risk_category

        p0_count = sum(1 for r in recommendations if r.priority.upper() == "P0")
        posture_rating = self._determine_posture_rating(max_risk_score, p0_count)

        directly_affected: set[str] = set()
        potentially_exposed: set[str] = set()
        threat_classes: set[str] = set()

        top_threats: List[Dict[str, Any]] = []

        for ass in assessments:
            det = ass.threat_detection
            if det:
                threat_classes.add(det.classification)
                if len(top_threats) < 3:
                    top_threats.append({
                        "detection_id": str(det.id),
                        "detection_code": det.detection_code,
                        "title": det.title,
                        "classification": det.classification,
                        "severity": det.severity,
                        "risk_score": ass.risk_score,
                        "risk_category": ass.risk_category,
                    })
                if det.affected_asset_ids:
                    directly_affected.update(str(aid) for aid in det.affected_asset_ids)

            for imp in ass.asset_impacts:
                if imp.impact_type == "DIRECTLY_AFFECTED":
                    directly_affected.add(str(imp.asset_id))
                elif imp.impact_type == "POTENTIALLY_EXPOSED":
                    potentially_exposed.add(str(imp.asset_id))

        potentially_exposed -= directly_affected

        narrative_data = await self.ai_provider.generate_executive_narrative(
            posture_rating=posture_rating,
            max_risk_score=max_risk_score,
            risk_category=risk_category,
            total_detections=len(assessments),
            p0_count=p0_count,
            affected_asset_count=len(directly_affected),
            exposed_asset_count=len(potentially_exposed),
            threat_classes=sorted(list(threat_classes)),
            top_threats=top_threats,
        )

        return ExecutiveSummaryResponse(
            guardian_execution_id=execution_id,
            sandbox_id=sandbox_id,
            posture_rating=posture_rating,
            executive_summary=narrative_data["executive_summary"],
            total_detections=len(assessments),
            max_risk_score=max_risk_score,
            risk_category=risk_category,
            p0_recommendations_count=p0_count,
            total_recommendations=len(recommendations),
            affected_assets_count=len(directly_affected),
            exposed_assets_count=len(potentially_exposed),
            top_threats=top_threats,
            immediate_priorities=narrative_data.get("immediate_priorities", []),
            residual_risks_and_uncertainties=narrative_data.get("residual_risks_and_uncertainties", []),
            ai_enriched=narrative_data.get("ai_enriched", False),
            generated_at=datetime.now(timezone.utc),
        )

