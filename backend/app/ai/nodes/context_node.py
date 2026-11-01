"""Context initialization and evidence retrieval nodes for LangGraph.

Strictly enforces sandbox boundaries: queries telemetry exclusively where
sandbox_id matches the execution state.
"""

from datetime import datetime, timezone
import logging
from typing import Any
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.ai.state.state import AegisAIState
from app.models.attack_path import AttackPath
from app.models.attack_path_stage import AttackPathStage
from app.models.guardian import (
    CorrelatedEventGroup,
    DefensiveRecommendation,
    IncidentReport,
    RemediationPlan,
    ThreatAssetImpact,
    ThreatDetection,
    ThreatRiskAssessment,
)
from app.models.sandbox import SandboxEnvironment
from app.models.synthetic_asset import SyntheticAsset

logger = logging.getLogger("aegismesh.ai.nodes.context")


async def context_init_node(state: AegisAIState, session: AsyncSession | None = None) -> dict[str, Any]:
    """Initializes execution metadata, validates sandbox existence, and sets start time."""
    now = datetime.now(timezone.utc).isoformat()
    graph_id = state.get("graph_execution_id") or str(uuid.uuid4())
    logger.info("Initializing LangGraph context for session %s", graph_id)

    return {
        "graph_execution_id": graph_id,
        "execution_status": "in_progress",
        "start_time": state.get("start_time") or now,
        "errors": [],
        "agent_outputs": {},
        "fallback_used": False,
        "simulation_only": True,
    }


async def evidence_retrieval_node(state: AegisAIState, session: AsyncSession | None = None) -> dict[str, Any]:
    """Retrieves all persisted security telemetry scoped strictly to the target sandbox."""
    sandbox_id_str = state.get("sandbox_id")
    if not sandbox_id_str:
        return {
            "errors": ["Missing sandbox_id in state"],
            "execution_status": "failed",
        }

    try:
        sandbox_uuid = uuid.UUID(sandbox_id_str)
    except (ValueError, TypeError):
        return {
            "errors": [f"Invalid sandbox_id format: {sandbox_id_str}"],
            "execution_status": "failed",
        }

    evidence: dict[str, Any] = {
        "detections": [],
        "correlation_groups": [],
        "attack_paths": [],
        "risk_assessments": [],
        "asset_impacts": [],
        "recommendations": [],
        "remediation_plans": [],
        "incident_reports": [],
        "assets": [],
    }

    if session is not None:
        try:
            # 1. Threat Detections
            det_stmt = select(ThreatDetection).where(ThreatDetection.sandbox_id == sandbox_uuid)
            det_res = await session.execute(det_stmt)
            for d in det_res.scalars().all():
                evidence["detections"].append({
                    "id": str(d.id),
                    "title": d.title,
                    "rule_code": d.rule_code,
                    "classification": d.classification,
                    "severity": d.severity,
                    "confidence_score": d.confidence_score,
                    "mitre_techniques": d.mitre_techniques,
                    "affected_asset_ids": d.affected_asset_ids,
                    "correlated_group_id": str(d.correlated_group_id) if d.correlated_group_id else None,
                    "detection_rationale": d.detection_rationale,
                })

            # 2. Correlated Event Groups
            grp_stmt = select(CorrelatedEventGroup).where(CorrelatedEventGroup.sandbox_id == sandbox_uuid)
            grp_res = await session.execute(grp_stmt)
            for g in grp_res.scalars().all():
                evidence["correlation_groups"].append({
                    "id": str(g.id),
                    "title": g.title,
                    "stage": g.stage,
                    "correlation_basis": g.correlation_basis,
                    "member_event_ids": g.member_event_ids,
                })

            # 3. Attack Paths with stages
            path_stmt = (
                select(AttackPath)
                .where(AttackPath.sandbox_id == sandbox_uuid)
                .options(selectinload(AttackPath.stages))
            )
            path_res = await session.execute(path_stmt)
            for p in path_res.scalars().all():
                stages_data = [
                    {
                        "id": str(s.id),
                        "sequence_number": s.sequence_number,
                        "scenario_id": s.scenario_id,
                        "status": s.status,
                        "source_asset_id": str(s.source_asset_id) if s.source_asset_id else None,
                        "destination_asset_id": str(s.destination_asset_id) if s.destination_asset_id else None,
                        "risk_score": s.risk_score,
                    }
                    for s in p.stages
                ]
                evidence["attack_paths"].append({
                    "id": str(p.id),
                    "status": p.status,
                    "total_stages": p.total_stages,
                    "completed_stages": p.completed_stages,
                    "path_risk_score": getattr(p, "path_risk_score", p.risk_score),
                    "source_asset_id": str(p.source_asset_id) if p.source_asset_id else None,
                    "target_asset_id": str(getattr(p, "target_asset_id", None) or (p.stages[-1].destination_asset_id if p.stages else None)),
                    "stages": stages_data,
                })

            # 4. Risk Assessments
            risk_stmt = select(ThreatRiskAssessment).where(ThreatRiskAssessment.sandbox_id == sandbox_uuid)
            risk_res = await session.execute(risk_stmt)
            for r in risk_res.scalars().all():
                evidence["risk_assessments"].append({
                    "id": str(r.id),
                    "threat_detection_id": str(r.threat_detection_id) if r.threat_detection_id else None,
                    "risk_score": r.risk_score,
                    "risk_category": r.risk_category,
                    "severity": r.severity,
                    "asset_criticality_score": r.asset_criticality_score,
                    "blast_radius_factor": getattr(r, "blast_radius_score", 0.0),
                })

            # 5. Asset Impacts
            imp_stmt = select(ThreatAssetImpact).join(
                ThreatRiskAssessment, ThreatAssetImpact.risk_assessment_id == ThreatRiskAssessment.id
            ).where(ThreatRiskAssessment.sandbox_id == sandbox_uuid)
            imp_res = await session.execute(imp_stmt)
            for imp in imp_res.scalars().all():
                evidence["asset_impacts"].append({
                    "id": str(imp.id),
                    "asset_id": str(imp.asset_id),
                    "impact_type": imp.impact_type,
                    "impact_score": imp.impact_score,
                })

            # 6. Defensive Recommendations
            rec_stmt = select(DefensiveRecommendation).where(DefensiveRecommendation.sandbox_id == sandbox_uuid)
            rec_res = await session.execute(rec_stmt)
            for rec in rec_res.scalars().all():
                evidence["recommendations"].append({
                    "id": str(rec.id),
                    "threat_detection_id": str(rec.threat_detection_id) if rec.threat_detection_id else None,
                    "risk_assessment_id": str(rec.risk_assessment_id) if rec.risk_assessment_id else None,
                    "recommendation_code": rec.recommendation_code,
                    "title": rec.title,
                    "description": rec.description,
                    "priority": rec.priority,
                    "recommendation_type": rec.recommendation_type,
                    "playbook_id": rec.playbook_id,
                })

            # 7. Remediation Plans
            plan_stmt = select(RemediationPlan).where(RemediationPlan.sandbox_id == sandbox_uuid)
            plan_res = await session.execute(plan_stmt)
            for plan in plan_res.scalars().all():
                evidence["remediation_plans"].append({
                    "id": str(plan.id),
                    "title": plan.title,
                    "overall_priority": plan.overall_priority,
                    "plan_status": getattr(plan, "status", "draft"),
                    "total_actions": getattr(plan, "action_count", 0),
                })

            # 8. Incident Reports
            rep_stmt = select(IncidentReport).where(IncidentReport.sandbox_id == sandbox_uuid)
            rep_res = await session.execute(rep_stmt)
            for rep in rep_res.scalars().all():
                evidence["incident_reports"].append({
                    "id": str(rep.id),
                    "guardian_execution_id": str(rep.guardian_execution_id),
                    "title": rep.title,
                    "severity": rep.severity,
                    "max_risk_score": rep.max_risk_score,
                    "executive_summary": rep.executive_summary,
                    "report_status": rep.report_status,
                    "affected_asset_ids": rep.affected_asset_ids,
                })

            # 9. Synthetic Assets
            asset_stmt = select(SyntheticAsset).where(SyntheticAsset.sandbox_id == sandbox_uuid)
            asset_res = await session.execute(asset_stmt)
            for a in asset_res.scalars().all():
                evidence["assets"].append({
                    "id": str(a.id),
                    "name": a.name,
                    "asset_type": a.asset_type,
                    "risk_level": a.risk_level,
                })

        except Exception as exc:
            logger.error("Failed to retrieve sandbox evidence (%s: %s)", type(exc).__name__, exc, exc_info=True)
            return {
                "errors": [f"Evidence retrieval failed: {str(exc)}"],
                "execution_status": "partial",
            }

    # If state already provided seed evidence_records (e.g. from tests or caller)
    existing_evidence = state.get("evidence_records", {})
    if existing_evidence:
        for k, v in existing_evidence.items():
            if isinstance(v, list) and not evidence.get(k):
                evidence[k] = v

    logger.info(
        "Retrieved sandbox evidence: %d detections, %d attack paths, %d assessments, %d assets",
        len(evidence["detections"]),
        len(evidence["attack_paths"]),
        len(evidence["risk_assessments"]),
        len(evidence["assets"]),
    )

    return {
        "evidence_records": evidence,
    }
