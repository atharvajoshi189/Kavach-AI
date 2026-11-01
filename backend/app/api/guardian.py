"""REST API endpoints for Blue Guardian Defensive Ingestion & Correlation."""

from __future__ import annotations

import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.blue_guardian.schemas import (
    CorrelatedGroupDetailResponse,
    CorrelatedGroupListResponse,
    CorrelatedGroupResponse,
    DefensiveEventListResponse,
    DefensiveEventRecordResponse,
    DetectionRuleListResponse,
    DetectionRuleMetadataResponse,
    GuardianExecutionCreateRequest,
    GuardianExecutionDetailResponse,
    GuardianExecutionResponse,
    ThreatDetectionListResponse,
    ThreatDetectionResponse,
    ThreatDetectionSummaryResponse,
    AssetRiskProfileResponse,
    RiskPrioritiesResponse,
    RiskSummaryResponse,
    ThreatAssetImpactResponse,
    ThreatRiskAssessmentDetailResponse,
    ThreatRiskAssessmentListResponse,
    ThreatRiskAssessmentResponse,
    PlaybookListResponse,
    PlaybookResponse,
    DefensiveRecommendationResponse,
    DefensiveRecommendationListResponse,
    RemediationPlanResponse,
    RemediationPlanDetailResponse,
    RemediationPlanListResponse,
    RemediationPlanActionResponse,
    IncidentReportResponse,
    IncidentReportDetailResponse,
    IncidentReportListResponse,
    IncidentReportGenerateRequest,
    ExecutiveSummaryResponse,
    ApprovalStatus,
    ApprovalDecisionType,
    ExecutionStatus,
    VerificationStatus,
    ApprovalRequestCreate,
    ApprovalDecisionCreate,
    ApprovalRequestCancel,
    SyntheticExecutionCreate,
    ApprovalRequestResponse,
    ApprovalRequestListResponse,
    ApprovalDecisionResponse,
    ApprovalPolicyResponse,
    SyntheticRemediationExecutionResponse,
    SyntheticRemediationExecutionListResponse,
    SyntheticStateSnapshotResponse,
    SyntheticSnapshotComparisonResponse,
    RemediationVerificationResponse,
    RemediationVerificationSummaryResponse,
)
from app.core.permissions import get_current_user
from app.database.session import get_db
from app.models.guardian import (
    CorrelatedEventGroup,
    DefensiveEventRecord,
    GuardianExecution,
    ThreatDetection,
    ThreatRiskAssessment,
    ThreatAssetImpact,
    DefensiveRecommendation,
    RemediationPlan,
    RemediationPlanAction,
    IncidentReport,
    ApprovalRequest,
    ApprovalDecision,
    SyntheticRemediationExecution,
    SyntheticStateSnapshot,
    RemediationVerification,
)
from app.models.user import User
from app.security.gateway import authorize_action
from app.services.guardian.detection_rules import DetectionRuleRegistry
from app.services.guardian.orchestrator_service import GuardianOrchestrationService
from app.services.guardian.risk_analysis_service import RiskAnalysisService
from app.services.guardian.playbook_library import PlaybookLibrary
from app.services.guardian.recommendation_engine import RecommendationEngine
from app.services.guardian.remediation_planner import RemediationPlanner
from app.services.guardian.incident_report_service import IncidentReportService
from app.services.guardian.approval_service import ApprovalService
from app.services.guardian.approval_policy import ApprovalPolicyEngine
from app.services.guardian.synthetic_state_snapshot import SyntheticStateSnapshotService
from app.services.guardian.synthetic_remediation_executor import SyntheticRemediationExecutor
from app.services.guardian.regression_verification_engine import RegressionVerificationEngine
from app.workers.guardian_tasks import execute_synthetic_remediation_task
from app.services.sandbox_service import get_sandbox_by_id, verify_sandbox_access

logger = logging.getLogger("aegismesh.api.guardian")

router = APIRouter(prefix="/guardian", tags=["Blue Guardian Defensive Engine"])


def _execution_to_summary(ex: GuardianExecution) -> GuardianExecutionResponse:
    return GuardianExecutionResponse(
        execution_id=ex.id,
        sandbox_id=ex.sandbox_id,
        attack_run_id=ex.attack_run_id,
        attack_path_id=ex.attack_path_id,
        status=ex.status,  # type: ignore[arg-type]
        started_at=ex.started_at,
        completed_at=ex.completed_at,
        events_ingested=ex.events_ingested,
        correlation_groups_count=ex.correlation_groups_count,
        threat_detections_count=getattr(ex, "threat_detections_count", 0),
        risk_assessments_count=getattr(ex, "risk_assessments_count", 0),
        max_risk_score=getattr(ex, "max_risk_score", 0.0),
        error_message=ex.error_message,
    )


def _execution_to_detail(ex: GuardianExecution) -> GuardianExecutionDetailResponse:
    return GuardianExecutionDetailResponse(
        execution_id=ex.id,
        sandbox_id=ex.sandbox_id,
        attack_run_id=ex.attack_run_id,
        attack_path_id=ex.attack_path_id,
        status=ex.status,  # type: ignore[arg-type]
        started_at=ex.started_at,
        completed_at=ex.completed_at,
        events_ingested=ex.events_ingested,
        correlation_groups_count=ex.correlation_groups_count,
        threat_detections_count=getattr(ex, "threat_detections_count", 0),
        risk_assessments_count=getattr(ex, "risk_assessments_count", 0),
        max_risk_score=getattr(ex, "max_risk_score", 0.0),
        error_message=ex.error_message,
        execution_metadata=ex.execution_metadata or {},
        created_at=ex.created_at,
        updated_at=ex.updated_at,
    )


def _detection_to_response(det: ThreatDetection) -> ThreatDetectionResponse:
    return ThreatDetectionResponse(
        id=det.id,
        guardian_execution_id=det.guardian_execution_id,
        correlated_group_id=det.correlated_group_id,
        sandbox_id=det.sandbox_id,
        detection_code=det.detection_code,
        rule_code=det.rule_code,
        rule_version=det.rule_version,
        title=det.title,
        description=det.description,
        classification=det.classification,
        severity=det.severity,
        confidence_score=det.confidence_score,
        mitre_techniques=det.mitre_techniques or [],
        mitre_tactics=det.mitre_tactics or [],
        affected_asset_ids=det.affected_asset_ids or [],
        evidence_references=det.evidence_references or {},
        detection_rationale=det.detection_rationale,
        status=det.status,
        is_simulated=det.is_simulated,
        simulation_only=det.simulation_only,
        created_at=det.created_at,
        updated_at=det.updated_at,
    )


def _event_record_to_response(rec: DefensiveEventRecord) -> DefensiveEventRecordResponse:
    return DefensiveEventRecordResponse(
        id=rec.id,
        guardian_execution_id=rec.guardian_execution_id,
        sandbox_id=rec.sandbox_id,
        source_event_id=rec.source_event_id,
        attack_run_id=rec.attack_run_id,
        campaign_id=rec.campaign_id,
        attack_path_id=rec.attack_path_id,
        scenario_id=rec.scenario_id,
        source_asset_id=rec.source_asset_id,
        destination_asset_id=rec.destination_asset_id,
        event_type=rec.event_type,
        severity=rec.severity,
        original_timestamp=rec.original_timestamp,
        ingested_at=rec.ingested_at,
        is_simulated=rec.is_simulated,
        simulation_only=rec.simulation_only,
        sha256_hash=rec.sha256_hash,
        raw_payload=rec.raw_payload or {},
        provenance_metadata=rec.provenance_metadata or {},
    )


def _group_to_response(group: CorrelatedEventGroup) -> CorrelatedGroupResponse:
    return CorrelatedGroupResponse(
        id=group.id,
        guardian_execution_id=group.guardian_execution_id,
        sandbox_id=group.sandbox_id,
        campaign_id=group.campaign_id,
        title=group.title,
        stage=group.stage,
        correlation_basis=group.correlation_basis,  # type: ignore[arg-type]
        correlation_rule=group.correlation_rule,
        member_event_ids=group.member_event_ids or [],
        root_cause_asset_id=group.root_cause_asset_id,
        impacted_asset_ids=group.impacted_asset_ids or [],
        earliest_event_timestamp=group.earliest_event_timestamp,
        latest_event_timestamp=group.latest_event_timestamp,
        correlation_confidence=group.correlation_confidence,
        simulation_only=group.simulation_only,
        is_simulated=group.is_simulated,
        group_metadata=group.group_metadata or {},
        created_at=group.created_at,
    )


@router.post(
    "/executions",
    response_model=GuardianExecutionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Blue Guardian Defensive Ingestion & Correlation",
)
async def create_guardian_execution(
    request: GuardianExecutionCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Triggers defensive telemetry ingestion and deterministic event correlation."""
    service = GuardianOrchestrationService(session=db)
    execution = await service.execute_analysis(request=request, user=current_user)
    return _execution_to_summary(execution)


@router.get(
    "/executions",
    response_model=list[GuardianExecutionResponse],
    summary="List Blue Guardian Executions",
)
async def list_guardian_executions(
    sandbox_id: Optional[uuid.UUID] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists defensive executions, optionally filtered by sandbox."""
    query = select(GuardianExecution)
    if sandbox_id:
        query = query.where(GuardianExecution.sandbox_id == sandbox_id)
    query = query.order_by(GuardianExecution.started_at.desc()).limit(limit)
    res = await db.execute(query)
    return [_execution_to_summary(ex) for ex in res.scalars().all()]


@router.get(
    "/executions/{execution_id}",
    response_model=GuardianExecutionDetailResponse,
    summary="Get Blue Guardian Execution Details",
)
async def get_guardian_execution(
    execution_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves full status and metadata for a defensive analysis execution."""
    execution = await db.get(GuardianExecution, execution_id)
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Guardian execution '{execution_id}' not found.",
        )

    # Authorize read
    decision = await authorize_action(
        user=current_user,
        operation="guardian.read",
        capability="read",
        resource_type="guardian_execution",
        resource_id=str(execution.sandbox_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
        )

    sandbox = await get_sandbox_by_id(db, execution.sandbox_id)
    if not sandbox or not verify_sandbox_access(sandbox, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to sandbox environment for this execution.",
        )

    return _execution_to_detail(execution)


@router.get(
    "/executions/{execution_id}/events",
    response_model=DefensiveEventListResponse,
    summary="List Ingested Defensive Events for an Execution",
)
async def list_guardian_events(
    execution_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns paginated, deterministically sorted ingested defensive event records."""
    execution = await db.get(GuardianExecution, execution_id)
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Guardian execution '{execution_id}' not found.",
        )

    # Authorize read
    decision = await authorize_action(
        user=current_user,
        operation="guardian.events_read",
        capability="read",
        resource_type="guardian_execution",
        resource_id=str(execution.sandbox_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
        )

    sandbox = await get_sandbox_by_id(db, execution.sandbox_id)
    if not sandbox or not verify_sandbox_access(sandbox, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to sandbox environment for this execution.",
        )

    # Total count
    count_query = (
        select(func.count(DefensiveEventRecord.id))
        .where(DefensiveEventRecord.guardian_execution_id == execution_id)
    )
    total = (await db.execute(count_query)).scalar_one()

    # Paginated query
    query = (
        select(DefensiveEventRecord)
        .where(DefensiveEventRecord.guardian_execution_id == execution_id)
        .order_by(DefensiveEventRecord.original_timestamp, DefensiveEventRecord.source_event_id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    records = (await db.execute(query)).scalars().all()

    return DefensiveEventListResponse(
        items=[_event_record_to_response(r) for r in records],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/executions/{execution_id}/correlated-groups",
    response_model=CorrelatedGroupListResponse,
    summary="List Correlated Event Groups for an Execution",
)
async def list_guardian_correlated_groups(
    execution_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns all deterministic correlated event groups generated by an execution."""
    execution = await db.get(GuardianExecution, execution_id)
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Guardian execution '{execution_id}' not found.",
        )

    # Authorize read
    decision = await authorize_action(
        user=current_user,
        operation="guardian.groups_read",
        capability="read",
        resource_type="guardian_execution",
        resource_id=str(execution.sandbox_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
        )

    sandbox = await get_sandbox_by_id(db, execution.sandbox_id)
    if not sandbox or not verify_sandbox_access(sandbox, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to sandbox environment for this execution.",
        )

    query = (
        select(CorrelatedEventGroup)
        .where(CorrelatedEventGroup.guardian_execution_id == execution_id)
        .order_by(CorrelatedEventGroup.earliest_event_timestamp, CorrelatedEventGroup.title)
    )
    groups = (await db.execute(query)).scalars().all()

    return CorrelatedGroupListResponse(
        items=[_group_to_response(g) for g in groups],
        total=len(groups),
    )


@router.get(
    "/executions/{execution_id}/correlated-groups/{group_id}",
    response_model=CorrelatedGroupDetailResponse,
    summary="Get Correlated Event Group Detail with Source Events",
)
async def get_guardian_correlated_group_detail(
    execution_id: uuid.UUID,
    group_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves a single correlated event group along with its full source event records."""
    group = await db.get(CorrelatedEventGroup, group_id)
    if not group or group.guardian_execution_id != execution_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlated group '{group_id}' not found for execution '{execution_id}'.",
        )

    # Authorize read
    decision = await authorize_action(
        user=current_user,
        operation="guardian.groups_read",
        capability="read",
        resource_type="guardian_execution",
        resource_id=str(group.sandbox_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
        )

    sandbox = await get_sandbox_by_id(db, group.sandbox_id)
    if not sandbox or not verify_sandbox_access(sandbox, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to sandbox environment for this group.",
        )

    # Fetch corresponding source event records
    member_ids = group.member_event_ids or []
    events_query = (
        select(DefensiveEventRecord)
        .where(
            DefensiveEventRecord.guardian_execution_id == execution_id,
            DefensiveEventRecord.source_event_id.in_(member_ids),
        )
        .order_by(DefensiveEventRecord.original_timestamp, DefensiveEventRecord.source_event_id)
    )
    events = (await db.execute(events_query)).scalars().all()

    return CorrelatedGroupDetailResponse(
        group=_group_to_response(group),
        events=[_event_record_to_response(e) for e in events],
    )


# =============================================================================
# Threat Detection Endpoints
# =============================================================================

@router.get(
    "/detection-rules",
    response_model=DetectionRuleListResponse,
    summary="List Registered Blue Guardian Detection Rules",
)
async def list_guardian_detection_rules(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves metadata for all registered Blue Guardian threat detection rules."""
    decision = await authorize_action(
        user=current_user,
        operation="guardian.rules_read",
        capability="read",
        resource_type="detection_rule",
        resource_id="global",
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
        )

    registry = DetectionRuleRegistry()
    rules = registry.get_all_rules()

    items = [
        DetectionRuleMetadataResponse(
            rule_code=r.rule_code,
            rule_version=r.rule_version,
            rule_name=r.rule_name,
            description=r.description,
            enabled=r.enabled,
            severity=r.severity,
            confidence=r.confidence,
            classification=r.classification,
            mitre_tactics=r.mitre_tactics,
            mitre_techniques=r.mitre_techniques,
            required_event_types=r.required_event_types,
            min_event_count=r.min_event_count,
            false_positive_conditions=r.false_positive_conditions,
        )
        for r in rules
    ]

    return DetectionRuleListResponse(
        rules=items,
        total=len(items),
    )


@router.get(
    "/detections/summary",
    response_model=ThreatDetectionSummaryResponse,
    summary="Get Aggregated Threat Metrics for SOC Dashboard",
)
async def get_guardian_detections_summary(
    sandbox_id: Optional[uuid.UUID] = Query(None, description="Filter metrics by sandbox environment"),
    execution_id: Optional[uuid.UUID] = Query(None, description="Filter metrics by execution"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregates threat detections by severity, classification, MITRE technique, and affected assets."""
    auth_resource_id = str(sandbox_id) if sandbox_id else "global"
    decision = await authorize_action(
        user=current_user,
        operation="guardian.detections_read",
        capability="read",
        resource_type="threat_detection",
        resource_id=auth_resource_id,
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
        )

    base_query = select(ThreatDetection)
    if sandbox_id:
        sandbox = await get_sandbox_by_id(db, sandbox_id)
        if not sandbox or not verify_sandbox_access(sandbox, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to specified sandbox environment.",
            )
        base_query = base_query.where(ThreatDetection.sandbox_id == sandbox_id)
    else:
        is_admin = getattr(current_user.role, "value", str(current_user.role)) == "admin"
        if not is_admin:
            from app.models.sandbox import SandboxEnvironment
            accessible_sandboxes = select(SandboxEnvironment.id).where(SandboxEnvironment.owner_id == current_user.id)
            base_query = base_query.where(ThreatDetection.sandbox_id.in_(accessible_sandboxes))

    if execution_id:
        base_query = base_query.where(ThreatDetection.guardian_execution_id == execution_id)

    detections = list((await db.execute(base_query)).scalars().all())

    # Initialize aggregations with standard keys
    by_severity: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    by_classification: Dict[str, int] = {}
    by_mitre: Dict[str, int] = {}
    distinct_assets: set[str] = set()

    for det in detections:
        # Severity
        sev = det.severity.capitalize()
        by_severity[sev] = by_severity.get(sev, 0) + 1

        # Classification
        cls_name = det.classification
        by_classification[cls_name] = by_classification.get(cls_name, 0) + 1

        # MITRE techniques
        for tech in (det.mitre_techniques or []):
            tid = tech.get("technique_id")
            if tid:
                by_mitre[tid] = by_mitre.get(tid, 0) + 1

        # Assets
        for aid in (det.affected_asset_ids or []):
            distinct_assets.add(str(aid))

    return ThreatDetectionSummaryResponse(
        total_detections=len(detections),
        by_severity=by_severity,
        by_classification=by_classification,
        by_mitre_technique=by_mitre,
        affected_assets_count=len(distinct_assets),
    )


@router.get(
    "/detections",
    response_model=ThreatDetectionListResponse,
    summary="List Global Threat Detections with Filtering",
)
async def list_all_guardian_detections(
    sandbox_id: Optional[uuid.UUID] = Query(None, description="Filter by sandbox environment"),
    execution_id: Optional[uuid.UUID] = Query(None, description="Filter by guardian execution ID"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    classification: Optional[str] = Query(None, description="Filter by threat classification"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by detection status"),
    mitre_technique: Optional[str] = Query(None, description="Filter by MITRE ATT&CK technique ID (e.g. T1046)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns a filtered, paginated list of threat detections across accessible sandboxes."""
    auth_resource_id = str(sandbox_id) if sandbox_id else "global"
    decision = await authorize_action(
        user=current_user,
        operation="guardian.detections_read",
        capability="read",
        resource_type="threat_detection",
        resource_id=auth_resource_id,
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
        )

    base_query = select(ThreatDetection)

    # Scoping by sandbox
    if sandbox_id:
        sandbox = await get_sandbox_by_id(db, sandbox_id)
        if not sandbox or not verify_sandbox_access(sandbox, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to specified sandbox environment.",
            )
        base_query = base_query.where(ThreatDetection.sandbox_id == sandbox_id)
    else:
        is_admin = getattr(current_user.role, "value", str(current_user.role)) == "admin"
        if not is_admin:
            from app.models.sandbox import SandboxEnvironment
            accessible_sandboxes = select(SandboxEnvironment.id).where(SandboxEnvironment.owner_id == current_user.id)
            base_query = base_query.where(ThreatDetection.sandbox_id.in_(accessible_sandboxes))

    if execution_id:
        base_query = base_query.where(ThreatDetection.guardian_execution_id == execution_id)
    if severity:
        base_query = base_query.where(ThreatDetection.severity == severity.capitalize())
    if classification:
        base_query = base_query.where(ThreatDetection.classification == classification)
    if status_filter:
        base_query = base_query.where(ThreatDetection.status == status_filter.lower())

    count_query = select(func.count()).select_from(base_query.subquery())
    total = (await db.execute(count_query)).scalar_one()

    paged_query = (
        base_query
        .order_by(ThreatDetection.created_at.desc(), ThreatDetection.detection_code)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    detections = list((await db.execute(paged_query)).scalars().all())

    # Optional in-memory MITRE filter if requested
    if mitre_technique:
        target_tech = mitre_technique.upper()
        detections = [
            d for d in detections
            if any(t.get("technique_id", "").upper() == target_tech for t in (d.mitre_techniques or []))
        ]
        total = len(detections)

    return ThreatDetectionListResponse(
        items=[_detection_to_response(d) for d in detections],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/executions/{execution_id}/detections",
    response_model=ThreatDetectionListResponse,
    summary="List Threat Detections for an Execution",
)
async def list_guardian_detections_for_execution(
    execution_id: uuid.UUID,
    severity: Optional[str] = Query(None, description="Filter by severity level (Low, Medium, High, Critical)"),
    classification: Optional[str] = Query(None, description="Filter by threat classification"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by detection status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns paginated threat detections produced by detection rules for a specific execution."""
    execution = await db.get(GuardianExecution, execution_id)
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Guardian execution '{execution_id}' not found.",
        )

    # Authorize read
    decision = await authorize_action(
        user=current_user,
        operation="guardian.detections_read",
        capability="read",
        resource_type="guardian_execution",
        resource_id=str(execution.sandbox_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
        )

    sandbox = await get_sandbox_by_id(db, execution.sandbox_id)
    if not sandbox or not verify_sandbox_access(sandbox, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to sandbox environment for this execution.",
        )

    # Base query
    base_query = select(ThreatDetection).where(ThreatDetection.guardian_execution_id == execution_id)
    if severity:
        base_query = base_query.where(ThreatDetection.severity == severity.capitalize())
    if classification:
        base_query = base_query.where(ThreatDetection.classification == classification)
    if status_filter:
        base_query = base_query.where(ThreatDetection.status == status_filter.lower())

    # Count
    count_query = select(func.count()).select_from(base_query.subquery())
    total = (await db.execute(count_query)).scalar_one()

    # Paginate
    paged_query = (
        base_query
        .order_by(ThreatDetection.created_at, ThreatDetection.detection_code)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    detections = (await db.execute(paged_query)).scalars().all()

    return ThreatDetectionListResponse(
        items=[_detection_to_response(d) for d in detections],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/detections/{detection_id}",
    response_model=ThreatDetectionResponse,
    summary="Get Threat Detection Detail",
)
async def get_guardian_detection_detail(
    detection_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves full forensic details for a specific ThreatDetection record."""
    detection = await db.get(ThreatDetection, detection_id)
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat detection '{detection_id}' not found.",
        )

    # Authorize read
    decision = await authorize_action(
        user=current_user,
        operation="guardian.detections_read",
        capability="read",
        resource_type="threat_detection",
        resource_id=str(detection.sandbox_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason,
        )

    sandbox = await get_sandbox_by_id(db, detection.sandbox_id)
    if not sandbox or not verify_sandbox_access(sandbox, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to sandbox environment for this detection.",
        )

    return _detection_to_response(detection)


def _assessment_to_response(a: ThreatRiskAssessment) -> ThreatRiskAssessmentResponse:
    return ThreatRiskAssessmentResponse.model_validate(a)


def _assessment_to_detail(a: ThreatRiskAssessment) -> ThreatRiskAssessmentDetailResponse:
    return ThreatRiskAssessmentDetailResponse(
        assessment=ThreatRiskAssessmentResponse.model_validate(a),
        impacted_assets=[
            ThreatAssetImpactResponse.model_validate(imp) for imp in (a.asset_impacts or [])
        ],
    )


@router.get(
    "/risk-summary",
    response_model=RiskSummaryResponse,
    summary="Get Risk Analysis Summary",
)
async def get_risk_summary(
    sandbox_id: Optional[uuid.UUID] = Query(None, description="Optional sandbox environment ID filter"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves aggregated risk scoring and impact metrics across executions."""
    if sandbox_id:
        sandbox = await get_sandbox_by_id(db, sandbox_id)
        if not sandbox:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Sandbox '{sandbox_id}' not found.",
            )
        if not verify_sandbox_access(sandbox, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to target sandbox environment.",
            )

    decision = await authorize_action(
        user=current_user,
        operation="guardian.risk_read",
        capability="read",
        resource_type="threat_risk_assessment",
        resource_id=str(sandbox_id) if sandbox_id else "global",
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    risk_service = RiskAnalysisService(db)
    summary_data = await risk_service.get_risk_summary(sandbox_id=sandbox_id)
    return RiskSummaryResponse(**summary_data)


@router.get(
    "/risk-priorities",
    response_model=RiskPrioritiesResponse,
    summary="Get Prioritized Threats and Exposed Assets",
)
async def get_risk_priorities(
    sandbox_id: Optional[uuid.UUID] = Query(None, description="Optional sandbox environment ID filter"),
    limit: int = Query(10, ge=1, le=100, description="Max priority items to return"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves deterministically ranked high-priority threats and vulnerable assets."""
    if sandbox_id:
        sandbox = await get_sandbox_by_id(db, sandbox_id)
        if not sandbox:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Sandbox '{sandbox_id}' not found.",
            )
        if not verify_sandbox_access(sandbox, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to target sandbox environment.",
            )

    decision = await authorize_action(
        user=current_user,
        operation="guardian.risk_read",
        capability="read",
        resource_type="threat_risk_assessment",
        resource_id=str(sandbox_id) if sandbox_id else "global",
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    risk_service = RiskAnalysisService(db)
    priorities_data = await risk_service.get_risk_priorities(sandbox_id=sandbox_id, limit=limit)
    return RiskPrioritiesResponse(**priorities_data)


@router.get(
    "/risk-assessments",
    response_model=ThreatRiskAssessmentListResponse,
    summary="List Threat Risk Assessments",
)
async def list_risk_assessments(
    execution_id: Optional[uuid.UUID] = Query(None, description="Filter by guardian execution ID"),
    risk_category: Optional[str] = Query(None, description="Filter by risk category"),
    min_score: Optional[float] = Query(None, description="Minimum risk score filter"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves paginated threat risk assessments with optional filtering."""
    sandbox_id: Optional[uuid.UUID] = None
    if execution_id:
        execution = await db.get(GuardianExecution, execution_id)
        if not execution:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"GuardianExecution '{execution_id}' not found.",
            )
        sandbox_id = execution.sandbox_id
        sandbox = await get_sandbox_by_id(db, sandbox_id)
        if not sandbox or not verify_sandbox_access(sandbox, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to sandbox environment for this execution.",
            )

    decision = await authorize_action(
        user=current_user,
        operation="guardian.risk_read",
        capability="read",
        resource_type="threat_risk_assessment",
        resource_id=str(sandbox_id) if sandbox_id else "global",
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    risk_service = RiskAnalysisService(db)
    skip = (page - 1) * page_size
    if execution_id:
        assessments, total = await risk_service.get_assessments_for_execution(
            execution_id=execution_id,
            skip=skip,
            limit=page_size,
            risk_category=risk_category,
            min_score=min_score,
        )
    else:
        # Global or multi-execution query
        base_query = select(ThreatRiskAssessment)
        if risk_category:
            base_query = base_query.where(ThreatRiskAssessment.risk_category == risk_category)
        if min_score is not None:
            base_query = base_query.where(ThreatRiskAssessment.risk_score >= min_score)
        
        count_res = await db.execute(select(func.count()).select_from(base_query.subquery()))
        total = count_res.scalar_one()

        from sqlalchemy.orm import selectinload
        records_query = (
            base_query.options(
                selectinload(ThreatRiskAssessment.threat_detection),
                selectinload(ThreatRiskAssessment.asset_impacts),
            )
            .order_by(ThreatRiskAssessment.risk_score.desc(), ThreatRiskAssessment.created_at.desc())
            .offset(skip)
            .limit(page_size)
        )
        rec_res = await db.execute(records_query)
        assessments = list(rec_res.scalars().all())

    return ThreatRiskAssessmentListResponse(
        items=[_assessment_to_response(a) for a in assessments],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/risk-assessments/{assessment_id}",
    response_model=ThreatRiskAssessmentDetailResponse,
    summary="Get Threat Risk Assessment Detail",
)
async def get_risk_assessment_detail(
    assessment_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves full risk assessment detail including categorized asset impacts and rationale."""
    risk_service = RiskAnalysisService(db)
    assessment = await risk_service.get_assessment_by_id(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat risk assessment '{assessment_id}' not found.",
        )

    execution = await db.get(GuardianExecution, assessment.guardian_execution_id)
    sandbox_id = execution.sandbox_id if execution else None

    decision = await authorize_action(
        user=current_user,
        operation="guardian.risk_read",
        capability="read",
        resource_type="threat_risk_assessment",
        resource_id=str(sandbox_id) if sandbox_id else str(assessment_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    if sandbox_id:
        sandbox = await get_sandbox_by_id(db, sandbox_id)
        if not sandbox or not verify_sandbox_access(sandbox, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to sandbox environment for this risk assessment.",
            )

    return _assessment_to_detail(assessment)


@router.get(
    "/executions/{execution_id}/risk-assessments",
    response_model=ThreatRiskAssessmentListResponse,
    summary="List Risk Assessments for Execution",
)
async def list_execution_risk_assessments(
    execution_id: uuid.UUID,
    risk_category: Optional[str] = Query(None, description="Filter by risk category"),
    min_score: Optional[float] = Query(None, description="Minimum risk score filter"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves paginated risk assessments belonging to a specific Guardian execution."""
    execution = await db.get(GuardianExecution, execution_id)
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"GuardianExecution '{execution_id}' not found.",
        )

    sandbox = await get_sandbox_by_id(db, execution.sandbox_id)
    if not sandbox or not verify_sandbox_access(sandbox, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to sandbox environment for this execution.",
        )

    decision = await authorize_action(
        user=current_user,
        operation="guardian.risk_read",
        capability="read",
        resource_type="threat_risk_assessment",
        resource_id=str(execution.sandbox_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    risk_service = RiskAnalysisService(db)
    skip = (page - 1) * page_size
    assessments, total = await risk_service.get_assessments_for_execution(
        execution_id=execution_id,
        skip=skip,
        limit=page_size,
        risk_category=risk_category,
        min_score=min_score,
    )

    return ThreatRiskAssessmentListResponse(
        items=[_assessment_to_response(a) for a in assessments],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/assets/{asset_id}/risk",
    response_model=AssetRiskProfileResponse,
    summary="Get Asset Risk Profile",
)
async def get_asset_risk_profile(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves aggregated risk exposure and blast radius metrics for an asset."""
    risk_service = RiskAnalysisService(db)
    profile = await risk_service.get_asset_risk_profile(asset_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found or has no risk profile.",
        )

    decision = await authorize_action(
        user=current_user,
        operation="guardian.risk_read",
        capability="read",
        resource_type="threat_risk_assessment",
        resource_id=str(asset_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    return AssetRiskProfileResponse(**profile)


# =============================================================================
# Helper Serializers for Step 09.2.3.5
# =============================================================================

async def _check_sandbox_access(db: AsyncSession, sandbox_id: uuid.UUID, user: User) -> None:
    sandbox = await get_sandbox_by_id(db, sandbox_id)
    if not sandbox or not verify_sandbox_access(sandbox, user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to sandbox.")


def _rec_to_response(rec: DefensiveRecommendation) -> DefensiveRecommendationResponse:
    return DefensiveRecommendationResponse(
        id=rec.id,
        guardian_execution_id=rec.guardian_execution_id,
        threat_detection_id=rec.threat_detection_id,
        risk_assessment_id=rec.risk_assessment_id,
        sandbox_id=rec.sandbox_id,
        recommendation_code=rec.recommendation_code,
        title=rec.title,
        description=rec.description,
        priority=rec.priority,
        recommendation_type=rec.recommendation_type,
        playbook_id=rec.playbook_id,
        playbook_version=rec.playbook_version,
        affected_asset_ids=list(rec.affected_asset_ids or []),
        evidence_references=dict(rec.evidence_references or {}),
        rationale=rec.rationale,
        expected_outcome=rec.expected_outcome,
        verification_criteria=list(rec.verification_criteria or []),
        implementation_complexity=rec.implementation_complexity,
        status=rec.status,
        created_at=rec.created_at,
        updated_at=rec.updated_at,
        is_simulated=rec.is_simulated,
        simulation_only=rec.simulation_only,
    )


def _action_to_response(act: RemediationPlanAction) -> RemediationPlanActionResponse:
    return RemediationPlanActionResponse(
        id=act.id,
        remediation_plan_id=act.remediation_plan_id,
        recommendation_id=act.recommendation_id,
        action_code=act.action_code,
        title=act.title,
        description=act.description,
        sequence_order=act.sequence_order,
        priority=act.priority,
        depends_on=list(act.depends_on or []),
        target_asset_ids=list(act.target_asset_ids or []),
        expected_outcome=act.expected_outcome,
        verification_criteria=list(act.verification_criteria or []),
        action_type=act.action_type,
        status=act.status,
        created_at=act.created_at,
        updated_at=act.updated_at,
    )


def _plan_to_response(plan: RemediationPlan) -> RemediationPlanResponse:
    return RemediationPlanResponse(
        id=plan.id,
        guardian_execution_id=plan.guardian_execution_id,
        sandbox_id=plan.sandbox_id,
        title=plan.title,
        description=plan.description,
        overall_priority=plan.overall_priority,
        status=plan.status,
        plan_version=plan.plan_version,
        target_asset_ids=list(plan.target_asset_ids or []),
        plan_metadata=dict(plan.plan_metadata or {}),
        action_count=plan.action_count,
        created_at=plan.created_at,
        updated_at=plan.updated_at,
        is_simulated=plan.is_simulated,
        simulation_only=plan.simulation_only,
    )


def _plan_to_detail_response(plan: RemediationPlan) -> RemediationPlanDetailResponse:
    actions = [_action_to_response(a) for a in (plan.actions or [])]
    return RemediationPlanDetailResponse(
        id=plan.id,
        guardian_execution_id=plan.guardian_execution_id,
        sandbox_id=plan.sandbox_id,
        title=plan.title,
        description=plan.description,
        overall_priority=plan.overall_priority,
        status=plan.status,
        plan_version=plan.plan_version,
        target_asset_ids=list(plan.target_asset_ids or []),
        plan_metadata=dict(plan.plan_metadata or {}),
        action_count=len(actions),
        created_at=plan.created_at,
        updated_at=plan.updated_at,
        is_simulated=plan.is_simulated,
        simulation_only=plan.simulation_only,
        actions=actions,
    )


def _report_to_response(rep: IncidentReport) -> IncidentReportResponse:
    return IncidentReportResponse(
        id=rep.id,
        guardian_execution_id=rep.guardian_execution_id,
        sandbox_id=rep.sandbox_id,
        report_version=rep.report_version,
        title=rep.title,
        executive_summary=rep.executive_summary,
        threat_classifications=list(rep.threat_classifications or []),
        severity=rep.severity,
        max_risk_score=rep.max_risk_score,
        risk_category=rep.risk_category,
        affected_asset_ids=list(rep.affected_asset_ids or []),
        potentially_exposed_asset_ids=list(rep.potentially_exposed_asset_ids or []),
        blast_radius_nodes_count=rep.blast_radius_nodes_count,
        mitre_techniques=list(rep.mitre_techniques or []),
        remediation_plan_id=rep.remediation_plan_id,
        report_status=rep.report_status,
        generated_at=rep.generated_at,
        created_at=rep.created_at,
    )


def _report_to_detail_response(rep: IncidentReport) -> IncidentReportDetailResponse:
    return IncidentReportDetailResponse(
        id=rep.id,
        guardian_execution_id=rep.guardian_execution_id,
        sandbox_id=rep.sandbox_id,
        report_version=rep.report_version,
        title=rep.title,
        executive_summary=rep.executive_summary,
        threat_classifications=list(rep.threat_classifications or []),
        severity=rep.severity,
        max_risk_score=rep.max_risk_score,
        risk_category=rep.risk_category,
        affected_asset_ids=list(rep.affected_asset_ids or []),
        potentially_exposed_asset_ids=list(rep.potentially_exposed_asset_ids or []),
        blast_radius_nodes_count=rep.blast_radius_nodes_count,
        mitre_techniques=list(rep.mitre_techniques or []),
        remediation_plan_id=rep.remediation_plan_id,
        report_status=rep.report_status,
        generated_at=rep.generated_at,
        created_at=rep.created_at,
        event_timeline=list(rep.event_timeline or []),
        detection_summaries=list(rep.detection_summaries or []),
        recommendation_summaries=list(rep.recommendation_summaries or []),
        report_content=dict(rep.report_content or {}),
    )


# =============================================================================
# Playbook Endpoints
# =============================================================================

@router.get(
    "/playbooks",
    response_model=PlaybookListResponse,
    summary="List Remediation Playbooks",
)
async def list_playbooks(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves catalog of all registered defensive playbooks."""
    decision = await authorize_action(
        user=current_user,
        operation="guardian.playbook_read",
        capability="read",
        resource_type="playbook",
        resource_id="catalog",
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    library = PlaybookLibrary()
    playbooks = library.to_response_list()
    return PlaybookListResponse(playbooks=playbooks, total=len(playbooks))


# =============================================================================
# Recommendation Endpoints
# =============================================================================

@router.get(
    "/recommendations",
    response_model=DefensiveRecommendationListResponse,
    summary="List Defensive Recommendations",
)
async def list_recommendations(
    sandbox_id: Optional[uuid.UUID] = Query(None),
    priority: Optional[str] = Query(None),
    playbook_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Query defensive recommendations with optional sandbox, priority, and playbook filters."""
    decision = await authorize_action(
        user=current_user,
        operation="guardian.recommendation_read",
        capability="read",
        resource_type="defensive_recommendation",
        resource_id=str(sandbox_id) if sandbox_id else "all",
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    if sandbox_id:
        await _check_sandbox_access(db, sandbox_id, current_user)

    stmt = select(DefensiveRecommendation)
    if sandbox_id:
        stmt = stmt.where(DefensiveRecommendation.sandbox_id == sandbox_id)
    if priority:
        stmt = stmt.where(DefensiveRecommendation.priority == priority.upper())
    if playbook_id:
        stmt = stmt.where(DefensiveRecommendation.playbook_id == playbook_id)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    stmt = stmt.order_by(DefensiveRecommendation.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    recs = (await db.execute(stmt)).scalars().all()

    return DefensiveRecommendationListResponse(
        items=[_rec_to_response(r) for r in recs],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/recommendations/{recommendation_id}",
    response_model=DefensiveRecommendationResponse,
    summary="Get Defensive Recommendation Details",
)
async def get_recommendation(
    recommendation_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves details of a specific defensive recommendation."""
    rec = await db.get(DefensiveRecommendation, recommendation_id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recommendation '{recommendation_id}' not found.")

    await _check_sandbox_access(db, rec.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="guardian.recommendation_read",
        capability="read",
        resource_type="defensive_recommendation",
        resource_id=str(recommendation_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    return _rec_to_response(rec)


@router.get(
    "/executions/{execution_id}/recommendations",
    response_model=DefensiveRecommendationListResponse,
    summary="Get Recommendations for Execution",
)
async def get_execution_recommendations(
    execution_id: uuid.UUID,
    priority: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves all defensive recommendations generated for a specific Guardian execution."""
    execution = await db.get(GuardianExecution, execution_id)
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"GuardianExecution '{execution_id}' not found.")

    await _check_sandbox_access(db, execution.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="guardian.recommendation_read",
        capability="read",
        resource_type="defensive_recommendation",
        resource_id=str(execution_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    stmt = select(DefensiveRecommendation).where(DefensiveRecommendation.guardian_execution_id == execution_id)
    if priority:
        stmt = stmt.where(DefensiveRecommendation.priority == priority.upper())
    stmt = stmt.order_by(DefensiveRecommendation.priority, DefensiveRecommendation.created_at)

    recs = (await db.execute(stmt)).scalars().all()
    return DefensiveRecommendationListResponse(
        items=[_rec_to_response(r) for r in recs],
        total=len(recs),
        page=1,
        page_size=len(recs) or 50,
    )


# =============================================================================
# Remediation Plan Endpoints
# =============================================================================

@router.get(
    "/remediation-plans",
    response_model=RemediationPlanListResponse,
    summary="List Remediation Plans",
)
async def list_remediation_plans(
    sandbox_id: Optional[uuid.UUID] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Query remediation plans."""
    decision = await authorize_action(
        user=current_user,
        operation="guardian.remediation_read",
        capability="read",
        resource_type="remediation_plan",
        resource_id=str(sandbox_id) if sandbox_id else "all",
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    if sandbox_id:
        await _check_sandbox_access(db, sandbox_id, current_user)

    stmt = select(RemediationPlan)
    if sandbox_id:
        stmt = stmt.where(RemediationPlan.sandbox_id == sandbox_id)
    if status_filter:
        stmt = stmt.where(RemediationPlan.status == status_filter.lower())
    stmt = stmt.order_by(RemediationPlan.created_at.desc())

    plans = (await db.execute(stmt)).scalars().all()
    return RemediationPlanListResponse(
        items=[_plan_to_response(p) for p in plans],
        total=len(plans),
    )


@router.get(
    "/remediation-plans/{plan_id}",
    response_model=RemediationPlanDetailResponse,
    summary="Get Remediation Plan Details",
)
async def get_remediation_plan(
    plan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves full details of a remediation plan including all ordered mitigation actions."""
    from sqlalchemy.orm import selectinload
    stmt = select(RemediationPlan).where(RemediationPlan.id == plan_id).options(selectinload(RemediationPlan.actions))
    plan = (await db.execute(stmt)).scalars().first()
    if not plan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"RemediationPlan '{plan_id}' not found.")

    await _check_sandbox_access(db, plan.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="guardian.remediation_read",
        capability="read",
        resource_type="remediation_plan",
        resource_id=str(plan_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    return _plan_to_detail_response(plan)


@router.get(
    "/executions/{execution_id}/remediation-plans",
    response_model=RemediationPlanListResponse,
    summary="Get Remediation Plans for Execution",
)
async def get_execution_remediation_plans(
    execution_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves remediation plans generated for a specific execution."""
    execution = await db.get(GuardianExecution, execution_id)
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"GuardianExecution '{execution_id}' not found.")

    await _check_sandbox_access(db, execution.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="guardian.remediation_read",
        capability="read",
        resource_type="remediation_plan",
        resource_id=str(execution_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    stmt = select(RemediationPlan).where(RemediationPlan.guardian_execution_id == execution_id).order_by(RemediationPlan.created_at.desc())
    plans = (await db.execute(stmt)).scalars().all()
    return RemediationPlanListResponse(
        items=[_plan_to_response(p) for p in plans],
        total=len(plans),
    )


# =============================================================================
# Incident Report Endpoints
# =============================================================================

@router.post(
    "/executions/{execution_id}/incident-reports/generate",
    response_model=IncidentReportDetailResponse,
    summary="Generate Incident Report",
)
async def generate_incident_report_endpoint(
    execution_id: uuid.UUID,
    payload: IncidentReportGenerateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Synthesizes or updates an incident report for an execution with epistemic boundary tracking."""
    execution = await db.get(GuardianExecution, execution_id)
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"GuardianExecution '{execution_id}' not found.")

    await _check_sandbox_access(db, execution.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="guardian.report_generate",
        capability="scan",
        resource_type="incident_report",
        resource_id=str(execution_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    report_service = IncidentReportService(db)
    report = await report_service.generate_incident_report(
        execution=execution,
        report_version=payload.report_version,
        custom_title=payload.custom_title,
        include_ai_narrative=payload.include_ai_narrative,
    )
    await db.commit()
    await db.refresh(report)

    return _report_to_detail_response(report)


@router.get(
    "/incident-reports",
    response_model=IncidentReportListResponse,
    summary="List Incident Reports",
)
async def list_incident_reports(
    sandbox_id: Optional[uuid.UUID] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Query generated incident reports."""
    decision = await authorize_action(
        user=current_user,
        operation="guardian.report_read",
        capability="read",
        resource_type="incident_report",
        resource_id=str(sandbox_id) if sandbox_id else "all",
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    if sandbox_id:
        await _check_sandbox_access(db, sandbox_id, current_user)

    stmt = select(IncidentReport)
    if sandbox_id:
        stmt = stmt.where(IncidentReport.sandbox_id == sandbox_id)
    if status_filter:
        stmt = stmt.where(IncidentReport.report_status == status_filter.lower())
    stmt = stmt.order_by(IncidentReport.created_at.desc())

    reports = (await db.execute(stmt)).scalars().all()
    return IncidentReportListResponse(
        items=[_report_to_response(r) for r in reports],
        total=len(reports),
    )


@router.get(
    "/incident-reports/{report_id}",
    response_model=IncidentReportDetailResponse,
    summary="Get Incident Report Details",
)
async def get_incident_report(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves full details of an incident report including evidence timeline and epistemic sections."""
    rep = await db.get(IncidentReport, report_id)
    if not rep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"IncidentReport '{report_id}' not found.")

    await _check_sandbox_access(db, rep.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="guardian.report_read",
        capability="read",
        resource_type="incident_report",
        resource_id=str(report_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    return _report_to_detail_response(rep)


@router.get(
    "/executions/{execution_id}/incident-reports",
    response_model=IncidentReportListResponse,
    summary="Get Incident Reports for Execution",
)
async def get_execution_incident_reports(
    execution_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves all versioned incident reports for a specific execution."""
    execution = await db.get(GuardianExecution, execution_id)
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"GuardianExecution '{execution_id}' not found.")

    await _check_sandbox_access(db, execution.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="guardian.report_read",
        capability="read",
        resource_type="incident_report",
        resource_id=str(execution_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    stmt = select(IncidentReport).where(IncidentReport.guardian_execution_id == execution_id).order_by(IncidentReport.report_version.desc())
    reports = (await db.execute(stmt)).scalars().all()
    return IncidentReportListResponse(
        items=[_report_to_response(r) for r in reports],
        total=len(reports),
    )


# =============================================================================
# Executive Summary Endpoint
# =============================================================================

@router.get(
    "/executions/{execution_id}/executive-summary",
    response_model=ExecutiveSummaryResponse,
    summary="Get Executive Security Posture Summary",
)
async def get_execution_executive_summary(
    execution_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves an executive posture summary, top threats, priorities, and uncertainties."""
    execution = await db.get(GuardianExecution, execution_id)
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"GuardianExecution '{execution_id}' not found.")

    await _check_sandbox_access(db, execution.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="guardian.report_read",
        capability="read",
        resource_type="incident_report",
        resource_id=str(execution_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    report_service = IncidentReportService(db)
    summary = await report_service.generate_executive_summary(
        execution_id=execution.id,
        sandbox_id=execution.sandbox_id,
    )
    return summary


# =============================================================================
# Human Approval & Synthetic Remediation Execution Endpoints (Step 09.2.3.6)
# =============================================================================

@router.post(
    "/remediation-plans/{plan_id}/approval-requests",
    response_model=ApprovalRequestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Human Approval Request for Remediation Plan",
)
async def create_plan_approval_request(
    plan_id: uuid.UUID,
    payload: ApprovalRequestCreate = ApprovalRequestCreate(),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Submits a remediation plan for human multi-party review and approval."""
    service = ApprovalService(db)
    return await service.create_request(
        plan_id=plan_id,
        user=current_user,
        payload=payload,
    )


@router.get(
    "/approval-requests",
    response_model=ApprovalRequestListResponse,
    summary="List Human Approval Requests",
)
async def list_approval_requests(
    sandbox_id: Optional[uuid.UUID] = Query(None, description="Filter by sandbox ID"),
    remediation_plan_id: Optional[uuid.UUID] = Query(None, description="Filter by remediation plan ID"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by approval status"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists human approval requests with optional filtering."""
    service = ApprovalService(db)
    items, total = await service.list_requests(
        user=current_user,
        sandbox_id=sandbox_id,
        plan_id=remediation_plan_id,
        status_filter=status_filter,
    )
    return ApprovalRequestListResponse(items=items, total=total)


@router.get(
    "/approval-requests/{request_id}",
    response_model=ApprovalRequestResponse,
    summary="Get Approval Request by ID",
)
async def get_approval_request(
    request_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves full details of a specific approval request including all decisions."""
    service = ApprovalService(db)
    return await service.get_request(request_id=request_id, user=current_user)


@router.post(
    "/approval-requests/{request_id}/approve",
    response_model=ApprovalRequestResponse,
    summary="Record Approval Decision",
)
async def approve_request(
    request_id: uuid.UUID,
    payload: ApprovalDecisionCreate = ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Records an explicit approval decision under the multi-person four-eyes policy."""
    payload.decision = ApprovalDecisionType.APPROVED
    service = ApprovalService(db)
    return await service.record_decision(
        request_id=request_id,
        approver=current_user,
        payload=payload,
    )


@router.post(
    "/approval-requests/{request_id}/reject",
    response_model=ApprovalRequestResponse,
    summary="Record Rejection Decision",
)
async def reject_request(
    request_id: uuid.UUID,
    payload: ApprovalDecisionCreate = ApprovalDecisionCreate(decision=ApprovalDecisionType.REJECTED),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Rejects an approval request, transitioning it to REJECTED."""
    payload.decision = ApprovalDecisionType.REJECTED
    service = ApprovalService(db)
    return await service.record_decision(
        request_id=request_id,
        approver=current_user,
        payload=payload,
    )


@router.post(
    "/approval-requests/{request_id}/cancel",
    response_model=ApprovalRequestResponse,
    summary="Cancel Approval Request",
)
async def cancel_approval_request(
    request_id: uuid.UUID,
    payload: ApprovalRequestCancel = ApprovalRequestCancel(),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cancels a pending approval request."""
    service = ApprovalService(db)
    return await service.cancel_request(
        request_id=request_id,
        user=current_user,
        reason=payload.reason,
    )


@router.post(
    "/approval-requests/{request_id}/execute",
    response_model=SyntheticRemediationExecutionResponse,
    summary="Execute Approved Remediation Plan (Synthetic Only)",
)
async def execute_approved_remediation(
    request_id: uuid.UUID,
    payload: SyntheticExecutionCreate = SyntheticExecutionCreate(),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Executes an approved remediation plan inside the synthetic sandbox boundary only."""
    executor = SyntheticRemediationExecutor(session=db)
    execution = await executor.execute_approved_plan(
        approval_request_id=request_id,
        user=current_user,
    )
    return executor.execution_to_response(execution)


@router.get(
    "/remediation-executions",
    response_model=SyntheticRemediationExecutionListResponse,
    summary="List Synthetic Remediation Executions",
)
async def list_remediation_executions(
    sandbox_id: Optional[uuid.UUID] = Query(None, description="Filter by sandbox ID"),
    remediation_plan_id: Optional[uuid.UUID] = Query(None, description="Filter by remediation plan ID"),
    approval_request_id: Optional[uuid.UUID] = Query(None, description="Filter by approval request ID"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by execution status"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists synthetic remediation executions."""
    stmt = select(SyntheticRemediationExecution)
    if sandbox_id:
        stmt = stmt.where(SyntheticRemediationExecution.sandbox_id == sandbox_id)
    if remediation_plan_id:
        stmt = stmt.where(SyntheticRemediationExecution.remediation_plan_id == remediation_plan_id)
    if approval_request_id:
        stmt = stmt.where(SyntheticRemediationExecution.approval_request_id == approval_request_id)
    if status_filter:
        stmt = stmt.where(SyntheticRemediationExecution.execution_status == status_filter.lower())

    stmt = stmt.order_by(SyntheticRemediationExecution.created_at.desc())
    executions = (await db.execute(stmt)).scalars().all()

    # Authorize read
    items = []
    for ex in executions:
        try:
            await _check_sandbox_access(db, ex.sandbox_id, current_user)
            decision = await authorize_action(
                user=current_user,
                operation="guardian.approval_read",
                capability="read",
                resource_type="remediation_execution",
                resource_id=str(ex.id),
                environment="sandbox",
                session=db,
            )
            if decision.allowed:
                items.append(SyntheticRemediationExecutor.execution_to_response(ex))
        except HTTPException:
            continue

    return SyntheticRemediationExecutionListResponse(items=items, total=len(items))


@router.get(
    "/remediation-executions/{execution_id}",
    response_model=SyntheticRemediationExecutionResponse,
    summary="Get Synthetic Remediation Execution Details",
)
async def get_remediation_execution(
    execution_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves full details of a synthetic remediation execution."""
    ex = await db.get(SyntheticRemediationExecution, execution_id)
    if not ex:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SyntheticRemediationExecution '{execution_id}' not found.",
        )

    await _check_sandbox_access(db, ex.sandbox_id, current_user)
    decision = await authorize_action(
        user=current_user,
        operation="guardian.approval_read",
        capability="read",
        resource_type="remediation_execution",
        resource_id=str(execution_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    return SyntheticRemediationExecutor.execution_to_response(ex)


@router.get(
    "/remediation-executions/{execution_id}/status",
    summary="Get Execution Status and Action Summary",
)
async def get_remediation_execution_status(
    execution_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves concise status counters and verification state for an execution."""
    ex = await db.get(SyntheticRemediationExecution, execution_id)
    if not ex:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SyntheticRemediationExecution '{execution_id}' not found.",
        )

    await _check_sandbox_access(db, ex.sandbox_id, current_user)
    meta = ex.execution_metadata or {}
    return {
        "execution_id": str(ex.id),
        "sandbox_id": str(ex.sandbox_id),
        "remediation_plan_id": str(ex.remediation_plan_id),
        "approval_request_id": str(ex.approval_request_id),
        "status": ex.execution_status,
        "actions_executed": meta.get("actions_executed", 0),
        "actions_succeeded": meta.get("actions_succeeded", 0),
        "actions_failed": meta.get("actions_failed", 0),
        "verification_status": meta.get("verification_status", "pending"),
        "started_at": ex.started_at.isoformat() if ex.started_at else None,
        "completed_at": ex.completed_at.isoformat() if ex.completed_at else None,
        "is_simulated": ex.is_simulated,
    }


@router.get(
    "/remediation-executions/{execution_id}/snapshots",
    response_model=SyntheticSnapshotComparisonResponse,
    summary="Get Before and After Synthetic State Snapshots",
)
async def get_execution_snapshots(
    execution_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Compares immutable BEFORE and AFTER state snapshots with SHA-256 integrity verification."""
    query = (
        select(SyntheticRemediationExecution)
        .options(selectinload(SyntheticRemediationExecution.snapshots))
        .where(SyntheticRemediationExecution.id == execution_id)
    )
    res = await db.execute(query)
    ex = res.scalar_one_or_none()
    if not ex:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SyntheticRemediationExecution '{execution_id}' not found.",
        )

    await _check_sandbox_access(db, ex.sandbox_id, current_user)
    decision = await authorize_action(
        user=current_user,
        operation="guardian.approval_read",
        capability="read",
        resource_type="remediation_execution",
        resource_id=str(execution_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    before = next((s for s in ex.snapshots if s.snapshot_type == "BEFORE"), None)
    after = next((s for s in ex.snapshots if s.snapshot_type == "AFTER"), None)
    if not before:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Execution does not have a before snapshot available.",
        )

    return SyntheticStateSnapshotService.compare_snapshots(
        before=before,
        after=after,
    )


@router.get(
    "/remediation-executions/{execution_id}/verification",
    response_model=RemediationVerificationSummaryResponse,
    summary="Get Remediation Verification Findings",
)
async def get_execution_verification(
    execution_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves regression verification evaluation results for all actions in an execution."""
    ex = await db.get(SyntheticRemediationExecution, execution_id)
    if not ex:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SyntheticRemediationExecution '{execution_id}' not found.",
        )

    await _check_sandbox_access(db, ex.sandbox_id, current_user)
    decision = await authorize_action(
        user=current_user,
        operation="guardian.verification_read",
        capability="read",
        resource_type="remediation_verification",
        resource_id=str(execution_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    verification_engine = RegressionVerificationEngine(db)
    return await verification_engine.get_execution_verification_summary(execution_id=execution_id)


@router.get(
    "/remediation-plans/{plan_id}/verification-history",
    summary="Get Plan Verification History",
)
async def get_plan_verification_history(
    plan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves historical verification records across all executions of a remediation plan."""
    plan = await db.get(RemediationPlan, plan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"RemediationPlan '{plan_id}' not found.",
        )

    await _check_sandbox_access(db, plan.sandbox_id, current_user)
    decision = await authorize_action(
        user=current_user,
        operation="guardian.verification_read",
        capability="read",
        resource_type="remediation_verification",
        resource_id=str(plan_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    stmt = (
        select(RemediationVerification)
        .where(RemediationVerification.sandbox_id == plan.sandbox_id)
        .join(RemediationPlanAction, RemediationVerification.remediation_plan_action_id == RemediationPlanAction.id)
        .where(RemediationPlanAction.remediation_plan_id == plan_id)
        .order_by(RemediationVerification.verified_at.desc())
    )
    verifications = (await db.execute(stmt)).scalars().all()

    return {
        "remediation_plan_id": str(plan_id),
        "total": len(verifications),
        "items": [
            {
                "verification_id": str(v.id),
                "execution_id": str(v.execution_id),
                "remediation_plan_action_id": str(v.remediation_plan_action_id),
                "verification_status": v.verification_status,
                "expected_condition": v.expected_condition,
                "actual_condition": v.actual_condition,
                "verified_at": v.verified_at.isoformat(),
            }
            for v in verifications
        ],
    }


@router.get(
    "/approval-policies",
    response_model=ApprovalPolicyResponse,
    summary="Get Multi-Person Approval Policy Configuration",
)
@router.get(
    "/approval-policies/current",
    response_model=ApprovalPolicyResponse,
    summary="Get Current Approval Policy Configuration",
)
async def get_approval_policies(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns the four-eyes multi-person approval policy tiers, roles, and allowed state transitions."""
    decision = await authorize_action(
        user=current_user,
        operation="guardian.approval_policy_read",
        capability="read",
        resource_type="approval_policy",
        resource_id="current",
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    return ApprovalPolicyEngine.get_current_policy()





