"""REST API endpoints for Gemini AI Provider & Intelligence Gateway."""

import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.registry import agent_registry
from app.ai.gateway.intelligence_gateway import intelligence_gateway
from app.ai.graphs.execution_service import graph_execution_service
from app.ai.schemas.agent_schemas import (
    AegisAgentOutput,
    AgentListResponse,
    GraphExecutionRequest,
    GraphExecutionResponse,
    GraphHealthResponse,
    SingleAgentExecuteRequest,
)
from app.ai.schemas.ai_responses import (
    AIAnalysisListResponse,
    AIAnalysisRecordResponse,
    AIHealthResponse,
    AIUsageMetricsResponse,
    AttackPathAnalysisResponse,
    ExecutiveBriefingResponse,
    IncidentSummaryResponse,
    RecommendationExplanationResponse,
    RiskExplanationResponse,
    SecurityQAResponse,
    ThreatExplanationResponse,
)
from app.ai.services.ai_usage_service import ai_usage
from app.core.config import settings
from app.core.permissions import get_current_user
from app.database.session import get_db
from app.models.attack_path import AttackPath
from app.models.guardian import (
    DefensiveRecommendation,
    GuardianExecution,
    IncidentReport,
    ThreatDetection,
    ThreatRiskAssessment,
)
from app.models.user import User
from app.security.gateway import authorize_action
from app.services.sandbox_service import get_sandbox_by_id, verify_sandbox_access

logger = logging.getLogger("aegismesh.api.ai")

router = APIRouter(prefix="/ai", tags=["AI Intelligence Gateway"])


async def _check_sandbox_access(session: AsyncSession, sandbox_id: uuid.UUID, user: User) -> None:
    """Verify that the user has permission to access the target sandbox."""
    sandbox = await get_sandbox_by_id(session, sandbox_id)
    if not sandbox or not verify_sandbox_access(sandbox, user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to sandbox.",
        )


class SecurityQARequest(BaseModel):
    """Payload for natural language security Q&A."""

    question: str = Field(
        ...,
        min_length=3,
        max_length=1000,
        description="The cybersecurity question to answer using execution telemetry",
    )


# --------------------------------------------------------------------------
# 1. Threat Explanation
# --------------------------------------------------------------------------
@router.post(
    "/threats/{detection_id}/explain",
    response_model=ThreatExplanationResponse,
    summary="Explain a Threat Detection",
    description="Generates an evidence-grounded explanation of a Blue Guardian threat detection.",
)
async def explain_threat(
    detection_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatExplanationResponse:
    stmt = select(ThreatDetection).where(ThreatDetection.id == detection_id)
    res = await session.execute(stmt)
    detection = res.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Threat detection not found.")

    await _check_sandbox_access(session, detection.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="ai.threat_explain",
        capability="read",
        resource_type="threat_detection",
        resource_id=str(detection.id),
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    return await intelligence_gateway.explain_threat(
        session=session,
        user=current_user,
        detection_id=detection.id,
        sandbox_id=detection.sandbox_id,
    )


# --------------------------------------------------------------------------
# 2. Attack Path Analysis
# --------------------------------------------------------------------------
@router.post(
    "/attack-paths/{attack_path_id}/analyze",
    response_model=AttackPathAnalysisResponse,
    summary="Analyze Multi-Stage Attack Path",
    description="Explains multi-stage synthetic attack progression and defensive intervention points.",
)
async def analyze_attack_path(
    attack_path_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AttackPathAnalysisResponse:
    stmt = select(AttackPath).where(AttackPath.id == attack_path_id)
    res = await session.execute(stmt)
    attack_path = res.scalar_one_or_none()
    if not attack_path:
        raise HTTPException(status_code=404, detail="Attack path not found.")

    await _check_sandbox_access(session, attack_path.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="ai.attack_path_analyze",
        capability="read",
        resource_type="attack_path",
        resource_id=str(attack_path.id),
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    return await intelligence_gateway.analyze_attack_path(
        session=session,
        user=current_user,
        attack_path_id=attack_path.id,
        sandbox_id=attack_path.sandbox_id,
    )


# --------------------------------------------------------------------------
# 3. Risk Assessment Explanation
# --------------------------------------------------------------------------
@router.post(
    "/risks/{assessment_id}/explain",
    response_model=RiskExplanationResponse,
    summary="Explain Calculated Risk Score",
    description="Explains the deterministic 6-dimensional risk score without modifying it.",
)
async def explain_risk(
    assessment_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RiskExplanationResponse:
    stmt = select(ThreatRiskAssessment).where(ThreatRiskAssessment.id == assessment_id)
    res = await session.execute(stmt)
    assessment = res.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=404, detail="Risk assessment not found.")

    await _check_sandbox_access(session, assessment.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="ai.risk_explain",
        capability="read",
        resource_type="threat_risk_assessment",
        resource_id=str(assessment.id),
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    return await intelligence_gateway.explain_risk(
        session=session,
        user=current_user,
        assessment_id=assessment.id,
        sandbox_id=assessment.sandbox_id,
    )


# --------------------------------------------------------------------------
# 4. Incident Intelligence Summary
# --------------------------------------------------------------------------
@router.post(
    "/incidents/{report_id}/summarize",
    response_model=IncidentSummaryResponse,
    summary="Synthesize Incident Summary",
    description="Synthesizes an incident narrative and defensive priorities from an IncidentReport.",
)
async def summarize_incident(
    report_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentSummaryResponse:
    stmt = select(IncidentReport).where(IncidentReport.id == report_id)
    res = await session.execute(stmt)
    report = res.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Incident report not found.")

    await _check_sandbox_access(session, report.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="ai.incident_summarize",
        capability="read",
        resource_type="incident_report",
        resource_id=str(report.id),
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    return await intelligence_gateway.summarize_incident(
        session=session,
        user=current_user,
        report_id=report.id,
        sandbox_id=report.sandbox_id,
    )


# --------------------------------------------------------------------------
# 5. Recommendation Explanation
# --------------------------------------------------------------------------
@router.post(
    "/recommendations/{recommendation_id}/explain",
    response_model=RecommendationExplanationResponse,
    summary="Explain Defensive Recommendation",
    description="Explains technical rationale, side effects, and verification criteria for a playbook countermeasure.",
)
async def explain_recommendation(
    recommendation_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RecommendationExplanationResponse:
    stmt = select(DefensiveRecommendation).where(DefensiveRecommendation.id == recommendation_id)
    res = await session.execute(stmt)
    rec = res.scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=404, detail="Defensive recommendation not found.")

    await _check_sandbox_access(session, rec.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="ai.recommendation_explain",
        capability="read",
        resource_type="defensive_recommendation",
        resource_id=str(rec.id),
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    return await intelligence_gateway.explain_recommendation(
        session=session,
        user=current_user,
        recommendation_id=rec.id,
        sandbox_id=rec.sandbox_id,
    )


# --------------------------------------------------------------------------
# 6. Executive Security Briefing
# --------------------------------------------------------------------------
@router.post(
    "/executions/{execution_id}/briefing",
    response_model=ExecutiveBriefingResponse,
    summary="Generate Executive Briefing",
    description="Produces high-level executive security briefing for a GuardianExecution run.",
)
async def generate_executive_briefing(
    execution_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ExecutiveBriefingResponse:
    stmt = select(GuardianExecution).where(GuardianExecution.id == execution_id)
    res = await session.execute(stmt)
    execution = res.scalar_one_or_none()
    if not execution:
        raise HTTPException(status_code=404, detail="Guardian execution not found.")

    await _check_sandbox_access(session, execution.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="ai.executive_briefing",
        capability="read",
        resource_type="guardian_execution",
        resource_id=str(execution.id),
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    return await intelligence_gateway.generate_executive_briefing(
        session=session,
        user=current_user,
        execution_id=execution.id,
        sandbox_id=execution.sandbox_id,
    )


# --------------------------------------------------------------------------
# 7. Security Q&A
# --------------------------------------------------------------------------
@router.post(
    "/executions/{execution_id}/qa",
    response_model=SecurityQAResponse,
    summary="Contextual Security Q&A",
    description="Answers an ad-hoc security question grounded in verified execution telemetry.",
)
async def answer_security_question(
    execution_id: uuid.UUID,
    payload: SecurityQARequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecurityQAResponse:
    stmt = select(GuardianExecution).where(GuardianExecution.id == execution_id)
    res = await session.execute(stmt)
    execution = res.scalar_one_or_none()
    if not execution:
        raise HTTPException(status_code=404, detail="Guardian execution not found.")

    await _check_sandbox_access(session, execution.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="ai.security_qa",
        capability="read",
        resource_type="guardian_execution",
        resource_id=str(execution.id),
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    return await intelligence_gateway.answer_security_question(
        session=session,
        user=current_user,
        execution_id=execution.id,
        question=payload.question,
        sandbox_id=execution.sandbox_id,
    )


# --------------------------------------------------------------------------
# 8. List Persisted Analyses
# --------------------------------------------------------------------------
@router.get(
    "/executions/{execution_id}/analyses",
    response_model=AIAnalysisListResponse,
    summary="List Persisted AI Analyses",
    description="Retrieves paginated historical AI analyses generated for an execution session.",
)
async def list_execution_analyses(
    execution_id: uuid.UUID,
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AIAnalysisListResponse:
    stmt = select(GuardianExecution).where(GuardianExecution.id == execution_id)
    res = await session.execute(stmt)
    execution = res.scalar_one_or_none()
    if not execution:
        raise HTTPException(status_code=404, detail="Guardian execution not found.")

    await _check_sandbox_access(session, execution.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="ai.analysis_read",
        capability="read",
        resource_type="guardian_execution",
        resource_id=str(execution.id),
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    items, total = await intelligence_gateway.list_execution_analyses(
        session=session,
        execution_id=execution.id,
        sandbox_id=execution.sandbox_id,
        page=page,
        page_size=page_size,
    )

    record_responses = [
        AIAnalysisRecordResponse(
            id=item.id,
            sandbox_id=item.sandbox_id,
            guardian_execution_id=item.guardian_execution_id,
            analysis_type=item.analysis_type,
            source_entity_type=item.source_entity_type,
            source_entity_id=item.source_entity_id,
            source_version=item.source_version,
            provider=item.provider,
            model=item.model,
            prompt_version=item.prompt_version,
            response_content=item.response_content,
            evidence_references=item.evidence_references,
            fallback_used=item.fallback_used,
            fallback_reason=item.fallback_reason,
            tokens_used=item.tokens_used,
            latency_ms=item.latency_ms,
            created_at=item.created_at,
            created_by=item.created_by,
        )
        for item in items
    ]

    return AIAnalysisListResponse(
        items=record_responses,
        total=total,
        page=page,
        page_size=page_size,
    )


# --------------------------------------------------------------------------
# 9. Health Status
# --------------------------------------------------------------------------
@router.get(
    "/health",
    response_model=AIHealthResponse,
    summary="AI Gateway Health Status",
    description="Probes AI Gateway provider availability and fallback readiness.",
)
async def get_ai_health() -> AIHealthResponse:
    provider_configured = bool(settings.GEMINI_ENABLED and settings.GEMINI_API_KEY)
    status_str = "healthy" if provider_configured else "degraded" if settings.GEMINI_ENABLED else "disabled"

    return AIHealthResponse(
        status=status_str,
        provider_configured=provider_configured,
        gemini_enabled=settings.GEMINI_ENABLED,
        model=settings.GEMINI_MODEL,
        fallback_ready=True,
        cache_ready=True,
    )


# --------------------------------------------------------------------------
# 10. Usage & Observability Metrics
# --------------------------------------------------------------------------
@router.get(
    "/usage",
    response_model=AIUsageMetricsResponse,
    summary="AI Gateway Usage Metrics",
    description="Returns aggregated metrics regarding token consumption, latencies, and fallbacks.",
)
async def get_ai_usage(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AIUsageMetricsResponse:
    decision = await authorize_action(
        user=current_user,
        operation="ai.usage_read",
        capability="admin",
        resource_type="ai_gateway",
        resource_id="usage",
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    return ai_usage.get_metrics()


# =============================================================================
# LangGraph Multi-Agent Orchestration Endpoints (Step 09.2.6.2)
# =============================================================================

@router.post(
    "/agents/execute",
    response_model=AegisAgentOutput,
    summary="Execute Single Specialized Agent",
    description="Invokes an individual specialized AI agent directly against sandbox evidence.",
)
async def execute_single_agent(
    payload: SingleAgentExecuteRequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AegisAgentOutput:
    await _check_sandbox_access(session, payload.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="ai.agent_execute",
        capability="read",
        resource_type="agent",
        resource_id=payload.agent_name,
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    try:
        return await graph_execution_service.execute_single_agent(
            session=session,
            user=current_user,
            request=payload,
        )
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.post(
    "/graphs/execute",
    response_model=GraphExecutionResponse,
    summary="Execute Multi-Agent Security Graph",
    description="Orchestrates specialized AI agents to analyze and correlate evidence using LangGraph.",
)
async def execute_graph(
    payload: GraphExecutionRequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GraphExecutionResponse:
    await _check_sandbox_access(session, payload.sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="ai.graph_execute",
        capability="read",
        resource_type="graph",
        resource_id=str(payload.sandbox_id),
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    return await graph_execution_service.execute_graph(
        session=session,
        user=current_user,
        request=payload,
    )


@router.get(
    "/graphs/health",
    response_model=GraphHealthResponse,
    summary="LangGraph Layer Health Probe",
    description="Reports the availability of LangGraph multi-agent coordination layer.",
)
async def get_graph_health() -> GraphHealthResponse:
    provider_ready = bool(settings.GEMINI_ENABLED and settings.GEMINI_API_KEY)
    status_str = "healthy" if provider_ready else "degraded"

    return GraphHealthResponse(
        status=status_str,
        langgraph_available=True,
        gemini_provider_available=provider_ready,
        active_registered_agents=[a.agent_name for a in agent_registry.list_all()],
    )


@router.get(
    "/graphs/{graph_execution_id}",
    response_model=GraphExecutionResponse,
    summary="Get Multi-Agent Graph Execution Result",
    description="Retrieves a persisted multi-agent graph execution result by session UUID.",
)
async def get_graph_execution(
    graph_execution_id: uuid.UUID,
    sandbox_id: uuid.UUID = Query(..., description="Target sandbox UUID for authorization"),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> GraphExecutionResponse:
    await _check_sandbox_access(session, sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="ai.graph_read",
        capability="read",
        resource_type="graph",
        resource_id=str(graph_execution_id),
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    resp = await graph_execution_service.get_graph_execution(
        session=session,
        graph_execution_id=graph_execution_id,
        sandbox_id=sandbox_id,
    )
    if not resp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Graph execution record not found in sandbox.",
        )
    return resp


@router.get(
    "/graphs/{graph_execution_id}/agents",
    response_model=dict[str, AegisAgentOutput],
    summary="Get Individual Agent Outputs from Graph Run",
    description="Returns the breakdown of outputs produced by each specialized agent during a graph run.",
)
async def get_graph_agent_outputs(
    graph_execution_id: uuid.UUID,
    sandbox_id: uuid.UUID = Query(..., description="Target sandbox UUID"),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, AegisAgentOutput]:
    await _check_sandbox_access(session, sandbox_id, current_user)

    decision = await authorize_action(
        user=current_user,
        operation="ai.graph_read",
        capability="read",
        resource_type="graph",
        resource_id=str(graph_execution_id),
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    resp = await graph_execution_service.get_graph_execution(
        session=session,
        graph_execution_id=graph_execution_id,
        sandbox_id=sandbox_id,
    )
    if not resp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Graph execution record not found in sandbox.",
        )
    return resp.agent_outputs


@router.get(
    "/agents",
    response_model=AgentListResponse,
    summary="List Registered Specialized AI Agents",
    description="Returns public metadata specifications and responsibilities for all registered agents.",
)
async def list_agents(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AgentListResponse:
    decision = await authorize_action(
        user=current_user,
        operation="ai.agent_list",
        capability="read",
        resource_type="agents",
        resource_id="registry",
        environment="sandbox",
        session=session,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    metadata_list = agent_registry.list_metadata()
    return AgentListResponse(
        agents=metadata_list,
        total_agents=len(metadata_list),
    )
