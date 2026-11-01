"""Result aggregation, cross-agent evidence validation, and persistence nodes.

Combines parallel agent outputs into a unified synthesis, verifies EvidenceGuard
invariants, and persists forensic graph records.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Optional
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.safety.evidence_guard import EvidenceGuard
from app.ai.schemas.agent_schemas import AegisAgentOutput, GraphExecutionResponse
from app.ai.state.state import AegisAIState
from app.models.ai import AIAnalysisRecord

logger = logging.getLogger("aegismesh.ai.nodes.aggregation")


async def result_aggregation_node(state: AegisAIState) -> dict[str, Any]:
    """Aggregates all agent outputs, verifies evidence grounding, and builds composite synthesis."""
    logger.info("Executing result aggregation node for graph %s", state.get("graph_execution_id"))

    agent_outputs_raw = state.get("agent_outputs") or {}
    selected_agents = state.get("selected_agents") or []
    errors = state.get("errors") or []

    individual_statuses: dict[str, str] = {}
    validated_agent_outputs: dict[str, Any] = {}
    confidence_scores: list[float] = []
    fallback_used = state.get("fallback_used", False)
    all_evidence_ids: set[str] = set()

    for agent_name in selected_agents:
        output_data = agent_outputs_raw.get(agent_name)
        if output_data is None:
            individual_statuses[agent_name] = "skipped"
            continue

        if isinstance(output_data, AegisAgentOutput):
            output_dict = output_data.model_dump(mode="json")
        elif isinstance(output_data, dict):
            output_dict = output_data
        else:
            individual_statuses[agent_name] = "failed"
            continue

        # Grounding & safety enforcement
        output_dict = EvidenceGuard.enforce_synthetic_boundary(output_dict)
        if output_dict.get("fallback_used"):
            fallback_used = True

        for eid in output_dict.get("supporting_evidence_ids", []):
            all_evidence_ids.add(str(eid))

        status = output_dict.get("execution_status", "completed")
        individual_statuses[agent_name] = status
        confidence_scores.append(float(output_dict.get("confidence", 0.85)))
        validated_agent_outputs[agent_name] = output_dict

    # Determine composite execution status
    completed_count = sum(1 for s in individual_statuses.values() if s in ["completed", "fallback"])
    if not selected_agents or completed_count == 0:
        overall_status = "failed"
    elif completed_count == len(selected_agents):
        overall_status = "completed"
    else:
        overall_status = "partial"

    overall_confidence = (
        round(sum(confidence_scores) / len(confidence_scores), 2)
        if confidence_scores
        else 0.0
    )

    # Narrative synthesis
    summaries = [
        f"[{agent_name}]: {out.get('summary', '')}"
        for agent_name, out in validated_agent_outputs.items()
        if out.get("summary")
    ]
    synthesis_summary = (
        "Multi-Agent Security Synthesis: Coordinated analysis completed across "
        f"{completed_count}/{len(selected_agents)} specialized agents. "
        + " ".join(summaries[:3])
    )

    now = datetime.now(timezone.utc)
    start_time_str = state.get("start_time")
    latency_ms = 0.0
    if start_time_str:
        try:
            start_dt = datetime.fromisoformat(start_time_str)
            latency_ms = round((now - start_dt).total_seconds() * 1000, 2)
        except Exception:
            latency_ms = 10.0

    return {
        "execution_status": overall_status,
        "fallback_used": fallback_used,
        "completion_time": now.isoformat(),
        "total_latency_ms": latency_ms,
        "evidence_validation_results": {
            "total_cited_evidence_ids": len(all_evidence_ids),
            "individual_statuses": individual_statuses,
            "overall_confidence": overall_confidence,
            "synthesis_summary": synthesis_summary,
            "validated_agent_outputs": validated_agent_outputs,
        },
    }


async def final_persistence_node(
    state: AegisAIState,
    session: AsyncSession | None = None,
) -> dict[str, Any]:
    """Constructs final GraphExecutionResponse and persists record into PostgreSQL."""
    graph_id_str = state.get("graph_execution_id") or str(uuid.uuid4())
    graph_uuid = uuid.UUID(graph_id_str)
    sandbox_id_str = state.get("sandbox_id") or str(uuid.uuid4())
    sandbox_uuid = uuid.UUID(sandbox_id_str)

    parent_exec_str = state.get("execution_id")
    parent_exec_uuid = uuid.UUID(parent_exec_str) if parent_exec_str else None

    validation_results = state.get("evidence_validation_results") or {}
    individual_statuses = validation_results.get("individual_statuses") or {}
    validated_outputs_raw = validation_results.get("validated_agent_outputs") or {}
    synthesis_summary = validation_results.get("synthesis_summary") or "Multi-agent analysis completed."
    overall_confidence = float(validation_results.get("overall_confidence", 0.85))

    typed_agent_outputs: dict[str, AegisAgentOutput] = {}
    for name, out in validated_outputs_raw.items():
        try:
            typed_agent_outputs[name] = AegisAgentOutput.model_validate(out)
        except Exception as exc:
            logger.warning("Could not validate output for agent %s (%s)", name, exc)

    start_dt = (
        datetime.fromisoformat(state["start_time"])
        if state.get("start_time")
        else datetime.now(timezone.utc)
    )
    completion_dt = (
        datetime.fromisoformat(state["completion_time"])
        if state.get("completion_time")
        else datetime.now(timezone.utc)
    )

    response = GraphExecutionResponse(
        graph_execution_id=graph_uuid,
        parent_execution_id=parent_exec_uuid,
        sandbox_id=sandbox_uuid,
        request_type=state.get("request_type") or "full_investigation",
        selected_agents=state.get("selected_agents") or [],
        individual_agent_statuses=individual_statuses,
        agent_outputs=typed_agent_outputs,
        synthesis_summary=synthesis_summary,
        overall_confidence=overall_confidence,
        execution_status=state.get("execution_status") or "completed",
        fallback_used=state.get("fallback_used", False),
        is_simulated=True,
        simulation_only=True,
        started_at=start_dt,
        completed_at=completion_dt,
        total_latency_ms=state.get("total_latency_ms") or 10.0,
        total_tokens=state.get("total_tokens"),
        disclaimer=(
            "AI multi-agent outputs are strictly advisory. Deterministic risk scores, "
            "policies, and human approval remain authoritative."
        ),
    )

    # Database persistence
    if session is not None:
        try:
            record = AIAnalysisRecord(
                id=graph_uuid,
                sandbox_id=sandbox_uuid,
                guardian_execution_id=parent_exec_uuid,
                analysis_type="multi_agent_graph",
                source_entity_type="guardian_execution" if parent_exec_uuid else "sandbox",
                source_entity_id=parent_exec_uuid or sandbox_uuid,
                source_version="v1.0",
                provider="gemini/langgraph",
                model="multi-agent-orchestrator",
                prompt_version="v1.0",
                response_content=response.model_dump(mode="json"),
                evidence_references=list({
                    eid
                    for out in typed_agent_outputs.values()
                    for eid in out.supporting_evidence_ids
                }),
                fallback_used=response.fallback_used,
                fallback_reason="Template fallback used by one or more agents" if response.fallback_used else None,
                tokens_used=response.total_tokens,
                latency_ms=response.total_latency_ms,
                created_at=completion_dt,
                created_by=None,
            )
            session.add(record)
            await session.commit()
            logger.info("Persisted multi-agent graph execution record %s", graph_uuid)
        except Exception as exc:
            logger.error("Failed to persist graph record (%s: %s)", type(exc).__name__, exc, exc_info=True)

    return {
        "final_response": response.model_dump(mode="json"),
    }

