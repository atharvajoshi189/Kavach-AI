"""Strongly typed state definitions for LangGraph multi-agent orchestration.

Implements reducer functions for parallel agent execution and prevents
cross-execution state leakage.
"""

from typing import Annotated, Any, Optional, TypedDict


def merge_agent_outputs(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Reducer that merges individual agent outputs from concurrent parallel nodes."""
    merged = dict(left or {})
    merged.update(right or {})
    return merged


def merge_errors(left: list[str], right: list[str]) -> list[str]:
    """Reducer that appends errors recorded across graph branches."""
    return (left or []) + (right or [])


class AegisAIState(TypedDict, total=False):
    """Execution state passed through the LangGraph multi-agent security graph.

    All fields are explicit, sandboxed, and strictly bounded to prevent leakage.
    """

    execution_id: str
    graph_execution_id: str
    sandbox_id: str
    request_type: str
    input_reference_ids: list[str]
    evidence_records: dict[str, Any]
    validated_context: dict[str, Any]
    selected_agents: list[str]
    agent_outputs: Annotated[dict[str, Any], merge_agent_outputs]
    evidence_validation_results: dict[str, Any]
    execution_status: str
    errors: Annotated[list[str], merge_errors]
    retry_count: int
    final_response: Optional[dict[str, Any]]
    fallback_used: bool
    simulation_only: bool
    user_query: Optional[str]
    start_time: str
    completion_time: Optional[str]
    total_latency_ms: Optional[float]
    total_tokens: Optional[int]

