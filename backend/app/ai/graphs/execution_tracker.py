"""AgentExecutionTracker for monitoring and auditing live LangGraph runs."""

from datetime import datetime, timezone
import logging
import threading
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger("aegismesh.ai.graph.tracker")


class AgentExecutionTracker:
    """Thread-safe telemetry tracker for in-flight and historical multi-agent graph executions."""

    def __init__(self, max_history: int = 200) -> None:
        self._lock = threading.Lock()
        self._max_history = max_history
        self._active_runs: Dict[str, Dict[str, Any]] = {}
        self._history: List[Dict[str, Any]] = []

    def start_execution(
        self,
        graph_execution_id: uuid.UUID,
        sandbox_id: uuid.UUID,
        request_type: str,
        selected_agents: List[str],
    ) -> None:
        """Records the start of a graph execution session."""
        gid = str(graph_execution_id)
        with self._lock:
            self._active_runs[gid] = {
                "graph_execution_id": gid,
                "sandbox_id": str(sandbox_id),
                "request_type": request_type,
                "selected_agents": selected_agents,
                "status": "in_progress",
                "started_at": datetime.now(timezone.utc).isoformat(),
            }

    def complete_execution(
        self,
        graph_execution_id: uuid.UUID,
        status: str,
        fallback_used: bool,
        latency_ms: float,
        agent_statuses: Dict[str, str],
    ) -> None:
        """Records the completion of a graph execution session."""
        gid = str(graph_execution_id)
        with self._lock:
            record = self._active_runs.pop(gid, None)
            if not record:
                record = {
                    "graph_execution_id": gid,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                }
            record.update({
                "status": status,
                "fallback_used": fallback_used,
                "latency_ms": latency_ms,
                "agent_statuses": agent_statuses,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            })
            self._history.append(record)
            if len(self._history) > self._max_history:
                self._history.pop(0)

    def get_execution(self, graph_execution_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        """Retrieves tracking telemetry for a specific graph execution."""
        gid = str(graph_execution_id)
        with self._lock:
            if gid in self._active_runs:
                return dict(self._active_runs[gid])
            for h in reversed(self._history):
                if h["graph_execution_id"] == gid:
                    return dict(h)
        return None

    def get_metrics(self) -> Dict[str, Any]:
        """Returns aggregate execution telemetry for health and monitoring."""
        with self._lock:
            total = len(self._history)
            fallbacks = sum(1 for h in self._history if h.get("fallback_used"))
            completed = sum(1 for h in self._history if h.get("status") == "completed")
            latencies = [h.get("latency_ms", 0.0) for h in self._history if "latency_ms" in h]
            avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

            return {
                "active_runs_count": len(self._active_runs),
                "total_completed_runs": total,
                "successful_runs": completed,
                "fallback_runs": fallbacks,
                "average_latency_ms": avg_latency,
            }


# Global execution tracker
agent_tracker = AgentExecutionTracker()

