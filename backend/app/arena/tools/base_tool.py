"""Base class for all synthetic Target AI Agent tools in the AegisMesh Arena.

STRICT INVARIANT:
All tools in this package are 100% synthetic and execute strictly within
an isolated in-memory simulation boundary. No external network requests,
no physical filesystem access outside synthetic memory, and no real monetary
transactions can ever occur.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class ToolActionLog(BaseModel):
    """Audit log record for an attempted or executed synthetic tool action."""
    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    action: str
    parameters: Dict[str, Any]
    status: str  # "BLOCKED", "EXECUTED", "FAILED"
    result: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_simulated: bool = True


class BaseArenaTool(ABC):
    """Abstract base class for simulated target agent tools."""

    name: str = "base_tool"
    description: str = "Simulated tool"
    simulation_only: bool = True

    def __init__(self) -> None:
        if not self.simulation_only:
            raise RuntimeError("Arena tools MUST have simulation_only=True")
        self._history: List[ToolActionLog] = []

    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """Return list of supported action names."""
        pass

    @abstractmethod
    def execute_simulated(self, action: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a simulated tool action inside the synthetic boundary."""
        pass

    def record_action(
        self,
        action: str,
        parameters: Dict[str, Any],
        status: str,
        result: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
    ) -> ToolActionLog:
        """Record an attempted or executed tool action for audit and visualization."""
        entry = ToolActionLog(
            tool_name=self.name,
            action=action,
            parameters=parameters,
            status=status,
            result=result,
            reason=reason,
        )
        self._history.append(entry)
        return entry

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent action history as dictionaries."""
        return [entry.model_dump() for entry in self._history[-limit:]]

    def reset(self) -> None:
        """Reset internal tool state and logs."""
        self._history.clear()

