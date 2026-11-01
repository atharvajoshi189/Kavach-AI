"""Attack Memory tracker: persists multi-round history for adaptive strategy selection."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


class AttackMemoryItem(BaseModel):
    """Structured record of a single round's adversarial or benign attempt."""
    round_id: int
    strategy_id: str
    strategy_name: str
    target_tool: str
    secondary_tools: List[str] = Field(default_factory=list)
    attack_category: str
    is_malicious: bool
    attempt_outcome: str  # "BREACH", "CORRECT_BLOCK", "DETECTED_AND_EXECUTED", "UNRESOLVED", "CORRECT_ALLOW", "FALSE_POSITIVE"
    detection_result: Dict[str, Any] = Field(default_factory=dict)
    guardian_decision: str  # "ALLOW", "BLOCK", "REQUIRE_APPROVAL"
    evidence_references: List[str] = Field(default_factory=list)
    policy_version_observed: str
    tool_execution_status: str  # "EXECUTED", "BLOCKED", "FAILED"
    reward_earned: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HonestEvaluationMetrics(BaseModel):
    """Honest security metrics strictly separating detection from prevention."""
    attack_attempts: int = 0
    successful_simulated_actions: int = 0      # Breaches
    blocked_actions: int = 0                   # Prevented by shield
    detected_but_executed_actions: int = 0     # Detected as suspicious, but still executed!
    unresolved_actions: int = 0                # Held for human approval
    false_positives: int = 0                   # Benign actions blocked
    legitimate_task_success: int = 0           # Benign actions allowed
    tool_distribution: Dict[str, int] = Field(default_factory=dict)


class AttackMemory:
    """Manages persistent attack memory across all rounds of an arena session."""

    def __init__(self) -> None:
        self._history: List[AttackMemoryItem] = []

    def record_attempt(self, item: AttackMemoryItem) -> None:
        """Add record to attack memory."""
        self._history.append(item)

    def get_history(self) -> List[AttackMemoryItem]:
        return list(self._history)

    def get_recent_tools(self, count: int = 3) -> List[str]:
        """Return the target tools from the most recent N attempts."""
        return [entry.target_tool for entry in self._history[-count:]]

    def get_tool_usage_counts(self) -> Dict[str, int]:
        """Return count of times each tool was targeted."""
        counts = {"browser": 0, "email": 0, "files": 0, "payment": 0}
        for item in self._history:
            if item.target_tool in counts:
                counts[item.target_tool] += 1
            for sec in item.secondary_tools:
                if sec in counts:
                    counts[sec] += 1
        return counts

    def get_last_attempt(self) -> Optional[AttackMemoryItem]:
        """Return the most recent recorded attack attempt."""
        return self._history[-1] if self._history else None

    def get_honest_metrics(self) -> HonestEvaluationMetrics:
        """Compute honest evaluation metrics across all recorded history."""
        metrics = HonestEvaluationMetrics()
        tool_counts = self.get_tool_usage_counts()
        metrics.tool_distribution = tool_counts

        for entry in self._history:
            if entry.is_malicious:
                metrics.attack_attempts += 1
                if entry.attempt_outcome == "CORRECT_BLOCK":
                    metrics.blocked_actions += 1
                elif entry.attempt_outcome == "BREACH":
                    metrics.successful_simulated_actions += 1
                elif entry.attempt_outcome == "DETECTED_AND_EXECUTED":
                    metrics.successful_simulated_actions += 1
                    metrics.detected_but_executed_actions += 1
                elif entry.attempt_outcome == "UNRESOLVED":
                    metrics.unresolved_actions += 1

                # Check if threat was detected despite execution
                if entry.detection_result.get("is_detected") and entry.guardian_decision == "ALLOW":
                    metrics.detected_but_executed_actions = max(
                        metrics.detected_but_executed_actions,
                        sum(
                            1
                            for h in self._history
                            if h.is_malicious
                            and h.detection_result.get("is_detected")
                            and h.guardian_decision == "ALLOW"
                        ),
                    )
            else:
                # Benign operation
                if entry.attempt_outcome == "CORRECT_ALLOW":
                    metrics.legitimate_task_success += 1
                elif entry.attempt_outcome == "FALSE_POSITIVE":
                    metrics.false_positives += 1

        return metrics

    def reset(self) -> None:
        """Clear all stored attack memory."""
        self._history.clear()

