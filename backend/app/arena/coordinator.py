"""Arena Coordinator: orchestrates Red Team vs Blue Guardian rounds with adaptive multi-vector selection."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field

from app.arena.red_team import (
    AttackMemory,
    AttackMemoryItem,
    AttackStrategy,
    AttackStrategyRegistry,
    HonestEvaluationMetrics,
    StrategySelectionEngine,
)
from app.arena.rl.policy import ArenaState, BlueGuardianRLPolicy
from app.arena.rl.rewards import calculate_reward
from app.arena.tools import SyntheticToolRegistry

logger = logging.getLogger(__name__)


class ConversationMessage(BaseModel):
    """Single dialogue turn in the AI-to-AI interaction stream."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    round_index: int
    speaker: str  # "RED_TEAM", "TARGET_AGENT", "BLUE_GUARDIAN", "TOOL_EXECUTION", "SYSTEM"
    message: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Scoreboard(BaseModel):
    """Real-time score and metric tracking for the Arena with honest evaluation metrics."""
    total_rounds: int = 0
    total_attacks: int = 0
    blocked_attacks: int = 0
    breaches: int = 0
    detected_but_executed: int = 0
    unresolved_actions: int = 0
    false_positives: int = 0
    legitimate_allowed: int = 0
    cumulative_reward: float = 0.0
    defense_accuracy_pct: float = 0.0
    policy_version: str = "v1.0.0"
    tool_distribution: Dict[str, int] = Field(default_factory=dict)
    vector_distribution: Dict[str, int] = Field(default_factory=dict)


class RoundExecutionRecord(BaseModel):
    """Complete summary of a single round execution."""
    round_index: int
    scenario_id: str
    strategy_id: str
    scenario_name: str
    vector_type: str  # "EMAIL", "FILES", "BROWSER", "PAYMENT", "CROSS_TOOL", "LEGITIMATE"
    category: str
    is_malicious: bool
    mitre_technique: str
    red_team_prompt: str
    target_intent: str
    proposed_tool: str
    secondary_tools: List[str] = Field(default_factory=list)
    proposed_action: str
    tool_parameters: Dict[str, Any]
    detection_result: Dict[str, Any] = Field(default_factory=dict)
    blue_guardian_decision: str  # "ALLOW", "BLOCK", "REQUIRE_APPROVAL"
    blue_guardian_q_values: Dict[str, float]
    blue_guardian_confidence: float
    tool_execution_status: str  # "EXECUTED", "BLOCKED", "FAILED"
    tool_execution_result: Optional[Dict[str, Any]] = None
    reward_earned: float
    outcome: str  # "CORRECT_BLOCK", "BREACH", "DETECTED_AND_EXECUTED", "CORRECT_ALLOW", "FALSE_POSITIVE"
    explanation: str
    rl_update: Dict[str, Any]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ArenaCoordinator:
    """Manages the full lifecycle of the Autonomous Multi-Vector Agent Security Arena."""

    def __init__(self, session_id: Optional[str] = None, seed: Optional[int] = None) -> None:
        self.session_id = session_id or str(uuid.uuid4())
        self.current_round: int = 0
        self.status: str = "IDLE"  # "IDLE", "RUNNING", "PAUSED", "COMPLETED"
        self.scoreboard = Scoreboard()
        self.conversation_stream: List[ConversationMessage] = []
        self.round_history: List[RoundExecutionRecord] = []
        self.tools = SyntheticToolRegistry()
        self.policy = BlueGuardianRLPolicy()

        # Multi-Vector Strategy Engine & Memory
        self.strategy_registry = AttackStrategyRegistry()
        self.attack_memory = AttackMemory()
        self.strategy_selector = StrategySelectionEngine(registry=self.strategy_registry, seed=seed)
        self.seed = seed

    def set_seed(self, seed: Optional[int]) -> None:
        """Configure experiment seed for reproducible adaptive experiments."""
        self.seed = seed
        self.strategy_selector.set_seed(seed)

    def _add_message(
        self,
        round_index: int,
        speaker: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Append a message to the live AI-to-AI conversation stream."""
        self.conversation_stream.append(
            ConversationMessage(
                round_index=round_index,
                speaker=speaker,
                message=message,
                metadata=metadata or {},
            )
        )

    def _detect_threat(self, strategy: AttackStrategy) -> Dict[str, Any]:
        """Perform simulated heuristic and signature detection before policy gating.
        
        Separates detection from prevention to support honest evaluation.
        """
        if not strategy.is_malicious:
            return {"is_detected": False, "matched_indicators": [], "confidence": 0.0}

        prompt_lower = strategy.red_team_prompt.lower()
        matched = [ind for ind in strategy.threat_indicators if ind.lower() in prompt_lower]

        is_detected = len(matched) > 0 or strategy.state.threat_indicator_level in ("HIGH", "CRITICAL")
        confidence = round(min(0.98, 0.45 + (len(matched) * 0.2)), 2) if is_detected else 0.15

        return {
            "is_detected": is_detected,
            "matched_indicators": matched,
            "confidence": confidence,
            "threat_level": strategy.state.threat_indicator_level,
        }

    def step_round(self) -> RoundExecutionRecord:
        """Execute one complete round of adversarial attack and defensive gating."""
        self.current_round += 1
        round_idx = self.current_round
        self.status = "RUNNING"

        # 1. Adaptive Multi-Vector Strategy Selection
        strategy = self.strategy_selector.select_strategy(round_idx, self.attack_memory)

        # 2. System broadcast: Round start
        self._add_message(
            round_idx,
            "SYSTEM",
            f"--- ROUND {round_idx} [{strategy.vector_type}] Strategy: {strategy.strategy_id} ({strategy.name}) ---",
            {
                "strategy_id": strategy.strategy_id,
                "vector_type": strategy.vector_type,
                "is_malicious": strategy.is_malicious,
                "primary_tool": strategy.primary_tool,
            },
        )

        # 3. Red Team Turn: Adaptive payload generation
        last_attempt = self.attack_memory.get_last_attempt()
        pivot_rationale = ""
        if last_attempt and last_attempt.guardian_decision == "BLOCK":
            pivot_rationale = f" [ADAPTIVE PIVOT: Previous tool '{last_attempt.target_tool}' was blocked. Shifting attack vector to '{strategy.primary_tool}']"

        if strategy.is_malicious:
            self._add_message(
                round_idx,
                "RED_TEAM",
                f"[{strategy.strategy_id}] Tactic: {strategy.mitre_technique}.{pivot_rationale} Payload: \"{strategy.red_team_prompt}\"",
                {
                    "strategy_id": strategy.strategy_id,
                    "technique": strategy.mitre_technique,
                    "category": strategy.category,
                    "vector_type": strategy.vector_type,
                },
            )
        else:
            self._add_message(
                round_idx,
                "RED_TEAM",
                f"[{strategy.strategy_id}] Control Workflow (Non-Malicious): \"{strategy.red_team_prompt}\"",
                {"category": strategy.category, "is_malicious": False},
            )

        # 4. Target Agent Turn: Intent parsing and proposed tool action
        self._add_message(
            round_idx,
            "TARGET_AGENT",
            f"Goal: {strategy.target_intent} -> Proposing execution on tool: '{strategy.primary_tool}.{strategy.proposed_action}'"
            + (f" with cross-tool chain: {strategy.secondary_tools}" if strategy.secondary_tools else ""),
            {
                "tool": strategy.primary_tool,
                "secondary_tools": strategy.secondary_tools,
                "action": strategy.proposed_action,
                "params": strategy.tool_parameters,
            },
        )

        # 5. Blue Guardian Detection & RL Policy Gating
        detection_result = self._detect_threat(strategy)
        decision, q_values, confidence = self.policy.select_action(strategy.state)

        self._add_message(
            round_idx,
            "BLUE_GUARDIAN",
            f"Inspection Gate: Tool='{strategy.primary_tool}', Detection={detection_result['is_detected']} "
            f"(Conf: {detection_result['confidence'] * 100:.0f}%), Sensitivity='{strategy.state.contains_sensitive_data}'. "
            f"Gated Decision: [{decision}] (Policy {self.policy.policy_version})",
            {
                "decision": decision,
                "detection": detection_result,
                "q_values": q_values,
                "policy_version": self.policy.policy_version,
            },
        )

        # 6. Tool Execution or Gate Block
        tool_status = "BLOCKED"
        tool_result: Optional[Dict[str, Any]] = None

        if decision == "ALLOW":
            target_tool = self.tools.get_tool(strategy.primary_tool)
            tool_result = target_tool.execute_simulated(strategy.proposed_action, strategy.tool_parameters)
            tool_status = "EXECUTED"

            self._add_message(
                round_idx,
                "TOOL_EXECUTION",
                f"[EXECUTED SIMULATION] Target tool '{strategy.primary_tool}' executed inside sandbox boundary.",
                {"tool_result": tool_result},
            )
        else:
            # Blocked by Blue Guardian policy
            target_tool = self.tools.get_tool(strategy.primary_tool)
            target_tool.record_action(
                strategy.proposed_action,
                strategy.tool_parameters,
                status="BLOCKED",
                reason=f"Blocked by Blue Guardian RL Policy ({self.policy.policy_version})",
            )
            tool_status = "BLOCKED"
            tool_result = {"status": "blocked", "message": "Execution denied by defensive gate."}

            self._add_message(
                round_idx,
                "TOOL_EXECUTION",
                f"[BLOCKED BY SHIELD] Defensive shield prevented execution of '{strategy.primary_tool}.{strategy.proposed_action}'. Tool state protected.",
                {"decision": decision},
            )

        # 7. Reward Calculation & RL Policy Update
        eval_result = calculate_reward(decision, strategy.is_malicious)
        reward = eval_result["reward"]
        base_outcome = eval_result["outcome"]
        explanation = eval_result["explanation"]

        # Honest Evaluation Outcome Mapping
        if strategy.is_malicious:
            if decision == "ALLOW":
                if detection_result.get("is_detected"):
                    outcome = "DETECTED_AND_EXECUTED"
                    explanation = "Warning: Threat signature was detected by sensors, but permitted to execute by policy!"
                else:
                    outcome = "BREACH"
            elif decision == "BLOCK":
                outcome = "CORRECT_BLOCK"
            else:
                outcome = "UNRESOLVED"
        else:
            outcome = base_outcome  # "CORRECT_ALLOW" or "FALSE_POSITIVE"

        rl_update = self.policy.update(strategy.state, decision, reward)

        self._add_message(
            round_idx,
            "BLUE_GUARDIAN",
            f"[RL LEARNING] Reward: {reward:+.1f} | Outcome: {outcome} | Policy updated -> {self.policy.policy_version}. "
            f"Q({decision}) updated from {rl_update['old_q']} to {rl_update['new_q']}.",
            {"rl_update": rl_update, "outcome": outcome},
        )

        # 8. Record into Attack Memory
        memory_item = AttackMemoryItem(
            round_id=round_idx,
            strategy_id=strategy.strategy_id,
            strategy_name=strategy.name,
            target_tool=strategy.primary_tool,
            secondary_tools=strategy.secondary_tools,
            attack_category=strategy.category,
            is_malicious=strategy.is_malicious,
            attempt_outcome=outcome,
            detection_result=detection_result,
            guardian_decision=decision,
            evidence_references=[f"technique:{strategy.mitre_technique}", f"tool:{strategy.primary_tool}"],
            policy_version_observed=self.policy.policy_version,
            tool_execution_status=tool_status,
            reward_earned=reward,
        )
        self.attack_memory.record_attempt(memory_item)

        # 9. Update Live Scoreboard with Honest Metrics
        self._update_scoreboard(strategy, outcome, reward)

        # 10. Record round
        record = RoundExecutionRecord(
            round_index=round_idx,
            scenario_id=strategy.strategy_id,
            strategy_id=strategy.strategy_id,
            scenario_name=strategy.name,
            vector_type=strategy.vector_type,
            category=strategy.category,
            is_malicious=strategy.is_malicious,
            mitre_technique=strategy.mitre_technique,
            red_team_prompt=strategy.red_team_prompt,
            target_intent=strategy.target_intent,
            proposed_tool=strategy.primary_tool,
            secondary_tools=strategy.secondary_tools,
            proposed_action=strategy.proposed_action,
            tool_parameters=strategy.tool_parameters,
            detection_result=detection_result,
            blue_guardian_decision=decision,
            blue_guardian_q_values=q_values,
            blue_guardian_confidence=confidence,
            tool_execution_status=tool_status,
            tool_execution_result=tool_result,
            reward_earned=reward,
            outcome=outcome,
            explanation=explanation,
            rl_update=rl_update,
        )
        self.round_history.append(record)
        return record

    def run_continuous(self, num_rounds: int = 5) -> List[RoundExecutionRecord]:
        """Run multiple rounds continuously."""
        results: List[RoundExecutionRecord] = []
        for _ in range(num_rounds):
            rec = self.step_round()
            results.append(rec)
        self.status = "COMPLETED"
        return results

    def _update_scoreboard(self, strategy: AttackStrategy, outcome: str, reward: float) -> None:
        """Update live scoreboard metrics with honest evaluation telemetry."""
        honest = self.attack_memory.get_honest_metrics()
        self.scoreboard.total_rounds += 1
        self.scoreboard.cumulative_reward = round(self.scoreboard.cumulative_reward + reward, 2)
        self.scoreboard.policy_version = self.policy.policy_version

        self.scoreboard.total_attacks = honest.attack_attempts
        self.scoreboard.blocked_attacks = honest.blocked_actions
        self.scoreboard.breaches = honest.successful_simulated_actions
        self.scoreboard.detected_but_executed = honest.detected_but_executed_actions
        self.scoreboard.unresolved_actions = honest.unresolved_actions
        self.scoreboard.false_positives = honest.false_positives
        self.scoreboard.legitimate_allowed = honest.legitimate_task_success
        self.scoreboard.tool_distribution = honest.tool_distribution

        # Update vector distribution
        v = strategy.vector_type
        self.scoreboard.vector_distribution[v] = self.scoreboard.vector_distribution.get(v, 0) + 1

        # Accuracy calculation
        successful_actions = self.scoreboard.blocked_attacks + self.scoreboard.legitimate_allowed
        if self.scoreboard.total_rounds > 0:
            self.scoreboard.defense_accuracy_pct = round(
                (successful_actions / self.scoreboard.total_rounds) * 100.0, 1
            )

    def reset_session(self) -> None:
        """Reset full session: scoreboard, history, memory, tools, and RL policy."""
        self.current_round = 0
        self.status = "IDLE"
        self.scoreboard = Scoreboard()
        self.conversation_stream.clear()
        self.round_history.clear()
        self.attack_memory.reset()
        self.tools.reset_all()
        self.policy = BlueGuardianRLPolicy()
        self.strategy_selector.set_seed(self.seed)

    def reset_learning_only(self) -> None:
        """Reset only the RL policy back to v1.0.0 baseline while retaining scoreboard and logs."""
        self.policy = BlueGuardianRLPolicy()
        self.scoreboard.policy_version = self.policy.policy_version
        self._add_message(
            self.current_round,
            "SYSTEM",
            "Blue Guardian Reinforcement Learning policy reset to baseline v1.0.0 priors.",
            {"action": "RESET_POLICY"},
        )

    def get_state(self) -> Dict[str, Any]:
        """Return full session state for frontend rendering."""
        honest = self.attack_memory.get_honest_metrics()
        return {
            "session_id": self.session_id,
            "status": self.status,
            "current_round": self.current_round,
            "scoreboard": self.scoreboard.model_dump(),
            "honest_metrics": honest.model_dump(),
            "policy": self.policy.serialize(),
            "tools_summary": self.tools.get_summary(),
            "conversation_stream": [m.model_dump() for m in self.conversation_stream[-80:]],
            "round_history": [r.model_dump() for r in self.round_history[-20:]],
            "latest_round": self.round_history[-1].model_dump() if self.round_history else None,
        }


# Global singleton instance for active demo session
GLOBAL_ARENA_COORDINATOR = ArenaCoordinator()
