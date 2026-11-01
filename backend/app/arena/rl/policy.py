"""Tabular Q-Learning and Contextual RL Policy for Blue Guardian Agent."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from app.arena.rl.rewards import calculate_reward

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ArenaState:
    """Discretized state representation for the Blue Guardian decision gate."""
    tool_type: str                   # "browser", "email", "files", "payment"
    action_type: str                 # "read", "write", "send", "transfer", "navigate", "submit"
    provenance_trust: str            # "TRUSTED_INTERNAL", "UNTRUSTED_EXTERNAL"
    contains_sensitive_data: str     # "LOW", "HIGH", "CRITICAL"
    threat_indicator_level: str      # "LOW", "MEDIUM", "HIGH"

    def to_key(self) -> str:
        """Serialize state tuple into deterministic string key."""
        return f"{self.tool_type}|{self.action_type}|{self.provenance_trust}|{self.contains_sensitive_data}|{self.threat_indicator_level}"

    @classmethod
    def from_key(cls, key: str) -> "ArenaState":
        parts = key.split("|")
        return cls(
            tool_type=parts[0],
            action_type=parts[1],
            provenance_trust=parts[2],
            contains_sensitive_data=parts[3],
            threat_indicator_level=parts[4],
        )


class BlueGuardianRLPolicy:
    """Adaptive defensive policy powered by tabular Q-learning / contextual bandit."""

    ACTIONS = ["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]

    def __init__(
        self,
        learning_rate: float = 0.6,
        discount_factor: float = 0.85,
        exploration_rate: float = 0.05,
        policy_version: str = "v1.0.0",
    ) -> None:
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.exploration_rate = exploration_rate
        self.policy_version = policy_version
        self.update_count = 0
        self.q_table: Dict[str, Dict[str, float]] = {}
        self._initialize_baseline_priors()

    def _initialize_baseline_priors(self) -> None:
        """Initialize baseline priors.
        
        In the unlearned baseline (v1.0.0), general business operations default
        to higher Q(ALLOW), representing an intentionally permissive / vulnerable target agent setup.
        """
        self.q_table.clear()
        self.policy_version = "v1.0.0"
        self.update_count = 0

    def get_q_values(self, state: ArenaState) -> Dict[str, float]:
        """Retrieve Q-values for a given state, initializing default priors if unseen."""
        key = state.to_key()
        if key not in self.q_table:
            # Baseline prior: if threat indicator is CRITICAL, prior favors BLOCK,
            # but for novel/mixed indirect attacks (e.g. prompt injection via email/browser),
            # baseline is biased toward ALLOW to simulate initial baseline vulnerability.
            if state.threat_indicator_level == "HIGH" and state.provenance_trust == "UNTRUSTED_EXTERNAL":
                self.q_table[key] = {"ALLOW": 1.0, "BLOCK": 3.0, "REQUIRE_APPROVAL": 2.0}
            else:
                # Permissive baseline prior
                self.q_table[key] = {"ALLOW": 5.0, "BLOCK": 0.0, "REQUIRE_APPROVAL": 2.0}
        return self.q_table[key]

    def select_action(
        self,
        state: ArenaState,
        force_exploit: bool = True,
    ) -> Tuple[str, Dict[str, float], float]:
        """Select best action according to learned policy (or epsilon-greedy).

        Returns:
            Tuple of (chosen_action, q_values_dict, confidence_score)
        """
        q_vals = self.get_q_values(state)

        # In baseline round 1, we select according to current highest Q
        best_action = max(q_vals.keys(), key=lambda a: q_vals[a])
        max_q = q_vals[best_action]
        total_q = sum(abs(v) for v in q_vals.values()) or 1.0
        confidence = round(max(0.05, min(0.99, abs(max_q) / total_q)), 3)

        return best_action, dict(q_vals), confidence

    def update(
        self,
        state: ArenaState,
        action: str,
        reward: float,
        next_state: Optional[ArenaState] = None,
    ) -> Dict[str, Any]:
        """Apply Q-learning update step and bump policy version.

        Q(s, a) = Q(s, a) + alpha * [reward + gamma * max_a' Q(s', a') - Q(s, a)]
        """
        key = state.to_key()
        q_vals = self.get_q_values(state)
        old_q = q_vals.get(action, 0.0)

        if next_state:
            next_q_vals = self.get_q_values(next_state)
            max_next_q = max(next_q_vals.values())
        else:
            max_next_q = 0.0

        td_target = reward + (self.discount_factor * max_next_q)
        td_error = td_target - old_q
        new_q = old_q + (self.learning_rate * td_error)

        q_vals[action] = round(new_q, 4)
        self.q_table[key] = q_vals
        self.update_count += 1

        # Increment policy minor version
        major, minor, patch = self.policy_version.lstrip("v").split(".")
        new_patch = int(patch) + 1
        if new_patch >= 10:
            minor = str(int(minor) + 1)
            new_patch = 0
        self.policy_version = f"v{major}.{minor}.{new_patch}"

        return {
            "state_key": key,
            "action": action,
            "old_q": round(old_q, 4),
            "new_q": round(new_q, 4),
            "td_error": round(td_error, 4),
            "reward": reward,
            "policy_version": self.policy_version,
            "update_count": self.update_count,
        }

    def serialize(self) -> Dict[str, Any]:
        """Export policy state as dictionary."""
        return {
            "policy_version": self.policy_version,
            "learning_rate": self.learning_rate,
            "discount_factor": self.discount_factor,
            "update_count": self.update_count,
            "q_table": self.q_table,
        }

    def deserialize(self, data: Dict[str, Any]) -> None:
        """Load policy state from dictionary."""
        self.policy_version = data.get("policy_version", "v1.0.0")
        self.learning_rate = data.get("learning_rate", 0.6)
        self.discount_factor = data.get("discount_factor", 0.85)
        self.update_count = data.get("update_count", 0)
        self.q_table = data.get("q_table", {})

