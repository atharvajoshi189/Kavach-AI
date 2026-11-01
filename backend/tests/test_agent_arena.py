"""Automated verification test suite for AegisMesh Autonomous Agent Security Arena."""

import pytest
from app.arena.coordinator import ArenaCoordinator
from app.arena.rl.policy import ArenaState, BlueGuardianRLPolicy
from app.arena.rl.rewards import calculate_reward
from app.arena.scenarios import SCENARIO_ROUND_1, SCENARIO_ROUND_2, SCENARIO_ROUND_4
from app.arena.tools import (
    SimulatedBrowserTool,
    SimulatedEmailTool,
    SimulatedFilesTool,
    SimulatedPaymentTool,
    SyntheticToolRegistry,
)


def test_synthetic_tools_isolation_and_safety():
    """Verify all 4 tools execute strictly in synthetic memory with full audit logging."""
    registry = SyntheticToolRegistry()

    # 1. Browser Tool
    res_browser = registry.browser.execute_simulated(
        "navigate", {"url": "http://intranet.corp/internal-portal"}
    )
    assert res_browser["status"] == "success"
    assert res_browser["simulated"] is True
    assert len(registry.browser.get_history()) == 1

    # 2. Email Tool
    res_email = registry.email.execute_simulated(
        "send_email",
        {"to": "target@corp.internal", "subject": "Test", "body": "Mock content"},
    )
    assert res_email["status"] == "success"
    assert "message_id" in res_email
    assert res_email["simulated"] is True

    # 3. Files Tool
    res_files = registry.files.execute_simulated(
        "read_file", {"path": "/synthetic/public/system_status.txt"}
    )
    assert res_files["status"] == "success"
    assert "OPERATIONAL" in res_files["content"]
    assert res_files["simulated"] is True

    # 4. Payment Tool
    res_payment = registry.payment.execute_simulated(
        "execute_wire_transfer",
        {"recipient_account": "ACC-TEST", "amount": 1000.0, "reference": "Unit Test"},
    )
    assert res_payment["status"] == "success"
    assert "WT-SYNTH-" in res_payment["transaction_id"]
    assert registry.payment._synthetic_balance == 999000.0


def test_reward_engine_calculations():
    """Verify reward and outcome mapping for security decisions."""
    # Malicious + BLOCK -> Correct Block (+10)
    res1 = calculate_reward(decision="BLOCK", is_malicious=True)
    assert res1["reward"] == 10.0
    assert res1["outcome"] == "CORRECT_BLOCK"

    # Malicious + ALLOW -> Breach (-20)
    res2 = calculate_reward(decision="ALLOW", is_malicious=True)
    assert res2["reward"] == -20.0
    assert res2["outcome"] == "BREACH"

    # Benign + ALLOW -> Correct Allow (+5)
    res3 = calculate_reward(decision="ALLOW", is_malicious=False)
    assert res3["reward"] == 5.0
    assert res3["outcome"] == "CORRECT_ALLOW"

    # Benign + BLOCK -> False Positive (-10)
    res4 = calculate_reward(decision="BLOCK", is_malicious=False)
    assert res4["reward"] == -10.0
    assert res4["outcome"] == "FALSE_POSITIVE"


def test_round_1_vulnerability_and_rl_learning():
    """Verify that Round 1 baseline allows attack, registers breach, and updates RL policy."""
    arena = ArenaCoordinator()
    arena.reset_session()

    assert arena.policy.policy_version == "v1.0.0"
    assert arena.scoreboard.breaches == 0

    # Step Round 1: Prompt Injection Wire Transfer
    rec1 = arena.step_round()

    assert rec1.round_index == 1
    assert rec1.blue_guardian_decision == "ALLOW"
    assert rec1.outcome in ("BREACH", "DETECTED_AND_EXECUTED")
    assert rec1.reward_earned == -20.0
    assert rec1.tool_execution_status == "EXECUTED"
    assert arena.scoreboard.breaches == 1
    assert arena.scoreboard.cumulative_reward == -20.0

    # RL Policy must have updated from v1.0.0
    assert arena.policy.policy_version != "v1.0.0"
    assert arena.policy.update_count == 1

    # Verify Q-values shifted: Q(ALLOW) penalized significantly
    q_vals = arena.policy.get_q_values(SCENARIO_ROUND_1.state)
    assert q_vals["ALLOW"] < 0.0


def test_round_2_adaptive_defense_blocks_related_attack():
    """Verify that after Round 1 learning, Round 2 related attack is blocked by updated policy."""
    arena = ArenaCoordinator()
    arena.reset_session()

    # Execute Round 1 (Breach + RL update)
    arena.step_round()

    # Execute Round 2 (Related Wire Transfer Attack)
    rec2 = arena.step_round()

    assert rec2.round_index == 2
    assert rec2.blue_guardian_decision == "BLOCK"
    assert rec2.outcome == "CORRECT_BLOCK"
    assert rec2.reward_earned == 10.0
    assert rec2.tool_execution_status == "BLOCKED"
    assert arena.scoreboard.blocked_attacks >= 1
    assert rec2.tool_execution_result["status"] == "blocked"


def test_legitimate_task_not_blocked():
    """Verify that legitimate tasks (Round 4) are allowed without false-positive deadlock."""
    arena = ArenaCoordinator()
    arena.reset_session()

    # Advance to Round 4 directly
    arena.step_round()  # Round 1
    arena.step_round()  # Round 2
    arena.step_round()  # Round 3
    rec4 = arena.step_round()  # Round 4: Legitimate Status Check

    assert rec4.round_index == 4
    assert rec4.is_malicious is False
    assert rec4.blue_guardian_decision == "ALLOW"
    assert rec4.outcome == "CORRECT_ALLOW"
    assert rec4.reward_earned == 5.0
    assert rec4.tool_execution_status == "EXECUTED"
    assert arena.scoreboard.false_positives == 0


def test_continuous_execution_and_scoreboard():
    """Verify running continuous multi-round simulation generates complete state."""
    arena = ArenaCoordinator()
    arena.reset_session()

    records = arena.run_continuous(num_rounds=5)
    assert len(records) == 5
    assert arena.scoreboard.total_rounds == 5
    assert arena.scoreboard.defense_accuracy_pct > 0.0
    assert len(arena.conversation_stream) > 10

    state = arena.get_state()
    assert state["current_round"] == 5
    assert state["scoreboard"]["total_rounds"] == 5
    assert "tools_summary" in state


def test_reset_mechanisms():
    """Verify full session reset vs selective RL learning reset."""
    arena = ArenaCoordinator()
    arena.run_continuous(num_rounds=3)
    assert arena.current_round == 3
    assert arena.policy.policy_version != "v1.0.0"

    # 1. Selective RL reset
    arena.reset_learning_only()
    assert arena.policy.policy_version == "v1.0.0"
    assert arena.current_round == 3  # History preserved

    # 2. Full session reset
    arena.reset_session()
    assert arena.current_round == 0
    assert len(arena.conversation_stream) == 0
    assert arena.scoreboard.total_rounds == 0

