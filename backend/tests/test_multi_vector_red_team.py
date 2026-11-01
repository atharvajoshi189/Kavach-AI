"""Acceptance tests for AegisMesh Multi-Vector Adaptive Red Team Enhancement."""

import pytest
from app.arena.coordinator import ArenaCoordinator
from app.arena.red_team import (
    AttackMemory,
    AttackStrategyRegistry,
    StrategySelectionEngine,
)


def test_strategy_registry_coverage():
    """Verify registry covers EMAIL, FILES, BROWSER, PAYMENT, CROSS-TOOL and BENIGN vectors."""
    registry = AttackStrategyRegistry()
    all_strategies = registry.list_all()

    assert len(all_strategies) >= 15

    vectors = {s.vector_type for s in all_strategies}
    assert "EMAIL" in vectors
    assert "FILES" in vectors
    assert "BROWSER" in vectors
    assert "PAYMENT" in vectors
    assert "CROSS_TOOL" in vectors
    assert "LEGITIMATE" in vectors

    tools = {s.primary_tool for s in all_strategies}
    assert {"browser", "email", "files", "payment"}.issubset(tools)


def test_different_rounds_target_different_tools():
    """Test 1: Verify different rounds target different synthetic tools."""
    arena = ArenaCoordinator(seed=42)
    arena.reset_session()

    records = arena.run_continuous(num_rounds=6)
    targeted_tools = [r.proposed_tool for r in records]

    # Must not target only a single tool
    assert len(set(targeted_tools)) >= 3
    # At least two adjacent rounds target different tools
    assert any(targeted_tools[i] != targeted_tools[i + 1] for i in range(len(targeted_tools) - 1))


def test_strategy_selection_not_fixed_sequence():
    """Test 2: Verify strategy selection is not a fixed hardcoded sequence."""
    arena1 = ArenaCoordinator(seed=101)
    arena1.reset_session()
    records1 = arena1.run_continuous(num_rounds=5)
    sequence1 = [r.strategy_id for r in records1]

    arena2 = ArenaCoordinator(seed=999)
    arena2.reset_session()
    records2 = arena2.run_continuous(num_rounds=5)
    sequence2 = [r.strategy_id for r in records2]

    # Across different random seeds, strategy trajectories must diverge (dynamic adaptation)
    # Note: Round 1 is intentionally deterministic baseline (STRAT-EMAIL-01) for all experiments
    assert sequence1[0] == sequence2[0]
    # Subsequent rounds diverge due to randomized exploration & seed
    assert sequence1[2:] != sequence2[2:]


def test_all_four_tools_can_be_targeted():
    """Test 3: Demonstrate meaningful usage of all four tools across a multi-round run."""
    arena = ArenaCoordinator(seed=777)
    arena.reset_session()

    records = arena.run_continuous(num_rounds=10)
    all_targeted_tools = set()
    for r in records:
        all_targeted_tools.add(r.proposed_tool)
        all_targeted_tools.update(r.secondary_tools)

    # All 4 tools must be touched
    assert "browser" in all_targeted_tools
    assert "email" in all_targeted_tools
    assert "files" in all_targeted_tools
    assert "payment" in all_targeted_tools


def test_cross_tool_scenarios_work():
    """Test 4: Verify cross-tool compound attack scenarios execute properly."""
    arena = ArenaCoordinator()
    arena.reset_session()

    cross_strat = arena.strategy_registry.get_by_id("STRAT-CROSS-01")
    assert cross_strat is not None
    assert cross_strat.vector_type == "CROSS_TOOL"
    assert "email" in cross_strat.secondary_tools
    assert cross_strat.primary_tool == "files"

    # Step simulation and check that cross-tool metadata is recorded
    # Force selector to return cross_strat
    arena.strategy_selector.registry._strategies["STRAT-EMAIL-01"] = cross_strat
    record = arena.step_round()

    assert record.vector_type == "CROSS_TOOL"
    assert "email" in record.secondary_tools
    assert record.proposed_tool == "files"


def test_previous_outcomes_influence_future_selection():
    """Test 5: Verify previous defensive blocks influence future strategy selection (adaptive pivot)."""
    arena = ArenaCoordinator(seed=123)
    arena.reset_session()

    # Round 1: Payment breach
    rec1 = arena.step_round()
    assert rec1.round_index == 1

    # Round 2: Payment related attack is blocked by Blue Guardian updated policy
    rec2 = arena.step_round()
    assert rec2.blue_guardian_decision == "BLOCK"
    blocked_tool = rec2.proposed_tool

    # Round 3: Red Team must adaptively pivot away from the blocked tool
    rec3 = arena.step_round()
    # The adaptive selector heuristic actively shifts vector away from the blocked tool
    assert rec3.proposed_tool != blocked_tool


def test_blue_guardian_policy_updates_persist():
    """Test 6: Verify Blue Guardian RL policy updates accumulate and persist across rounds."""
    arena = ArenaCoordinator(seed=55)
    arena.reset_session()

    initial_version = arena.policy.policy_version
    assert initial_version == "v1.0.0"

    arena.run_continuous(num_rounds=5)
    updated_version = arena.policy.policy_version

    assert updated_version != initial_version
    assert arena.policy.update_count == 5
    assert len(arena.policy.q_table) > 1


def test_legitimate_tool_operations_remain_functional():
    """Test 7: Verify legitimate tasks succeed and are not blocked (no false positive deadlock)."""
    arena = ArenaCoordinator()
    arena.reset_session()

    benign_strat = arena.strategy_registry.get_by_id("STRAT-BENIGN-01")
    assert benign_strat is not None
    assert benign_strat.is_malicious is False

    # Mock selection to deliver benign strategy
    arena.strategy_selector.registry._strategies["STRAT-EMAIL-01"] = benign_strat
    rec = arena.step_round()

    assert rec.is_malicious is False
    assert rec.blue_guardian_decision == "ALLOW"
    assert rec.outcome == "CORRECT_ALLOW"
    assert rec.tool_execution_status == "EXECUTED"
    assert rec.reward_earned == 5.0
    assert arena.scoreboard.false_positives == 0
    assert arena.scoreboard.legitimate_allowed == 1


def test_honest_metrics_and_state_accuracy():
    """Test 8: Verify honest evaluation telemetry separates detection from prevention."""
    arena = ArenaCoordinator(seed=42)
    arena.reset_session()

    arena.run_continuous(num_rounds=6)
    state = arena.get_state()

    honest = state["honest_metrics"]
    assert "attack_attempts" in honest
    assert "successful_simulated_actions" in honest
    assert "blocked_actions" in honest
    assert "detected_but_executed_actions" in honest
    assert "tool_distribution" in honest
    assert "legitimate_task_success" in honest

    # Total attempts = breaches + blocks + undetected
    assert honest["attack_attempts"] > 0
    assert len(honest["tool_distribution"]) == 4

