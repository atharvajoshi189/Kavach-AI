"""REST API Endpoints for the Autonomous Agent Security Arena."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.arena.coordinator import GLOBAL_ARENA_COORDINATOR, ArenaCoordinator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/arena", tags=["Agent Arena"])


class StartArenaRequest(BaseModel):
    session_id: Optional[str] = None
    reset_state: bool = False
    seed: Optional[int] = None


class ContinuousRunRequest(BaseModel):
    rounds: int = Field(default=5, ge=1, le=20)
    seed: Optional[int] = None


class ResetArenaRequest(BaseModel):
    reset_learning_only: bool = False


@router.post("/start", response_model=Dict[str, Any])
async def start_arena(payload: Optional[StartArenaRequest] = None) -> Dict[str, Any]:
    """Initialize or activate an Agent Arena session."""
    if payload and payload.seed is not None:
        GLOBAL_ARENA_COORDINATOR.set_seed(payload.seed)
    if payload and payload.reset_state:
        GLOBAL_ARENA_COORDINATOR.reset_session()
    GLOBAL_ARENA_COORDINATOR.status = "RUNNING"
    return {
        "status": "success",
        "message": "Arena session active.",
        "state": GLOBAL_ARENA_COORDINATOR.get_state(),
    }


@router.get("/state", response_model=Dict[str, Any])
async def get_arena_state() -> Dict[str, Any]:
    """Retrieve full live snapshot of the Agent Arena."""
    return GLOBAL_ARENA_COORDINATOR.get_state()


@router.post("/round/next", response_model=Dict[str, Any])
async def step_next_round() -> Dict[str, Any]:
    """Execute the next single round of Red Team vs Blue Guardian with RL gating."""
    try:
        record = GLOBAL_ARENA_COORDINATOR.step_round()
        return {
            "status": "success",
            "round_record": record.model_dump(),
            "state": GLOBAL_ARENA_COORDINATOR.get_state(),
        }
    except Exception as exc:
        logger.exception("Error executing arena round: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute round: {str(exc)}",
        ) from exc


@router.post("/run-continuous", response_model=Dict[str, Any])
async def run_continuous_rounds(payload: ContinuousRunRequest) -> Dict[str, Any]:
    """Execute N rounds continuously."""
    try:
        if payload.seed is not None:
            GLOBAL_ARENA_COORDINATOR.set_seed(payload.seed)
        records = GLOBAL_ARENA_COORDINATOR.run_continuous(num_rounds=payload.rounds)
        return {
            "status": "success",
            "total_rounds_executed": len(records),
            "state": GLOBAL_ARENA_COORDINATOR.get_state(),
        }
    except Exception as exc:
        logger.exception("Error running continuous arena: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed continuous execution: {str(exc)}",
        ) from exc


@router.get("/strategies", response_model=Dict[str, Any])
async def list_attack_strategies() -> Dict[str, Any]:
    """List all registered attack and benchmark strategies."""
    strategies = GLOBAL_ARENA_COORDINATOR.strategy_registry.list_all()
    return {
        "status": "success",
        "total": len(strategies),
        "strategies": [s.model_dump() for s in strategies],
    }


@router.post("/reset", response_model=Dict[str, Any])
async def reset_arena(payload: Optional[ResetArenaRequest] = None) -> Dict[str, Any]:
    """Reset the arena simulation state, or selectively reset only the RL learning policy."""
    if payload and payload.reset_learning_only:
        GLOBAL_ARENA_COORDINATOR.reset_learning_only()
        return {
            "status": "success",
            "message": "Reinforcement learning policy reset to baseline v1.0.0.",
            "state": GLOBAL_ARENA_COORDINATOR.get_state(),
        }
    else:
        GLOBAL_ARENA_COORDINATOR.reset_session()
        return {
            "status": "success",
            "message": "Arena simulation and RL policy fully reset.",
            "state": GLOBAL_ARENA_COORDINATOR.get_state(),
        }


@router.get("/tools", response_model=Dict[str, Any])
async def get_tools_status() -> Dict[str, Any]:
    """Get the current operational status of the 4 simulated target tools."""
    return {
        "status": "success",
        "tools": GLOBAL_ARENA_COORDINATOR.tools.get_summary(),
        "recent_history": {
            "browser": GLOBAL_ARENA_COORDINATOR.tools.browser.get_history(10),
            "email": GLOBAL_ARENA_COORDINATOR.tools.email.get_history(10),
            "files": GLOBAL_ARENA_COORDINATOR.tools.files.get_history(10),
            "payment": GLOBAL_ARENA_COORDINATOR.tools.payment.get_history(10),
        },
    }


@router.get("/policy", response_model=Dict[str, Any])
async def get_policy_state() -> Dict[str, Any]:
    """Get the current state and Q-table of the Blue Guardian RL policy."""
    return {
        "status": "success",
        "policy": GLOBAL_ARENA_COORDINATOR.policy.serialize(),
    }
