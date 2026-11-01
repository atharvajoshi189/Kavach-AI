"""Event correlation engine for attack path execution results."""
from typing import Any
import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.attack_path import AttackPath
from app.models.attack_path_stage import AttackPathStage
from app.models.attack_run import AttackRun


async def correlate_attack_path_events(
    session: AsyncSession,
    attack_path: AttackPath,
) -> list[dict[str, Any]]:
    """
    Reads AttackRun.execution_metadata for each completed stage's attack_run_id
    and assembles a correlated, deduplicated event stream sorted by timestamp.
    """
    correlated: list[dict[str, Any]] = []
    seen_event_ids: set[str] = set()

    for stage in attack_path.stages:
        if not stage.attack_run_id:
            continue

        run = await session.get(AttackRun, stage.attack_run_id)
        if not run:
            continue

        metadata = run.execution_metadata or {}
        events = metadata.get("events", [])
        for ev in events:
            event_id = ev.get("event_id") or ev.get("id")
            if event_id and event_id in seen_event_ids:
                continue
            if event_id:
                seen_event_ids.add(event_id)

            correlated.append({
                **ev,
                "attack_path_id": str(attack_path.id),
                "stage_id": str(stage.id),
                "execution_id": str(attack_path.execution_id) if attack_path.execution_id else None,
                "sequence_number": stage.sequence_number,
                "scenario_id": stage.scenario_id,
                "is_simulated": True,
                "simulation_only": True,
            })

    # Sort by timestamp
    def get_ts(ev: dict) -> str:
        return ev.get("timestamp") or ""

    correlated.sort(key=get_ts)
    return correlated

