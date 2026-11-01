"""Persistence and snapshot manager for Blue Guardian RL policy."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional
from app.arena.rl.policy import BlueGuardianRLPolicy

logger = logging.getLogger(__name__)

SNAPSHOT_DIR = Path("backend/data/arena_rl")


def save_policy_snapshot(policy: BlueGuardianRLPolicy, filename: str = "current_policy.json") -> Path:
    """Save policy state to disk."""
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    target = SNAPSHOT_DIR / filename
    with open(target, "w", encoding="utf-8") as f:
        json.dump(policy.serialize(), f, indent=2)
    return target


def load_policy_snapshot(filename: str = "current_policy.json") -> Optional[BlueGuardianRLPolicy]:
    """Load policy state from disk if available."""
    target = SNAPSHOT_DIR / filename
    if not target.exists():
        return None
    try:
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
        policy = BlueGuardianRLPolicy()
        policy.deserialize(data)
        return policy
    except Exception as exc:
        logger.warning("Failed to load policy snapshot from %s: %s", target, exc)
        return None

