"""Deterministic Simulation Engine for AegisMesh 2.0 Red Team Operations.

Provides fully synthetic attack simulation execution against synthetic target assets
without invoking network sockets, subprocesses, or real-world exploits.
"""

import logging
from typing import Any, Optional
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.red_team.scenario_registry import (
    RedTeamScenarioNotFoundError,
    ScenarioAssetIncompatibleError,
    registry,
)
from app.agents.red_team.schemas import ScenarioMetadataResponse, SimulationResult
from app.models.synthetic_asset import SyntheticAsset
from app.services.sandbox_service import get_asset_by_id

logger = logging.getLogger("aegismesh.simulation_engine")


class SimulationEngine:
    """Orchestrates deterministic synthetic attack scenario execution."""

    def __init__(self) -> None:
        self.registry = registry

    def list_available_scenarios(self) -> list[ScenarioMetadataResponse]:
        """Returns metadata for all registered simulation scenarios."""
        return [scenario.to_metadata() for scenario in self.registry.list_all()]

    def get_scenario_metadata(self, scenario_id: str) -> ScenarioMetadataResponse:
        """Returns metadata for a specific scenario, or raises RedTeamScenarioNotFoundError."""
        scenario = self.registry.get(scenario_id)
        return scenario.to_metadata()

    async def execute_simulation(
        self,
        scenario_id: str,
        asset: SyntheticAsset,
        parameters: Optional[dict[str, Any]] = None,
        session: Optional[AsyncSession] = None,
    ) -> SimulationResult:
        """Executes a registered simulation scenario deterministically against a synthetic asset.

        Enforces:
        - Scenario registration verification.
        - Asset type compatibility verification.
        - 100% synthetic execution invariant.
        """
        # 1. Lookup scenario definition (raises RedTeamScenarioNotFoundError if invalid)
        scenario_def = self.registry.get(scenario_id)

        # 2. Validate asset compatibility (raises ScenarioAssetIncompatibleError if invalid)
        self.registry.validate_asset_compatibility(scenario_id, asset.asset_type)

        logger.info(
            "Executing deterministic simulation scenario '%s' against synthetic asset '%s' (%s)",
            scenario_id,
            asset.name,
            asset.id,
        )

        # 3. Dispatch to deterministic handler (providing session if supported)
        import inspect
        sig = inspect.signature(scenario_def.handler)
        if "session" in sig.parameters:
            result = await scenario_def.handler(asset, parameters, session=session)
        else:
            result = await scenario_def.handler(asset, parameters)

        # 4. Strict safety verification: result must declare simulation_only
        if not result.simulation_only:
            logger.error("Simulation invariant violated: simulation_only was False.")
            raise RuntimeError("Simulation safety invariant violated.")

        return result


# Singleton instance for platform-wide simulation execution
simulation_engine = SimulationEngine()

