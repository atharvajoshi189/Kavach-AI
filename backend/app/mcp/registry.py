"""Centralized Tool Registry for the AegisMesh MCP server.

Enforces explicit metadata, strict validation schemas, role requirements, and environment
isolation for all registered tools. Prevents dynamic registration of untrusted code.
"""

from collections.abc import Callable
from dataclasses import dataclass
import logging
from typing import Any, Optional
from mcp.server import MCPServer
from pydantic import BaseModel
from app.mcp.schemas.tools import (
    GetAgentInput,
    GetCampaignInput,
    GetIncidentInput,
    ListAgentsInput,
    ListCampaignsInput,
    ListIncidentsInput,
    SystemHealthInput,
    TargetGetSimulatedFindingsInput,
    TargetInspectAssetInput,
    TargetListAssetsInput,
)
from app.mcp.tools.agent_tools import get_agent, list_agents
from app.mcp.tools.campaign_tools import get_campaign, list_campaigns
from app.mcp.tools.incident_tools import get_incident, list_incidents
from app.mcp.tools.system_tools import system_health
from app.mcp.tools.target_tools import (
    target_get_simulated_findings,
    target_inspect_asset,
    target_list_assets,
)

logger = logging.getLogger("aegismesh.mcp.registry")


@dataclass(frozen=True)
class ToolMetadata:
    """Metadata and security boundary parameters for an MCP tool."""

    name: str
    description: str
    input_schema: type[BaseModel]
    handler: Callable[..., Any]
    required_capability: str
    resource_type: str
    environment: str = "sandbox"


class ToolRegistry:
    """Central repository storing and binding verified MCP tools."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolMetadata] = {}

    def register(self, metadata: ToolMetadata) -> None:
        """Registers a verified tool with unique name and typed schema."""
        if metadata.name in self._tools:
            raise ValueError(f"Tool '{metadata.name}' is already registered.")
        self._tools[metadata.name] = metadata
        logger.info("Registered MCP tool: %s (resource=%s)", metadata.name, metadata.resource_type)

    def get(self, name: str) -> Optional[ToolMetadata]:
        """Retrieves metadata for a registered tool."""
        return self._tools.get(name)

    def list_all(self) -> list[ToolMetadata]:
        """Returns all registered tool definitions."""
        return list(self._tools.values())

    def bind_to_server(self, server: MCPServer) -> None:
        """Registers all tools with the MCPServer instance with strict schema enforcement."""
        for tool_meta in self._tools.values():
            # In MCP SDK 2.x, add_tool returns the created Tool instance
            server.add_tool(
                fn=tool_meta.handler,
                name=tool_meta.name,
                description=tool_meta.description,
            )
            # Access the registered tool from tool_manager
            registered = server._tool_manager.get_tool(tool_meta.name)
            if registered and hasattr(registered, "fn_metadata") and registered.fn_metadata:
                registered.fn_metadata.arg_model.model_config["extra"] = "forbid"
                registered.fn_metadata.arg_model.model_rebuild(force=True)
                registered.parameters = registered.fn_metadata.arg_model.model_json_schema(by_alias=True)


# Default registry initialized with the 7 foundational tools
registry = ToolRegistry()

# 1. System Health
registry.register(
    ToolMetadata(
        name="system_health",
        description="Inspects backend database, Redis, and OPA connectivity status without disclosing secrets.",
        input_schema=SystemHealthInput,
        handler=system_health,
        required_capability="read",
        resource_type="system",
    )
)

# 2. List Agents
registry.register(
    ToolMetadata(
        name="list_agents",
        description="Lists registered autonomous security agents with safe pagination and filters.",
        input_schema=ListAgentsInput,
        handler=list_agents,
        required_capability="read",
        resource_type="agent",
    )
)

# 3. Get Agent
registry.register(
    ToolMetadata(
        name="get_agent",
        description="Retrieves operational details and capabilities for a specific agent by UUID.",
        input_schema=GetAgentInput,
        handler=get_agent,
        required_capability="read",
        resource_type="agent",
    )
)

# 4. List Campaigns
registry.register(
    ToolMetadata(
        name="list_campaigns",
        description="Lists security campaigns with pagination and status/environment filters.",
        input_schema=ListCampaignsInput,
        handler=list_campaigns,
        required_capability="read",
        resource_type="campaign",
    )
)

# 5. Get Campaign
registry.register(
    ToolMetadata(
        name="get_campaign",
        description="Retrieves execution details for a specific campaign by UUID.",
        input_schema=GetCampaignInput,
        handler=get_campaign,
        required_capability="read",
        resource_type="campaign",
    )
)

# 6. List Incidents
registry.register(
    ToolMetadata(
        name="list_incidents",
        description="Lists security incidents with pagination and severity/status filters.",
        input_schema=ListIncidentsInput,
        handler=list_incidents,
        required_capability="read",
        resource_type="incident",
    )
)

# 7. Get Incident
registry.register(
    ToolMetadata(
        name="get_incident",
        description="Retrieves security incident findings and details by UUID.",
        input_schema=GetIncidentInput,
        handler=get_incident,
        required_capability="read",
        resource_type="incident",
    )
)

# 8. Target List Assets
registry.register(
    ToolMetadata(
        name="target_list_assets",
        description="Lists synthetic target assets within an assigned sandbox environment.",
        input_schema=TargetListAssetsInput,
        handler=target_list_assets,
        required_capability="read",
        resource_type="synthetic_asset",
        environment="sandbox",
    )
)

# 9. Target Inspect Asset
registry.register(
    ToolMetadata(
        name="target_inspect_asset",
        description="Inspects detailed metadata, OS details, services, and connections for a synthetic asset.",
        input_schema=TargetInspectAssetInput,
        handler=target_inspect_asset,
        required_capability="read",
        resource_type="synthetic_asset",
        environment="sandbox",
    )
)

# 10. Target Get Simulated Findings
registry.register(
    ToolMetadata(
        name="target_get_simulated_findings",
        description="Retrieves simulated vulnerability findings for a synthetic asset within its assigned sandbox.",
        input_schema=TargetGetSimulatedFindingsInput,
        handler=target_get_simulated_findings,
        required_capability="read",
        resource_type="synthetic_asset",
        environment="sandbox",
    )
)
