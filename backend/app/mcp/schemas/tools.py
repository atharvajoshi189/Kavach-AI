"""Pydantic input schemas for all AegisMesh MCP tools.

Enforces strict input validation and forbids unknown fields to prevent parameter injection.
Authentication is delivered at the transport layer via HTTP Authorization header,
so tool input schemas contain strictly domain parameters without credentials.
"""

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class BaseMCPToolInput(BaseModel):
    """Base class for all MCP tool arguments, enforcing strict extra-field rejection."""

    model_config = ConfigDict(extra="forbid")


class SystemHealthInput(BaseMCPToolInput):
    """Input parameters for system_health tool. Requires no model-supplied arguments."""

    pass


class ListAgentsInput(BaseMCPToolInput):
    """Input parameters for list_agents tool."""

    page: int = Field(default=1, ge=1, description="Page number starting at 1.")
    page_size: int = Field(default=50, ge=1, le=100, description="Items per page (max 100).")
    environment: Optional[str] = Field(default=None, description="Optional environment filter (e.g. 'sandbox').")
    status: Optional[str] = Field(default=None, description="Optional agent status filter.")


class GetAgentInput(BaseMCPToolInput):
    """Input parameters for get_agent tool."""

    agent_id: str = Field(..., description="UUID of the agent to retrieve.")


class ListCampaignsInput(BaseMCPToolInput):
    """Input parameters for list_campaigns tool."""

    page: int = Field(default=1, ge=1, description="Page number starting at 1.")
    page_size: int = Field(default=50, ge=1, le=100, description="Items per page (max 100).")
    environment: Optional[str] = Field(default=None, description="Optional environment filter.")
    status: Optional[str] = Field(default=None, description="Optional campaign status filter.")


class GetCampaignInput(BaseMCPToolInput):
    """Input parameters for get_campaign tool."""

    campaign_id: str = Field(..., description="UUID of the campaign to retrieve.")


class ListIncidentsInput(BaseMCPToolInput):
    """Input parameters for list_incidents tool."""

    page: int = Field(default=1, ge=1, description="Page number starting at 1.")
    page_size: int = Field(default=50, ge=1, le=100, description="Items per page (max 100).")
    severity: Optional[str] = Field(default=None, description="Optional incident severity filter.")
    status: Optional[str] = Field(default=None, description="Optional incident status filter.")


class GetIncidentInput(BaseMCPToolInput):
    """Input parameters for get_incident tool."""

    incident_id: str = Field(..., description="UUID of the incident to retrieve.")


class TargetListAssetsInput(BaseMCPToolInput):
    """Input parameters for target_list_assets tool."""

    sandbox_id: str = Field(..., description="UUID of the sandbox environment.")
    asset_type: Optional[str] = Field(default=None, description="Optional asset type filter (server, database, web_application, api, network_device).")
    page: int = Field(default=1, ge=1, description="Page number starting at 1.")
    page_size: int = Field(default=50, ge=1, le=100, description="Items per page (max 100).")


class TargetInspectAssetInput(BaseMCPToolInput):
    """Input parameters for target_inspect_asset tool."""

    sandbox_id: str = Field(..., description="UUID of the sandbox environment.")
    asset_id: str = Field(..., description="UUID of the synthetic asset to inspect.")


class TargetGetSimulatedFindingsInput(BaseMCPToolInput):
    """Input parameters for target_get_simulated_findings tool."""

    sandbox_id: str = Field(..., description="UUID of the sandbox environment.")
    asset_id: str = Field(..., description="UUID of the synthetic asset.")
    severity: Optional[str] = Field(default=None, description="Optional finding severity filter (low, medium, high, critical).")
