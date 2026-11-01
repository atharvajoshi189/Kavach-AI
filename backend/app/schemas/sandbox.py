"""Pydantic schemas for Sandbox API endpoints."""

from datetime import datetime
from typing import Any, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field


class SandboxResponse(BaseModel):
    """Schema representing a sandbox environment summary."""

    id: uuid.UUID
    name: str
    description: Optional[str] = None
    status: str
    isolation_mode: str
    owner_id: Optional[uuid.UUID] = None
    configuration: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SandboxDetailResponse(SandboxResponse):
    """Detailed sandbox environment representation including asset metrics."""

    asset_count: int = 0


class SandboxSeedResponse(BaseModel):
    """Result of demo synthetic sandbox seed operation."""

    sandbox_id: uuid.UUID
    name: str
    status: str
    seeded_assets_count: int
    message: str


class SyntheticAssetResponse(BaseModel):
    """Schema representing an individual synthetic target asset."""

    id: uuid.UUID
    sandbox_id: uuid.UUID
    name: str
    asset_type: str
    description: Optional[str] = None
    environment: str = "sandbox"
    status: str = "online"
    hostname: str
    ip_address: str
    os_metadata: dict[str, Any] = Field(default_factory=dict)
    service_metadata: dict[str, Any] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    simulated_vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    risk_level: str = "low"
    connected_asset_ids: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


