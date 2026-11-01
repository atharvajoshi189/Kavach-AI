"""Health check response schema."""

from datetime import datetime
from pydantic import BaseModel, Field


class HealthServices(BaseModel):
    """Health status of integrated subsystem services."""

    postgresql: str = Field(
        default="healthy",
        description="Health status of PostgreSQL connection ('healthy' or 'unhealthy')",
    )
    redis: str = Field(
        default="healthy",
        description="Health status of Redis connection ('healthy' or 'unhealthy')",
    )


class HealthResponse(BaseModel):
    """Schema returned by the /health endpoint."""

    status: str = Field(
        default="healthy",
        description="Overall service health status ('healthy' or 'degraded')",
    )
    application: str = Field(..., description="Application name")
    version: str = Field(..., description="API version")
    timestamp: datetime = Field(..., description="UTC ISO-8601 timestamp of health evaluation")
    services: HealthServices = Field(
        default_factory=HealthServices,
        description="Individual status of connected subsystem dependencies",
    )
