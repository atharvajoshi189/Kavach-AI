"""Base provider interfaces and contracts for external integrations.

Defines the core abstract contracts and delivery models for all external services.
Ensures uniform lifecycle, health monitoring, idempotency, and bounded execution.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field


class ProviderStatus(BaseModel):
    """Normalized provider status report. Never includes sensitive keys or credentials."""

    model_config = ConfigDict(extra="forbid")

    provider_name: str
    is_configured: bool
    mode: str
    status: str = Field(description="Operational status: 'ready', 'unconfigured', 'test_mode', 'degraded'")
    details: Dict[str, Any] = Field(default_factory=dict, description="Safe non-sensitive operational details")


class DeliveryResult(BaseModel):
    """Normalized external delivery result payload."""

    model_config = ConfigDict(extra="forbid")

    success: bool
    delivery_id: str
    provider_message_id: Optional[str] = None
    mode: str
    status: str = Field(description="'simulated_accepted', 'submitted', 'delivered', 'failed'")
    recipient: str
    template_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error_message: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class BaseEmailProvider(ABC):
    """Abstract interface defining the lifecycle and contract for transactional email providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Returns the canonical name of the integration provider."""
        ...

    @abstractmethod
    async def check_health(self) -> ProviderStatus:
        """Evaluates configuration and reachability without exposing secrets."""
        ...

    @abstractmethod
    async def send_email(
        self,
        from_address: str,
        to_address: str,
        subject: str,
        html_content: str,
        plain_text: Optional[str] = None,
        correlation_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> DeliveryResult:
        """Submits an email through the provider or executes a boundary-safe test simulation."""
        ...
