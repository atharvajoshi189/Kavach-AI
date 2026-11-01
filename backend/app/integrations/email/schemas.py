"""Strict Pydantic schemas for Email Gateway integration.

Enforces fail-closed validation, extra-forbid boundary controls, and strict typing.
Prevents header injection, sender overrides, and arbitrary client payloads.
"""

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Annotated, Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class EmailTemplateId(str, Enum):
    """Approved transactional email templates."""

    SECURITY_ALERT = "security_alert"
    INCIDENT_NOTIFICATION = "incident_notification"
    TEST_DELIVERY = "test_delivery"


# Robust RFC-compatible email address regex that permits internal/local test domains as well as standard TLDs
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


# ==============================================================================
# Template Parameter Schemas (extra="forbid")
# ==============================================================================


class SecurityAlertParams(BaseModel):
    """Strict parameters for the 'security_alert' template."""

    model_config = ConfigDict(extra="forbid")

    severity: Literal["low", "medium", "high", "critical"] = Field(
        description="Severity classification of the alert",
    )
    alert_title: str = Field(
        min_length=3,
        max_length=120,
        description="Concise summary header for the alert",
    )
    summary: str = Field(
        min_length=5,
        max_length=1000,
        description="Detailed alert context description",
    )
    indicators: List[str] = Field(
        default_factory=list,
        max_length=20,
        description="Observed threat indicators (IP, hash, URL, technique)",
    )
    timestamp: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Optional human-readable timestamp of alert occurrence",
    )


class IncidentNotificationParams(BaseModel):
    """Strict parameters for the 'incident_notification' template."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(
        min_length=3,
        max_length=64,
        description="Unique system identifier of the incident (e.g. INC-2026-001)",
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        description="Severity level of the security incident",
    )
    title: str = Field(
        min_length=3,
        max_length=150,
        description="Title of the incident",
    )
    description: str = Field(
        min_length=5,
        max_length=1500,
        description="Technical description of the incident scope and impact",
    )
    affected_assets: List[str] = Field(
        default_factory=list,
        max_length=50,
        description="Hostnames or asset identifiers affected by this incident",
    )


class TestDeliveryParams(BaseModel):
    """Strict parameters for the 'test_delivery' template."""

    __test__ = False  # Prevent pytest from treating this model as a test suite
    model_config = ConfigDict(extra="forbid")

    test_id: str = Field(
        min_length=3,
        max_length=64,
        description="Unique verification test probe identifier",
    )
    message: str = Field(
        min_length=1,
        max_length=500,
        description="Verification test message body",
    )
    initiated_by: str = Field(
        min_length=2,
        max_length=64,
        description="Actor or component initiating the test delivery",
    )


# ==============================================================================
# Email Action Request and Response Models
# ==============================================================================


class EmailDeliveryRequest(BaseModel):
    """External client request for transactional email delivery.

    Strictly forbids client-specified headers, arbitrary HTML, attachments, or sender overrides.
    """

    model_config = ConfigDict(extra="forbid")

    recipient: str = Field(
        min_length=5,
        max_length=255,
        description="Target recipient email address. Must be allowlisted during test mode.",
    )
    template_id: EmailTemplateId = Field(
        description="Approved template identifier from the registered catalog",
    )
    template_variables: Dict[str, Any] = Field(
        description="Template variables strictly conforming to the selected template schema",
    )
    correlation_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Optional tracking correlation identifier for tracing across systems",
    )

    @field_validator("recipient")
    @classmethod
    def validate_recipient_format(cls, v: str) -> str:
        clean = v.strip()
        if not EMAIL_REGEX.match(clean):
            raise ValueError(f"'{v}' is not a valid email address")
        return clean.lower()


class EmailDeliveryResponse(BaseModel):
    """Structured response acknowledging email action validation and processing status."""

    model_config = ConfigDict(extra="forbid")

    delivery_id: str = Field(description="Unique delivery tracking UUID assigned by AegisMesh")
    status: str = Field(description="Action status: 'simulated_accepted', 'queued', 'failed'")
    mode: str = Field(description="Active execution mode: 'test' or 'production'")
    recipient: str = Field(description="Recipient address")
    template_id: str = Field(description="Template identifier used")
    provider: str = Field(description="Configured provider adapter ('resend')")
    provider_message_id: Optional[str] = Field(
        default=None,
        description="Provider tracking identifier if accepted by provider",
    )
    correlation_id: Optional[str] = Field(default=None, description="Request correlation identifier")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the delivery action",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Safe non-sensitive delivery metadata",
    )


class EmailTemplateInfo(BaseModel):
    """Metadata describing an approved transactional email template."""

    model_config = ConfigDict(extra="forbid")

    template_id: str
    name: str
    description: str
    required_variables: List[str]
    variable_schema: Dict[str, Any]


class EmailStatusResponse(BaseModel):
    """Comprehensive status probe response for the email gateway integration."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    mode: str
    is_configured: bool
    status: str
    from_address: str
    allowed_recipients_count: int
    allowed_recipients: List[str]
    supported_templates: List[str]
    details: Dict[str, Any] = Field(default_factory=dict)
