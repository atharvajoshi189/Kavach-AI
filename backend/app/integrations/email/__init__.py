"""Transactional Email Integration Gateway for AegisMesh 2.0 / Kavach AI.

Provides approved template registries, strict Pydantic parameter validation, test-mode recipient
allowlisting, Resend provider integration, and tamper-evident audit logging.
"""

from app.integrations.email.schemas import (
    EmailDeliveryRequest,
    EmailDeliveryResponse,
    EmailStatusResponse,
    EmailTemplateId,
    EmailTemplateInfo,
    IncidentNotificationParams,
    SecurityAlertParams,
    TestDeliveryParams,
)
from app.integrations.email.service import EmailIntegrationService, email_service
from app.integrations.email.templates import template_registry

__all__ = [
    "EmailDeliveryRequest",
    "EmailDeliveryResponse",
    "EmailStatusResponse",
    "EmailTemplateId",
    "EmailTemplateInfo",
    "IncidentNotificationParams",
    "SecurityAlertParams",
    "TestDeliveryParams",
    "EmailIntegrationService",
    "email_service",
    "template_registry",
]
