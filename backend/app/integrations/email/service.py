"""Transactional Email Integration Service.

Coordinates validation, recipient allowlisting, template compilation, provider dispatch,
and tamper-evident SHA-256 chained audit logging for all transactional email operations.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid
from fastapi import HTTPException, status
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import Settings, settings as app_settings
from app.database.session import AsyncSessionLocal
from app.integrations.base import DeliveryResult
from app.integrations.email.providers.resend import ResendEmailProvider
from app.integrations.email.schemas import (
    EmailDeliveryRequest,
    EmailDeliveryResponse,
    EmailStatusResponse,
    EmailTemplateId,
    EmailTemplateInfo,
)
from app.integrations.email.templates import template_registry
from app.integrations.registry import integration_registry
from app.models.user import User
from app.services.audit_service import record_audit_log

logger = logging.getLogger("aegismesh.integrations.email.service")


class RecipientNotAllowedError(HTTPException):
    """Raised when an unauthorized recipient address is supplied in test mode."""

    def __init__(self, recipient: str, allowed: List[str]) -> None:
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Recipient '{recipient}' is not permitted under test mode. "
                f"Delivery is strictly restricted to allowlisted recipients: {allowed}"
            ),
        )


class TemplateValidationError(HTTPException):
    """Raised when template parameters fail strict schema validation."""

    def __init__(self, template_id: str, errors: Any) -> None:
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": f"Variables failed validation for template '{template_id}'",
                "validation_errors": errors,
            },
        )


class EmailIntegrationService:
    """Core email gateway coordinator managing templates, providers, allowlisting, and audit trails."""

    def __init__(self, config: Optional[Settings] = None, provider: Optional[Any] = None) -> None:
        self._config = config or app_settings
        self._provider = provider or ResendEmailProvider(self._config)

        # Register provider in global integration registry
        integration_registry.register_email_provider(
            self._provider.provider_name, self._provider
        )

    @property
    def config(self) -> Settings:
        return self._config

    def list_approved_templates(self) -> List[EmailTemplateInfo]:
        """Returns catalog of approved transactional email templates."""
        return template_registry.list_templates()

    async def get_gateway_status(self) -> EmailStatusResponse:
        """Evaluates gateway health, provider state, and recipient boundaries."""
        provider = self._provider
        provider_name = provider.provider_name
        status_report = await provider.check_health()

        supported_templates = [t.value for t in EmailTemplateId]

        return EmailStatusResponse(
            provider=provider_name,
            mode=self._config.EMAIL_MODE,
            is_configured=status_report.is_configured,
            status=status_report.status,
            from_address=self._config.EMAIL_FROM_ADDRESS,
            allowed_recipients_count=len(self._config.EMAIL_ALLOWED_RECIPIENTS),
            allowed_recipients=list(self._config.EMAIL_ALLOWED_RECIPIENTS),
            supported_templates=supported_templates,
            details=status_report.details,
        )

    def validate_recipient_boundary(self, recipient: str) -> None:
        """Enforces test-mode recipient allowlisting boundary.

        Fails closed if the recipient is not in EMAIL_ALLOWED_RECIPIENTS.
        """
        normalized_recipient = recipient.strip().lower()

        if self._config.EMAIL_MODE.lower() == "test":
            allowed = [r.strip().lower() for r in self._config.EMAIL_ALLOWED_RECIPIENTS]
            if normalized_recipient not in allowed:
                logger.warning(
                    "Recipient allowlist rejection: '%s' is not in %s",
                    normalized_recipient,
                    allowed,
                )
                raise RecipientNotAllowedError(recipient, allowed)

    async def process_delivery_request(
        self,
        request: EmailDeliveryRequest,
        user: User,
        session: Optional[AsyncSession] = None,
    ) -> EmailDeliveryResponse:
        """Validates, compiles, executes test simulation, and records SHA-256 chained audit evidence.

        Fails closed on any schema violation, recipient boundary violation, or audit failure.
        """
        delivery_id = str(uuid.uuid4())
        correlation_id = request.correlation_id or str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        normalized_recipient = str(request.recipient).strip().lower()

        # 1. Enforce Recipient Allowlist Boundary
        self.validate_recipient_boundary(normalized_recipient)

        # 2. Enforce Approved Template and Strict Parameter Schema
        try:
            template = template_registry.get_template(request.template_id)
            validated_params = template.validate_variables(request.template_variables)
        except KeyError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Template '{request.template_id}' is not in the approved catalog.",
            )
        except ValidationError as val_err:
            logger.warning("Strict template parameter validation failed: %s", val_err.errors())
            raise TemplateValidationError(request.template_id.value, val_err.errors())

        # 3. Render Template Safely (Preventing Header and Script Injection)
        subject, html_content, plain_text = template.render(validated_params)
        from_address = self._config.EMAIL_FROM_ADDRESS

        # 4. Dispatch to Provider Adapter
        provider = self._provider
        provider_name = provider.provider_name

        delivery_result: DeliveryResult = await provider.send_email(
            from_address=from_address,
            to_address=normalized_recipient,
            subject=subject,
            html_content=html_content,
            plain_text=plain_text,
            correlation_id=correlation_id,
            idempotency_key=delivery_id,
        )

        if not delivery_result.success:
            logger.error("Provider rejected delivery request: %s", delivery_result.error_message)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Provider '{provider_name}' error: {delivery_result.error_message}",
            )

        # 5. Persistent SHA-256 Chained Audit Trail
        audit_payload = {
            "delivery_id": delivery_id,
            "provider": provider_name,
            "mode": self._config.EMAIL_MODE,
            "status": delivery_result.status,
            "template_id": request.template_id.value,
            "recipient": normalized_recipient,
            "from_address": from_address,
            "correlation_id": correlation_id,
            "provider_message_id": delivery_result.provider_message_id,
            "actor_username": getattr(user, "username", "unknown"),
        }

        try:
            actor_role = getattr(user.role, "value", str(user.role))
            if session is not None:
                await record_audit_log(
                    session=session,
                    event_type="EMAIL_GATEWAY_ACTION",
                    action="email.delivery_request",
                    resource_type="email_gateway",
                    resource_id=delivery_id,
                    actor_id=user.id,
                    actor_role=actor_role,
                    decision=delivery_result.status,
                    event_data=audit_payload,
                )
            else:
                async with AsyncSessionLocal() as audit_session:
                    await record_audit_log(
                        session=audit_session,
                        event_type="EMAIL_GATEWAY_ACTION",
                        action="email.delivery_request",
                        resource_type="email_gateway",
                        resource_id=delivery_id,
                        actor_id=user.id,
                        actor_role=actor_role,
                        decision=delivery_result.status,
                        event_data=audit_payload,
                    )
                    await audit_session.commit()
        except Exception as audit_err:
            logger.critical("Audit persistence failed for email delivery: %s. Failing closed.", audit_err)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Security audit persistence failed: action rolled back (fail-closed)",
            )

        # 6. Formulate Return Response
        return EmailDeliveryResponse(
            delivery_id=delivery_id,
            status=delivery_result.status,
            mode=self._config.EMAIL_MODE,
            recipient=normalized_recipient,
            template_id=request.template_id.value,
            provider=provider_name,
            provider_message_id=delivery_result.provider_message_id,
            correlation_id=correlation_id,
            timestamp=now,
            details={
                "from": from_address,
                "simulated": True,
                "template_name": template.name,
                "audited": True,
            },
        )


# Global service instance
email_service = EmailIntegrationService()
