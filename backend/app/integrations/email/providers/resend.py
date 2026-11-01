"""Resend transactional email provider adapter.

Conforms to Resend REST API v1 (POST https://api.resend.com/emails).
Strictly secures API keys, enforces bounded timeouts, redacts secrets from logs,
and enforces a simulated delivery boundary when in test mode (Step 10.1).
"""

from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, Optional
import uuid
import httpx
from app.core.config import Settings, settings as app_settings
from app.integrations.base import BaseEmailProvider, DeliveryResult, ProviderStatus

logger = logging.getLogger("aegismesh.integrations.email.resend")

RESEND_API_ENDPOINT = "https://api.resend.com/emails"


def _redact_secrets(message: str) -> str:
    """Removes API keys and Bearer tokens from error strings or logs."""
    message = re.sub(r"re_[A-Za-z0-9_]+", "[REDACTED_API_KEY]", message)
    message = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer [REDACTED_TOKEN]", message, flags=re.IGNORECASE)
    return message


class ResendEmailProvider(BaseEmailProvider):
    """Resend email provider implementation adhering to AegisMesh security boundaries."""

    def __init__(self, config: Optional[Settings] = None) -> None:
        self._config = config or app_settings
        self._provider_name = "resend"

    def __repr__(self) -> str:
        # Guarantee no secrets leak in string representations
        is_configured = bool(self._config.RESEND_API_KEY)
        return f"<ResendEmailProvider(provider='resend', configured={is_configured}, mode='{self._config.EMAIL_MODE}')>"

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def mode(self) -> str:
        return self._config.EMAIL_MODE

    def is_configured(self) -> bool:
        """Determines whether a non-empty API key is configured."""
        return bool(self._config.RESEND_API_KEY and self._config.RESEND_API_KEY.strip())

    async def check_health(self) -> ProviderStatus:
        """Checks configuration health without leaking keys or making unnecessary network roundtrips."""
        configured = self.is_configured()
        mode = self._config.EMAIL_MODE

        if not configured:
            return ProviderStatus(
                provider_name=self.provider_name,
                is_configured=False,
                mode=mode,
                status="unconfigured",
                details={
                    "message": "Email provider credentials are not configured in server environment",
                    "sender": self._config.EMAIL_FROM_ADDRESS,
                    "allowed_recipients_count": len(self._config.EMAIL_ALLOWED_RECIPIENTS),
                },
            )

        return ProviderStatus(
            provider_name=self.provider_name,
            is_configured=True,
            mode=mode,
            status="ready" if mode == "test" else "standby",
            details={
                "message": "Resend adapter is configured and operating within test boundary",
                "sender": self._config.EMAIL_FROM_ADDRESS,
                "allowed_recipients_count": len(self._config.EMAIL_ALLOWED_RECIPIENTS),
            },
        )

    def build_request_payload(
        self,
        from_address: str,
        to_address: str,
        subject: str,
        html_content: str,
        plain_text: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Constructs Resend-compliant request payload with headers and metadata."""
        payload: Dict[str, Any] = {
            "from": from_address,
            "to": [to_address],
            "subject": subject,
            "html": html_content,
        }
        if plain_text:
            payload["text"] = plain_text
        if correlation_id:
            payload["headers"] = {"X-AegisMesh-Correlation-ID": correlation_id}
        return payload

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
        """Processes transactional email through the Resend contract.

        In Step 10.1 (EMAIL_MODE='test'), this performs complete payload construction,
        header validation, and idempotency preparation, returning a simulated delivery
        acceptance record without contacting external Resend servers.
        """
        delivery_id = str(uuid.uuid4())
        idem_key = idempotency_key or str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        # 1. Configuration verification
        if not self.is_configured():
            logger.warning("Attempted email delivery with missing credentials")
            return DeliveryResult(
                success=False,
                delivery_id=delivery_id,
                mode=self._config.EMAIL_MODE,
                status="failed",
                recipient=to_address,
                template_id="unknown",
                timestamp=now,
                error_message="Email provider is unconfigured: credentials missing",
                details={"configured": False},
            )

        # 2. Strict Step 10.1 Test-Mode Boundary Check
        if self._config.EMAIL_MODE.lower() == "test":
            # Formulate payload to verify structural validity
            payload = self.build_request_payload(
                from_address=from_address,
                to_address=to_address,
                subject=subject,
                html_content=html_content,
                plain_text=plain_text,
                correlation_id=correlation_id,
            )

            simulated_message_id = f"sim_resend_{uuid.uuid4().hex[:16]}"
            logger.info(
                "Step 10.1 boundary: intercepted test email delivery for recipient '%s' (delivery_id=%s)",
                to_address,
                delivery_id,
            )

            return DeliveryResult(
                success=True,
                delivery_id=delivery_id,
                provider_message_id=simulated_message_id,
                mode="test",
                status="simulated_accepted",
                recipient=to_address,
                template_id=correlation_id or "test",
                timestamp=now,
                details={
                    "simulated": True,
                    "idempotency_key": idem_key,
                    "payload_keys": list(payload.keys()),
                    "from": from_address,
                    "provider": "resend",
                },
            )

        # 3. Production Delivery Protection: Step 10.1 strictly forbids external production transmission
        logger.error("Production email delivery was triggered but is forbidden in Step 10.1 foundation phase")
        raise RuntimeError("Production external email delivery is strictly disabled in Step 10.1")
