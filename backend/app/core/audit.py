"""Security audit logging module for tracking sensitive platform operations.

Guarantees that credentials, tokens, and secret payloads are never included in audit trails.
"""

from datetime import datetime, timezone
import enum
import json
import logging
from typing import Any

logger = logging.getLogger("aegismesh.audit")


class AuditEvent(str, enum.Enum):
    """Categorized security audit event types."""

    REGISTER_SUCCESS = "AUTH_REGISTER_SUCCESS"
    REGISTER_FAILURE = "AUTH_REGISTER_FAILURE"
    LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
    LOGOUT = "AUTH_LOGOUT"
    TOKEN_REFRESH_SUCCESS = "AUTH_TOKEN_REFRESH_SUCCESS"
    TOKEN_REFRESH_FAILURE = "AUTH_TOKEN_REFRESH_FAILURE"
    PERMISSION_DENIED = "AUTH_PERMISSION_DENIED"
    ROLE_CHANGE = "AUTH_ROLE_CHANGE"
    ADMIN_BOOTSTRAP = "AUTH_ADMIN_BOOTSTRAP"
    SECURITY_GATEWAY_DECISION = "SECURITY_GATEWAY_DECISION"


def log_audit_event(
    event: AuditEvent | str,
    user_id: str | None = None,
    username: str | None = None,
    client_ip: str | None = None,
    status: str = "SUCCESS",
    details: dict[str, Any] | None = None,
) -> None:
    """Records a structured security audit event.

    Ensures no passwords, hashed credentials, or raw tokens are persisted.
    """
    from app.services.audit_service import sanitize_event_data

    safe_details = sanitize_event_data(details) if details else {}

    audit_entry = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "event": str(event),
        "status": status,
        "user_id": str(user_id) if user_id else None,
        "username": username,
        "client_ip": client_ip,
        "details": safe_details,
    }

    # Emit as structured JSON for log aggregators (SIEM / OpenTelemetry)
    logger.info("AUDIT_EVENT: %s", json.dumps(audit_entry))
