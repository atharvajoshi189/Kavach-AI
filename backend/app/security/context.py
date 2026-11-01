"""Context builder ensuring untrusted client inputs cannot forge security attributes."""

from datetime import datetime, timezone
import uuid
from app.models.user import User
from app.security.schemas import (
    PolicyAction,
    PolicyContext,
    PolicyInput,
    PolicyResource,
    PolicySubject,
)


def build_policy_input(
    user: User,
    operation: str,
    capability: str,
    resource_type: str,
    resource_id: str,
    environment: str = "sandbox",
    risk_level: str = "low",
    approval_status: str = "none",
    request_id: str | None = None,
) -> PolicyInput:
    """Constructs an immutable PolicyInput derived strictly from the verified User session."""
    subject = PolicySubject(
        user_id=str(user.id),
        role=user.role.value,
        is_authenticated=True,
    )

    action = PolicyAction(
        operation=operation.strip().lower(),
        capability=capability.strip().lower(),
    )

    resource = PolicyResource(
        type=resource_type.strip().lower(),
        id=str(resource_id).strip(),
        environment=environment.strip().lower(),
    )

    context = PolicyContext(
        request_id=request_id or str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        risk_level=risk_level.strip().lower(),
        approval_status=approval_status.strip().lower(),
    )

    return PolicyInput(
        subject=subject,
        action=action,
        resource=resource,
        context=context,
    )

