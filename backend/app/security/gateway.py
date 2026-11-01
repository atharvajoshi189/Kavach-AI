"""Centralized Security Gateway enforcing policy evaluations before sensitive executions."""

import logging
from typing import Optional
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.audit import AuditEvent, log_audit_event
from app.database.session import AsyncSessionLocal
from app.models.user import User
from app.security.context import build_policy_input
from app.security.opa_client import evaluate_policy
from app.security.schemas import AuthorizationDecision
from app.services.audit_service import record_audit_log

logger = logging.getLogger(__name__)


async def authorize_action(
    user: User,
    operation: str,
    capability: str,
    resource_type: str,
    resource_id: str,
    environment: str = "sandbox",
    risk_level: str = "low",
    approval_status: str = "none",
    request_id: str | None = None,
    session: Optional[AsyncSession] = None,
) -> AuthorizationDecision:
    """Evaluates requested operational capability through OPA and logs decision.

    Guarantees that unauthenticated or unauthorized actions fail closed, emitting
    an audit event for compliance monitoring and persisting an immutable audit record
    in PostgreSQL with hash chaining.
    """
    # 1. Construct trusted policy envelope
    policy_input = build_policy_input(
        user=user,
        operation=operation,
        capability=capability,
        resource_type=resource_type,
        resource_id=resource_id,
        environment=environment,
        risk_level=risk_level,
        approval_status=approval_status,
        request_id=request_id,
    )

    # 2. Query OPA decision engine
    decision = await evaluate_policy(policy_input)

    # 3. Log audit event to SIEM / console logger
    log_audit_event(
        event=AuditEvent.SECURITY_GATEWAY_DECISION,
        user_id=str(user.id),
        username=user.username,
        status="ALLOWED" if decision.allowed else "DENIED",
        details={
            "action": operation,
            "capability": capability,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "environment": environment,
            "risk_level": risk_level,
            "approval_status": approval_status,
            "decision": decision.decision,
            "reason": decision.reason,
            "policy_version": decision.policy_version,
            "request_id": policy_input.context.request_id,
        },
    )

    # 4. Mandatory PostgreSQL audit persistence
    audit_event_data = {
        "capability": capability,
        "environment": environment,
        "risk_level": risk_level,
        "approval_status": approval_status,
        "reason": decision.reason,
        "policy_version": decision.policy_version,
        "request_id": policy_input.context.request_id,
        "allowed": decision.allowed,
    }

    try:
        if session is not None:
            await record_audit_log(
                session=session,
                event_type=AuditEvent.SECURITY_GATEWAY_DECISION.value,
                action=operation,
                resource_type=resource_type,
                actor_id=user.id,
                actor_role=user.role.value if hasattr(user.role, "value") else str(user.role),
                resource_id=resource_id,
                decision=decision.decision,
                event_data=audit_event_data,
            )
        else:
            async with AsyncSessionLocal() as audit_session:
                await record_audit_log(
                    session=audit_session,
                    event_type=AuditEvent.SECURITY_GATEWAY_DECISION.value,
                    action=operation,
                    resource_type=resource_type,
                    actor_id=user.id,
                    actor_role=user.role.value if hasattr(user.role, "value") else str(user.role),
                    resource_id=resource_id,
                    decision=decision.decision,
                    event_data=audit_event_data,
                )
                await audit_session.commit()
    except Exception as e:
        logger.critical(
            "MANDATORY AUDIT PERSISTENCE FAILED for action '%s': %s", operation, e
        )
        raise HTTPException(
            status_code=500,
            detail="Security audit persistence failed; operation aborted.",
        ) from e

    return decision

