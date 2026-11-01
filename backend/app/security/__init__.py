"""AegisMesh Security Gateway and OPA policy evaluation subsystem."""

from app.security.context import build_policy_input
from app.security.gateway import authorize_action
from app.security.opa_client import check_opa_health, close_opa_client, evaluate_policy, get_opa_client
from app.security.schemas import (
    AuthorizationDecision,
    PolicyAction,
    PolicyContext,
    PolicyInput,
    PolicyResource,
    PolicySubject,
    SecurityCheckRequest,
)

__all__ = [
    "AuthorizationDecision",
    "PolicyAction",
    "PolicyContext",
    "PolicyInput",
    "PolicyResource",
    "PolicySubject",
    "SecurityCheckRequest",
    "authorize_action",
    "build_policy_input",
    "check_opa_health",
    "close_opa_client",
    "evaluate_policy",
    "get_opa_client",
]

