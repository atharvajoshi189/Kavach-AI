"""Pydantic schemas for OPA policy evaluation and Security Gateway enforcement."""

from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field


class PolicySubject(BaseModel):
    """Caller identity derived strictly from verified authentication context."""

    user_id: str = Field(..., description="Unique caller UUID string")
    role: str = Field(..., description="Caller platform role (e.g. admin, security_operator)")
    is_authenticated: bool = Field(default=True, description="Authentication confirmation status")


class PolicyAction(BaseModel):
    """Operation requested by the caller."""

    operation: str = Field(..., description="Specific operation identifier (e.g. scan.execute, remediation.execute)")
    capability: str = Field(..., description="High-level capability family (e.g. scan, read, remediate, admin)")


class PolicyResource(BaseModel):
    """Target resource subjected to policy evaluation."""

    type: str = Field(..., description="Resource entity type (e.g. target, job, policy, system)")
    id: str = Field(..., description="Unique resource identifier")
    environment: str = Field(default="sandbox", description="Operating environment (e.g. sandbox, staging, production)")


class PolicyContext(BaseModel):
    """Environmental and governance metadata."""

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Traceable correlation identifier")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="Evaluation UTC timestamp")
    risk_level: str = Field(default="low", description="Assessed risk level (low, medium, high, critical)")
    approval_status: str = Field(default="none", description="Human oversight status (none, pending, approved)")


class PolicyInput(BaseModel):
    """Complete envelope passed to OPA for policy evaluation."""

    subject: PolicySubject
    action: PolicyAction
    resource: PolicyResource
    context: PolicyContext = Field(default_factory=PolicyContext)


class AuthorizationDecision(BaseModel):
    """Structured decision returned by the Security Gateway."""

    allowed: bool = Field(..., description="Binary authorization decision")
    decision: str = Field(..., description="Decision classification ('allow' or 'deny')")
    reason: str = Field(..., description="Human-readable justification for the decision")
    policy_version: str = Field(default="1.0.0", description="Version of the governing policy rulebook")


class SecurityCheckRequest(BaseModel):
    """Payload for pre-flight authorization checks via the public API."""

    operation: str = Field(..., description="Requested operation name (e.g. scan.execute)")
    capability: str = Field(..., description="Operation capability category (e.g. scan, read, admin)")
    resource_type: str = Field(..., description="Target resource type (e.g. target, scan)")
    resource_id: str = Field(..., description="Target resource identifier")
    environment: str = Field(default="sandbox", description="Target environment (sandbox, staging, production)")
    risk_level: str = Field(default="low", description="Risk tier of the operation")
    approval_status: str = Field(default="none", description="Human authorization state (none, approved)")

