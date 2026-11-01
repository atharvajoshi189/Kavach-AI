"""Tests for core database models, schema constraints, JSONB, and relationships."""

import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from app.models import (
    Agent,
    Approval,
    AttackRun,
    AuditLog,
    Campaign,
    Evaluation,
    Incident,
    PolicyVersion,
    ToolAction,
    User,
    UserRole,
)


def test_all_models_can_be_imported():
    """Verifies that all core domain models are exposed and importable."""
    expected_models = [
        "Agent",
        "Approval",
        "AttackRun",
        "AuditLog",
        "Campaign",
        "Evaluation",
        "Incident",
        "PolicyVersion",
        "ToolAction",
        "User",
        "UserRole",
    ]
    import app.models

    for model_name in expected_models:
        assert hasattr(app.models, model_name), f"Model {model_name} not found in app.models"


@pytest.mark.asyncio
async def test_agent_campaign_attack_run_relationships(db_session):
    """Verifies creation and foreign key relationships between Agent, Campaign, and AttackRun."""
    # 1. Create Agent
    agent = Agent(
        name="RedTeam-T1059",
        agent_type="red_team",
        description="Autonomous command execution tester",
        capabilities={"supported_platforms": ["linux", "windows"], "max_depth": 3},
        status="active",
        environment="sandbox",
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)

    assert agent.id is not None
    assert agent.capabilities["max_depth"] == 3

    # 2. Create Campaign linked to Agent
    campaign = Campaign(
        agent_id=agent.id,
        name="Sandbox Defense Evaluation Q4",
        trigger_type="manual",
        status="running",
        environment="sandbox",
        configuration={"timeout_seconds": 120, "techniques": ["T1059.001"]},
    )
    db_session.add(campaign)
    await db_session.commit()
    await db_session.refresh(campaign)

    assert campaign.agent_id == agent.id
    assert campaign.configuration["timeout_seconds"] == 120

    # 3. Create AttackRun linked to Campaign
    attack_run = AttackRun(
        campaign_id=campaign.id,
        technique="T1059.001",
        scenario="PowerShell command injection simulation",
        outcome="detected",
        risk_score=7.8,
        execution_metadata={"process_name": "powershell.exe", "return_code": 0},
    )
    db_session.add(attack_run)
    await db_session.commit()
    await db_session.refresh(attack_run)

    assert attack_run.id is not None
    assert attack_run.campaign_id == campaign.id
    assert attack_run.risk_score == 7.8
    assert attack_run.execution_metadata["process_name"] == "powershell.exe"


@pytest.mark.asyncio
async def test_tool_action_and_evaluation_persistence(db_session):
    """Verifies persistence of ToolAction and Evaluation entities with JSONB metadata."""
    # Create Campaign
    campaign = Campaign(
        name="Tool Capability & Benchmark Run",
        trigger_type="scheduled",
        status="completed",
        environment="sandbox",
    )
    db_session.add(campaign)
    await db_session.commit()
    await db_session.refresh(campaign)

    # ToolAction
    tool_action = ToolAction(
        campaign_id=campaign.id,
        action_name="execute_sandbox_probe",
        resource="container:isolate-01",
        decision="allow",
        executed=True,
        reason="Action permitted within sandbox environment",
        environment="sandbox",
    )
    db_session.add(tool_action)

    # Evaluation
    evaluation = Evaluation(
        campaign_id=campaign.id,
        detection_rate=0.92,
        attack_success_rate=0.15,
        false_positive_rate=0.03,
        false_negative_rate=0.08,
        utility_rate=0.88,
        mean_latency_ms=145.2,
        metrics={
            "total_probes": 100,
            "blocked_probes": 85,
            "bypassed_probes": 15,
        },
    )
    db_session.add(evaluation)
    await db_session.commit()
    await db_session.refresh(tool_action)
    await db_session.refresh(evaluation)

    assert tool_action.id is not None
    assert tool_action.executed is True
    assert evaluation.detection_rate == 0.92
    assert evaluation.metrics["blocked_probes"] == 85


@pytest.mark.asyncio
async def test_incident_approval_policy_version_workflow(db_session, test_admin, test_operator):
    """Verifies relational lifecycle between Incident, PolicyVersion, and Approval."""
    # 1. Create PolicyVersion
    policy_v2 = PolicyVersion(
        version="2.1.0-draft",
        policy_content="package aegis\ndefault allow := false\n",
        status="draft",
        created_by=test_admin.id,
    )
    db_session.add(policy_v2)

    # 2. Create Incident
    incident = Incident(
        title="Unauthorized lateral movement probe detected",
        severity="high",
        status="open",
        source="sentinel_agent",
        description="Probe detected from 10.0.0.12 to 10.0.0.99",
    )
    db_session.add(incident)
    await db_session.commit()
    await db_session.refresh(policy_v2)
    await db_session.refresh(incident)

    # 3. Create Approval Request
    approval = Approval(
        incident_id=incident.id,
        policy_version_id=policy_v2.id,
        requested_by=test_operator.id,
        approval_reason="Request emergency containment isolation rule approval",
        status="pending",
    )
    db_session.add(approval)
    await db_session.commit()
    await db_session.refresh(approval)

    assert approval.id is not None
    assert approval.status == "pending"
    assert approval.requested_by == test_operator.id
    assert approval.incident_id == incident.id
    assert approval.policy_version_id == policy_v2.id


@pytest.mark.asyncio
async def test_foreign_key_delete_behavior_preserves_audit_logs(db_session):
    """Guarantees that deleting a User with audit logs is restricted to preserve identity and hash integrity."""
    from app.services.audit_service import (
        compute_canonical_payload,
        compute_event_hash,
        verify_event_hash,
    )
    from datetime import datetime, timezone

    # 1. Create transient user
    transient_user = User(
        email=f"transient_{uuid.uuid4().hex[:6]}@example.com",
        username=f"transient_{uuid.uuid4().hex[:6]}",
        hashed_password="HashPassWord123!",
        role=UserRole.SECURITY_ANALYST,
    )
    db_session.add(transient_user)
    await db_session.commit()
    await db_session.refresh(transient_user)
    user_id = transient_user.id

    # 2. Create properly computed and hashed audit log linked to this user
    created_at = datetime.now(timezone.utc)
    event_id = uuid.uuid4()
    prev_hash = "0" * 64
    event_data = {"scope": "read_only"}
    canonical = compute_canonical_payload(
        event_id=event_id,
        event_type="AUTH_ROLE_CHANGE",
        actor_id=user_id,
        actor_role="security_analyst",
        action="update_analyst_scope",
        resource_type="analyst_profile",
        resource_id=str(user_id),
        decision="allowed",
        event_data=event_data,
        created_at=created_at,
    )
    event_hash = compute_event_hash(prev_hash, canonical)

    audit_entry = AuditLog(
        id=event_id,
        event_type="AUTH_ROLE_CHANGE",
        actor_id=user_id,
        actor_role="security_analyst",
        action="update_analyst_scope",
        resource_type="analyst_profile",
        resource_id=str(user_id),
        decision="allowed",
        event_data=event_data,
        previous_hash=prev_hash,
        event_hash=event_hash,
        created_at=created_at,
    )
    db_session.add(audit_entry)
    await db_session.commit()
    await db_session.refresh(audit_entry)
    audit_id = audit_entry.id

    assert verify_event_hash(audit_entry) is True

    # 3. Attempting hard delete on User MUST be blocked by PostgreSQL ON DELETE RESTRICT
    await db_session.delete(transient_user)
    with pytest.raises(IntegrityError):
        await db_session.commit()

    # Roll back the aborted transaction
    await db_session.rollback()

    # 4. Correct lifecycle: user deactivation succeeds and preserves actor identity & hash validation
    user_query = await db_session.execute(select(User).where(User.id == user_id))
    active_user = user_query.scalar_one()
    active_user.is_active = False
    await db_session.commit()

    # Re-query audit log to verify it is intact and hash verification succeeds
    result = await db_session.execute(select(AuditLog).where(AuditLog.id == audit_id))
    persisted_log = result.scalar_one_or_none()

    assert persisted_log is not None
    assert persisted_log.actor_id == user_id
    assert verify_event_hash(persisted_log) is True


@pytest.mark.asyncio
async def test_campaign_deletion_restricted_when_attack_runs_exist(db_session):
    """Guarantees that deleting a Campaign with AttackRun records is blocked by ON DELETE RESTRICT."""
    # 1. Create Campaign
    campaign = Campaign(
        name=f"Forensic Campaign {uuid.uuid4().hex[:6]}",
        trigger_type="manual",
    )
    db_session.add(campaign)
    await db_session.commit()
    await db_session.refresh(campaign)

    # 2. Create AttackRun
    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1059",
        scenario="Command-line simulation",
        outcome="blocked",
    )
    db_session.add(run)
    await db_session.commit()
    await db_session.refresh(run)

    run_id = run.id
    campaign_id = campaign.id

    # 3. Attempting to delete Campaign MUST raise IntegrityError due to RESTRICT
    await db_session.delete(campaign)
    with pytest.raises(IntegrityError):
        await db_session.commit()

    await db_session.rollback()

    # 4. Verify both Campaign and AttackRun are preserved intact
    res_c = await db_session.execute(select(Campaign).where(Campaign.id == campaign_id))
    assert res_c.scalar_one_or_none() is not None

    res_r = await db_session.execute(select(AttackRun).where(AttackRun.id == run_id))
    assert res_r.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_campaign_deletion_restricted_when_evaluations_exist(db_session):
    """Guarantees that deleting a Campaign with Evaluation records is blocked by ON DELETE RESTRICT."""
    # 1. Create Campaign
    campaign = Campaign(
        name=f"Evaluation Campaign {uuid.uuid4().hex[:6]}",
        trigger_type="scheduled",
    )
    db_session.add(campaign)
    await db_session.commit()
    await db_session.refresh(campaign)

    # 2. Create Evaluation
    evaluation = Evaluation(
        campaign_id=campaign.id,
        detection_rate=0.98,
        attack_success_rate=0.02,
    )
    db_session.add(evaluation)
    await db_session.commit()
    await db_session.refresh(evaluation)

    eval_id = evaluation.id
    campaign_id = campaign.id

    # 3. Attempting to delete Campaign MUST raise IntegrityError due to RESTRICT
    await db_session.delete(campaign)
    with pytest.raises(IntegrityError):
        await db_session.commit()

    await db_session.rollback()

    # 4. Verify both Campaign and Evaluation are preserved intact
    res_c = await db_session.execute(select(Campaign).where(Campaign.id == campaign_id))
    assert res_c.scalar_one_or_none() is not None

    res_e = await db_session.execute(select(Evaluation).where(Evaluation.id == eval_id))
    assert res_e.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_empty_campaign_deletion_succeeds_and_preserves_agent(db_session):
    """Verifies that an empty campaign without forensic child records can be deleted without affecting Agent."""
    agent = Agent(
        name=f"ParentAgent-{uuid.uuid4().hex[:4]}",
        agent_type="evaluator",
        capabilities={},
        status="idle",
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)

    campaign = Campaign(
        agent_id=agent.id,
        name="Empty Ephemeral Campaign",
        trigger_type="automated",
    )
    db_session.add(campaign)
    await db_session.commit()
    await db_session.refresh(campaign)

    campaign_id = campaign.id
    agent_id = agent.id

    # Deleting campaign without children succeeds
    await db_session.delete(campaign)
    await db_session.commit()

    res_c = await db_session.execute(select(Campaign).where(Campaign.id == campaign_id))
    assert res_c.scalar_one_or_none() is None

    res_a = await db_session.execute(select(Agent).where(Agent.id == agent_id))
    assert res_a.scalar_one_or_none() is not None

