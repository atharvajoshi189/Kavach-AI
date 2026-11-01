"""Tests for database service / repository functions across agents, campaigns, incidents, and approvals."""

import uuid
import pytest
from app.services.agent_service import create_agent, get_agent_by_id, list_agents
from app.services.campaign_service import (
    create_campaign,
    get_attack_runs_by_campaign,
    get_campaign_by_id,
    get_evaluations_by_campaign,
    get_tool_actions_by_campaign,
    list_campaigns,
    record_attack_run,
    record_evaluation,
    record_tool_action,
    update_campaign_status,
)
from app.services.incident_service import (
    create_approval_request,
    create_incident,
    get_approval_by_id,
    get_incident_by_id,
    list_incidents,
    resolve_approval,
    update_incident_status,
)


@pytest.mark.asyncio
async def test_agent_service_lifecycle(db_session):
    """Verifies creating, fetching, and listing agents via service layer."""
    agent = await create_agent(
        session=db_session,
        name=f"ScannerAgent-{uuid.uuid4().hex[:4]}",
        agent_type="vulnerability_scanner",
        description="Autonomous port and service scanner",
        capabilities={"ports": [80, 443, 8080]},
        status="active",
        environment="sandbox",
    )
    await db_session.commit()

    fetched = await get_agent_by_id(db_session, agent.id)
    assert fetched is not None
    assert fetched.name == agent.name
    assert fetched.capabilities["ports"] == [80, 443, 8080]

    agents_list = await list_agents(db_session, environment="sandbox")
    assert any(a.id == agent.id for a in agents_list)


@pytest.mark.asyncio
async def test_campaign_and_sub_entities_service(db_session):
    """Verifies campaign lifecycle, attack runs, tool actions, and evaluations."""
    campaign = await create_campaign(
        session=db_session,
        name=f"ServiceCampaign-{uuid.uuid4().hex[:4]}",
        trigger_type="manual",
        environment="sandbox",
        configuration={"rate_limit": 10},
    )
    await db_session.commit()

    # Update status
    updated = await update_campaign_status(db_session, campaign.id, status="running")
    await db_session.commit()
    assert updated.status == "running"

    # Record attack run
    run = await record_attack_run(
        session=db_session,
        campaign_id=campaign.id,
        technique="T1046",
        scenario="Network service discovery probe",
        outcome="detected",
        risk_score=5.5,
    )
    await db_session.commit()

    runs = await get_attack_runs_by_campaign(db_session, campaign.id)
    assert len(runs) == 1
    assert runs[0].id == run.id

    # Record tool action
    action = await record_tool_action(
        session=db_session,
        campaign_id=campaign.id,
        action_name="nmap_scan",
        resource="192.168.1.0/24",
        decision="allow",
        executed=True,
    )
    await db_session.commit()

    actions = await get_tool_actions_by_campaign(db_session, campaign.id)
    assert len(actions) == 1
    assert actions[0].id == action.id

    # Record evaluation
    eval_rec = await record_evaluation(
        session=db_session,
        campaign_id=campaign.id,
        detection_rate=0.95,
        attack_success_rate=0.05,
    )
    await db_session.commit()

    evals = await get_evaluations_by_campaign(db_session, campaign.id)
    assert len(evals) == 1
    assert evals[0].detection_rate == 0.95


@pytest.mark.asyncio
async def test_incident_and_approval_service(db_session, test_admin, test_operator):
    """Verifies incident creation, status transition, and approval resolution."""
    incident = await create_incident(
        session=db_session,
        title="Excessive authentication failures detected",
        severity="medium",
        status="open",
        description="50 failed attempts within 1 minute",
    )
    await db_session.commit()

    fetched = await get_incident_by_id(db_session, incident.id)
    assert fetched is not None
    assert fetched.severity == "medium"

    updated = await update_incident_status(db_session, incident.id, status="resolved")
    await db_session.commit()
    assert updated.status == "resolved"
    assert updated.resolved_at is not None

    # Approval Request
    approval = await create_approval_request(
        session=db_session,
        incident_id=incident.id,
        requested_by=test_operator.id,
        approval_reason="Request IP blocklist application",
    )
    await db_session.commit()

    assert approval.status == "pending"

    # Resolve Approval
    resolved = await resolve_approval(
        session=db_session,
        approval_id=approval.id,
        approved_by=test_admin.id,
        status="approved",
        reason="Verified legitimate anomaly containment",
    )
    await db_session.commit()

    assert resolved.status == "approved"
    assert resolved.approved_by == test_admin.id
    assert resolved.approved_at is not None

