"""Tests for the tamper-evident persistent audit system, hash chaining, and audit API."""

import asyncio
from datetime import datetime, timezone
import uuid
import httpx
import pytest
from sqlalchemy import select
from app.core.audit import AuditEvent
from app.database.session import AsyncSessionLocal
from app.main import app
from app.models.audit_log import AuditLog
from app.security.gateway import authorize_action
from app.services.audit_service import (
    GENESIS_HASH,
    compute_canonical_payload,
    compute_event_hash,
    record_audit_log,
    sanitize_event_data,
    verify_audit_chain,
    verify_event_hash,
)


def test_audit_hash_generation_and_verification():
    """Verifies deterministic canonical payload generation and SHA-256 hash validation."""
    event_id = uuid.uuid4()
    actor_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    prev_hash = "0" * 64

    canonical = compute_canonical_payload(
        event_id=event_id,
        event_type="AUTH_LOGIN_SUCCESS",
        actor_id=actor_id,
        actor_role="admin",
        action="login",
        resource_type="user",
        resource_id=None,
        decision="success",
        event_data={"ip": "127.0.0.1", "browser": "pytest"},
        created_at=now_utc,
    )

    computed_hash = compute_event_hash(prev_hash, canonical)
    assert len(computed_hash) == 64
    assert int(computed_hash, 16) > 0

    # Create AuditLog entity and verify integrity check passes
    log = AuditLog(
        id=event_id,
        event_type="AUTH_LOGIN_SUCCESS",
        actor_id=actor_id,
        actor_role="admin",
        action="login",
        resource_type="user",
        resource_id=None,
        decision="success",
        event_data={"ip": "127.0.0.1", "browser": "pytest"},
        previous_hash=prev_hash,
        event_hash=computed_hash,
        created_at=now_utc,
    )
    assert verify_event_hash(log) is True


def test_sanitization_strips_sensitive_data():
    """Guarantees that credentials, tokens, and secret payloads are removed recursively."""
    dirty_payload = {
        "user_id": "123",
        "password": "SuperSecretPassword123!",
        "token": "eyJhbGciOi...",
        "access_token": "token_abc",
        "nested": {
            "api_key": "sk-12345",
            "safe_param": "visible_value",
            "hashed_password": "$argon2id$...",
        },
        "list_items": [
            {"secret": "hidden", "public_info": "ok"},
            "plain_string",
        ],
    }

    clean = sanitize_event_data(dirty_payload)
    assert "password" not in clean
    assert "token" not in clean
    assert "access_token" not in clean
    assert "api_key" not in clean["nested"]
    assert "hashed_password" not in clean["nested"]
    assert clean["nested"]["safe_param"] == "visible_value"
    assert "secret" not in clean["list_items"][0]
    assert clean["list_items"][0]["public_info"] == "ok"


@pytest.mark.asyncio
async def test_hash_chain_sequential_linkage(db_session, test_operator):
    """Verifies that multiple sequential audit entries form an unbroken cryptographic chain."""
    actor_id = test_operator.id

    entry1 = await record_audit_log(
        session=db_session,
        event_type="TEST_CHAIN_1",
        action="action_step_1",
        resource_type="test_resource",
        actor_id=actor_id,
        actor_role="security_operator",
        event_data={"step": 1},
    )
    await db_session.commit()

    entry2 = await record_audit_log(
        session=db_session,
        event_type="TEST_CHAIN_2",
        action="action_step_2",
        resource_type="test_resource",
        actor_id=actor_id,
        actor_role="security_operator",
        event_data={"step": 2},
    )
    await db_session.commit()

    entry3 = await record_audit_log(
        session=db_session,
        event_type="TEST_CHAIN_3",
        action="action_step_3",
        resource_type="test_resource",
        actor_id=actor_id,
        actor_role="security_operator",
        event_data={"step": 3},
    )
    await db_session.commit()

    # Verify link 2 points to link 1
    assert entry2.previous_hash == entry1.event_hash
    # Verify link 3 points to link 2
    assert entry3.previous_hash == entry2.event_hash

    # Verify chain validation helper passes
    is_valid, error = verify_audit_chain([entry1, entry2, entry3])
    assert is_valid is True
    assert error is None


@pytest.mark.asyncio
async def test_tampered_payload_detected(db_session):
    """Verifies that tampering with an audit record's payload breaks hash validation."""
    entry = await record_audit_log(
        session=db_session,
        event_type="TEST_TAMPER",
        action="original_action",
        resource_type="target",
        event_data={"amount": 100},
    )
    await db_session.commit()

    assert verify_event_hash(entry) is True

    # Tamper with the event data in-memory
    entry.event_data = {"amount": 999999}
    assert verify_event_hash(entry) is False


@pytest.mark.asyncio
async def test_concurrent_audit_writes():
    """Verifies that concurrent asynchronous tasks write to the audit log without collision."""
    num_concurrent = 10
    unique_event_type = f"CONCURRENT_TEST_{uuid.uuid4().hex[:8]}"
    start_barrier = asyncio.Event()

    async def write_log(idx: int):
        await start_barrier.wait()
        async with AsyncSessionLocal() as session:
            await record_audit_log(
                session=session,
                event_type=unique_event_type,
                action=f"concurrent_action_{idx}",
                resource_type="concurrency_test",
                event_data={"index": idx},
            )
            await session.commit()

    # Launch concurrent tasks waiting at barrier
    tasks = [asyncio.create_task(write_log(i)) for i in range(num_concurrent)]
    start_barrier.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        assert not isinstance(r, Exception), f"Concurrent write raised exception: {r}"

    # Query the 10 entries and verify their sequential hash chaining
    async with AsyncSessionLocal() as session:
        query = (
            select(AuditLog)
            .where(AuditLog.event_type == unique_event_type)
            .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
        )
        res = await session.execute(query)
        logs = list(res.scalars().all())

        assert len(logs) == num_concurrent
        # Verify unbroken subchain across these logs: no duplicate predecessors, no forks
        seen_prev_hashes = set()
        for i in range(len(logs)):
            assert verify_event_hash(logs[i]) is True
            assert logs[i].previous_hash not in seen_prev_hashes, f"Duplicate previous_hash detected at index {i}"
            seen_prev_hashes.add(logs[i].previous_hash)
            if i > 0:
                assert logs[i].previous_hash == logs[i - 1].event_hash


@pytest.mark.asyncio
async def test_security_decision_persisted_to_audit_log(db_session, test_operator):
    """Verifies that Security Gateway evaluations are durably persisted in PostgreSQL."""
    decision = await authorize_action(
        user=test_operator,
        operation="run_security_scan",
        capability="scan",
        resource_type="target",
        resource_id="10.0.0.15",
        environment="sandbox",
        session=db_session,
    )
    await db_session.commit()

    assert decision.allowed is True

    # Query the persisted audit log
    query = (
        select(AuditLog)
        .where(
            AuditLog.event_type == AuditEvent.SECURITY_GATEWAY_DECISION.value,
            AuditLog.actor_id == test_operator.id,
            AuditLog.resource_id == "10.0.0.15",
        )
        .order_by(AuditLog.created_at.desc())
        .limit(1)
    )
    result = await db_session.execute(query)
    persisted = result.scalar_one_or_none()

    assert persisted is not None
    assert persisted.action == "run_security_scan"
    assert persisted.decision == "allow"
    assert verify_event_hash(persisted) is True


@pytest.mark.asyncio
async def test_audit_api_admin_only_access(viewer_token, operator_token, admin_token):
    """Verifies that GET /api/v1/audit requires ADMIN role and rejects other roles."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Unauthenticated request
        resp_unauth = await client.get("/api/v1/audit")
        assert resp_unauth.status_code == 401

        # 2. Viewer request -> 403 Forbidden
        resp_viewer = await client.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp_viewer.status_code == 403

        # 3. Security Operator request -> 403 Forbidden
        resp_op = await client.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert resp_op.status_code == 403

        # 4. Admin request -> 200 OK
        resp_admin = await client.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp_admin.status_code == 200
        data = resp_admin.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data


@pytest.mark.asyncio
async def test_audit_api_pagination_and_filtering(admin_token, db_session):
    """Verifies audit API pagination parameters and event_type filtering."""
    unique_tag = f"FILTER_TEST_{uuid.uuid4().hex[:6]}"

    # Insert 3 test audit entries with unique tag
    for i in range(3):
        await record_audit_log(
            session=db_session,
            event_type=unique_tag,
            action=f"action_{i}",
            resource_type="test",
            event_data={"index": i},
        )
    await db_session.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Filter by unique event_type with page_size=2
        resp = await client.get(
            f"/api/v1/audit?event_type={unique_tag}&page=1&page_size=2",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["items"]) == 2
        assert data["page"] == 1
        assert data["page_size"] == 2
        assert data["total_pages"] == 2

        # Page 2
        resp_page2 = await client.get(
            f"/api/v1/audit?event_type={unique_tag}&page=2&page_size=2",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp_page2.status_code == 200
        data2 = resp_page2.json()
        assert len(data2["items"]) == 1


@pytest.mark.asyncio
async def test_audit_api_immutability(admin_token):
    """Guarantees that audit records cannot be modified, created, or deleted via the API."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        headers = {"Authorization": f"Bearer {admin_token}"}

        # POST attempt
        post_resp = await client.post("/api/v1/audit", headers=headers, json={"action": "inject"})
        assert post_resp.status_code in (404, 405)

        # PUT attempt
        put_resp = await client.put(f"/api/v1/audit/{uuid.uuid4()}", headers=headers, json={})
        assert put_resp.status_code in (404, 405)

        # DELETE attempt
        del_resp = await client.delete(f"/api/v1/audit/{uuid.uuid4()}", headers=headers)
        assert del_resp.status_code in (404, 405)


def test_each_canonical_field_modification_breaks_hash():
    """Verifies that altering ANY of the 11 canonical fields invalidates the cryptographic hash."""
    base_id = uuid.uuid4()
    base_actor_id = uuid.uuid4()
    base_created_at = datetime.now(timezone.utc)
    prev_hash = "0" * 64

    canonical = compute_canonical_payload(
        event_id=base_id,
        event_type="AUTH_LOGIN_SUCCESS",
        actor_id=base_actor_id,
        actor_role="admin",
        action="login",
        resource_type="user",
        resource_id="res_01",
        decision="success",
        event_data={"key": "value"},
        created_at=base_created_at,
    )
    valid_hash = compute_event_hash(prev_hash, canonical)

    # Factory returning a valid baseline record
    def make_log(**kwargs):
        data = {
            "id": base_id,
            "event_type": "AUTH_LOGIN_SUCCESS",
            "actor_id": base_actor_id,
            "actor_role": "admin",
            "action": "login",
            "resource_type": "user",
            "resource_id": "res_01",
            "decision": "success",
            "event_data": {"key": "value"},
            "previous_hash": prev_hash,
            "event_hash": valid_hash,
            "created_at": base_created_at,
        }
        data.update(kwargs)
        return AuditLog(**data)

    # 1. Baseline is valid
    assert verify_event_hash(make_log()) is True

    # 2. Modify each field individually and verify hash check failure
    assert verify_event_hash(make_log(id=uuid.uuid4())) is False
    assert verify_event_hash(make_log(event_type="TAMPERED_EVENT")) is False
    assert verify_event_hash(make_log(actor_id=uuid.uuid4())) is False
    assert verify_event_hash(make_log(actor_role="viewer")) is False
    assert verify_event_hash(make_log(action="logout")) is False
    assert verify_event_hash(make_log(resource_type="database")) is False
    assert verify_event_hash(make_log(resource_id="res_99")) is False
    assert verify_event_hash(make_log(decision="denied")) is False
    assert verify_event_hash(make_log(event_data={"key": "tampered"})) is False
    assert verify_event_hash(make_log(previous_hash="f" * 64)) is False
    assert verify_event_hash(make_log(created_at=datetime.fromtimestamp(0, tz=timezone.utc))) is False


def test_enhanced_compound_key_sanitization():
    """Verifies that compound credential patterns are recursively stripped."""
    payload = {
        "client_id": "safe_client_123",
        "client_secret": "sensitive_secret_value",
        "custom_api_key": "sk-test-12345",
        "user_password_hash": "argon2_string",
        "auth_token_value": "bearer_jwt",
        "nested_dict": {
            "my_private_key_pem": "-----BEGIN PRIVATE KEY-----",
            "public_key_ok": "ssh-rsa AAAAB3...",
        },
        "items": [
            {"stripe_api_key": "sec_stripe", "name": "item1"},
        ],
    }

    clean = sanitize_event_data(payload)
    assert clean["client_id"] == "safe_client_123"
    assert "client_secret" not in clean
    assert "custom_api_key" not in clean
    assert "user_password_hash" not in clean
    assert "auth_token_value" not in clean
    assert "my_private_key_pem" not in clean["nested_dict"]
    assert clean["nested_dict"]["public_key_ok"] == "ssh-rsa AAAAB3..."
    assert "stripe_api_key" not in clean["items"][0]
    assert clean["items"][0]["name"] == "item1"


@pytest.mark.asyncio
async def test_auth_registration_fails_closed_when_audit_persistence_fails(monkeypatch):
    """Verifies that user registration aborts and returns 500 if mandatory audit persistence fails."""
    async def mock_record_fail(*args, **kwargs):
        raise RuntimeError("Database audit write error injected")

    monkeypatch.setattr("app.api.auth.record_audit_log", mock_record_fail)

    unique_user = f"audit_fail_reg_{uuid.uuid4().hex[:6]}"
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": f"{unique_user}@example.com",
                "username": unique_user,
                "password": "ValidPassword123!",
            },
        )
        assert resp.status_code == 500
        assert "Security audit persistence failed" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_auth_login_fails_closed_when_audit_persistence_fails(test_operator, monkeypatch):
    """Verifies that login fails closed with HTTP 500 without issuing tokens if audit logging fails."""
    async def mock_record_fail(*args, **kwargs):
        raise RuntimeError("Database audit write error injected")

    monkeypatch.setattr("app.api.auth.record_audit_log", mock_record_fail)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            "/api/v1/auth/login",
            json={
                "username_or_email": test_operator.username,
                "password": "OperatorPass123!",
            },
        )
        assert resp.status_code == 500
        assert "Security audit persistence failed" in resp.json()["detail"]

