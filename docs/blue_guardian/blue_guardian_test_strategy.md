# Blue Guardian Agent — Defensive Test Strategy & Verification Plan
## AegisMesh 2.0 Subsystem Design Specification (Step 09.2.3.1)

---

## 1. Test Philosophy & Verification Objectives

The **Blue Guardian Agent** must deliver high diagnostic accuracy, strict security boundary enforcement, and deterministic reproducibility. Because it evaluates synthetic attack telemetry and generates high-consequence defensive guidance, its test suite must verify both positive detection capabilities and rigorous negative security controls.

### Core Testing Pillars:
1. **Deterministic Accuracy**: Zero tolerance for nondeterministic detection flakes or floating-point variance in risk scoring.
2. **Strict Schema Conformance**: 100% validation of all 13 Pydantic v2 contracts with forbidden extra fields.
3. **Security Invariant Verification**: Exhaustive verification of synthetic-only isolation, OPA authorization, sandbox boundary containment, and human approval barriers.
4. **Resiliency & Recovery**: Automated simulation of telemetry delays, malformed events, and concurrent execution requests.

---

## 2. Test Architecture & Pytest Hierarchy

The Blue Guardian test suite is organized into three distinct tiers:

```
backend/tests/guardian/
├── test_guardian_schemas.py           # Unit: Pydantic v2 schema validation & immutability
├── test_guardian_detection_rules.py   # Unit: Rule matching across all 8 attack scenarios
├── test_guardian_correlation.py       # Unit: Temporal & topological graph correlation
├── test_guardian_risk_scoring.py      # Unit: Bounded risk formula & edge case testing
├── test_guardian_recommendations.py   # Unit: Advisory recommendation generation & safety flags
├── test_guardian_ingestion_service.py # Integration: AttackRun telemetry ingestion & normalization
├── test_guardian_persistence.py       # Integration: Database ORM, FK constraints, ON DELETE RESTRICT
├── test_guardian_security_opa.py      # Security: OPA capability checks & role boundaries
├── test_guardian_sandbox_isolation.py # Security: Cross-sandbox telemetry leakage prevention
└── test_guardian_governance.py        # Governance: 4-eyes human remediation approval workflow
```

---

## 3. Test Fixture Matrix for the 8 Synthetic Attack Scenarios

The table below defines the test fixture inputs and expected deterministic outcomes for each scenario:

| Scenario Code | Scenario Name | Injected Synthetic Event Types | Expected Detection Rule | Expected Severity | Expected MITRE Technique |
|---|---|---|---|---|---|
| `SCN-001` | `scenario_api_auth_bypass` | `auth_bypass`, `token_missing_200` | `DET-AUTH-001` | `HIGH` | `T1078` |
| `SCN-002` | `scenario_privilege_escalation` | `role_escalation`, `unauthorized_admin_grant` | `DET-PRIV-002` | `CRITICAL` | `T1068` |
| `SCN-003` | `scenario_data_exfiltration` | `large_data_egress`, `synthetic_pii_dump` | `DET-EXFIL-003` | `HIGH` | `T1041` |
| `SCN-004` | `scenario_idor_data_leakage` | `cross_tenant_object_read`, `idor_access` | `DET-IDOR-004` | `HIGH` | `T1552` |
| `SCN-005` | `scenario_jwt_tampering` | `jwt_alg_none_accepted`, `expired_jwt_valid` | `DET-JWT-005` | `CRITICAL` | `T1606` |
| `SCN-006` | `scenario_ssrf_metadata` | `outbound_link_local_http`, `aws_metadata_probe` | `DET-SSRF-006` | `HIGH` | `T1090` |
| `SCN-007` | `scenario_rbac_creep` | `multi_asset_role_grant`, `unused_perm_accumulation` | `DET-CREEP-007` | `MEDIUM` | `T1078.004` |
| `SCN-008` | `scenario_crypto_exposure` | `private_key_in_log`, `cleartext_secret_leak` | `DET-CRYPTO-008` | `CRITICAL` | `T1552.001` |

---

## 4. Test Specifications by Functional Domain

### 4.1 Schema Validation & Immutability (`test_guardian_schemas.py`)
- **Frozen Contract Check**: Ensure assigning attributes to instantiated Pydantic models raises `ValidationError` or `TypeError`.
- **Forbidden Extra Fields**: Attempt to instantiate each model with `{"extra_field": "disallowed"}` and verify `ValidationError` is raised with `extra_forbidden`.
- **Epistemic Classification**: Verify that every schema enforces its designated `EpistemicClassification` (`OBSERVED`, `DERIVED`, `INFERRED`, `ADVISORY`).
- **UUID & SHA-256 Validation**: Validate that non-hex strings or invalid lengths for `sha256_hash` are rejected.

### 4.2 Deterministic Detection Rule Matching (`test_guardian_detection_rules.py`)
- **Positive Fixture Matching**: Pass synthetic event envelopes from all 8 scenarios through `RuleRegistry.evaluate_all()` and assert that the expected `rule_id`, `severity`, and `mitre_technique_id` are produced.
- **Negative Fixture Non-Matching**: Pass benign synthetic events (e.g., standard login with valid password, normal pagination query) and verify zero detections are matched.
- **Confidence Computation**: Verify confidence values always conform to $0.0 \le c \le 1.0$.

### 4.3 Correlation & Topological Traversal (`test_guardian_correlation.py`)
- **Temporal Window Boundary**: Provide two events separated by 299 seconds (clustered together) and another event separated by 301 seconds (split into separate cluster).
- **Graph Traversal**: Create a 3-node `SyntheticAsset` topology (`A -> B -> C`). Inject compromise at `A` and subsequent access at `B`. Verify the correlation engine identifies `A` as root cause and `B` as lateral movement target.

### 4.4 Bounded Risk Scoring (`test_guardian_risk_scoring.py`)
- **Upper Bound Invariant ($R \le 10.0$)**: Inject maximum parameters: severity=CRITICAL (1.0), blast radius=1.0, stage=PERSISTENCE (1.0), confidence=1.0. Verify calculated score is exactly $10.0$.
- **Lower Bound Invariant ($R \ge 0.0$)**: Inject minimal parameters: severity=LOW (0.25), blast radius=0.0, stage=RECON (0.2), confidence=0.1. Verify score is $\ge 0.0$ and strictly bounded.
- **Determinism Check**: Run 1,000 evaluations with random floating-point inputs within range and confirm $0.0 \le R \le 10.0$ for 100% of iterations.

### 4.5 Advisory Remediation Guardrails (`test_guardian_recommendations.py`)
- **Blocked Autonomous Execution**: Verify that all generated `DefensiveRecommendation` instances have `automated_remediation_blocked == True`.
- **Diff & Policy Formatting**: Validate that proposed patches conform to standard unified diff or valid Rego syntax.

### 4.6 Security & OPA Authorization (`test_guardian_security_opa.py`)
- **Default-Deny**: Invocations without token or with invalid role (e.g., `guest`, `developer`) must receive HTTP 403 / OPA denial.
- **Capability Scoping**: Verify `guardian.analyze` requires `scan`, `guardian.read` requires `read`, and `guardian.approve_remediation` requires `admin`.
- **Sandbox Ownership**: Verify that User A cannot trigger or view defensive analysis on Sandbox B.

### 4.7 Cross-Sandbox Isolation (`test_guardian_sandbox_isolation.py`)
- **Telemetry Contamination Test**: Inject a synthetic event with `sandbox_id = Sandbox_B` into an execution for `Sandbox_A`. Verify the event is strictly rejected and flagged as a security violation.

### 4.8 4-Eyes Human Governance Workflow (`test_guardian_governance.py`)
- **Self-Approval Prohibition**: User A requests remediation approval and attempts to approve their own request. Verify HTTP 400 / OPA denial.
- **Valid 4-Eyes Sign-Off**: User A requests, Admin User B approves. Verify transition to `APPROVED` and recording of `applied_patch_digest` and SHA-256 audit log.

---

## 5. Sample Pytest Fixture & Execution Assertion

```python
import pytest
from uuid import uuid4
from datetime import datetime, timezone
from app.agents.blue_guardian.contracts import (
    DefensiveEventEnvelope,
    EpistemicClassification,
    DetectionSeverity,
)
from app.agents.blue_guardian.rules import evaluate_rules

def test_scenario_jwt_tampering_detection():
    # Arrange synthetic JWT tampering event
    sandbox_id = uuid4()
    attack_run_id = uuid4()
    
    envelope = DefensiveEventEnvelope(
        source_event_id="sim-evt-jwt-001",
        attack_run_id=attack_run_id,
        sandbox_id=sandbox_id,
        scenario_id="scenario_jwt_tampering_session_takeover",
        timestamp=datetime.now(timezone.utc),
        event_type="jwt_tampering",
        source_asset_id="asset-attacker-client",
        target_asset_id="asset-auth-service",
        payload={
            "token_alg": "none",
            "claims": {"sub": "admin", "role": "superuser"},
            "endpoint": "/api/v1/admin/users",
            "status_code": 200
        },
        is_simulated=True,
        simulation_only=True,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        classification=EpistemicClassification.OBSERVED
    )
    
    # Act
    results = evaluate_rules([envelope])
    
    # Assert
    assert len(results) == 1
    match = results[0]
    assert match.rule_id == "DET-JWT-005"
    assert match.severity == DetectionSeverity.CRITICAL
    assert match.confidence >= 0.90
    assert match.classification == EpistemicClassification.DERIVED
```

