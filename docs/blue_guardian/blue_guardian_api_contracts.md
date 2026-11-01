# Blue Guardian Agent — REST API Contracts & Endpoint Specifications
## AegisMesh 2.0 Subsystem Design Specification (Step 09.2.3.1)

---

## 1. Overview & Authentication Standards

The Blue Guardian REST API exposes defensive intelligence capabilities to the AegisMesh platform, SOC Command Center frontend, and authorized external orchestration consumers.

### Universal Endpoint Invariants:
1. **Authentication**: All endpoints require a valid JWT Bearer token (`Authorization: Bearer <token>`).
2. **OPA Authorization**: Requests are gated through the Open Policy Agent (OPA) policy engine evaluating action, subject role, capability, and sandbox ownership.
3. **Sandbox Isolation**: Queries for executions, detections, or findings are bounded by the requesting user's accessible `sandbox_id`.
4. **Standard Error Schema**: All non-2xx responses conform to the standard RFC 7807 `ProblemDetails` format:
   ```json
   {
     "detail": "Descriptive error message",
     "error_code": "RESOURCE_NOT_FOUND",
     "timestamp": "2026-11-01T00:00:00Z"
   }
   ```

---

## 2. API Endpoint Specifications

### 2.1 Trigger Defensive Analysis Execution
- **Path**: `POST /api/v1/guardian/executions`
- **Description**: Triggers a defensive analysis session against an existing completed `AttackRun` or an `AttackPath`.
- **OPA Capability**: `guardian.analyze` (Required role: `admin` or `security_operator`, capability: `scan`)
- **Status Codes**:
  - `201 Created`: Execution initiated successfully.
  - `400 Bad Request`: Neither `attack_run_id` nor `attack_path_id` provided, or both invalid.
  - `401 Unauthorized`: Missing or invalid JWT.
  - `403 Forbidden`: OPA denied action or user lacks access to target sandbox.
  - `404 Not Found`: Referenced `attack_run_id` or `attack_path_id` does not exist.
  - `409 Conflict`: Analysis already currently running for this target.

#### Request Body Schema
```json
{
  "attack_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "attack_path_id": null,
  "sandbox_id": "4fa85f64-5717-4562-b3fc-2c963f66afa7",
  "correlation_window_seconds": 300,
  "generate_incident": true
}
```

#### Response Body Schema (`201 Created`)
```json
{
  "execution_id": "7fa85f64-5717-4562-b3fc-2c963f66afa9",
  "sandbox_id": "4fa85f64-5717-4562-b3fc-2c963f66afa7",
  "attack_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "attack_path_id": null,
  "status": "INGESTING",
  "started_at": "2026-11-01T01:30:00Z",
  "events_ingested": 0,
  "detections_matched": 0,
  "findings_generated": 0
}
```

---

### 2.2 Get Execution Details & Status
- **Path**: `GET /api/v1/guardian/executions/{id}`
- **Description**: Retrieves the status, execution metadata, and aggregate counts of a defensive analysis execution.
- **OPA Capability**: `guardian.read` (Required role: `admin`, `security_operator`, or `security_analyst`, capability: `read`)
- **Status Codes**:
  - `200 OK`: Details returned.
  - `401 Unauthorized`: Invalid credentials.
  - `403 Forbidden`: Access denied by OPA policy.
  - `404 Not Found`: Execution ID does not exist.

#### Response Body Schema (`200 OK`)
```json
{
  "execution_id": "7fa85f64-5717-4562-b3fc-2c963f66afa9",
  "sandbox_id": "4fa85f64-5717-4562-b3fc-2c963f66afa7",
  "attack_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "attack_path_id": null,
  "incident_id": "8fa85f64-5717-4562-b3fc-2c963f66afa8",
  "status": "COMPLETED",
  "started_at": "2026-11-01T01:30:00Z",
  "completed_at": "2026-11-01T01:30:04Z",
  "events_ingested": 28,
  "detections_matched": 7,
  "findings_generated": 3,
  "risk_score": 7.85,
  "error_message": null
}
```

---

### 2.3 Get Raw Matched Detections
- **Path**: `GET /api/v1/guardian/executions/{id}/detections`
- **Description**: Retrieves discrete detection results matched by the deterministic rule engine.
- **OPA Capability**: `guardian.read`
- **Query Parameters**:
  - `severity`: Optional filter (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - `rule_id`: Optional filter by rule code (e.g., `DET-AUTH-001`)

#### Response Body Schema (`200 OK`)
```json
[
  {
    "detection_id": "11a85f64-5717-4562-b3fc-2c963f66afa1",
    "rule_id": "DET-AUTH-001",
    "source_event_id": "evt-sim-8823-1",
    "envelope_id": "22a85f64-5717-4562-b3fc-2c963f66afa2",
    "matched_at": "2026-11-01T01:30:01Z",
    "severity": "HIGH",
    "confidence": 0.95,
    "matched_indicators": {
      "endpoint": "/api/v1/auth/token",
      "bypass_header": "X-Forwarded-For-Mock",
      "status_code": 200
    },
    "summary": "Simulated authentication bypass pattern detected on target API endpoint."
  }
]
```

---

### 2.4 Get Defensive Findings
- **Path**: `GET /api/v1/guardian/executions/{id}/findings`
- **Description**: Retrieves synthesized defensive findings with linked MITRE techniques, affected assets, and evidence references.
- **OPA Capability**: `guardian.read`

#### Response Body Schema (`200 OK`)
```json
[
  {
    "finding_id": "33a85f64-5717-4562-b3fc-2c963f66afa3",
    "guardian_execution_id": "7fa85f64-5717-4562-b3fc-2c963f66afa9",
    "title": "Unauthenticated Administrative Access via Header Forgery",
    "description": "Deterministic simulation exhibited authorization bypass allowing unauthenticated role escalation.",
    "severity": "HIGH",
    "confidence": 0.95,
    "rule_ids": ["DET-AUTH-001", "DET-PRIV-002"],
    "evidence_event_ids": ["evt-sim-8823-1", "evt-sim-8823-4"],
    "asset_ids": ["asset-api-gateway-01", "asset-auth-service-01"],
    "mitre_techniques": ["T1078", "T1068"],
    "created_at": "2026-11-01T01:30:02Z"
  }
]
```

---

### 2.5 Get Correlated Event Groups
- **Path**: `GET /api/v1/guardian/executions/{id}/correlated-groups`
- **Description**: Retrieves multi-event correlation groups representing kill-chain phases and lateral propagation.
- **OPA Capability**: `guardian.read`

#### Response Body Schema (`200 OK`)
```json
[
  {
    "group_id": "44a85f64-5717-4562-b3fc-2c963f66afa4",
    "sandbox_id": "4fa85f64-5717-4562-b3fc-2c963f66afa7",
    "title": "Initial Ingress and Pivot to Internal Database",
    "stage": "LATERAL_MOVEMENT",
    "primary_tactic": "Lateral Movement",
    "member_detection_ids": ["11a85f64-5717-4562-b3fc-2c963f66afa1"],
    "member_event_ids": ["evt-sim-8823-1", "evt-sim-8823-5"],
    "root_cause_asset_id": "asset-api-gateway-01",
    "impacted_asset_ids": ["asset-customer-db-01"],
    "time_window_start": "2026-11-01T01:30:00Z",
    "time_window_end": "2026-11-01T01:30:03Z",
    "correlation_confidence": 0.88
  }
]
```

---

### 2.6 Get Asset Impact & Blast Radius
- **Path**: `GET /api/v1/guardian/executions/{id}/impact`
- **Description**: Returns the comprehensive threat and blast radius assessment across all synthetic assets.
- **OPA Capability**: `guardian.read`

#### Response Body Schema (`200 OK`)
```json
{
  "assessment_id": "55a85f64-5717-4562-b3fc-2c963f66afa5",
  "guardian_execution_id": "7fa85f64-5717-4562-b3fc-2c963f66afa9",
  "sandbox_id": "4fa85f64-5717-4562-b3fc-2c963f66afa7",
  "risk_score": 7.85,
  "severity_factor": 0.75,
  "blast_radius_factor": 0.80,
  "stage_progression_factor": 0.70,
  "confidence_factor": 0.92,
  "asset_assessments": [
    {
      "asset_id": "asset-customer-db-01",
      "asset_name": "Customer Core Database",
      "criticality": "CRITICAL",
      "direct_compromise": true,
      "blast_radius_depth": 1,
      "downstream_impacted_assets": ["asset-analytics-warehouse-01"],
      "confidentiality_impact": 0.90,
      "integrity_impact": 0.50,
      "availability_impact": 0.10,
      "composite_impact_score": 0.82
    }
  ],
  "created_at": "2026-11-01T01:30:03Z"
}
```

---

### 2.7 Get Defensive Recommendations
- **Path**: `GET /api/v1/guardian/executions/{id}/recommendations`
- **Description**: Retrieves prioritized remediation recommendations with patch diffs, policy rules, and human-approval requirements.
- **OPA Capability**: `guardian.read`

#### Response Body Schema (`200 OK`)
```json
[
  {
    "recommendation_id": "66a85f64-5717-4562-b3fc-2c963f66afa6",
    "finding_id": "33a85f64-5717-4562-b3fc-2c963f66afa3",
    "guardian_execution_id": "7fa85f64-5717-4562-b3fc-2c963f66afa9",
    "category": "CONFIG",
    "priority": 1,
    "title": "Enforce Strict Cryptographic JWT Algorithm Validation",
    "remediation_guidance": "Disable acceptance of unverified tokens and enforce HMAC-SHA256 signature verification in API Gateway auth middleware.",
    "target_component": "app/core/auth_middleware.py",
    "proposed_patch_diff": "--- a/app/core/auth_middleware.py\n+++ b/app/core/auth_middleware.py\n@@ -12,2 +12,2 @@\n-    algorithms=['none', 'HS256']\n+    algorithms=['HS256']",
    "proposed_policy_rule": null,
    "automated_remediation_blocked": true,
    "approval_id": null
  }
]
```

---

### 2.8 Get Synthesized Incident Report
- **Path**: `GET /api/v1/guardian/executions/{id}/report`
- **Description**: Returns the complete synthesized incident report with cryptographic payload digest for compliance.
- **OPA Capability**: `guardian.read`

#### Response Body Schema (`200 OK`)
```json
{
  "report_id": "77a85f64-5717-4562-b3fc-2c963f66afa7",
  "incident_id": "8fa85f64-5717-4562-b3fc-2c963f66afa8",
  "guardian_execution_id": "7fa85f64-5717-4562-b3fc-2c963f66afa9",
  "sandbox_id": "4fa85f64-5717-4562-b3fc-2c963f66afa7",
  "generated_at": "2026-11-01T01:30:04Z",
  "findings_count": 3,
  "recommendations_count": 3,
  "correlated_group_count": 1,
  "detection_rate": 0.875,
  "summary_markdown": "# AegisMesh 2.0 Incident Report\n...",
  "report_sha256": "8a35e69bf90c1f6b15e2195fbc999d3ae3b95c32410a5e884e92d7732ad50f01"
}
```

---

### 2.9 Submit Remediation Approval Request
- **Path**: `POST /api/v1/guardian/approvals`
- **Description**: Submits an operator sign-off or approval request for a defensive recommendation. Enforces 4-eyes principle.
- **OPA Capability**: `guardian.approve_remediation` (Required role: `admin`, capability: `admin`)
- **Status Codes**:
  - `201 Created`: Approval decision recorded.
  - `400 Bad Request`: Requester and approver are the same user (violates 4-eyes rule) or invalid state.
  - `403 Forbidden`: Insufficient role to approve remediation.
  - `404 Not Found`: Recommendation ID does not exist.

#### Request Body Schema
```json
{
  "recommendation_id": "66a85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "APPROVED",
  "approval_reason": "Verified configuration change in staging environment. Ready for controlled application."
}
```

#### Response Body Schema (`201 Created`)
```json
{
  "approval_id": "99a85f64-5717-4562-b3fc-2c963f66afa9",
  "recommendation_id": "66a85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "APPROVED",
  "requested_by_user_id": "1fa85f64-5717-4562-b3fc-2c963f66afa1",
  "approver_user_id": "2fa85f64-5717-4562-b3fc-2c963f66afa2",
  "decided_at": "2026-11-01T01:35:00Z",
  "decision_rationale": "Verified configuration change in staging environment. Ready for controlled application."
}
```

