# AegisMesh 2.0 — Security Gateway & OPA Policy Enforcement

This document specifies the authorization architecture, Rego policy rulebooks, fail-closed mechanics, and testing procedures for the **AegisMesh Security Gateway**.

---

## 1. Architectural Philosophy

In an autonomous AI security operations platform, **LLMs are untrusted for authorization decisions**. An AI agent or caller can request an action, but the action must be independently evaluated and verified by a deterministic policy engine prior to execution.

```
+---------------------------------------------------------------------------------+
|                                 FASTAPI BACKEND                                 |
|                                                                                 |
|  +--------------------+     1. Authenticate       +--------------------------+  |
|  |   Incoming Client  | ------------------------> | RBAC Verification        |  |
|  |       Request      |                           | (Role, Token, Revocation)|  |
|  +--------------------+                           +--------------------------+  |
|                                                                |                |
|                                                                | 2. Trusted     |
|                                                                |    Input       |
|                                                                v                |
|  +--------------------+    4. Enforce / Audit     +--------------------------+  |
|  |  Action Execution  | <------------------------ |     Security Gateway     |  |
|  | (or 403 Forbidden) |                           |  (gateway.py / Context)  |  |
|  +--------------------+                           +--------------------------+  |
|                                                                |                |
+----------------------------------------------------------------|----------------+
                                                                 |
                                              3. Evaluate Policy | (HTTP POST /v1/data/aegis/decision)
                                                                 v
                                                    +--------------------------+
                                                    |  Open Policy Agent (OPA) |
                                                    |  Docker (localhost:8181) |
                                                    |  Rulebook: aegis.rego    |
                                                    +--------------------------+
```

* **Policy Enforcement Point (PEP)**: FastAPI Security Gateway ([`backend/app/security/gateway.py`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/backend/app/security/gateway.py)).
* **Policy Decision Point (PDP)**: Open Policy Agent daemon ([`backend/policies/aegis.rego`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/backend/policies/aegis.rego)).
* **Tamper-Proof Subject Identity**: Caller identity (`user_id`, `role`, `is_authenticated`) is derived strictly from the cryptographically verified JWT bearer token and database user record, never from unverified request payloads.

---

## 2. Policy Input Schema

The Security Gateway formats every authorization query into a structured, validated envelope:

```json
{
  "input": {
    "subject": {
      "user_id": "f7ebc154-8da1-4179-96b2-92873564102d",
      "role": "security_operator",
      "is_authenticated": true
    },
    "action": {
      "operation": "scan.execute",
      "capability": "scan"
    },
    "resource": {
      "type": "target",
      "id": "192.168.1.50",
      "environment": "sandbox"
    },
    "context": {
      "request_id": "c1f7a049-9f7a-4c92-bf38-518cb8702b8d",
      "timestamp": "2026-10-31T14:15:00.000000Z",
      "risk_level": "medium",
      "approval_status": "none"
    }
  }
}
```

---

## 3. Rego Policy Rules (`backend/policies/aegis.rego`)

The governing Rego policy is written in **Rego v1** and loaded into OPA.

### Core Invariants
1. **Default Deny**: Every action is denied by default unless an explicit, narrowly scoped rule matches.
2. **Mandatory Authentication**: All rules require `input.subject.is_authenticated == true`.
3. **Role Segregation**:
   * **`admin`**: System administration and governance.
   * **`security_operator`**: Operational scans, approved remediations, and sandbox testing.
   * **`security_analyst`**: Read-only threat investigations and report analysis.
   * **`viewer`**: Read-only inspection of non-sensitive assets; blocked from all scans and executions.
4. **Environment Isolation**: Attack and intrusive scans are strictly blocked outside the `sandbox` environment (`environment == "sandbox"`).
5. **Human-in-the-Loop Safeguards**:
   * Remediation actions (`remediation.execute`) require `context.approval_status == "approved"`.
   * Policy modifications (`policy.modify`) require `admin` role **and** `context.approval_status == "approved"`.
6. **External Target Boundary**: Scans directed against `external_target` resources outside the sandbox require explicit human approval.

---

## 4. Structured Decision Format

OPA returns a deterministic decision document:

```json
{
  "result": {
    "allowed": false,
    "decision": "deny",
    "reason": "Human approval required for remediation execution.",
    "policy_version": "1.0.0"
  }
}
```

When allowed:
```json
{
  "result": {
    "allowed": true,
    "decision": "allow",
    "reason": "Authorized by policy.",
    "policy_version": "1.0.0"
  }
}
```

---

## 5. Fail-Closed Mechanics

If the OPA daemon becomes unreachable (network disconnection, crash, or timeout):
* The Security Gateway **does not** fail open.
* It immediately generates a synthetic deny decision:
  ```json
  {
    "allowed": false,
    "decision": "deny",
    "reason": "Authorization service unavailable (fail-closed)",
    "policy_version": "1.0.0"
  }
  ```
* Emits a `SECURITY_GATEWAY_DECISION` audit event logging the outage.
* Protects downstream systems from executing unauthorized actions during authorization infrastructure failure.

---

## 6. Pre-flight Security Check API

Authorized callers can test permissions ahead of execution via:

`POST /api/v1/security/check`

**Headers**:
```text
Authorization: Bearer <access_token>
```

**Request Body**:
```json
{
  "operation": "scan.execute",
  "capability": "scan",
  "resource_type": "target",
  "resource_id": "srv-101",
  "environment": "sandbox",
  "risk_level": "low",
  "approval_status": "none"
}
```

**Response (HTTP 200)**:
```json
{
  "allowed": true,
  "decision": "allow",
  "reason": "Authorized by policy.",
  "policy_version": "1.0.0"
}
```

---

## 7. Adding New Policies Safely

1. Edit [`backend/policies/aegis.rego`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/backend/policies/aegis.rego).
2. Validate syntax using the OPA CLI inside Docker:
   ```powershell
   docker exec aegismesh-opa-1 opa check /policies/aegis.rego
   ```
3. Restart or reload OPA:
   ```powershell
   docker restart aegismesh-opa-1
   ```
4. Add corresponding test cases to [`backend/tests/test_security_gateway.py`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/backend/tests/test_security_gateway.py).
5. Run the test suite:
   ```powershell
   cd backend
   .\.venv\Scripts\pytest -v tests/test_security_gateway.py
   ```

