# Blue Guardian Agent — Defensive Security Model & Boundary Invariants
## AegisMesh 2.0 Subsystem Design Specification (Step 09.2.3.1)

---

## 1. Threat Model & Defensive Security Mission

The **Blue Guardian Agent** is designed to provide cognitive defensive analysis while enforcing strict security boundaries. Because it operates alongside autonomous offensive simulation (Red Team) and attack orchestration engines, it must maintain rigorous isolation to prevent security feedback loops, unauthorized infrastructure changes, or telemetry poisoning.

### Core Security Objectives:
1. **Zero Real-World Impact**: Guarantee that defensive analysis never interacts with production infrastructure, external networks, or physical devices.
2. **Forensic Immutability**: Ensure that red-team evidence, detection outputs, and audit logs are cryptographically protected against tampering or deletion.
3. **Strict Human Governance**: Prevent autonomous remediation agents from enacting configuration changes without human authorization.
4. **Tenant & Sandbox Containment**: Prevent multi-tenant cross-contamination or cross-sandbox data leakage.

---

## 2. Platform Security Invariants

```
+----------------------------------------------------------------------------------------------------+
|                                      SECURITY INVARIANT MATRIX                                     |
+------------------------------+----------------------------------+----------------------------------+
| Invariant Dimension          | Rule Specification              | Enforcement Mechanism            |
+------------------------------+----------------------------------+----------------------------------+
| 1. Synthetic-Only Telemetry  | Defensive engine only ingests    | Ingestion schema validator:      |
|                              | events with is_simulated=True    | is_simulated == True,            |
|                              | and simulation_only=True.        | rejects non-synthetic events.    |
+------------------------------+----------------------------------+----------------------------------+
| 2. Evidence Immutability     | Red team telemetry cannot be     | PostgreSQL read-only queries,    |
|                              | mutated, deleted, or truncated.  | ON DELETE RESTRICT on AttackRun. |
+------------------------------+----------------------------------+----------------------------------+
| 3. Sandbox Isolation         | Cross-sandbox queries or         | Mandatory sandbox_id predicate   |
|                              | correlations are forbidden.      | on all ORM queries and indexes.  |
+------------------------------+----------------------------------+----------------------------------+
| 4. OPA Default-Deny Access   | Every API invocation requires    | OPA Rego policy evaluation       |
|                              | active JWT & role permissions.   | checking action, role, and cap.  |
+------------------------------+----------------------------------+----------------------------------+
| 5. Human-in-the-Loop Barrier | Autonomous patching or system    | automated_remediation_blocked=T, |
|                              | mutation is strictly prohibited. | requires signed Approval entity. |
+------------------------------+----------------------------------+----------------------------------+
| 6. Forensic Audit Integrity  | All defensive transitions must   | SHA-256 hash chaining into       |
|                              | append to persistent audit chain.| platform audit_logs table.       |
+------------------------------+----------------------------------+----------------------------------+
```

---

## 3. Detailed Security Architecture

### 3.1 Synthetic-Only Isolation Guarantee
Blue Guardian consumes data exclusively from:
- `AttackRun.execution_metadata`
- `AttackPath.graph_data`
- `SyntheticAsset` tables

The engine has no outbound HTTP client capability to arbitrary Internet hosts, no subprocess execution tools (`os.system`, `subprocess.Popen`), and no socket listeners. Ingested events undergo strict verification:
```python
def verify_synthetic_envelope(envelope: DefensiveEventEnvelope) -> None:
    if not envelope.is_simulated or not envelope.simulation_only:
        raise SecurityException("DEFENSIVE_REJECT_NON_SYNTHETIC: Telemetry must be purely synthetic.")
```

### 3.2 Evidence Immutability & Provenance Chains
When Blue Guardian ingests events, it calculates a deterministic SHA-256 digest over the canonical JSON representation of the payload. The resulting digest is stored in `DefensiveEventEnvelope.sha256_hash`.
- Defensive findings and recommendations maintain a direct foreign-key link to the originating execution and an immutable reference list to `evidence_event_ids`.
- Deletion of an `AttackRun` or `SandboxEnvironment` while defensive records reference them is strictly blocked via `ON DELETE RESTRICT` constraints in PostgreSQL.

### 3.3 Sandbox Boundary Isolation
Every invocation of Blue Guardian requires a validated `sandbox_id`.
- The correlation engine enforces:
  $$\forall e_i, e_j \in \text{CorrelatedGroup}: \text{sandbox}(e_i) = \text{sandbox}(e_j) = \text{execution.sandbox\_id}$$
- Any event possessing an inconsistent `sandbox_id` is discarded, and a security warning is logged to the audit chain.

### 3.4 Open Policy Agent (OPA) Authorization Architecture
Blue Guardian integrates with the platform's default-deny OPA Rego engine. All defensive actions map to specific capabilities and minimum roles:

| Action | Required Capability | Minimum Role | Evaluation Policy Rule |
|---|---|---|---|
| `guardian.analyze` | `scan` | `security_operator` | Validates user holds `scan` capability on target sandbox. |
| `guardian.read` | `read` | `security_analyst` | Validates read access on target sandbox. |
| `guardian.generate_report` | `report` | `security_analyst` | Validates reporting capability on target campaign/sandbox. |
| `guardian.request_approval` | `scan` | `security_operator` | Submits remediation advice for human sign-off. |
| `guardian.approve_remediation` | `admin` | `admin` | Enforces 4-eyes principle (requester $\ne$ approver). |

#### Rego Authorization Policy Snippet (`authz/guardian.rego`):
```rego
package aegismesh.authz.guardian

default allow = false

# Allow security operators and admins to trigger defensive analysis
allow {
    input.action == "guardian.analyze"
    input.user.role in ["admin", "security_operator"]
    input.user.capabilities[_] == "scan"
    input.target.sandbox_id == input.user.assigned_sandbox_id
}

# Allow analysts, operators, and admins to inspect defensive intelligence
allow {
    input.action == "guardian.read"
    input.user.role in ["admin", "security_operator", "security_analyst"]
    input.user.capabilities[_] == "read"
}

# Four-eyes governance rule for remediation sign-off
allow {
    input.action == "guardian.approve_remediation"
    input.user.role == "admin"
    input.user.capabilities[_] == "admin"
    input.approval.requested_by != input.user.id
}
```

### 3.5 Advisory Remediation Guardrails (Human-in-the-Loop Barrier)
To prevent rogue agent behavior or unintended disruption:
1. `DefensiveRecommendation` entities are schema-restricted with `automated_remediation_blocked: Literal[True] = True`.
2. The recommendation engine cannot invoke sandbox mutation tools, patch apply scripts, or firewall reconfiguration APIs.
3. Recommendations serve solely as advisory manifests containing `remediation_guidance`, `proposed_patch_diff`, and `proposed_policy_rule`.
4. Only when an authenticated administrator submits a `RemediationApproval` with status `APPROVED` may a human operator (or an explicitly authorized execution pipeline) apply the changes.
5. The 4-eyes principle is enforced: the user who requested the remediation approval cannot be the approving administrator.

### 3.6 Cryptographic Audit Logging
All state transitions in Blue Guardian append to the platform's cryptographic SHA-256 audit log. Each log entry records:
- `timestamp`: UTC timestamp.
- `actor_id`: UUID of requesting user or agent service account.
- `action`: Specific lifecycle stage (`guardian.execution_started`, `guardian.detection_completed`, etc.).
- `sandbox_id`: Associated sandbox.
- `details`: Contextual metadata including counts, risk score, and finding IDs.
- `previous_hash`: SHA-256 digest of the previous audit log entry.
- `hash`: SHA-256 digest of the current record concatenated with `previous_hash`.

