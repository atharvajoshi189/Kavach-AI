# AegisMesh 2.0 — Database Architecture & Persistent Audit Specification

## 1. Executive Summary

AegisMesh 2.0 utilizes PostgreSQL 17 with the `pgvector` extension, managed through SQLAlchemy 2.x asynchronous ORM (`asyncpg`) and Alembic schema migrations. This layer establishes durable relational models for autonomous security agents, operational campaigns, attack simulations, tool executions, incidents, human-in-the-loop approvals, evaluation metrics, and a cryptographically chained, tamper-evident audit log.

---

## 2. Entity Relationship Overview

```
                                  +------------+
                                  |   users    |
                                  +-----+------+
                                        | 1
              +-------------------------+-------------------------+
              | 0..*                    | 0..*                    | 0..*
              v                         v                         v
       +--------------+          +--------------+          +--------------+
       | policy_ver.  |          |  audit_logs  |          |  approvals   |
       +------+-------+          +--------------+          +------+-------+
              | 1 (0..*)                                          |
              +-------------------------+                         |
                                        v                         v
+------------+ 1       0..* +-------------------+ 0..*        +------------+
|   agents   +------------->|     campaigns     |<------------+ incidents  |
+-----+------+              +----+----+----+----+             +------------+
      | 1                        | 1  | 1  | 1
      |                          |    |    |
      | 0..*                     v    |    v 0..*
      |                    +-----+--+ |  +-------------+
      +------------------->|  tool  | |  | evaluations |
                           | action | |  +-------------+
                           +--------+ |
                                      v 0..*
                               +--------------+
                               | attack_runs  |
                               +--------------+
```

### Key Relationships & Delete Semantics

1. **Agent $\rightarrow$ Campaigns (`1:N`)**:
   - `Campaign.agent_id` references `agents.id` with `ondelete="SET NULL"`.
   - Removing an agent preserves historical campaigns for post-mortem auditing.
2. **Campaign $\rightarrow$ AttackRuns (`1:N`) & Evaluations (`1:N`)**:
   - `AttackRun.campaign_id` and `Evaluation.campaign_id` reference `campaigns.id` with `ondelete="RESTRICT"` (enforced via database constraint and SQLAlchemy `passive_deletes="all"` on `Campaign.attack_runs` and `Campaign.evaluations`).
   - **Forensic Evidence Retention**: Attack simulation runs and quantitative benchmark metrics represent critical forensic evidence and evaluation baselines. Deleting a campaign that possesses associated attack runs or evaluations is strictly restricted by PostgreSQL, preventing accidental or automated destruction of security telemetry.
3. **Agent / Campaign $\rightarrow$ ToolActions (`1:N`)**:
   - `ToolAction.agent_id` and `ToolAction.campaign_id` reference parents with `ondelete="SET NULL"`.
   - Tool actions represent forensic evidence and must never be deleted if a campaign or agent record is cleared.
4. **Campaign $\rightarrow$ Incidents (`1:N`) $\rightarrow$ Approvals (`1:N`)**:
   - `Incident.campaign_id` references `campaigns.id` with `ondelete="SET NULL"`.
   - `Approval.incident_id` references `incidents.id` with `ondelete="SET NULL"`.
   - `Approval.requested_by` references `users.id` with `ondelete="RESTRICT"` to prevent deleting users with pending approvals.
5. **PolicyVersion $\rightarrow$ Approvals (`1:N`)**:
   - `PolicyVersion.created_by` and `approved_by` reference `users.id` with `ondelete="SET NULL"`.
   - `Approval.policy_version_id` references `policy_versions.id` with `ondelete="SET NULL"`.
6. **User $\rightarrow$ AuditLog (`1:N`)**:
   - `AuditLog.actor_id` references `users.id` with `ondelete="RESTRICT"` (enforced via database constraint and SQLAlchemy `passive_deletes="all"` on `User.audit_logs`).
   - **Crucial Non-Repudiation Invariant**: A user who has an audit history cannot be hard deleted. Attempted deletion is rejected by PostgreSQL, permanently preserving the actor identity and the unbroken cryptographic hash chain. Offboarding is handled exclusively via account deactivation (`user.is_active = False`).

---

## 3. Schema Design and Indexes

| Table | Primary Key | Critical Foreign Keys | High-Value Indexes |
|---|---|---|---|
| `users` | `id` (UUID) | None | `ix_users_email` (unique), `ix_users_username` (unique) |
| `agents` | `id` (UUID) | None | `ix_agents_name`, `ix_agents_agent_type` |
| `campaigns` | `id` (UUID) | `agent_id` $\rightarrow$ `agents.id` | `ix_campaigns_name`, `ix_campaigns_agent_id` |
| `attack_runs` | `id` (UUID) | `campaign_id` $\rightarrow$ `campaigns.id` | `ix_attack_runs_campaign_id` |
| `tool_actions` | `id` (UUID) | `agent_id`, `campaign_id` | `ix_tool_actions_action_name`, `ix_tool_actions_agent_id`, `ix_tool_actions_campaign_id` |
| `incidents` | `id` (UUID) | `campaign_id` | `ix_incidents_severity`, `ix_incidents_status`, `ix_incidents_campaign_id` |
| `policy_versions` | `id` (UUID) | `created_by`, `approved_by` | `ix_policy_versions_version`, `ix_policy_versions_status`, `ix_policy_versions_created_by` |
| `approvals` | `id` (UUID) | `incident_id`, `policy_version_id`, `requested_by`, `approved_by` | `ix_approvals_status`, `ix_approvals_requested_by`, `ix_approvals_incident_id` |
| `evaluations` | `id` (UUID) | `campaign_id` $\rightarrow$ `campaigns.id` | `ix_evaluations_campaign_id` |
| `audit_logs` | `id` (UUID) | `actor_id` $\rightarrow$ `users.id` | `ix_audit_logs_event_type`, `ix_audit_logs_actor_id`, `ix_audit_logs_created_at`, `ix_audit_logs_previous_hash`, `ix_audit_logs_event_hash` (unique) |

---

## 4. Cryptographic Audit Hash Chain Design

To provide tamper evidence for forensic verification, every persistent audit record is cryptographically bound to its immediate predecessor.

### Formula

$$\text{event\_hash} = \text{SHA-256}(\text{previous\_hash} + \text{canonical\_payload})$$

### Canonical Payload Fields (Exact Ordered Construction)

The following 10 exact keys comprise the canonical payload dictionary prior to deterministic serialization:

| Field Name | Type | Description |
|---|---|---|
| `id` | `str` (UUID) | Unique identifier of the audit log record. |
| `event_type` | `str` | Formal categorized audit event identifier (e.g. `SECURITY_GATEWAY_DECISION`). |
| `actor_id` | `str` (UUID) or `null` | UUID string of the authenticated user, or `null` if unauthenticated/system. |
| `actor_role` | `str` or `null` | Primary platform role of the actor at event time. |
| `action` | `str` | Name of the operation or capability requested. |
| `resource_type` | `str` | Target domain entity type (e.g. `user`, `target`, `job`). |
| `resource_id` | `str` or `null` | Identifier of the specific resource acted upon. |
| `decision` | `str` or `null` | Enforcement outcome (e.g. `allow`, `deny`, `success`). |
| `event_data` | `dict` | Recursively sanitized metadata with all sensitive keys removed. |
| `created_at` | `str` (ISO 8601 UTC) | Deterministically normalized UTC timestamp (`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`). |

### Canonical Serialization Rules
1. **Deterministic Keys**: Field names are sorted alphabetically (`sort_keys=True`).
2. **Compact Whitespace**: Separators are strictly normalized to `(’,’, ’:’)` without extraneous whitespace.
3. **UTC Timestamps**: `created_at` formatted strictly as ISO 8601 UTC string (`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`).
4. **Sanitized Payload**: Sensitive credential keys (`password`, `token`, `access_token`, `refresh_token`, `secret`, `api_key`) are stripped recursively.
5. **Genesis Origin**: The initial record links to `GENESIS_HASH = "0" * 64`.

### Verification Functionality
The platform provides two verification primitives:
- `verify_event_hash(log: AuditLog) -> bool`: Recalculates the hash of a single record against its own content and its declared `previous_hash`.
- `verify_audit_chain(logs: list[AuditLog]) -> tuple[bool, Optional[str]]`: Verifies both individual hash integrity and contiguous pointer linkage ($\text{log}[i].\text{previous\_hash} == \text{log}[i-1].\text{event\_hash}$).

---

## 5. Concurrency & Transaction Strategy

### The Challenge
In an asynchronous, multi-worker FastAPI deployment, concurrent writes to the audit chain risk reading the same `previous_hash` simultaneously, which would produce a fork in the chain or trigger a unique constraint violation on `event_hash`.

### The Solution: PostgreSQL Advisory Locking
During `record_audit_log`, a transaction-level advisory lock is acquired prior to reading the latest record:

```sql
SELECT pg_advisory_xact_lock(847291047192);
```

#### Why Advisory Locks?
1. **Zero Table Locking Overhead**: Does not lock the `audit_logs` table itself, avoiding index contention for read queries.
2. **Strict Serialization**: Concurrent insertion transactions wait their turn. Transaction $B$ is unblocked only after Transaction $A$ commits, guaranteeing that $B$ reads $A$'s freshly committed `event_hash`.
3. **Automatic Lifecycle**: `pg_advisory_xact_lock` releases automatically upon commit or rollback.

---

## 6. Audit Retention & Immutability

1. **Read-Only API**: The `GET /api/v1/audit` endpoint is strictly read-only and restricted to the `ADMIN` role. No `POST`, `PUT`, `PATCH`, or `DELETE` endpoints exist for the audit log resource.
2. **Cold Storage Export**: Production environments should ship signed batches of audit blocks to WORM (Write Once, Read Many) cloud storage (e.g. AWS S3 Object Lock, Google Cloud Storage Bucket Lock) or dedicated SIEM solutions.
3. **Retention Policy**: Audit entries must never be truncated in-place. If aging partitions are archived, the archive must begin with the terminal `event_hash` of the preceding partition to maintain external audit continuity.

---

## 7. Known Limitations

> [!WARNING]
> **Tamper-Evident vs. Tamper-Proof**:
> A cryptographic hash chain stored within a relational database is **tamper-evident**, not tamper-proof.
> - Any modification of a historical row's fields, order, or deletion of a row invalidates all downstream hashes and is immediately detected by `verify_audit_chain`.
> - However, an attacker who obtains root database superuser access could theoretically rewrite the entire table and recompute all downstream hashes from the tampered record to the head.
> - **Defense**: Pair database hash chaining with external write-only SIEM forwarders (e.g., Fluent Bit to OpenSearch / CloudWatch) and periodically anchor current head hashes to an external immutable ledger or timestamping authority (RFC 3161).

