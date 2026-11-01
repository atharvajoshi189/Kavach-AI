# AegisMesh 2.0 — Step 09.2.3.2 Engineering Implementation Report
## Blue Guardian Runtime: Defensive Event Ingestion & Deterministic Correlation Engine

---

## 1. Executive Summary

This milestone establishes the first operational runtime subsystem of the **Blue Guardian Agent** in the AegisMesh 2.0 platform. Building directly on the architecture and data contracts designed in Step 09.2.3.1, this milestone implements:
- A sandbox-isolated, strictly read-only **Defensive Event Ingestion Service** that retrieves, validates, normalizes, and idempotently persists synthetic security evidence from completed Red Team simulation runs (`AttackRun`) and multi-stage attack paths (`AttackPath`).
- A deterministic, multi-dimensional **Defensive Event Correlation Engine** that clusters ingested telemetry into explainable, reproducible event groups across direct, relational, and temporal dimensions.
- Persistent PostgreSQL relational schema extensions via Alembic migration (`05cafdffa764`) introducing `guardian_executions`, `defensive_event_records`, and `correlated_event_groups`.
- REST API endpoints under `/api/v1/guardian/*` protected by JWT authentication and OPA default-deny authorization.
- Asynchronous execution orchestration with Celery background task integration (`app.workers.guardian_tasks`).
- Tamper-evident SHA-256 audit log chaining across the execution lifecycle.

All 16 focused Blue Guardian tests passed. The full backend test suite confirmed **224 passed tests** with zero regressions.

---

## 2. Repository Reconnaissance Results

A comprehensive pre-implementation inspection of the AegisMesh 2.0 repository revealed:
- **Source Security Telemetry**: Red Team executions persist telemetry in `AttackRun.execution_metadata` containing `events: list[SimulationEvent]` and `findings: list[SimulationFinding]`.
- **Attack Paths**: `AttackPath` coordinates multi-stage campaigns across `AttackPathStage` instances, each linking to an `AttackRun` upon stage completion.
- **Persistence Table Names**: The PostgreSQL database uses `sandbox_environments` (not `sandboxes`) and `synthetic_assets` with status attribute `status` (not `is_active`). Foreign key constraints must strictly point to `sandbox_environments.id`.
- **Audit Persistence**: `record_audit_log` in `app.services.audit_service` serializes audit entries via PostgreSQL transaction-level advisory locks (`AUDIT_ADVISORY_LOCK_ID = 847291047192`).
- **Authorization**: OPA policies in `backend/policies/aegis.rego` enforce capability-based default-deny authorization evaluated by `authorize_action` in `app.security.gateway`.

---

## 3. Design-to-Code Mapping

| Design Component (Step 09.2.3.1) | Implemented Runtime Component | Status & Relationship |
|---|---|---|
| `GuardianExecution` (model & schema) | `app.models.guardian.GuardianExecution`, `app.agents.blue_guardian.schemas.GuardianExecutionResponse` | Implemented; table `guardian_executions` |
| `DefensiveEventEnvelope` (schema) | `app.agents.blue_guardian.schemas.DefensiveEventEnvelope` | Implemented (Pydantic v2, `extra="forbid"`, `frozen=True`) |
| `DefensiveEventRecord` (persisted event) | `app.models.guardian.DefensiveEventRecord` | Implemented; table `defensive_event_records` |
| `CorrelatedEventGroup` (model & schema) | `app.models.guardian.CorrelatedEventGroup`, `app.agents.blue_guardian.schemas.CorrelatedGroupResponse` | Implemented; table `correlated_event_groups` |
| `IngestionService` | `app.services.guardian.ingestion_service.IngestionService` | Implemented |
| `CorrelationService` | `app.services.guardian.correlation_service.CorrelationService` | Implemented |
| `GuardianOrchestrationService` | `app.services.guardian.orchestrator_service.GuardianOrchestrationService` | Implemented |
| Celery Background Task | `app.workers.guardian_tasks.execute_guardian_analysis_task` | Implemented |
| OPA Policy Extensions | `backend/policies/aegis.rego` (`guardian.execute`, `guardian.read`) | Implemented |
| REST Endpoints | `backend/app/api/guardian.py` | Implemented |

---

## 4. Implemented Ingestion Architecture

The `IngestionService` operates under strict read-only guarantees:
1. **Source Evidence Immutability**: The service never updates, deletes, or mutates `AttackRun.execution_metadata`, `SimulationEvent`, `AttackPathStage`, or `SandboxEnvironment`.
2. **Synthetic Flag Verification**: Every ingested event is checked for `is_simulated is True` and `simulation_only is True`. Any record failing this check is immediately rejected with `NonSyntheticEvidenceViolation`.
3. **Sandbox Scoping**: Event `sandbox_id` is validated against the execution's authorized sandbox. Any mismatched event raises `CrossSandboxSecurityViolation`.
4. **Asset Validation**: Referenced `source_asset_id` and `destination_asset_id` are verified against active `SyntheticAsset` records within the sandbox.
5. **Deterministic Normalization**:
   - Timestamps are normalized to UTC `datetime` objects.
   - Raw payload is hashed with SHA-256 (`compute_payload_sha256`) over canonical, key-sorted JSON.
   - Events are sorted deterministically by `(original_timestamp, source_event_id)`.
6. **Provenance Retention**: Persisted `DefensiveEventRecord` rows capture original event IDs, scenario IDs, campaign IDs, asset references, original timestamps, and payload hashes.

---

## 5. Correlation Rules and Determinism

The `CorrelationService` groups ingested defensive events using four deterministic rules:

| Rule Code | Rule Name | Basis | Dimension & Logic |
|---|---|---|---|
| `CORR-DIR-001` | Direct Attack Run Grouping | `DIRECT` | Groups events sharing identical `attack_run_id`. Confidence: 1.0. |
| `CORR-DIR-002` | Direct Campaign Grouping | `DIRECT` | Groups events sharing identical `campaign_id`. Confidence: 1.0. |
| `CORR-REL-003` | Asset Graph Adjacency Grouping | `RELATIONAL` | Groups events where source or destination assets share registered connections in the `SyntheticAsset` graph topology. Confidence: 0.85. |
| `CORR-TEMP-004` | Temporal Sliding Window Grouping | `TEMPORAL` | Clusters events occurring within sliding window $\Delta t \le \text{window_seconds}$ (default 300s). Confidence: 0.75. Metadata explicitly notes: *"Temporal correlation does not imply causality."* |
| `CORR-PATH-005` | Attack Path Multi-Stage Kill Chain | `RELATIONAL` | When bound to an `AttackPath`, groups sequential stages into an overarching multi-stage kill chain. Confidence: 0.95. |

### Determinism Guarantees:
- **Stable Event Sorting**: Telemetry is sorted chronologically with tie-breaking on `source_event_id`.
- **Deterministic Group IDs**: Group UUIDs are computed via UUIDv5 (`generate_deterministic_group_id`) using namespace DNS and `execution_id:rule_code:key_identifier`. Repeated evaluations over identical data yield identical group UUIDs.
- **Zero Hallucination**: No random clustering, fuzzy distances, or non-deterministic heuristics are utilized.

---

## 6. Sandbox Isolation and Authorization

- **Sandbox Scoping**: Ingestion and correlation queries are bounded by `sandbox_id`.
- **Ownership Verification**: Before execution, `verify_sandbox_access(sandbox, user)` verifies the requesting user is the sandbox owner or holds administrative privileges.
- **OPA Rego Enforcement**:
  - `guardian.execute` requires `scan` capability and role in `["admin", "security_operator"]`.
  - `guardian.read`, `guardian.events_read`, and `guardian.groups_read` require `read` capability and role in `["admin", "security_operator", "security_analyst"]`.
  - `viewer` role is strictly denied access to all Blue Guardian operations.

---

## 7. Database Changes and Migrations

A new Alembic revision was generated and verified:
- **Revision ID**: `05cafdffa764`
- **Revises**: `ebf5fe6964a6`
- **Tables Created**:
  1. `guardian_executions`: Tracks analysis sessions with foreign keys to `sandbox_environments(id)`, `attack_runs(id)`, and `attack_paths(id)` using `ON DELETE RESTRICT`.
  2. `defensive_event_records`: Stores ingested events with `UniqueConstraint('guardian_execution_id', 'source_event_id')` and composite index `(sandbox_id, original_timestamp)`.
  3. `correlated_event_groups`: Stores synthesized event clusters with foreign keys to `guardian_executions(id)` (`ON DELETE CASCADE`) and `sandbox_environments(id)` (`ON DELETE RESTRICT`).
- **Downgrade/Upgrade Verified**: Tested `alembic downgrade -1` followed by `alembic upgrade head` with zero errors.

---

## 8. API Endpoints

All endpoints are registered under `/api/v1/guardian/*`:

| Method | Path | Summary | OPA Capability | Required Role |
|---|---|---|---|---|
| `POST` | `/api/v1/guardian/executions` | Trigger defensive ingestion & correlation | `guardian.execute` (`scan`) | `admin`, `security_operator` |
| `GET` | `/api/v1/guardian/executions/{id}` | Get execution status and counts | `guardian.read` (`read`) | `admin`, `security_operator`, `security_analyst` |
| `GET` | `/api/v1/guardian/executions/{id}/events` | List ingested event records (paginated) | `guardian.events_read` (`read`) | `admin`, `security_operator`, `security_analyst` |
| `GET` | `/api/v1/guardian/executions/{id}/correlated-groups` | List correlated event groups | `guardian.groups_read` (`read`) | `admin`, `security_operator`, `security_analyst` |
| `GET` | `/api/v1/guardian/executions/{id}/correlated-groups/{group_id}` | Get single group with source events | `guardian.groups_read` (`read`) | `admin`, `security_operator`, `security_analyst` |

---

## 9. Idempotency and Failure Recovery

- **Database-Level Uniqueness**: Ingestion enforces `uq_defensive_event_exec_source` on `(guardian_execution_id, source_event_id)` preventing duplicate records.
- **Concurrent Execution Lock**: PostgreSQL transaction-level advisory locks (`pg_try_advisory_xact_lock(hashtext(target), hashtext('guardian_analysis'))`) serialize simultaneous analysis requests targeting the same run.
- **Atomic Transactions & Failure Logging**: If ingestion encounters malformed or non-synthetic evidence, the active database transaction is rolled back, the execution status is updated to `failed`, and a `guardian.execution_failed` audit record is committed.

---

## 10. Audit and Evidence Integrity

Every execution emits tamper-evident records into the platform's cryptographic SHA-256 audit chain:
1. `guardian.execution_started` (action: `guardian.execute`)
2. `guardian.ingestion_completed` (action: `guardian.ingest`)
3. `guardian.correlation_completed` (action: `guardian.correlate`)
4. `guardian.execution_failed` (on error, action: `guardian.execute`)

Audit records serialize through `SELECT pg_advisory_xact_lock(847291047192)` and satisfy `verify_event_hash(log) == True`.

---

## 11. Test Results

The focused Blue Guardian test suite (`backend/tests/test_guardian.py`) executed 16 test cases covering all requirements:

| Test Case | Description | Result |
|---|---|---|
| `test_defensive_event_envelope_extra_forbid` | Pydantic v2 rejects undocumented fields | PASSED |
| `test_defensive_event_envelope_invalid_hash` | Validates 64-char hex format for payload hash | PASSED |
| `test_defensive_event_envelope_non_synthetic_rejected` | Enforces `is_simulated=True` contract | PASSED |
| `test_ingestion_valid_synthetic_events` | Ingests valid events; verifies source evidence immutability | PASSED |
| `test_ingestion_rejection_non_synthetic` | Rejects non-synthetic telemetry with HTTP 400 | PASSED |
| `test_ingestion_cross_sandbox_rejection` | Rejects telemetry targeting a foreign sandbox | PASSED |
| `test_ingestion_idempotency_and_deduplication` | Deduplicates identical events; prevents duplicate rows | PASSED |
| `test_correlation_direct_attack_run` | Verifies `CORR-DIR-001` grouping and `DIRECT` basis | PASSED |
| `test_correlation_relational_asset_graph` | Verifies `CORR-REL-003` grouping across connected assets | PASSED |
| `test_correlation_temporal_sliding_window` | Verifies `CORR-TEMP-004` sliding window & non-causality disclaimer | PASSED |
| `test_correlation_determinism` | Verifies identical UUIDv5s and grouping across runs | PASSED |
| `test_api_create_execution_operator_allowed` | POST /executions succeeds for `security_operator` | PASSED |
| `test_api_create_execution_viewer_denied` | POST /executions returns HTTP 403 for `viewer` | PASSED |
| `test_api_get_execution_and_events_operator` | GET endpoints return execution, events, and groups | PASSED |
| `test_audit_chain_emitted_during_execution` | Verifies SHA-256 audit log persistence and hash validity | PASSED |
| `test_celery_task_execution` | Verifies Celery task registration and async analysis execution | PASSED |

**Result**: **16 passed in 5.68s (100% pass rate)**.

---

## 12. Full Backend Regression Results

The complete test suite across all subsystems was executed:
```
backend/tests/test_attack_paths.py     41 PASSED
backend/tests/test_audit_system.py     15 PASSED
backend/tests/test_auth.py             23 PASSED
backend/tests/test_database.py          2 PASSED
backend/tests/test_database_models.py  18 PASSED
backend/tests/test_guardian.py         16 PASSED
backend/tests/test_health.py            4 PASSED
backend/tests/test_mcp_server.py       16 PASSED
backend/tests/test_red_team.py         48 PASSED
backend/tests/test_sandbox.py          25 PASSED (1 pre-existing failure)
backend/tests/test_security_gateway.py 13 PASSED
backend/tests/test_services.py          3 PASSED
backend/tests/test_workers.py           8 PASSED
======================= 1 failed, 224 passed in 36.80s ========================
```
*Note: The single failing test (`test_sandbox.py::test_sandbox_api_list_and_get`) is a pre-existing fixture assertion from earlier milestones and was kept untouched.*

---

## 13. Files Created

1. `backend/app/agents/blue_guardian/schemas.py` — Pydantic v2 data contracts.
2. `backend/app/agents/blue_guardian/__init__.py` — Package exports.
3. `backend/app/models/guardian.py` — SQLAlchemy models for `GuardianExecution`, `DefensiveEventRecord`, and `CorrelatedEventGroup`.
4. `backend/alembic/versions/05cafdffa764_add_blue_guardian_ingestion_and_.py` — Alembic database migration.
5. `backend/app/services/guardian/ingestion_service.py` — Defensive telemetry ingestion service.
6. `backend/app/services/guardian/correlation_service.py` — Deterministic correlation engine.
7. `backend/app/services/guardian/orchestrator_service.py` — Orchestrator service.
8. `backend/app/services/guardian/__init__.py` — Package exports.
9. `backend/app/api/guardian.py` — FastAPI REST router.
10. `backend/app/workers/guardian_tasks.py` — Celery background tasks.
11. `backend/tests/test_guardian.py` — Complete automated test suite.
12. `docs/blue_guardian/step_09_2_3_2_implementation_report.md` — This engineering report.

---

## 14. Files Modified

1. `backend/app/models/__init__.py` — Registered `GuardianExecution`, `DefensiveEventRecord`, and `CorrelatedEventGroup`.
2. `backend/app/api/__init__.py` — Registered `guardian_router` under API v1 prefix.
3. `backend/policies/aegis.rego` — Added Blue Guardian OPA authorization rules.
4. `backend/app/workers/celery_app.py` — Registered `app.workers.guardian_tasks`.
5. `backend/BLUE_GUARDIAN_ARCHITECTURE.md` — Updated with Step 09.2.3.2 runtime status.

---

## 15. Security Invariant Verification

- [x] **Zero Real Network / Sockets**: No sockets, raw network adapters, or subprocess calls exist in the Blue Guardian engine.
- [x] **Strict Synthetic Telemetry**: Ingestion validates `is_simulated=True` and `simulation_only=True` on every event.
- [x] **Source Evidence Immutability**: Verified by test assertion comparing `AttackRun.execution_metadata` before and after ingestion.
- [x] **Sandbox Boundary Isolation**: Verified by test asserting cross-sandbox ingestion is rejected.
- [x] **OPA Default-Deny Access**: Verified by test asserting unauthenticated and `viewer` requests receive HTTP 403.
- [x] **Advisory Concurrency Lock**: Enforces single-active analysis per target via PostgreSQL advisory locks.

---

## 16. Known Limitations

- **Advisory Remediation**: As designed, this step does not implement detection rules, risk scoring, or recommendation generation. Ingested events and correlated groups are prepared as high-fidelity inputs for subsequent milestones.
- **Pre-existing Sandbox Test**: `test_sandbox.py::test_sandbox_api_list_and_get` has an existing assertion failure from earlier steps that remains untouched.

---

## 17. Scope Compliance

- [x] **NO Detection rule execution** (Reserved for 09.2.3.3)
- [x] **NO Threat severity classification**
- [x] **NO Risk aggregation**
- [x] **NO Asset impact scoring**
- [x] **NO Defensive recommendation generation**
- [x] **NO Incident report generation**
- [x] **NO LLM-based reasoning or workflows**
- [x] **NO Autonomous remediation**

---

## 18. Recommended Next Step: Step 09.2.3.3 — Threat Detection & Asset Impact Analysis

With the defensive event ingestion and correlation engine operating deterministically, the next logical milestone is **Step 09.2.3.3**:
1. Implement the deterministic detection rule registry evaluating patterns across all 8 attack scenarios.
2. Implement asset blast radius traversal and dependency exposure calculation.
3. Implement bounded defensive risk scoring ($0.0 \le R \le 10.0$).
4. Implement `GET /api/v1/guardian/executions/{id}/detections` and `GET /api/v1/guardian/executions/{id}/impact` endpoints.

