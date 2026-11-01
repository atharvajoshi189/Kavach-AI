# Blue Guardian Agent — Defensive Architecture & Runtime Implementation
## AegisMesh 2.0 Subsystem Documentation & Architecture Index

This document provides a developer overview and navigation index for the **Blue Guardian Agent** subsystem in AegisMesh 2.0.

---

### Implementation Status Overview

| Milestone | Subsystem / Focus | Status | Deliverables |
|---|---|---|---|
| **Step 09.2.3.1** | Architecture Design, Threat Intelligence Contracts & Defensive Data Model | **COMPLETE** | [Design Specifications](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/docs/blue_guardian/) |
| **Step 09.2.3.2** | Defensive Event Ingestion & Deterministic Correlation Engine | **COMPLETE** | [Step 09.2.3.2 Report](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/docs/blue_guardian/step_09_2_3_2_implementation_report.md) |
| **Step 09.2.3.3** | Deterministic Threat Detection & Asset Impact Analysis Engine | *PLANNED* | Detection rules, blast radius, bounded risk |
| **Step 09.2.3.4** | Advisory Recommendations, Human Governance & Incident Synthesis | *PLANNED* | Advisory engine, 4-eyes approval, Incident reporting |

---

### Runtime Modules (Step 09.2.3.2)

1. **Data Contracts & Schemas**: [`app/agents/blue_guardian/schemas.py`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/backend/app/agents/blue_guardian/schemas.py)
   - `DefensiveEventEnvelope`: Strict Pydantic v2 normalized envelope with SHA-256 payload digest.
   - Four epistemic tiers: `OBSERVED`, `DERIVED`, `INFERRED`, `ADVISORY`.
   - `GuardianExecutionCreateRequest`, `GuardianExecutionResponse`, `CorrelatedGroupResponse`.

2. **Database Models & Alembic Migration**: [`app/models/guardian.py`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/backend/app/models/guardian.py)
   - `GuardianExecution`: Tracks analysis execution sessions.
   - `DefensiveEventRecord`: Persisted immutable defensive records with unique constraint on `(guardian_execution_id, source_event_id)`.
   - `CorrelatedEventGroup`: Clusters events by `DIRECT`, `RELATIONAL`, and `TEMPORAL` rules.
   - Alembic Migration: `05cafdffa764_add_blue_guardian_ingestion_and_.py` (head).

3. **Ingestion Service**: [`app/services/guardian/ingestion_service.py`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/backend/app/services/guardian/ingestion_service.py)
   - Validates `is_simulated=True` and `simulation_only=True`.
   - Validates sandbox boundary and active `SyntheticAsset` references.
   - Read-only guarantee: source evidence in `AttackRun` and `AttackPath` is never mutated.

4. **Deterministic Correlation Engine**: [`app/services/guardian/correlation_service.py`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/backend/app/services/guardian/correlation_service.py)
   - `CORR-DIR-001`: Direct Attack Run Correlation (`DIRECT`).
   - `CORR-DIR-002`: Direct Campaign Correlation (`DIRECT`).
   - `CORR-REL-003`: Relational Asset Graph Correlation (`RELATIONAL`).
   - `CORR-TEMP-004`: Temporal Sliding Window Correlation (`TEMPORAL`).
   - `CORR-PATH-005`: Multi-Stage Attack Path Kill-Chain Correlation (`RELATIONAL`).
   - Deterministic UUIDv5 group identifiers and chronological tie-breaking.

5. **Execution Orchestration**: [`app/services/guardian/orchestrator_service.py`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/backend/app/services/guardian/orchestrator_service.py)
   - PostgreSQL transaction-level advisory locks for concurrency control.
   - OPA gateway capability evaluation (`guardian.execute`, `guardian.read`).
   - Cryptographic SHA-256 chained audit logs: `guardian.execution_started`, `guardian.ingestion_completed`, `guardian.correlation_completed`.

6. **REST API Router**: [`app/api/guardian.py`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/backend/app/api/guardian.py)
   - `POST /api/v1/guardian/executions`
   - `GET /api/v1/guardian/executions/{id}`
   - `GET /api/v1/guardian/executions/{id}/events`
   - `GET /api/v1/guardian/executions/{id}/correlated-groups`
   - `GET /api/v1/guardian/executions/{id}/correlated-groups/{group_id}`

7. **Celery Worker Integration**: [`app/workers/guardian_tasks.py`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/backend/app/workers/guardian_tasks.py)
   - `execute_guardian_analysis_task` registered in Celery task registry.

---

### Authoritative Architecture & Design Documents

Located in [`docs/blue_guardian/`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/docs/blue_guardian/):
- [`blue_guardian_architecture.md`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/docs/blue_guardian/blue_guardian_architecture.md)
- [`blue_guardian_data_contracts.md`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/docs/blue_guardian/blue_guardian_data_contracts.md)
- [`blue_guardian_database_design.md`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/docs/blue_guardian/blue_guardian_database_design.md)
- [`blue_guardian_api_contracts.md`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/docs/blue_guardian/blue_guardian_api_contracts.md)
- [`blue_guardian_security_model.md`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/docs/blue_guardian/blue_guardian_security_model.md)
- [`blue_guardian_failure_recovery.md`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/docs/blue_guardian/blue_guardian_failure_recovery.md)
- [`blue_guardian_test_strategy.md`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/docs/blue_guardian/blue_guardian_test_strategy.md)
- [`step_09_2_3_2_implementation_report.md`](file:///c:/Users/Atharva/OneDrive/Desktop/AEGISMesh/docs/blue_guardian/step_09_2_3_2_implementation_report.md)
