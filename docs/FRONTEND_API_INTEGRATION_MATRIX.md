# AegisMesh 2.0 — Frontend API Integration Matrix

This matrix maps every endpoint discovered from the backend OpenAPI 3.1 specification (`/openapi.json`, 90 total endpoints) to its target frontend view in the SOC Control Center.

| Functional Module | API Endpoint | Method | Target Frontend View / Component | Integration Status |
|---|---|---|---|---|
| **Root & System Health** | `/` | GET | `SystemHealthView` / Header | Pending Integration |
| **Root & System Health** | `/api/v1/health` | GET | `Header` / `SystemHealthView` | **Integrated** |
| **Authentication** | `/api/v1/auth/register` | POST | `AuthModal` | **Integrated** |
| **Authentication** | `/api/v1/auth/login` | POST | `AuthModal` | **Integrated** |
| **Authentication** | `/api/v1/auth/refresh` | POST | `lib/api.ts` / `AuthModal` | **Integrated** |
| **Authentication** | `/api/v1/auth/me` | GET | `Header` / `AuthContext` | **Integrated** |
| **Authentication** | `/api/v1/auth/logout` | POST | `Header` / `AuthContext` | **Integrated** |
| **Sandbox Environments** | `/api/v1/sandboxes/` | GET | `AssetsSandboxView` / Header Scope | **Integrated** |
| **Sandbox Environments** | `/api/v1/sandboxes/{sandbox_id}` | GET | `AssetsSandboxView` | **Integrated** |
| **Sandbox Environments** | `/api/v1/sandboxes/{sandbox_id}/assets` | GET | `AssetsSandboxView` / `OverviewView` | **Integrated** |
| **Sandbox Environments** | `/api/v1/sandboxes/seed` | POST | `Header` Quick Action / `AssetsSandboxView` | **Integrated** |
| **Red Team Simulation** | `/api/v1/red-team/scenarios` | GET | `RedTeamView` / `AttackSimulation` | **Integrated** |
| **Red Team Simulation** | `/api/v1/red-team/campaigns/{campaign_id}/runs` | POST | `RedTeamView` / `AttackSimulation` | **Integrated** |
| **Red Team Simulation** | `/api/v1/red-team/runs/{run_id}` | GET | `RedTeamView` / Run Drawer | **Integrated** |
| **Attack Path Orchestration** | `/api/v1/attack-paths/plan` | POST | `AttackPathIntelligence` | **Integrated** |
| **Attack Path Orchestration** | `/api/v1/attack-paths/{attack_path_id}/execute` | POST | `AttackPathIntelligence` | **Integrated** |
| **Attack Path Orchestration** | `/api/v1/attack-paths` | GET | `AttackPathIntelligence` | **Integrated** |
| **Attack Path Orchestration** | `/api/v1/attack-paths/{attack_path_id}` | GET | `AttackPathIntelligence` | **Integrated** |
| **Attack Path Orchestration** | `/api/v1/attack-paths/{attack_path_id}/graph` | GET | `AttackPathIntelligence` (Graph Visualizer) | **Integrated** |
| **Attack Path Orchestration** | `/api/v1/attack-paths/{attack_path_id}/report` | GET | `AttackPathIntelligence` (Report Modal) | **Integrated** |
| **Attack Path Orchestration** | `/api/v1/attack-paths/{attack_path_id}/stages` | GET | `AttackPathIntelligence` (Stage Timeline) | **Integrated** |
| **Attack Path Orchestration** | `/api/v1/attack-paths/{attack_path_id}/cancel` | POST | `AttackPathIntelligence` | **Integrated** |
| **Blue Guardian Ingestion** | `/api/v1/guardian/executions` | POST | `BlueGuardianView` (Ingestion Tab) | **Integrated** |
| **Blue Guardian Ingestion** | `/api/v1/guardian/executions` | GET | `BlueGuardianView` (Execution History) | **Integrated** |
| **Blue Guardian Ingestion** | `/api/v1/guardian/executions/{execution_id}` | GET | `BlueGuardianView` (Execution Header) | **Integrated** |
| **Blue Guardian Ingestion** | `/api/v1/guardian/executions/{execution_id}/events` | GET | `BlueGuardianView` (Security Events Tab) | **Integrated** |
| **Blue Guardian Correlation** | `/api/v1/guardian/executions/{execution_id}/correlated-groups` | GET | `BlueGuardianView` (Correlation Tab) | **Integrated** |
| **Blue Guardian Correlation** | `/api/v1/guardian/executions/{execution_id}/correlated-groups/{group_id}` | GET | `BlueGuardianView` (Group Detail Drawer) | **Integrated** |
| **Blue Guardian Threat Detection** | `/api/v1/guardian/detection-rules` | GET | `BlueGuardianView` (Detection Rules Tab) | Pending Integration |
| **Blue Guardian Threat Detection** | `/api/v1/guardian/detections/summary` | GET | `OverviewView` / `BlueGuardianView` | **Integrated** |
| **Blue Guardian Threat Detection** | `/api/v1/guardian/detections` | GET | `BlueGuardianView` (Threat Detections Tab) | **Integrated** |
| **Blue Guardian Threat Detection** | `/api/v1/guardian/executions/{execution_id}/detections` | GET | `BlueGuardianView` (Threat Detections Tab) | **Integrated** |
| **Blue Guardian Threat Detection** | `/api/v1/guardian/detections/{detection_id}` | GET | `BlueGuardianView` (Detection Detail Drawer) | **Integrated** |
| **Blue Guardian Risk Analysis** | `/api/v1/guardian/risk-summary` | GET | `OverviewView` / `BlueGuardianView` | **Integrated** |
| **Blue Guardian Risk Analysis** | `/api/v1/guardian/risk-priorities` | GET | `BlueGuardianView` (Risk Priorities Tab) | **Integrated** |
| **Blue Guardian Risk Analysis** | `/api/v1/guardian/risk-assessments` | GET | `BlueGuardianView` (Risk Assessments Tab) | **Integrated** |
| **Blue Guardian Risk Analysis** | `/api/v1/guardian/risk-assessments/{assessment_id}` | GET | `BlueGuardianView` (Risk Assessment Detail) | **Integrated** |
| **Blue Guardian Risk Analysis** | `/api/v1/guardian/executions/{execution_id}/risk-assessments` | GET | `BlueGuardianView` (Risk Assessments Tab) | **Integrated** |
| **Blue Guardian Risk Analysis** | `/api/v1/guardian/assets/{asset_id}/risk` | GET | `AssetsSandboxView` / `BlueGuardianView` | **Integrated** |
| **Blue Guardian Defense & Playbooks** | `/api/v1/guardian/playbooks` | GET | `BlueGuardianView` (Playbooks Tab) | **Integrated** |
| **Blue Guardian Defense & Playbooks** | `/api/v1/guardian/recommendations` | GET | `BlueGuardianView` / `ResponseCenterView` | **Integrated** |
| **Blue Guardian Defense & Playbooks** | `/api/v1/guardian/recommendations/{recommendation_id}` | GET | `ResponseCenterView` (Recommendation Detail) | **Integrated** |
| **Blue Guardian Defense & Playbooks** | `/api/v1/guardian/executions/{execution_id}/recommendations` | GET | `BlueGuardianView` / `ResponseCenterView` | **Integrated** |
| **Blue Guardian Remediation Planning** | `/api/v1/guardian/remediation-plans` | GET | `ResponseCenterView` (Remediation Plans Tab) | **Integrated** |
| **Blue Guardian Remediation Planning** | `/api/v1/guardian/remediation-plans/{plan_id}` | GET | `ResponseCenterView` (Plan Action Inspector) | **Integrated** |
| **Blue Guardian Remediation Planning** | `/api/v1/guardian/executions/{execution_id}/remediation-plans` | GET | `ResponseCenterView` (Remediation Plans Tab) | **Integrated** |
| **Blue Guardian Incident Reports** | `/api/v1/guardian/executions/{execution_id}/incident-reports/generate` | POST | `BlueGuardianView` (Incident Reports Tab) | **Integrated** |
| **Blue Guardian Incident Reports** | `/api/v1/guardian/incident-reports` | GET | `BlueGuardianView` (Incident Reports Tab) | **Integrated** |
| **Blue Guardian Incident Reports** | `/api/v1/guardian/incident-reports/{report_id}` | GET | `BlueGuardianView` (Report Viewer Modal) | **Integrated** |
| **Blue Guardian Incident Reports** | `/api/v1/guardian/executions/{execution_id}/incident-reports` | GET | `BlueGuardianView` (Incident Reports Tab) | **Integrated** |
| **Blue Guardian Posture Summary** | `/api/v1/guardian/executions/{execution_id}/executive-summary` | GET | `BlueGuardianView` (Executive Summary Tab) | **Integrated** |
| **Human Approval & Governance** | `/api/v1/guardian/remediation-plans/{plan_id}/approval-requests` | POST | `ResponseCenterView` / `ApprovalCenter` | **Integrated** |
| **Human Approval & Governance** | `/api/v1/guardian/approval-requests` | GET | `ResponseCenterView` / `ApprovalCenter` | **Integrated** |
| **Human Approval & Governance** | `/api/v1/guardian/approval-requests/{request_id}` | GET | `ResponseCenterView` / `ApprovalCenter` | **Integrated** |
| **Human Approval & Governance** | `/api/v1/guardian/approval-requests/{request_id}/approve` | POST | `ResponseCenterView` (Dual-Approval Action) | **Integrated** |
| **Human Approval & Governance** | `/api/v1/guardian/approval-requests/{request_id}/reject` | POST | `ResponseCenterView` (Rejection Action) | **Integrated** |
| **Human Approval & Governance** | `/api/v1/guardian/approval-requests/{request_id}/cancel` | POST | `ResponseCenterView` | **Integrated** |
| **Synthetic Remediation Execution** | `/api/v1/guardian/approval-requests/{request_id}/execute` | POST | `ResponseCenterView` (Synthetic Executor) | **Integrated** |
| **Synthetic Remediation Execution** | `/api/v1/guardian/remediation-executions` | GET | `SyntheticRemediationView` | **Integrated** |
| **Synthetic Remediation Execution** | `/api/v1/guardian/remediation-executions/{execution_id}` | GET | `SyntheticRemediationView` | **Integrated** |
| **Synthetic Remediation Execution** | `/api/v1/guardian/remediation-executions/{execution_id}/status` | GET | `SyntheticRemediationView` (Progress Bar) | **Integrated** |
| **State Snapshots & Verification** | `/api/v1/guardian/remediation-executions/{execution_id}/snapshots` | GET | `SyntheticRemediationView` (Diff Drawer) | **Integrated** |
| **State Snapshots & Verification** | `/api/v1/guardian/remediation-executions/{execution_id}/verification` | GET | `VerificationCenter` | **Integrated** |
| **State Snapshots & Verification** | `/api/v1/guardian/remediation-plans/{plan_id}/verification-history` | GET | `VerificationCenter` | Pending Integration |
| **Governance Policies** | `/api/v1/guardian/approval-policies/current` | GET | `ResponseCenterView` (Quorum Badge) | **Integrated** |
| **Governance Policies** | `/api/v1/guardian/approval-policies` | GET | `ResponseCenterView` (Policy Drawer) | Pending Integration |
| **Audit Explorer** | `/api/v1/audit` | GET | `AuditExplorer` / `AuditTrail` | **Integrated** |
| **Unified Orchestrator** | `/api/v1/orchestration/pipeline/start` | POST | `PipelineControlModal` / `OverviewView` | **Integrated** |
| **Unified Orchestrator** | `/api/v1/orchestration/pipeline` | GET | `PipelineExecutionView` / `OverviewView` | **Integrated** |
| **Unified Orchestrator** | `/api/v1/orchestration/pipeline/{execution_id}` | GET | `PipelineExecutionView` (15-Stage Stepper) | **Integrated** |
| **Unified Orchestrator** | `/api/v1/orchestration/pipeline/{execution_id}/resume` | POST | `PipelineExecutionView` (Resume Action) | **Integrated** |
| **Unified Orchestrator** | `/api/v1/orchestration/metrics` | GET | `OverviewView` (Performance Metrics) | **Integrated** |
| **AI Intelligence Gateway** | `/api/v1/ai/threats/{detection_id}/explain` | POST | `AIIntelligenceCenter` / Threat Drawer | Pending Integration |
| **AI Intelligence Gateway** | `/api/v1/ai/attack-paths/{attack_path_id}/analyze` | POST | `AIIntelligenceCenter` / Attack Path View | Pending Integration |
| **AI Intelligence Gateway** | `/api/v1/ai/risks/{assessment_id}/explain` | POST | `AIIntelligenceCenter` / Risk Drawer | Pending Integration |
| **AI Intelligence Gateway** | `/api/v1/ai/incidents/{report_id}/summarize` | POST | `AIIntelligenceCenter` / Incident Viewer | Pending Integration |
| **AI Intelligence Gateway** | `/api/v1/ai/recommendations/{recommendation_id}/explain` | POST | `AIIntelligenceCenter` / Recommendation Drawer | Pending Integration |
| **AI Intelligence Gateway** | `/api/v1/ai/executions/{execution_id}/briefing` | POST | `AIIntelligenceCenter` / Posture View | Pending Integration |
| **AI Intelligence Gateway** | `/api/v1/ai/executions/{execution_id}/qa` | POST | `AIIntelligenceCenter` (Contextual Q&A) | Pending Integration |
| **AI Intelligence Gateway** | `/api/v1/ai/executions/{execution_id}/analyses` | GET | `AIIntelligenceCenter` (Analysis History) | Pending Integration |
| **AI Intelligence Gateway** | `/api/v1/ai/health` | GET | `AIIntelligenceCenter` / `SystemHealthView` | Pending Integration |
| **AI Intelligence Gateway** | `/api/v1/ai/usage` | GET | `AIIntelligenceCenter` (Usage Gauges) | Pending Integration |
| **LangGraph Multi-Agent** | `/api/v1/ai/agents/execute` | POST | `AIIntelligenceCenter` (Agent Cards) | Pending Integration |
| **LangGraph Multi-Agent** | `/api/v1/ai/graphs/execute` | POST | `AIIntelligenceCenter` (Multi-Agent Graph) | Pending Integration |
| **LangGraph Multi-Agent** | `/api/v1/ai/graphs/health` | GET | `AIIntelligenceCenter` / `SystemHealthView` | Pending Integration |
| **LangGraph Multi-Agent** | `/api/v1/ai/graphs/{graph_execution_id}` | GET | `AIIntelligenceCenter` (Graph Execution) | Pending Integration |
| **LangGraph Multi-Agent** | `/api/v1/ai/graphs/{graph_execution_id}/agents` | GET | `AIIntelligenceCenter` (Agent Timeline) | Pending Integration |
| **LangGraph Multi-Agent** | `/api/v1/ai/agents` | GET | `AIIntelligenceCenter` (Agent Cards) | Pending Integration |
| **Background Jobs** | `/api/v1/jobs/health-check` | POST | `SystemHealthView` (Trigger Health Job) | Pending Integration |
| **Background Jobs** | `/api/v1/jobs/{task_id}` | GET | `SystemHealthView` (Poll Job Status) | Pending Integration |
| **Security Gateway** | `/api/v1/security/check` | POST | `SettingsView` (Authorization Evaluator) | Pending Integration |

