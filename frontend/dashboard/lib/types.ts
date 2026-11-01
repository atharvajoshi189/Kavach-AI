/**
 * AegisMesh 2.0 TypeScript Domain Types
 * Exactly mapped to FastAPI and SQLAlchemy models & schemas.
 */

export type UserRole = "admin" | "security_operator" | "security_analyst" | "viewer";

export interface User {
  id: string;
  email: string;
  username: string;
  role: UserRole;
  is_active: boolean;
  is_verified: boolean;
  created_at?: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in?: number;
}

export interface SystemHealth {
  status: "healthy" | "unhealthy" | "degraded" | "simulation_mode";
  application: string;
  version: string;
  timestamp: string;
  services: {
    postgresql: string;
    redis: string;
  };
}

export interface SyntheticAsset {
  id: string;
  sandbox_id: string;
  name: string;
  asset_type: "server" | "database" | "web_application" | "api" | "network_device" | string;
  description?: string;
  environment: string;
  status: string;
  hostname: string;
  ip_address: string;
  os_metadata: Record<string, any>;
  service_metadata: Record<string, any>;
  configuration: Record<string, any>;
  simulated_vulnerabilities: Array<{
    cve?: string;
    name?: string;
    severity?: string;
    description?: string;
    score?: number;
  }>;
  risk_level: "low" | "medium" | "high" | "critical";
  connected_asset_ids: string[];
  created_at: string;
  updated_at?: string;
}

export interface SandboxEnvironment {
  id: string;
  name: string;
  description?: string;
  status: "active" | "archived" | string;
  isolation_mode: "simulated" | string;
  owner_id?: string | null;
  configuration: Record<string, any>;
  created_at: string;
  updated_at?: string;
  asset_count?: number;
}

export interface RedTeamScenario {
  scenario_id: string;
  name: string;
  description: string;
  category: string;
  technique: string;
  technique_id: string;
  applicable_asset_types: string[];
  parameters: Record<string, any>;
  mapping_type: string;
  is_synthetic: boolean;
  risk_classification: "low" | "medium" | "high" | "critical" | string;
}

export interface SimulationEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  scenario_id?: string;
  campaign_id?: string;
  attack_run_id?: string;
  sandbox_id?: string;
  source_asset_id?: string;
  destination_asset_id?: string;
  severity: "info" | "warning" | "high" | "critical";
  message: string;
  details: Record<string, any>;
  event_metadata: Record<string, any>;
  is_simulated: boolean;
  simulation_only: boolean;
}

export interface SimulationEvidence {
  evidence_id: string;
  scenario_id: string;
  evidence_type: string;
  synthetic_asset_references: string[];
  finding_description: string;
  severity: string;
  confidence: string;
  supporting_synthetic_metadata: Record<string, any>;
  is_simulated: boolean;
  simulation_only: boolean;
}

export interface SimulationFinding {
  finding_id: string;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  technique: string;
  asset_id: string;
  details: Record<string, any>;
  evidence?: SimulationEvidence;
  remediation_recommendation: string;
  is_simulated: boolean;
  simulation_only: boolean;
}

export interface RedTeamRun {
  run_id: string;
  campaign_id: string;
  scenario: string;
  technique: string;
  outcome: "pending" | "running" | "completed" | "failed";
  risk_score?: number | null;
  created_at: string;
  simulation_only: boolean;
  execution_metadata?: {
    findings?: SimulationFinding[];
    events?: SimulationEvent[];
    status?: string;
    error?: string;
    started_at?: string;
    completed_at?: string;
    [key: string]: any;
  };
}

export interface AttackPathNode {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  sandbox_id: string;
  status: string;
  risk_level: string;
}

export interface AttackPathEdge {
  source_asset_id: string;
  destination_asset_id: string;
  relationship_type: string;
  scenario_reference?: string | null;
  edge_status: "confirmed_relationship" | "completed_stage" | "failed_stage" | "skipped_stage" | "planned_only" | string;
}

export interface AttackPathStage {
  id: string;
  attack_path_id: string;
  sequence_number: number;
  scenario_id: string;
  source_asset_id: string;
  destination_asset_id?: string | null;
  status: "pending" | "validating" | "running" | "completed" | "failed" | "skipped";
  prerequisites: any[];
  attack_run_id?: string | null;
  risk_score?: number | null;
  stage_metadata: Record<string, any>;
  started_at?: string | null;
  completed_at?: string | null;
  error_message?: string | null;
  simulation_only: boolean;
  is_simulated: boolean;
}

export interface AttackPath {
  id: string;
  campaign_id: string;
  sandbox_id: string;
  source_asset_id: string;
  status: "planned" | "validating" | "ready" | "running" | "completed" | "partially_completed" | "failed" | "cancelled";
  execution_mode: "exploratory" | "targeted";
  total_stages: number;
  completed_stages: number;
  failed_stages: number;
  risk_score?: number | null;
  path_metadata: {
    planning_explanation?: string[];
    rejected_candidates?: Array<{ scenario_id: string; reason: string; asset_id?: string }>;
    campaign_name?: string;
    sandbox_name?: string;
    source_asset_name?: string;
    [key: string]: any;
  };
  execution_id?: string | null;
  simulation_only: boolean;
  created_at: string;
  completed_at?: string | null;
  error_message?: string | null;
  stages: AttackPathStage[];
}

export interface AttackPathPlanResponse {
  attack_path: AttackPath;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  planning_explanation: string[];
  rejected_candidates: Array<{ scenario_id: string; reason: string }>;
}

export interface AttackPathReport {
  attack_path_id: string;
  campaign_id: string;
  sandbox_id: string;
  status: string;
  execution_mode: string;
  risk_score?: number | null;
  total_stages: number;
  completed_stages: number;
  failed_stages: number;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  correlated_events: SimulationEvent[];
  planning_explanation: string[];
  created_at: string;
  completed_at?: string | null;
}

export interface AuditLogItem {
  id: string;
  event_type: string;
  actor_id?: string | null;
  actor_role?: string | null;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  decision?: string | null;
  event_data: Record<string, any>;
  previous_hash: string;
  event_hash: string;
  created_at: string;
}

export interface McpToolItem {
  name: string;
  description: string;
  capability: string;
  resource_type: string;
  environment: string;
  input_schema?: Record<string, any>;
}

// =============================================================================
// Blue Guardian Defensive Intelligence Types
// =============================================================================

export type EpistemicClassification = "OBSERVED" | "DERIVED" | "INFERRED" | "ADVISORY";
export type CorrelationBasis = "DIRECT" | "RELATIONAL" | "TEMPORAL" | "INFERRED";
export type GuardianExecutionStatus =
  | "pending"
  | "ingesting"
  | "correlating"
  | "detecting"
  | "analyzing_risk"
  | "recommending"
  | "planning"
  | "completed"
  | "failed";

export type AssetImpactType = "DIRECTLY_AFFECTED" | "POTENTIALLY_EXPOSED" | "INFERRED_EXPOSURE";
export type RiskCategory = "Informational" | "Low" | "Medium" | "High" | "Critical";
export type RecommendationPriority = "P0" | "P1" | "P2" | "P3";
export type RecommendationType = "preventive" | "detective" | "corrective" | "compensating";
export type RecommendationStatus = "proposed" | "planned" | "applied" | "dismissed";
export type RemediationPlanStatus = "draft" | "approved" | "rejected" | "executed";
export type ActionStatus = "pending" | "in_progress" | "completed" | "failed";
export type IncidentReportStatus = "draft" | "published" | "archived";

export interface DefensiveEventRecord {
  id: string;
  guardian_execution_id: string;
  sandbox_id: string;
  source_event_id: string;
  attack_run_id?: string | null;
  campaign_id?: string | null;
  attack_path_id?: string | null;
  scenario_id?: string | null;
  source_asset_id?: string | null;
  destination_asset_id?: string | null;
  event_type: string;
  severity: string;
  original_timestamp: string;
  ingested_at: string;
  is_simulated: boolean;
  simulation_only: boolean;
  sha256_hash: string;
  raw_payload: Record<string, any>;
  provenance_metadata: Record<string, any>;
}

export interface DefensiveEventListResponse {
  items: DefensiveEventRecord[];
  total: number;
  page: number;
  page_size: number;
}

export interface CorrelatedEventGroup {
  id: string;
  guardian_execution_id: string;
  sandbox_id: string;
  campaign_id?: string | null;
  title: string;
  stage: string;
  correlation_basis: CorrelationBasis;
  correlation_rule: string;
  member_event_ids: string[];
  root_cause_asset_id?: string | null;
  impacted_asset_ids: string[];
  earliest_event_timestamp: string;
  latest_event_timestamp: string;
  correlation_confidence: number;
  simulation_only: boolean;
  is_simulated: boolean;
  group_metadata: Record<string, any>;
  created_at: string;
}

export interface GuardianExecution {
  execution_id: string;
  sandbox_id: string;
  attack_run_id?: string | null;
  attack_path_id?: string | null;
  status: GuardianExecutionStatus;
  started_at: string;
  completed_at?: string | null;
  events_ingested: number;
  correlation_groups_count: number;
  threat_detections_count: number;
  risk_assessments_count: number;
  max_risk_score: number;
  error_message?: string | null;
  execution_metadata?: Record<string, any>;
  created_at?: string;
  updated_at?: string;
}

export interface ThreatDetection {
  id: string;
  guardian_execution_id: string;
  correlated_group_id: string;
  sandbox_id: string;
  detection_code: string;
  rule_code: string;
  rule_version: string;
  title: string;
  description: string;
  classification: string;
  severity: "low" | "medium" | "high" | "critical" | string;
  confidence_score: number;
  mitre_techniques: Array<{
    id?: string;
    technique_id?: string;
    name?: string;
    tactic?: string;
    [key: string]: any;
  }>;
  mitre_tactics: string[];
  affected_asset_ids: string[];
  evidence_references: Record<string, any>;
  detection_rationale: string;
  status: string;
  is_simulated: boolean;
  simulation_only: boolean;
  created_at: string;
  updated_at?: string;
}

export interface ThreatDetectionSummary {
  total_detections: number;
  by_severity: Record<string, number>;
  by_classification: Record<string, number>;
  by_mitre_technique: Record<string, number>;
  affected_assets_count: number;
}

export interface ThreatAssetImpact {
  id: string;
  risk_assessment_id: string;
  asset_id: string;
  sandbox_id: string;
  impact_type: AssetImpactType;
  impact_score: number;
  traversal_depth: number;
  relationship_path: string[];
  impact_rationale: string;
  evidence_references: Record<string, any>;
  created_at: string;
}

export interface ThreatRiskAssessment {
  id: string;
  threat_detection_id: string;
  guardian_execution_id: string;
  sandbox_id: string;
  risk_score: number;
  risk_category: RiskCategory;
  severity: string;
  asset_criticality_score: number;
  direct_impact_score: number;
  blast_radius_score: number;
  attack_stage_score: number;
  evidence_confidence_score: number;
  scoring_formula_version: string;
  assessment_rationale: string;
  assessment_status: string;
  assessed_at: string;
  created_at: string;
  updated_at?: string;
  is_simulated: boolean;
  simulation_only: boolean;
}

export interface ThreatRiskAssessmentDetail {
  assessment: ThreatRiskAssessment;
  impacted_assets: ThreatAssetImpact[];
}

export interface RiskSummary {
  total_assessments: number;
  max_risk_score: number;
  average_risk_score: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
  directly_affected_assets_count: number;
  potentially_exposed_assets_count: number;
}

export interface RiskPriorityItem {
  rank: number;
  risk_assessment_id: string;
  threat_detection_id: string;
  detection_code: string;
  title: string;
  classification: string;
  severity: string;
  risk_score: number;
  risk_category: RiskCategory;
  critical_asset_exposed: boolean;
  directly_affected_asset_count: number;
  detected_at: string;
}

export interface RiskPrioritiesResponse {
  items: RiskPriorityItem[];
  total: number;
  highest_risk_detection_id?: string | null;
  highest_risk_asset_id?: string | null;
}

export interface AssetRiskProfile {
  asset_id: string;
  sandbox_id: string;
  asset_name: string;
  asset_type: string;
  criticality: string;
  highest_risk_score: number;
  highest_risk_category: RiskCategory;
  direct_detections_count: number;
  indirect_exposure_count: number;
  total_assessments_count: number;
}

export interface Playbook {
  playbook_id: string;
  playbook_version: string;
  title: string;
  description: string;
  category: string;
  recommendation_type: RecommendationType;
  target_threat_classes: string[];
  mitre_techniques: string[];
  default_priority: RecommendationPriority;
  complexity: string;
  rationale: string;
  expected_outcome: string;
  verification_criteria: string[];
  action_templates: Array<Record<string, any>>;
}

export interface DefensiveRecommendation {
  id: string;
  guardian_execution_id: string;
  threat_detection_id: string;
  risk_assessment_id: string;
  sandbox_id: string;
  recommendation_code: string;
  title: string;
  description: string;
  priority: RecommendationPriority;
  recommendation_type: RecommendationType;
  playbook_id: string;
  playbook_version: string;
  affected_asset_ids: string[];
  evidence_references: Record<string, any>;
  rationale: string;
  expected_outcome: string;
  verification_criteria: string[];
  implementation_complexity: string;
  status: RecommendationStatus;
  created_at: string;
  updated_at?: string;
  is_simulated: boolean;
  simulation_only: boolean;
}

export interface RemediationPlanAction {
  id: string;
  remediation_plan_id: string;
  recommendation_id: string;
  action_code: string;
  title: string;
  description: string;
  sequence_order: number;
  priority: RecommendationPriority;
  depends_on: string[];
  target_asset_ids: string[];
  expected_outcome: string;
  verification_criteria: string[];
  action_type: string;
  status: ActionStatus;
  created_at: string;
  updated_at?: string;
}

export interface RemediationPlan {
  id: string;
  guardian_execution_id: string;
  sandbox_id: string;
  title: string;
  description: string;
  overall_priority: RecommendationPriority;
  status: RemediationPlanStatus;
  plan_version: string;
  target_asset_ids: string[];
  plan_metadata: Record<string, any>;
  action_count: number;
  created_at: string;
  updated_at?: string;
  is_simulated: boolean;
  simulation_only: boolean;
  actions?: RemediationPlanAction[];
}

export interface IncidentReport {
  id: string;
  guardian_execution_id: string;
  sandbox_id: string;
  report_version: number;
  title: string;
  executive_summary: string;
  threat_classifications: string[];
  severity: string;
  max_risk_score: number;
  risk_category: string;
  affected_asset_ids: string[];
  potentially_exposed_asset_ids: string[];
  blast_radius_nodes_count: number;
  mitre_techniques: Array<Record<string, any>>;
  remediation_plan_id?: string | null;
  report_status: IncidentReportStatus;
  generated_at: string;
  created_at: string;
  event_timeline?: Array<Record<string, any>>;
  detection_summaries?: Array<Record<string, any>>;
  recommendation_summaries?: Array<Record<string, any>>;
  report_content?: Record<string, any>;
}

export interface ExecutiveSummary {
  guardian_execution_id: string;
  sandbox_id: string;
  posture_rating: string;
  executive_summary: string;
  total_detections: number;
  max_risk_score: number;
  risk_category: string;
  p0_recommendations_count: number;
  total_recommendations: number;
  affected_assets_count: number;
  exposed_assets_count: number;
  top_threats: Array<Record<string, any>>;
  immediate_priorities: string[];
  residual_risks_and_uncertainties: string[];
  ai_enriched: boolean;
  generated_at: string;
}

// =============================================================================
// Step 09.2.3.6 & Step 09.2.4: Unified Orchestration & Human-in-the-Loop Types
// =============================================================================

export type PipelineStage =
  | "SANDBOX_CREATION"
  | "ASSET_REGISTRATION"
  | "RED_TEAM_SIMULATION"
  | "ATTACK_PATH_EXECUTION"
  | "BLUE_GUARDIAN_ANALYSIS"
  | "EVENT_INGESTION"
  | "EVENT_CORRELATION"
  | "THREAT_DETECTION"
  | "RISK_ASSESSMENT"
  | "DEFENSIVE_RECOMMENDATIONS"
  | "REMEDIATION_PLANNING"
  | "HUMAN_APPROVAL"
  | "SYNTHETIC_REMEDIATION"
  | "REGRESSION_VERIFICATION"
  | "FINAL_AUDIT_SUMMARY"
  | "COMPLETED";

export const PipelineExecutionStatus = {
  PENDING: "pending",
  RUNNING: "running",
  WAITING_FOR_APPROVAL: "waiting_for_approval",
  COMPLETED: "completed",
  FAILED: "failed",
  PARTIAL_FAILURE: "partial_failure",
  CANCELLED: "cancelled",
} as const;

export type PipelineExecutionStatus =
  | "pending"
  | "running"
  | "waiting_for_approval"
  | "completed"
  | "failed"
  | "partial_failure"
  | "cancelled";

export interface StageMetric {
  status: "pending" | "in_progress" | "completed" | "failed" | "skipped" | string;
  started_at?: string;
  completed_at?: string;
  failed_at?: string;
  duration_seconds?: number;
  error?: string;
}

export interface OrchestrationExecutionResponse {
  id: string;
  sandbox_id: string;
  campaign_id?: string | null;
  simulation_id?: string | null;
  attack_path_id?: string | null;
  guardian_execution_id?: string | null;
  remediation_plan_id?: string | null;
  approval_request_id?: string | null;
  synthetic_execution_id?: string | null;
  verification_id?: string | null;
  current_stage: PipelineStage | string;
  execution_status: PipelineExecutionStatus | string;
  failed_stage?: string | null;
  error_message?: string | null;
  retry_count: number;
  is_resumable: boolean;
  stage_metrics: Record<string, StageMetric>;
  execution_metadata: Record<string, any>;
  started_at: string;
  completed_at?: string | null;
  created_at: string;
  updated_at?: string;
}

export interface OrchestrationExecutionListResponse {
  items: OrchestrationExecutionResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface PipelineObservabilityMetrics {
  total_executions: number;
  successful_executions: number;
  failed_executions: number;
  partial_failure_executions: number;
  running_executions: number;
  waiting_approval_executions: number;
  average_stage_durations: Record<string, number>;
  average_approval_wait_seconds: number;
  verification_outcomes: Record<string, number>;
  retry_counts_total: number;
}

export type ApprovalStatus =
  | "pending_approval"
  | "approved"
  | "rejected"
  | "expired"
  | "cancelled"
  | "executing"
  | "verifying"
  | "verified"
  | "verification_failed"
  | "failed";

export type ApprovalDecisionType = "approved" | "rejected";

export interface ApprovalDecisionResponse {
  id: string;
  approval_request_id: string;
  approver_id: string;
  approver_username?: string;
  approver_role?: string;
  decision: ApprovalDecisionType | string;
  comments?: string | null;
  decided_at: string;
}

export interface ApprovalRequestResponse {
  id: string;
  remediation_plan_id: string;
  sandbox_id: string;
  overall_priority?: RecommendationPriority | string;
  approval_status: ApprovalStatus | string;
  required_approvals: number;
  approvals_received: number;
  received_approvals?: number;
  requested_by: string;
  requester_id?: string;
  requester_username?: string;
  plan_version: string;
  approval_policy_version: string;
  request_comments?: string | null;
  expires_at: string;
  created_at: string;
  updated_at?: string;
  decisions: ApprovalDecisionResponse[];
  remediation_plan?: RemediationPlan;
}

export interface ApprovalRequestListResponse {
  items: ApprovalRequestResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface SyntheticRemediationExecutionResponse {
  id: string;
  approval_request_id: string;
  remediation_plan_id: string;
  sandbox_id: string;
  execution_status: "queued" | "executing" | "verifying" | "completed" | "failed" | "partial_failure" | string;
  is_simulated: boolean;
  simulation_only: boolean;
  started_at: string;
  completed_at?: string | null;
  error_summary?: string | null;
  execution_metadata: {
    requester_id?: string;
    plan_version?: string;
    actions_total?: number;
    actions_executed?: number;
    actions_succeeded?: number;
    actions_failed?: number;
    actions_successful?: string[];
    actions_skipped?: string[];
    action_results?: Record<string, { success?: boolean; skipped?: boolean; reason?: string; error?: string; applied_changes?: any }>;
    verification_status?: string;
    verification_summary?: any;
    [key: string]: any;
  };
  created_at: string;
  updated_at?: string;
}

export interface SyntheticRemediationExecutionListResponse {
  items: SyntheticRemediationExecutionResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface SyntheticStateSnapshotResponse {
  id: string;
  remediation_execution_id: string;
  snapshot_type: "BEFORE" | "AFTER";
  captured_at: string;
  asset_states: Record<string, any>;
  topology_state: Record<string, any>;
  sha256_hash: string;
  actor_id?: string | null;
}

export interface SyntheticSnapshotComparisonResponse {
  execution_id: string;
  before_snapshot?: SyntheticStateSnapshotResponse | null;
  after_snapshot?: SyntheticStateSnapshotResponse | null;
  diff_summary: Record<string, any>;
}

export interface VerificationCheckDetail {
  action_code: string;
  title: string;
  criteria: string;
  status: "PASSED" | "PARTIALLY_PASSED" | "FAILED" | "INCONCLUSIVE" | string;
  expected_condition: string;
  actual_condition: string;
  before_value: any;
  after_value: any;
  failure_reason?: string | null;
  evidence_references?: Record<string, any>;
}

export interface RemediationVerificationSummaryResponse {
  id: string;
  remediation_execution_id: string;
  remediation_plan_id: string;
  sandbox_id: string;
  overall_status: "PASSED" | "PARTIALLY_PASSED" | "FAILED" | "INCONCLUSIVE" | string;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  inconclusive_checks: number;
  check_details: VerificationCheckDetail[];
  evaluated_at: string;
  evidence_hash: string;
  actor_id?: string | null;
}

export interface ApprovalPolicyTier {
  priority_level: string;
  required_approvals: number;
  independent_approver_required?: boolean;
  requires_admin_or_senior: boolean;
  timeout_hours?: number;
  description?: string;
}

export interface ApprovalPolicyResponse {
  policy_version?: string;
  version?: string;
  name?: string;
  default_expiry_hours?: number;
  rules?: ApprovalPolicyTier[];
  tiers?: Record<string, ApprovalPolicyTier>;
}

// =============================================================================
// Step 09.2.6: AI Intelligence Gateway & LangGraph Multi-Agent Types
// =============================================================================

export interface AegisAgentOutput {
  agent_name: string;
  execution_status: "completed" | "partial" | "failed" | "fallback" | string;
  summary: string;
  observations: string[];
  supporting_evidence_ids: string[];
  derived_conclusions: string[];
  inferred_exposure: string[];
  uncertainty: string[];
  missing_information: string[];
  advisory_recommendations: string[];
  confidence: number;
  fallback_used: boolean;
  simulation_only: boolean;
  is_ai_generated?: boolean;
}

export interface GraphExecutionResponse {
  graph_execution_id: string;
  sandbox_id: string;
  parent_execution_id?: string | null;
  request_type: string;
  execution_status: "completed" | "partial" | "failed" | string;
  status?: string;
  started_at: string;
  completed_at: string;
  total_latency_ms: number;
  duration_ms?: number | null;
  selected_agents: string[];
  completed_agents?: string[];
  fallback_agents?: string[];
  individual_agent_statuses?: Record<string, string>;
  agent_outputs: Record<string, AegisAgentOutput>;
  synthesis_summary: string;
  overall_confidence: number;
  fallback_used: boolean;
  is_simulated: boolean;
  simulation_only: boolean;
}

export interface AgentMetadata {
  agent_name: string;
  name?: string;
  display_name: string;
  description: string;
  responsibilities: string[];
  supported_request_types: string[];
  advisory_boundary: string;
}

export interface AgentListResponse {
  total_agents: number;
  total?: number;
  agents: AgentMetadata[];
}

export interface GraphHealthResponse {
  status: "healthy" | "degraded" | "unavailable" | string;
  langgraph_available: boolean;
  gemini_provider_available: boolean;
  active_registered_agents: string[];
  timestamp: string;
}

export interface AIGatewayHealth {
  status: string;
  provider: string;
  model: string;
  is_available: boolean;
  gemini_enabled: boolean;
  cache_entries: number;
  timestamp: string;
}

export interface AIUsageMetrics {
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  fallback_requests: number;
  cached_requests: number;
  total_input_tokens: number;
  total_output_tokens: number;
  average_latency_ms: number;
  by_capability: Record<string, { requests: number; fallbacks: number }>;
}

export interface AIAnalysisRecord {
  id: string;
  capability: string;
  sandbox_id: string;
  execution_id?: string | null;
  detection_id?: string | null;
  attack_path_id?: string | null;
  risk_assessment_id?: string | null;
  report_id?: string | null;
  recommendation_id?: string | null;
  prompt_template_version: string;
  model_name: string;
  prompt_tokens?: number | null;
  completion_tokens?: number | null;
  total_tokens?: number | null;
  latency_ms?: number | null;
  fallback_used: boolean;
  cached: boolean;
  sanitized: boolean;
  content: Record<string, any>;
  created_at: string;
}

export interface DetectionRule {
  rule_code: string;
  name: string;
  category: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;
  description: string;
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  detection_type: string;
  enabled: boolean;
}

// ===========================================================================
// AGENT ARENA & REINFORCEMENT LEARNING TYPES
// ===========================================================================

export interface ArenaScoreboard {
  total_rounds: number;
  total_attacks: number;
  blocked_attacks: number;
  breaches: number;
  detected_but_executed?: number;
  unresolved_actions?: number;
  false_positives: number;
  legitimate_allowed: number;
  cumulative_reward: number;
  defense_accuracy_pct: number;
  policy_version: string;
  tool_distribution?: Record<string, number>;
  vector_distribution?: Record<string, number>;
}

export interface ArenaConversationMessage {
  message_id: string;
  round_index: number;
  speaker: "RED_TEAM" | "TARGET_AGENT" | "BLUE_GUARDIAN" | "TOOL_EXECUTION" | "SYSTEM" | string;
  message: string;
  metadata?: Record<string, any>;
  timestamp: string;
}

export interface ArenaRoundRecord {
  round_index: number;
  scenario_id: string;
  strategy_id?: string;
  scenario_name: string;
  vector_type?: string;
  category: string;
  is_malicious: boolean;
  mitre_technique: string;
  red_team_prompt: string;
  target_intent: string;
  proposed_tool: "browser" | "email" | "files" | "payment" | string;
  secondary_tools?: string[];
  proposed_action: string;
  tool_parameters: Record<string, any>;
  detection_result?: {
    is_detected?: boolean;
    confidence?: number;
    matched_indicators?: string[];
    threat_level?: string;
  };
  blue_guardian_decision: "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL" | string;
  blue_guardian_q_values: Record<string, number>;
  blue_guardian_confidence: number;
  tool_execution_status: "EXECUTED" | "BLOCKED" | "FAILED" | string;
  tool_execution_result?: Record<string, any> | null;
  reward_earned: number;
  outcome: "CORRECT_BLOCK" | "BREACH" | "DETECTED_AND_EXECUTED" | "CORRECT_ALLOW" | "FALSE_POSITIVE" | "UNRESOLVED" | string;
  explanation: string;
  rl_update: {
    state_key: string;
    action: string;
    old_q: number;
    new_q: number;
    td_error: number;
    reward: number;
    policy_version: string;
    update_count: number;
  };
  timestamp: string;
}

export interface ArenaToolItem {
  name: string;
  capabilities: string[];
  history_count: number;
}

export interface ArenaStateSnapshot {
  session_id: string;
  status: "IDLE" | "RUNNING" | "PAUSED" | "COMPLETED" | string;
  current_round: number;
  scoreboard: ArenaScoreboard;
  honest_metrics?: {
    attack_attempts: number;
    successful_simulated_actions: number;
    blocked_actions: number;
    detected_but_executed_actions: number;
    unresolved_actions: number;
    false_positives: number;
    legitimate_task_success: number;
    tool_distribution: Record<string, number>;
  };
  policy: {
    policy_version: string;
    learning_rate: number;
    discount_factor: number;
    update_count: number;
    q_table: Record<string, Record<string, number>>;
  };
  tools_summary: {
    browser: ArenaToolItem;
    email: ArenaToolItem;
    files: ArenaToolItem;
    payment: ArenaToolItem;
  };
  conversation_stream: ArenaConversationMessage[];
  round_history: ArenaRoundRecord[];
  latest_round?: ArenaRoundRecord | null;
}



