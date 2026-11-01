/**
 * AegisMesh 2.0 Centralized API Client
 * Uses native fetch with automatic Bearer token injection, typed responses, and resilient error handling.
 */

import {
  AssetRiskProfile,
  AttackPath,
  AttackPathPlanResponse,
  AttackPathReport,
  AuditLogItem,
  AuthTokens,
  CorrelatedEventGroup,
  DefensiveEventListResponse,
  DefensiveRecommendation,
  ExecutiveSummary,
  GuardianExecution,
  IncidentReport,
  Playbook,
  RedTeamRun,
  RedTeamScenario,
  RemediationPlan,
  RiskPrioritiesResponse,
  RiskSummary,
  SandboxEnvironment,
  SyntheticAsset,
  SystemHealth,
  ThreatDetection,
  ThreatDetectionSummary,
  ThreatRiskAssessment,
  ThreatRiskAssessmentDetail,
  User,
  ApprovalDecisionResponse,
  ApprovalPolicyResponse,
  ApprovalRequestListResponse,
  ApprovalRequestResponse,
  OrchestrationExecutionListResponse,
  OrchestrationExecutionResponse,
  PipelineObservabilityMetrics,
  RemediationVerificationSummaryResponse,
  SyntheticRemediationExecutionListResponse,
  SyntheticRemediationExecutionResponse,
  SyntheticSnapshotComparisonResponse,
  AegisAgentOutput,
  AgentListResponse,
  AIGatewayHealth,
  AIAnalysisRecord,
  AIUsageMetrics,
  DetectionRule,
  GraphExecutionResponse,
  GraphHealthResponse,
  ArenaStateSnapshot,
  ArenaRoundRecord,
} from "./types";

const API_BASE = typeof window !== "undefined" ? "/api/v1" : "http://localhost:8000/api/v1";

class ApiError extends Error {
  status: number;
  data: any;

  constructor(status: number, message: string, data?: any) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

export const getStoredToken = (): string | null => {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("aegis_access_token");
};

export const setStoredTokens = (tokens: AuthTokens) => {
  if (typeof window === "undefined") return;
  localStorage.setItem("aegis_access_token", tokens.access_token);
  localStorage.setItem("aegis_refresh_token", tokens.refresh_token);
};

export const clearStoredTokens = () => {
  if (typeof window === "undefined") return;
  localStorage.removeItem("aegis_access_token");
  localStorage.removeItem("aegis_refresh_token");
};

async function apiFetch<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (token && !headers["Authorization"]) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const url = endpoint.startsWith("http") ? endpoint : `${API_BASE}${endpoint}`;

  try {
    const res = await fetch(url, {
      ...options,
      headers,
    });

    if (!res.ok) {
      let errorData: any = {};
      const rawText = await res.text().catch(() => "");
      try {
        errorData = JSON.parse(rawText);
      } catch {
        errorData = { detail: rawText };
      }
      const message =
        errorData?.detail ||
        errorData?.message ||
        `Request failed with status ${res.status}`;
      throw new ApiError(res.status, message, errorData);
    }

    if (res.status === 204) {
      return {} as T;
    }

    return (await res.json()) as T;
  } catch (err: any) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(0, err.message || "Network error. Please check server connectivity.");
  }
}

export const api = {
  // --- HEALTH & STATUS ---
  getHealth: () => apiFetch<SystemHealth>("/health"),

  // --- AUTHENTICATION ---
  login: async (username_or_email: string, password: string) => {
    const data = await apiFetch<AuthTokens>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username_or_email, password }),
    });
    setStoredTokens(data);
    return data;
  },

  getMe: () => apiFetch<User>("/auth/me"),

  refreshToken: async () => {
    const refresh = typeof window !== "undefined" ? localStorage.getItem("aegis_refresh_token") : null;
    if (!refresh) throw new Error("No refresh token stored");
    const data = await apiFetch<AuthTokens>("/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh_token: refresh }),
    });
    setStoredTokens(data);
    return data;
  },

  logout: () => {
    clearStoredTokens();
  },

  // --- SANDBOXES & ASSETS ---
  listSandboxes: (skip = 0, limit = 50) =>
    apiFetch<SandboxEnvironment[]>(`/sandboxes/?skip=${skip}&limit=${limit}`),

  getSandbox: (sandboxId: string) =>
    apiFetch<SandboxEnvironment>(`/sandboxes/${sandboxId}`),

  seedDemoSandbox: () =>
    apiFetch<{
      sandbox_id: string;
      name: string;
      status: string;
      seeded_assets_count: number;
      message: string;
    }>("/sandboxes/seed", { method: "POST" }),

  // Fetch all synthetic assets for a given sandbox
  listAssets: (sandboxId: string) =>
    apiFetch<SyntheticAsset[]>(`/sandboxes/${sandboxId}/assets`),

  // --- RED TEAM SCENARIOS & RUNS ---
  listScenarios: () =>
    apiFetch<RedTeamScenario[]>("/red-team/scenarios"),

  executeRun: (campaignId: string, payload: { scenario: string; asset_id: string; parameters?: Record<string, any> }) =>
    apiFetch<RedTeamRun>(`/red-team/campaigns/${campaignId}/runs`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getRunDetails: (runId: string) =>
    apiFetch<RedTeamRun>(`/red-team/runs/${runId}`),

  // --- ATTACK PATHS (Step 09.2.2) ---
  planAttackPath: (payload: {
    campaign_id: string;
    source_asset_id: string;
    destination_asset_id?: string;
    execution_mode?: "exploratory" | "targeted";
    max_stages?: number;
    scenario_constraints?: string[];
  }) =>
    apiFetch<AttackPathPlanResponse>("/attack-paths/plan", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  executeAttackPath: (attackPathId: string) =>
    apiFetch<AttackPath>(`/attack-paths/${attackPathId}/execute`, {
      method: "POST",
    }),

  listAttackPaths: (skip = 0, limit = 50) =>
    apiFetch<{ items: AttackPath[]; total: number; skip: number; limit: number }>(
      `/attack-paths?skip=${skip}&limit=${limit}`
    ),

  getAttackPath: (attackPathId: string) =>
    apiFetch<AttackPath>(`/attack-paths/${attackPathId}`),

  getAttackPathGraph: (attackPathId: string) =>
    apiFetch<{ attack_path_id: string; nodes: any[]; edges: any[] }>(
      `/attack-paths/${attackPathId}/graph`
    ),

  getAttackPathReport: (attackPathId: string) =>
    apiFetch<AttackPathReport>(`/attack-paths/${attackPathId}/report`),

  getAttackPathStages: (attackPathId: string) =>
    apiFetch<any[]>(`/attack-paths/${attackPathId}/stages`),

  cancelAttackPath: (attackPathId: string, reason?: string) =>
    apiFetch<AttackPath>(`/attack-paths/${attackPathId}/cancel`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),

  // --- AUDIT TRAIL ---
  listAuditLogs: (page = 1, page_size = 50) =>
    apiFetch<{ items: AuditLogItem[]; total: number; page: number; total_pages: number }>(
      `/audit?page=${page}&page_size=${page_size}`
    ),

  // --- BLUE GUARDIAN DEFENSIVE INTELLIGENCE ---
  guardian: {
    createExecution: (payload: {
      sandbox_id: string;
      attack_run_id?: string;
      attack_path_id?: string;
      correlation_window_seconds?: number;
    }) =>
      apiFetch<GuardianExecution>("/guardian/executions", {
        method: "POST",
        body: JSON.stringify(payload),
      }),

    getExecution: (executionId: string) =>
      apiFetch<GuardianExecution>(`/guardian/executions/${executionId}`),

    listExecutions: (sandboxId?: string, limit = 20) => {
      const q = new URLSearchParams();
      if (sandboxId) q.set("sandbox_id", sandboxId);
      q.set("limit", String(limit));
      return apiFetch<GuardianExecution[]>(`/guardian/executions?${q.toString()}`);
    },

    listExecutionEvents: (executionId: string, page = 1, pageSize = 50) =>
      apiFetch<DefensiveEventListResponse>(
        `/guardian/executions/${executionId}/events?page=${page}&page_size=${pageSize}`
      ),

    listExecutionCorrelatedGroups: (executionId: string) =>
      apiFetch<{ items: CorrelatedEventGroup[]; total: number }>(
        `/guardian/executions/${executionId}/correlated-groups`
      ),

    getCorrelatedGroupDetail: (executionId: string, groupId: string) =>
      apiFetch<{ group: CorrelatedEventGroup; events: any[] }>(
        `/guardian/executions/${executionId}/correlated-groups/${groupId}`
      ),

    listDetections: (params: {
      sandbox_id?: string;
      execution_id?: string;
      severity?: string;
      classification?: string;
      page?: number;
      page_size?: number;
    } = {}) => {
      const q = new URLSearchParams();
      if (params.sandbox_id) q.set("sandbox_id", params.sandbox_id);
      if (params.severity) q.set("severity", params.severity);
      if (params.classification) q.set("classification", params.classification);
      if (params.page) q.set("page", String(params.page));
      if (params.page_size) q.set("page_size", String(params.page_size));

      if (params.execution_id) {
        return apiFetch<{ items: ThreatDetection[]; total: number; page: number; page_size: number }>(
          `/guardian/executions/${params.execution_id}/detections?${q.toString()}`
        );
      }
      return apiFetch<{ items: ThreatDetection[]; total: number; page: number; page_size: number }>(
        `/guardian/detections?${q.toString()}`
      );
    },

    getDetectionSummary: (params: { sandbox_id?: string; execution_id?: string } = {}) => {
      const q = new URLSearchParams();
      if (params.sandbox_id) q.set("sandbox_id", params.sandbox_id);
      if (params.execution_id) q.set("execution_id", params.execution_id);
      return apiFetch<ThreatDetectionSummary>(`/guardian/detections/summary?${q.toString()}`);
    },

    getDetection: (detectionId: string) =>
      apiFetch<ThreatDetection>(`/guardian/detections/${detectionId}`),

    getRiskSummary: (params: { sandbox_id?: string; execution_id?: string } = {}) => {
      const q = new URLSearchParams();
      if (params.sandbox_id) q.set("sandbox_id", params.sandbox_id);
      if (params.execution_id) q.set("execution_id", params.execution_id);
      return apiFetch<RiskSummary>(`/guardian/risk-summary?${q.toString()}`);
    },

    getRiskPriorities: (params: { sandbox_id?: string; execution_id?: string; limit?: number } = {}) => {
      const q = new URLSearchParams();
      if (params.sandbox_id) q.set("sandbox_id", params.sandbox_id);
      if (params.execution_id) q.set("execution_id", params.execution_id);
      if (params.limit) q.set("limit", String(params.limit));
      return apiFetch<RiskPrioritiesResponse>(`/guardian/risk-priorities?${q.toString()}`);
    },

    listRiskAssessments: (params: {
      sandbox_id?: string;
      execution_id?: string;
      risk_category?: string;
      min_score?: number;
      page?: number;
      page_size?: number;
    } = {}) => {
      const q = new URLSearchParams();
      if (params.sandbox_id) q.set("sandbox_id", params.sandbox_id);
      if (params.risk_category) q.set("risk_category", params.risk_category);
      if (params.min_score !== undefined) q.set("min_score", String(params.min_score));
      if (params.page) q.set("page", String(params.page));
      if (params.page_size) q.set("page_size", String(params.page_size));

      if (params.execution_id) {
        return apiFetch<{ items: ThreatRiskAssessment[]; total: number; page: number; page_size: number }>(
          `/guardian/executions/${params.execution_id}/risk-assessments?${q.toString()}`
        );
      }
      return apiFetch<{ items: ThreatRiskAssessment[]; total: number; page: number; page_size: number }>(
        `/guardian/risk-assessments?${q.toString()}`
      );
    },

    getRiskAssessment: (assessmentId: string) =>
      apiFetch<ThreatRiskAssessmentDetail>(`/guardian/risk-assessments/${assessmentId}`),

    getAssetRiskProfile: (assetId: string) =>
      apiFetch<AssetRiskProfile>(`/guardian/assets/${assetId}/risk`),

    listPlaybooks: () =>
      apiFetch<{ playbooks: Playbook[]; total: number }>("/guardian/playbooks"),

    listRecommendations: (params: {
      sandbox_id?: string;
      execution_id?: string;
      priority?: string;
      playbook_id?: string;
      page?: number;
      page_size?: number;
    } = {}) => {
      const q = new URLSearchParams();
      if (params.sandbox_id) q.set("sandbox_id", params.sandbox_id);
      if (params.priority) q.set("priority", params.priority);
      if (params.playbook_id) q.set("playbook_id", params.playbook_id);
      if (params.page) q.set("page", String(params.page));
      if (params.page_size) q.set("page_size", String(params.page_size));

      if (params.execution_id) {
        return apiFetch<{ items: DefensiveRecommendation[]; total: number; page: number; page_size: number }>(
          `/guardian/executions/${params.execution_id}/recommendations?${q.toString()}`
        );
      }
      return apiFetch<{ items: DefensiveRecommendation[]; total: number; page: number; page_size: number }>(
        `/guardian/recommendations?${q.toString()}`
      );
    },

    getRecommendation: (recommendationId: string) =>
      apiFetch<DefensiveRecommendation>(`/guardian/recommendations/${recommendationId}`),

    listRemediationPlans: (params: {
      sandbox_id?: string;
      execution_id?: string;
      status?: string;
    } = {}) => {
      const q = new URLSearchParams();
      if (params.sandbox_id) q.set("sandbox_id", params.sandbox_id);
      if (params.status) q.set("status", params.status);

      if (params.execution_id) {
        return apiFetch<{ items: RemediationPlan[]; total: number }>(
          `/guardian/executions/${params.execution_id}/remediation-plans?${q.toString()}`
        );
      }
      return apiFetch<{ items: RemediationPlan[]; total: number }>(
        `/guardian/remediation-plans?${q.toString()}`
      );
    },

    getRemediationPlan: (planId: string) =>
      apiFetch<RemediationPlan>(`/guardian/remediation-plans/${planId}`),

    generateIncidentReport: (
      executionId: string,
      payload: { report_version?: number; custom_title?: string; include_ai_narrative?: boolean } = {}
    ) =>
      apiFetch<IncidentReport>(`/guardian/executions/${executionId}/incident-reports/generate`, {
        method: "POST",
        body: JSON.stringify(payload),
      }),

    listIncidentReports: (params: {
      sandbox_id?: string;
      execution_id?: string;
      status?: string;
    } = {}) => {
      const q = new URLSearchParams();
      if (params.sandbox_id) q.set("sandbox_id", params.sandbox_id);
      if (params.status) q.set("status", params.status);

      if (params.execution_id) {
        return apiFetch<{ items: IncidentReport[]; total: number }>(
          `/guardian/executions/${params.execution_id}/incident-reports?${q.toString()}`
        );
      }
      return apiFetch<{ items: IncidentReport[]; total: number }>(
        `/guardian/incident-reports?${q.toString()}`
      );
    },

    getIncidentReport: (reportId: string) =>
      apiFetch<IncidentReport>(`/guardian/incident-reports/${reportId}`),

    getExecutiveSummary: (executionId: string) =>
      apiFetch<ExecutiveSummary>(`/guardian/executions/${executionId}/executive-summary`),
  },

  // ===========================================================================
  // Step 09.2.4: Unified Platform Orchestrator APIs
  // ===========================================================================
  orchestration: {
    startPipeline: (payload: {
      sandbox_id: string;
      scenario_id?: string;
      run_attack_path?: boolean;
      auto_approve?: boolean;
      correlation_window_seconds?: number;
      client_metadata?: Record<string, any>;
    }) =>
      apiFetch<OrchestrationExecutionResponse>("/orchestration/pipeline/start", {
        method: "POST",
        body: JSON.stringify(payload),
      }),

    listPipelines: (params: {
      sandbox_id?: string;
      status?: string;
      page?: number;
      page_size?: number;
    } = {}) => {
      const q = new URLSearchParams();
      if (params.sandbox_id) q.set("sandbox_id", params.sandbox_id);
      if (params.status) q.set("status", params.status);
      if (params.page) q.set("page", params.page.toString());
      if (params.page_size) q.set("page_size", params.page_size.toString());
      return apiFetch<OrchestrationExecutionListResponse>(`/orchestration/pipeline?${q.toString()}`);
    },

    getPipeline: (executionId: string) =>
      apiFetch<OrchestrationExecutionResponse>(`/orchestration/pipeline/${executionId}`),

    resumePipeline: (executionId: string) =>
      apiFetch<OrchestrationExecutionResponse>(`/orchestration/pipeline/${executionId}/resume`, {
        method: "POST",
      }),

    getMetrics: (sandboxId?: string) => {
      const q = sandboxId ? `?sandbox_id=${sandboxId}` : "";
      return apiFetch<PipelineObservabilityMetrics>(`/orchestration/metrics${q}`);
    },
  },

  // ===========================================================================
  // Step 09.2.3.6: Human Approval, Synthetic Remediation & Verification APIs
  // ===========================================================================
  approval: {
    createApprovalRequest: (planId: string) =>
      apiFetch<ApprovalRequestResponse>(`/guardian/remediation-plans/${planId}/approval-requests`, {
        method: "POST",
      }),

    listApprovalRequests: (params: {
      sandbox_id?: string;
      status?: string;
      page?: number;
      page_size?: number;
    } = {}) => {
      const q = new URLSearchParams();
      if (params.sandbox_id) q.set("sandbox_id", params.sandbox_id);
      if (params.status) q.set("status", params.status);
      if (params.page) q.set("page", params.page.toString());
      if (params.page_size) q.set("page_size", params.page_size.toString());
      return apiFetch<ApprovalRequestListResponse>(`/guardian/approval-requests?${q.toString()}`);
    },

    getApprovalRequest: (requestId: string) =>
      apiFetch<ApprovalRequestResponse>(`/guardian/approval-requests/${requestId}`),

    approveRequest: (requestId: string, comments?: string) =>
      apiFetch<ApprovalRequestResponse>(`/guardian/approval-requests/${requestId}/approve`, {
        method: "POST",
        body: JSON.stringify({ decision: "APPROVED", comments }),
      }),

    rejectRequest: (requestId: string, comments?: string) =>
      apiFetch<ApprovalRequestResponse>(`/guardian/approval-requests/${requestId}/reject`, {
        method: "POST",
        body: JSON.stringify({ decision: "REJECTED", comments }),
      }),

    cancelRequest: (requestId: string) =>
      apiFetch<ApprovalRequestResponse>(`/guardian/approval-requests/${requestId}/cancel`, {
        method: "POST",
      }),

    executeRemediation: (requestId: string) =>
      apiFetch<SyntheticRemediationExecutionResponse>(`/guardian/approval-requests/${requestId}/execute`, {
        method: "POST",
      }),

    listRemediationExecutions: (params: {
      sandbox_id?: string;
      status?: string;
      page?: number;
      page_size?: number;
    } = {}) => {
      const q = new URLSearchParams();
      if (params.sandbox_id) q.set("sandbox_id", params.sandbox_id);
      if (params.status) q.set("status", params.status);
      if (params.page) q.set("page", params.page.toString());
      if (params.page_size) q.set("page_size", params.page_size.toString());
      return apiFetch<SyntheticRemediationExecutionListResponse>(`/guardian/remediation-executions?${q.toString()}`);
    },

    getRemediationExecution: (executionId: string) =>
      apiFetch<SyntheticRemediationExecutionResponse>(`/guardian/remediation-executions/${executionId}`),

    getRemediationSnapshots: (executionId: string) =>
      apiFetch<SyntheticSnapshotComparisonResponse>(`/guardian/remediation-executions/${executionId}/snapshots`),

    getRemediationVerification: (executionId: string) =>
      apiFetch<RemediationVerificationSummaryResponse>(`/guardian/remediation-executions/${executionId}/verification`),

    getCurrentApprovalPolicy: () =>
      apiFetch<ApprovalPolicyResponse>("/guardian/approval-policies/current"),

    getApprovalPolicies: () =>
      apiFetch<ApprovalPolicyResponse>("/guardian/approval-policies"),

    listDetectionRules: () =>
      apiFetch<DetectionRule[]>("/guardian/detection-rules"),

    getPlanVerificationHistory: (planId: string) =>
      apiFetch<{ plan_id: string; verifications: any[] }>(`/guardian/remediation-plans/${planId}/verification-history`),
  },

  // ===========================================================================
  // Step 09.2.6: AI Intelligence Gateway & LangGraph Multi-Agent APIs
  // ===========================================================================
  ai: {
    explainThreat: (detectionId: string, options: { user_query?: string } = {}) =>
      apiFetch<any>(`/ai/threats/${detectionId}/explain`, {
        method: "POST",
        body: JSON.stringify(options),
      }),

    analyzeAttackPath: (attackPathId: string, options: { user_query?: string } = {}) =>
      apiFetch<any>(`/ai/attack-paths/${attackPathId}/analyze`, {
        method: "POST",
        body: JSON.stringify(options),
      }),

    explainRisk: (assessmentId: string, options: { user_query?: string } = {}) =>
      apiFetch<any>(`/ai/risks/${assessmentId}/explain`, {
        method: "POST",
        body: JSON.stringify(options),
      }),

    summarizeIncident: (reportId: string, options: { user_query?: string } = {}) =>
      apiFetch<any>(`/ai/incidents/${reportId}/summarize`, {
        method: "POST",
        body: JSON.stringify(options),
      }),

    explainRecommendation: (recommendationId: string, options: { user_query?: string } = {}) =>
      apiFetch<any>(`/ai/recommendations/${recommendationId}/explain`, {
        method: "POST",
        body: JSON.stringify(options),
      }),

    getExecutiveBriefing: (executionId: string, options: { user_query?: string } = {}) =>
      apiFetch<any>(`/ai/executions/${executionId}/briefing`, {
        method: "POST",
        body: JSON.stringify(options),
      }),

    askSecurityQuestion: (executionId: string, question: string) =>
      apiFetch<any>(`/ai/executions/${executionId}/qa`, {
        method: "POST",
        body: JSON.stringify({ question }),
      }),

    listAnalyses: (executionId: string) =>
      apiFetch<{ execution_id: string; analyses: AIAnalysisRecord[]; count: number }>(
        `/ai/executions/${executionId}/analyses`
      ),

    getGatewayHealth: () => apiFetch<AIGatewayHealth>("/ai/health"),

    getUsageMetrics: () => apiFetch<AIUsageMetrics>("/ai/usage"),

    executeSingleAgent: (payload: {
      sandbox_id: string;
      agent_name: string;
      execution_id?: string;
      user_query?: string;
    }) =>
      apiFetch<AegisAgentOutput>("/ai/agents/execute", {
        method: "POST",
        body: JSON.stringify(payload),
      }),

    executeGraph: (payload: {
      sandbox_id: string;
      execution_id?: string;
      request_type?: string;
      selected_agents?: string[];
      user_query?: string;
    }) => {
      const body: Record<string, any> = {
        sandbox_id: payload.sandbox_id,
        request_type: payload.request_type || "full_investigation",
      };
      if (payload.execution_id) body.execution_id = payload.execution_id;
      if (payload.selected_agents) body.selected_agents = payload.selected_agents;
      if (payload.user_query) body.user_query = payload.user_query;
      return apiFetch<GraphExecutionResponse>("/ai/graphs/execute", {
        method: "POST",
        body: JSON.stringify(body),
      });
    },

    getGraphHealth: () => apiFetch<GraphHealthResponse>("/ai/graphs/health"),

    getGraphExecution: (graphExecutionId: string) =>
      apiFetch<GraphExecutionResponse>(`/ai/graphs/${graphExecutionId}`),

    getGraphAgents: (graphExecutionId: string) =>
      apiFetch<{ graph_execution_id: string; agent_outputs: Record<string, AegisAgentOutput> }>(
        `/ai/graphs/${graphExecutionId}/agents`
      ),

    listAgents: () => apiFetch<AgentListResponse>("/ai/agents"),
  },

  // ===========================================================================
  // Background Job & Asynchronous Worker APIs
  // ===========================================================================
  jobs: {
    enqueueHealthCheck: () =>
      apiFetch<{ task_id: string; status: string; enqueued_at: string }>("/jobs/health-check", {
        method: "POST",
      }),

    getJobStatus: (taskId: string) =>
      apiFetch<{ task_id: string; status: string; result?: any; error?: string }>(`/jobs/${taskId}`),
  },

  // ===========================================================================
  // Security Gateway Authorization Evaluator
  // ===========================================================================
  security: {
    checkPermission: (payload: {
      operation: string;
      capability?: string;
      resource_type?: string;
      resource_id?: string;
      environment?: string;
    }) =>
      apiFetch<{ allowed: boolean; reason?: string; evaluated_at: string }>("/security/check", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
  },

  // ===========================================================================
  // Audit Trail APIs
  // ===========================================================================
  audit: {
    listAuditLogs: (params: {
      page?: number;
      page_size?: number;
      event_type?: string;
      actor_id?: string;
      start_date?: string;
      end_date?: string;
    } = {}) => {
      const q = new URLSearchParams();
      if (params.page) q.set("page", params.page.toString());
      if (params.page_size) q.set("page_size", params.page_size.toString());
      if (params.event_type) q.set("event_type", params.event_type);
      if (params.actor_id) q.set("actor_id", params.actor_id);
      if (params.start_date) q.set("start_date", params.start_date);
      if (params.end_date) q.set("end_date", params.end_date);
      return apiFetch<{ items: AuditLogItem[]; total: number; page: number; page_size: number; total_pages: number }>(
        `/audit?${q.toString()}`
      );
    },
  },

  // ===========================================================================
  // Autonomous Agent Arena & Reinforcement Learning APIs
  // ===========================================================================
  arena: {
    getState: () => apiFetch<ArenaStateSnapshot>("/arena/state"),
    start: (resetState: boolean = false) =>
      apiFetch<{ status: string; message: string; state: ArenaStateSnapshot }>("/arena/start", {
        method: "POST",
        body: JSON.stringify({ reset_state: resetState }),
      }),
    stepNextRound: () =>
      apiFetch<{ status: string; round_record: ArenaRoundRecord; state: ArenaStateSnapshot }>("/arena/round/next", {
        method: "POST",
      }),
    runContinuous: (rounds: number = 5) =>
      apiFetch<{ status: string; total_rounds_executed: number; state: ArenaStateSnapshot }>("/arena/run-continuous", {
        method: "POST",
        body: JSON.stringify({ rounds }),
      }),
    reset: (resetLearningOnly: boolean = false) =>
      apiFetch<{ status: string; message: string; state: ArenaStateSnapshot }>("/arena/reset", {
        method: "POST",
        body: JSON.stringify({ reset_learning_only: resetLearningOnly }),
      }),
    getTools: () => apiFetch<{ status: string; tools: Record<string, any>; recent_history: Record<string, any> }>("/arena/tools"),
    getPolicy: () => apiFetch<{ status: string; policy: Record<string, any> }>("/arena/policy"),
    speak: (text: string, voice: string = "Puck") =>
      apiFetch<{ status: string; audio_base64: string | null; voice: string; format: string; source: string }>("/arena/speak", {
        method: "POST",
        body: JSON.stringify({ text, voice }),
      }),
  },
};
