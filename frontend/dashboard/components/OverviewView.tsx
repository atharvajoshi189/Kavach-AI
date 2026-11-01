"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import {
  RiskSummary,
  RiskPrioritiesResponse,
  ThreatDetectionSummary,
  PipelineObservabilityMetrics,
  OrchestrationExecutionResponse,
} from "../lib/types";
import {
  ShieldAlert,
  AlertTriangle,
  Flame,
  CheckCircle2,
  TrendingUp,
  Server,
  Crosshair,
  ShieldCheck,
  FileText,
  ArrowRight,
  RefreshCw,
  Activity,
  Layers,
  Play,
  Clock,
  UserCheck,
  Cpu,
  GitBranch,
} from "lucide-react";
import { PipelineControlModal } from "./PipelineControlModal";
import { PipelineExecutionView } from "./PipelineExecutionView";

interface OverviewViewProps {
  onNavigate: (tab: any) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({ onNavigate }) => {
  const { activeSandbox } = useAuth();
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [riskSummary, setRiskSummary] = useState<RiskSummary | null>(null);
  const [threatSummary, setThreatSummary] = useState<ThreatDetectionSummary | null>(null);
  const [priorities, setPriorities] = useState<RiskPrioritiesResponse | null>(null);
  const [metrics, setMetrics] = useState<PipelineObservabilityMetrics | null>(null);
  const [recentPipelines, setRecentPipelines] = useState<OrchestrationExecutionResponse[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Pipeline modal & inspection state
  const [isPipelineModalOpen, setIsPipelineModalOpen] = useState(false);
  const [inspectingExecutionId, setInspectingExecutionId] = useState<string | null>(null);

  const fetchDashboardData = useCallback(async (isSilent = false) => {
    if (!activeSandbox) {
      setLoading(false);
      return;
    }
    if (!isSilent) setLoading(true);
    else setRefreshing(true);
    setError(null);

    try {
      const [rSum, tSum, prio, mRes, pList] = await Promise.allSettled([
        api.guardian.getRiskSummary({ sandbox_id: activeSandbox.id }),
        api.guardian.getDetectionSummary({ sandbox_id: activeSandbox.id }),
        api.guardian.getRiskPriorities({ sandbox_id: activeSandbox.id, limit: 5 }),
        api.orchestration.getMetrics(activeSandbox.id),
        api.orchestration.listPipelines({ sandbox_id: activeSandbox.id, page_size: 10 }),
      ]);

      if (rSum.status === "fulfilled") setRiskSummary(rSum.value);
      if (tSum.status === "fulfilled") setThreatSummary(tSum.value);
      if (prio.status === "fulfilled") setPriorities(prio.value);
      if (mRes.status === "fulfilled") setMetrics(mRes.value);
      if (pList.status === "fulfilled") setRecentPipelines(pList.value.items || []);
    } catch (err: any) {
      setError(err?.message || "Failed to load overview telemetry");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [activeSandbox]);

  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  // If inspecting a specific execution, render the complete 15-stage view
  if (inspectingExecutionId) {
    return (
      <PipelineExecutionView
        executionId={inspectingExecutionId}
        onNavigateToTab={onNavigate}
        onBackToList={() => setInspectingExecutionId(null)}
      />
    );
  }

  const maxScore = riskSummary?.max_risk_score ?? 0;
  const getRiskScoreColor = (score: number) => {
    if (score >= 8.0) return "text-rose-400 border-rose-500/40 bg-rose-950/30";
    if (score >= 6.0) return "text-amber-400 border-amber-500/40 bg-amber-950/30";
    if (score >= 4.0) return "text-yellow-400 border-yellow-500/40 bg-yellow-950/30";
    return "text-cyan-400 border-cyan-500/40 bg-cyan-950/30";
  };

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case "completed":
        return "bg-emerald-950 text-emerald-300 border-emerald-800";
      case "running":
        return "bg-cyan-950 text-cyan-300 border-cyan-800 animate-pulse";
      case "waiting_for_approval":
        return "bg-amber-950 text-amber-300 border-amber-800 animate-pulse";
      case "failed":
        return "bg-red-950 text-red-300 border-red-800";
      case "partial_failure":
        return "bg-orange-950 text-orange-300 border-orange-800";
      default:
        return "bg-slate-900 text-slate-400 border-slate-800";
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Sandbox Scope Status */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 backdrop-blur-md">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              Autonomous SOC Command Center
              <span className="text-xs font-mono font-normal px-2 py-0.5 rounded border border-cyan-500/30 bg-cyan-950/50 text-cyan-400">
                LIVE ORCHESTRATION
              </span>
            </h1>
          </div>
          <p className="text-xs text-slate-400">
            Real-time multi-agent execution: Red Team simulation, Blue Guardian detection, four-eyes approval, and synthetic verification.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-[#1a2744] bg-[#070a13] text-xs">
            <Layers className="h-3.5 w-3.5 text-cyan-400" />
            <span className="text-slate-400">Target Sandbox:</span>
            <span className="font-semibold text-white">{activeSandbox?.name || "None Selected"}</span>
            <span className="text-[10px] font-mono text-emerald-400 px-1.5 py-0.2 rounded bg-emerald-950 border border-emerald-800/60">
              SIMULATED
            </span>
          </div>

          {/* Primary Action: Start Unified 15-Stage Pipeline */}
          <button
            onClick={() => setIsPipelineModalOpen(true)}
            className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 px-4 py-1.5 text-xs font-bold text-white shadow-md shadow-cyan-950/60 transition-all"
          >
            <Play className="h-3.5 w-3.5" />
            <span>⚡ Start Unified Pipeline</span>
          </button>

          <button
            onClick={() => fetchDashboardData(true)}
            disabled={refreshing || loading}
            title="Refresh Overview Telemetry"
            className="flex items-center gap-1.5 rounded-lg border border-[#1a2744] bg-[#070a13] px-3 py-1.5 text-xs text-slate-300 hover:border-cyan-500/50 hover:text-white transition-all disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin text-cyan-400" : ""}`} />
            <span>Sync</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-950/40 p-3 text-xs text-red-200">
          <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Persisted Orchestration Observability KPI Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
        {/* Total Executions */}
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222]/60 p-4 backdrop-blur-sm">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total Executions</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-white">
              {metrics?.total_executions ?? 0}
            </span>
            <span className="text-xs text-slate-500">runs</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 font-mono">
            {metrics?.successful_executions ?? 0} completed • {metrics?.failed_executions ?? 0} failed • {metrics?.partial_failure_executions ?? 0} partial
          </div>
        </div>

        {/* Currently Active / Running */}
        <div className="rounded-xl border border-cyan-500/30 bg-cyan-950/20 p-4 backdrop-blur-sm">
          <div className="flex items-center justify-between text-xs text-cyan-300">
            <span>Running Pipelines</span>
            <Clock className="h-4 w-4 text-cyan-400 animate-spin" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-cyan-200">
              {metrics?.running_executions ?? 0}
            </span>
            <span className="text-xs text-cyan-400/80">active</span>
          </div>
          <div className="mt-2 text-[11px] text-cyan-300/80 font-mono">
            Deterministic stage progression
          </div>
        </div>

        {/* Awaiting Four-Eyes Approval */}
        <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 p-4 backdrop-blur-sm">
          <div className="flex items-center justify-between text-xs text-amber-300">
            <span>Awaiting Approval</span>
            <UserCheck className="h-4 w-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-amber-200">
              {metrics?.waiting_approval_executions ?? 0}
            </span>
            <span className="text-xs text-amber-400/80">paused</span>
          </div>
          <div className="mt-2 text-[11px] text-amber-300/80 font-mono">
            Four-Eyes signoff required
          </div>
        </div>

        {/* Average Approval Wait */}
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222]/60 p-4 backdrop-blur-sm">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Approval Wait Avg</span>
            <Clock className="h-4 w-4 text-blue-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-white">
              {metrics?.average_approval_wait_seconds !== undefined
                ? metrics.average_approval_wait_seconds.toFixed(2)
                : "0.0"}
            </span>
            <span className="text-xs text-slate-400">seconds</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 font-mono">
            {metrics?.retry_counts_total ?? 0} total retry attempts
          </div>
        </div>

        {/* Regression Verification Outcomes */}
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-4 backdrop-blur-sm">
          <div className="flex items-center justify-between text-xs text-emerald-300">
            <span>Verifications</span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-emerald-300">
              {metrics?.verification_outcomes?.passed ?? 0}
            </span>
            <span className="text-xs text-emerald-400/80">Passed</span>
          </div>
          <div className="mt-2 text-[11px] text-emerald-400/80 font-mono">
            {metrics?.verification_outcomes?.failed ?? 0} failed • {metrics?.verification_outcomes?.inconclusive ?? 0} inconclusive
          </div>
        </div>
      </div>

      {/* Recent Unified Pipeline Executions Table */}
      <div className="rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 backdrop-blur-md">
        <div className="flex items-center justify-between pb-4 border-b border-[#1a2744]">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              Recent 15-Stage Pipeline Runs
            </h2>
            <p className="text-xs text-slate-400">
              Complete end-to-end multi-agent executions with live stage state machine metrics.
            </p>
          </div>
          <button
            onClick={() => setIsPipelineModalOpen(true)}
            className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
          >
            <span>+ New Execution</span>
            <ArrowRight className="h-3 w-3" />
          </button>
        </div>

        {recentPipelines.length === 0 ? (
          <div className="py-10 text-center text-xs text-slate-400">
            <p className="font-medium text-white">No pipeline executions yet in this sandbox.</p>
            <p className="text-slate-500 mt-1">
              Click &ldquo;Start Unified Pipeline&rdquo; above to execute the complete synthetic security lifecycle.
            </p>
          </div>
        ) : (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#1a2744] text-[10px] text-slate-400 font-mono uppercase">
                  <th className="pb-2.5 font-normal">EXECUTION ID</th>
                  <th className="pb-2.5 font-normal">CURRENT STAGE</th>
                  <th className="pb-2.5 font-normal">STATUS</th>
                  <th className="pb-2.5 font-normal">STARTED AT</th>
                  <th className="pb-2.5 font-normal">DURATION</th>
                  <th className="pb-2.5 font-normal text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1a2744]/60 font-sans">
                {recentPipelines.map((ex) => (
                  <tr key={ex.id} className="hover:bg-[#10192e] transition-colors">
                    <td className="py-3 font-mono font-bold text-cyan-400">
                      {ex.id.slice(0, 8)}...
                    </td>

                    <td className="py-3 font-mono text-[11px] text-slate-300">
                      {ex.current_stage}
                    </td>

                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${getStatusBadge(
                          ex.execution_status
                        )}`}
                      >
                        {ex.execution_status.replace(/_/g, " ")}
                      </span>
                    </td>

                    <td className="py-3 font-mono text-[11px] text-slate-400">
                      {new Date(ex.started_at).toLocaleTimeString()}
                    </td>

                    <td className="py-3 font-mono text-[11px] text-slate-300">
                      {ex.completed_at
                        ? `${Math.round(
                            (new Date(ex.completed_at).getTime() - new Date(ex.started_at).getTime()) / 1000
                          )}s`
                        : "Active"}
                    </td>

                    <td className="py-3 text-right">
                      <button
                        onClick={() => setInspectingExecutionId(ex.id)}
                        className="px-2.5 py-1 rounded border border-cyan-800/60 bg-cyan-950/40 text-cyan-300 hover:bg-cyan-900/60 hover:text-white transition-all text-[11px]"
                      >
                        View 15 Stages →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Operational Subsystems Quick Access */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button
          onClick={() => onNavigate("red_team")}
          className="group flex flex-col justify-between text-left p-4 rounded-xl border border-[#1a2744] bg-gradient-to-br from-[#0c1222] to-[#070a13] hover:border-cyan-500/50 hover:shadow-lg hover:shadow-cyan-950/30 transition-all"
        >
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider font-semibold">
                RED TEAM
              </span>
              <Crosshair className="h-4 w-4 text-cyan-400 group-hover:scale-110 transition-transform" />
            </div>
            <h3 className="text-sm font-bold text-white mt-2">Attack Path Simulation</h3>
            <p className="text-xs text-slate-400 mt-1">
              Deterministic MITRE ATT&CK techniques, multi-hop kill-chains, and relational asset traversal.
            </p>
          </div>
          <div className="mt-4 flex items-center gap-1 text-xs font-medium text-cyan-400 group-hover:text-cyan-300">
            <span>Explore Attack Paths</span>
            <ArrowRight className="h-3.5 w-3.5 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>

        <button
          onClick={() => onNavigate("blue_guardian")}
          className="group flex flex-col justify-between text-left p-4 rounded-xl border border-[#1a2744] bg-gradient-to-br from-[#0c1222] to-[#070a13] hover:border-cyan-500/50 hover:shadow-lg hover:shadow-cyan-950/30 transition-all"
        >
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider font-semibold">
                BLUE GUARDIAN
              </span>
              <ShieldAlert className="h-4 w-4 text-cyan-400 group-hover:scale-110 transition-transform" />
            </div>
            <h3 className="text-sm font-bold text-white mt-2">Threat Detection & Risk</h3>
            <p className="text-xs text-slate-400 mt-1">
              Ingestion envelopes, sliding correlation windows, and 6-dimensional bounded risk scoring.
            </p>
          </div>
          <div className="mt-4 flex items-center gap-1 text-xs font-medium text-cyan-400 group-hover:text-cyan-300">
            <span>Inspect Threat Detections</span>
            <ArrowRight className="h-3.5 w-3.5 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>

        <button
          onClick={() => onNavigate("response_center")}
          className="group flex flex-col justify-between text-left p-4 rounded-xl border border-[#1a2744] bg-gradient-to-br from-[#0c1222] to-[#070a13] hover:border-cyan-500/50 hover:shadow-lg hover:shadow-cyan-950/30 transition-all"
        >
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider font-semibold">
                DEFENSIVE RESPONSE
              </span>
              <FileText className="h-4 w-4 text-cyan-400 group-hover:scale-110 transition-transform" />
            </div>
            <h3 className="text-sm font-bold text-white mt-2">Approvals & Verifications</h3>
            <p className="text-xs text-slate-400 mt-1">
              Four-Eyes approval voting, synthetic handler progress, before/after snapshots, and audit trail.
            </p>
          </div>
          <div className="mt-4 flex items-center gap-1 text-xs font-medium text-cyan-400 group-hover:text-cyan-300">
            <span>Open Response Center</span>
            <ArrowRight className="h-3.5 w-3.5 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>
      </div>

      {/* Start Pipeline Modal */}
      <PipelineControlModal
        isOpen={isPipelineModalOpen}
        onClose={() => setIsPipelineModalOpen(false)}
        onPipelineStarted={(newExecution) => {
          setInspectingExecutionId(newExecution.id);
          fetchDashboardData(true);
        }}
      />
    </div>
  );
};
