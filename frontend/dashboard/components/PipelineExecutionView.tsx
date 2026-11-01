"use client";

import React, { useEffect, useState, useCallback, useRef } from "react";
import { api } from "../lib/api";
import {
  OrchestrationExecutionResponse,
  PipelineStage,
  PipelineExecutionStatus,
} from "../lib/types";
import {
  ShieldAlert,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  Layers,
  Crosshair,
  GitBranch,
  ShieldCheck,
  FileCheck,
  FileText,
  Activity,
  UserCheck,
  RefreshCw,
  Cpu,
  Terminal,
} from "lucide-react";

interface PipelineExecutionViewProps {
  executionId: string;
  onNavigateToTab?: (tab: any) => void;
  onBackToList?: () => void;
}

const ORDERED_STAGES: Array<{ id: PipelineStage; label: string; description: string; icon: any }> = [
  { id: "SANDBOX_CREATION", label: "1. Sandbox Creation", description: "Validate isolation boundary & active state", icon: Layers },
  { id: "ASSET_REGISTRATION", label: "2. Asset Registration", description: "Register & verify synthetic target topology", icon: Cpu },
  { id: "RED_TEAM_SIMULATION", label: "3. Red Team Simulation", description: "Execute deterministic synthetic attack run", icon: Crosshair },
  { id: "ATTACK_PATH_EXECUTION", label: "4. Attack Path Execution", description: "Multi-stage graph traversal across kill-chain", icon: GitBranch },
  { id: "BLUE_GUARDIAN_ANALYSIS", label: "5. Blue Guardian Analysis", description: "Defensive telemetry ingestion & processing", icon: ShieldAlert },
  { id: "EVENT_INGESTION", label: "6. Event Ingestion", description: "Deduplication and SHA-256 payload integrity", icon: Terminal },
  { id: "EVENT_CORRELATION", label: "7. Event Correlation", description: "Relational, temporal, and direct rule grouping", icon: Activity },
  { id: "THREAT_DETECTION", label: "8. Threat Detection", description: "MITRE ATT&CK rule matches & confidence evaluation", icon: ShieldAlert },
  { id: "RISK_ASSESSMENT", label: "9. Risk Assessment", description: "Blast radius scoring & asset criticality analysis", icon: AlertTriangle },
  { id: "DEFENSIVE_RECOMMENDATIONS", label: "10. Recommendations", description: "Generate defensive playbooks & counteractions", icon: FileCheck },
  { id: "REMEDIATION_PLANNING", label: "11. Remediation Planning", description: "Synthesize prioritized remediation plan", icon: FileText },
  { id: "HUMAN_APPROVAL", label: "12. Human Approval", description: "Four-Eyes governance, admin signoff & vetoes", icon: UserCheck },
  { id: "SYNTHETIC_REMEDIATION", label: "13. Synthetic Remediation", description: "Execute allowlisted handlers on sandbox state", icon: ShieldCheck },
  { id: "REGRESSION_VERIFICATION", label: "14. Regression Verification", description: "Compare BEFORE/AFTER snapshots & check criteria", icon: CheckCircle2 },
  { id: "FINAL_AUDIT_SUMMARY", label: "15. Final Audit Summary", description: "Verify cryptographic SHA-256 chained audit integrity", icon: FileText },
];

export const PipelineExecutionView: React.FC<PipelineExecutionViewProps> = ({
  executionId,
  onNavigateToTab,
  onBackToList,
}) => {
  const [execution, setExecution] = useState<OrchestrationExecutionResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isResuming, setIsResuming] = useState(false);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const pollingRef = useRef<NodeJS.Timeout | null>(null);

  const fetchExecution = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const data = await api.orchestration.getPipeline(executionId);
      setExecution(data);
      setError(null);
    } catch (err: any) {
      console.error("Failed to load pipeline execution:", err);
      setError(err?.message || "Failed to load execution status.");
    } finally {
      if (!silent) setLoading(false);
    }
  }, [executionId]);

  useEffect(() => {
    fetchExecution();

    // Auto-poll if running or waiting
    pollingRef.current = setInterval(() => {
      fetchExecution(true);
    }, 2500);

    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [fetchExecution]);

  // Handle Resume
  const handleResume = async () => {
    setIsResuming(true);
    setActionSuccess(null);
    setError(null);
    try {
      const resumed = await api.orchestration.resumePipeline(executionId);
      setExecution(resumed);
      setActionSuccess("Pipeline execution successfully resumed!");
    } catch (err: any) {
      console.error("Failed to resume pipeline:", err);
      setError(err?.message || "Failed to resume pipeline execution.");
    } finally {
      setIsResuming(false);
    }
  };

  if (loading && !execution) {
    return (
      <div className="flex h-96 items-center justify-center rounded-xl border border-[#1a2744] bg-[#070e22]">
        <div className="flex flex-col items-center gap-3">
          <Clock className="h-8 w-8 animate-spin text-cyan-400" />
          <span className="text-xs text-slate-400">Loading orchestration pipeline telemetry...</span>
        </div>
      </div>
    );
  }

  if (!execution) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-6 text-center">
        <AlertTriangle className="mx-auto h-8 w-8 text-red-400 mb-2" />
        <p className="text-sm font-semibold text-white">Pipeline Execution Not Found</p>
        <p className="text-xs text-slate-400 mt-1">{error || "Could not retrieve execution data."}</p>
        {onBackToList && (
          <button
            onClick={onBackToList}
            className="mt-4 px-4 py-2 rounded-lg bg-slate-800 text-xs font-semibold text-slate-200 hover:bg-slate-700"
          >
            Back to Executions List
          </button>
        )}
      </div>
    );
  }

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case "completed":
        return "bg-emerald-950 text-emerald-300 border-emerald-500/40";
      case "running":
        return "bg-cyan-950 text-cyan-300 border-cyan-500/40 animate-pulse";
      case "waiting_for_approval":
        return "bg-amber-950 text-amber-300 border-amber-500/40 animate-pulse";
      case "failed":
        return "bg-red-950 text-red-300 border-red-500/40";
      case "partial_failure":
        return "bg-orange-950 text-orange-300 border-orange-500/40";
      case "cancelled":
        return "bg-slate-900 text-slate-400 border-slate-700";
      default:
        return "bg-slate-900 text-slate-400 border-slate-800";
    }
  };

  const getStageStatus = (stageId: PipelineStage) => {
    const metric = execution.stage_metrics?.[stageId];
    if (metric) {
      return metric.status;
    }
    // Determine status from current stage
    if (execution.current_stage === stageId) {
      if (execution.execution_status === "failed") return "failed";
      if (execution.execution_status === "waiting_for_approval") return "waiting_for_approval";
      return "in_progress";
    }
    if (execution.failed_stage === stageId) return "failed";
    return "pending";
  };

  const isResumable =
    execution.execution_status === PipelineExecutionStatus.WAITING_FOR_APPROVAL ||
    execution.is_resumable;

  return (
    <div className="space-y-6">
      {/* Top Banner & Execution Meta */}
      <div className="rounded-xl border border-[#1a2744] bg-[#070e22] p-5 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-950 border border-cyan-500/40 text-cyan-400">
              <Activity className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-base font-bold text-white tracking-wide">
                  Unified Pipeline Execution
                </h1>
                <span
                  className={`rounded-full px-2.5 py-0.5 text-[10px] font-mono uppercase tracking-wider border font-bold ${getStatusBadge(
                    execution.execution_status
                  )}`}
                >
                  {execution.execution_status.replace(/_/g, " ")}
                </span>
                <span className="rounded bg-cyan-950/80 px-2 py-0.5 text-[10px] font-mono text-cyan-300 border border-cyan-800/60">
                  SYNTHETIC SIMULATION
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 mt-1 font-mono">
                <span>ID: {execution.id}</span>
                <span>•</span>
                <span>Sandbox: {execution.sandbox_id.slice(0, 8)}</span>
                <span>•</span>
                <span>Started: {new Date(execution.started_at).toLocaleTimeString()}</span>
                {execution.completed_at && (
                  <>
                    <span>•</span>
                    <span>Completed: {new Date(execution.completed_at).toLocaleTimeString()}</span>
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start md:self-auto">
            {isResumable && (
              <button
                onClick={handleResume}
                disabled={isResuming}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 text-xs font-semibold text-white hover:bg-emerald-500 transition-colors shadow-md shadow-emerald-950"
              >
                {isResuming ? (
                  <Clock className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Play className="h-3.5 w-3.5" />
                )}
                <span>Resume Pipeline</span>
              </button>
            )}

            <button
              onClick={() => fetchExecution()}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-[#1a2744] bg-[#0b1329] text-xs font-semibold text-slate-300 hover:bg-slate-800 transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              <span>Refresh</span>
            </button>

            {onBackToList && (
              <button
                onClick={onBackToList}
                className="px-3 py-2 rounded-lg border border-[#1a2744] text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                Back
              </button>
            )}
          </div>
        </div>

        {/* Action Alerts */}
        {actionSuccess && (
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-950/40 p-3 text-xs text-emerald-200">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <span>{actionSuccess}</span>
          </div>
        )}

        {error && (
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-950/40 p-3 text-xs text-red-200">
            <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {execution.error_message && (
          <div className="mt-4 rounded-lg border border-red-500/40 bg-red-950/30 p-3.5 text-xs text-red-200">
            <div className="flex items-center gap-2 font-semibold text-red-300 mb-1">
              <XCircle className="h-4 w-4 text-red-400" />
              <span>Pipeline Stage Failure at: {execution.failed_stage || execution.current_stage}</span>
            </div>
            <p className="font-mono text-[11px] text-red-300/90 pl-6">{execution.error_message}</p>
          </div>
        )}

        {/* Human Approval Notice Banner */}
        {execution.execution_status === "waiting_for_approval" && (
          <div className="mt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-lg border border-amber-500/40 bg-amber-950/30 p-4">
            <div className="flex items-start gap-3">
              <UserCheck className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-xs font-bold text-amber-200">
                  Pipeline Paused: Human-in-the-Loop Signoff Required
                </h4>
                <p className="text-[11px] text-amber-300/80 mt-0.5">
                  Remediation Plan has been synthesized. According to Four-Eyes Security Policy, independent
                  approver signatures are required before synthetic countermeasure execution.
                </p>
              </div>
            </div>
            {onNavigateToTab && (
              <button
                onClick={() => onNavigateToTab("response_center")}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-600 text-xs font-semibold text-black hover:bg-amber-500 transition-colors shrink-0 font-sans"
              >
                <span>Go to Approval Center</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        )}
      </div>

      {/* Linked Platform Entities */}
      <div className="rounded-xl border border-[#1a2744] bg-[#070e22] p-4">
        <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
          Persisted Multi-Agent Entity Linkages
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2.5">
          <div className="rounded-lg border border-[#1a2744] bg-[#050914] p-2.5">
            <span className="text-[10px] text-slate-500 block uppercase font-mono">Red Team Run</span>
            <span className="text-xs font-mono font-medium text-cyan-300 truncate block mt-0.5">
              {execution.simulation_id ? execution.simulation_id.slice(0, 8) : "—"}
            </span>
          </div>

          <div className="rounded-lg border border-[#1a2744] bg-[#050914] p-2.5">
            <span className="text-[10px] text-slate-500 block uppercase font-mono">Attack Path</span>
            <span className="text-xs font-mono font-medium text-cyan-300 truncate block mt-0.5">
              {execution.attack_path_id ? execution.attack_path_id.slice(0, 8) : "—"}
            </span>
          </div>

          <div className="rounded-lg border border-[#1a2744] bg-[#050914] p-2.5">
            <span className="text-[10px] text-slate-500 block uppercase font-mono">Guardian Exec</span>
            <span className="text-xs font-mono font-medium text-cyan-300 truncate block mt-0.5">
              {execution.guardian_execution_id ? execution.guardian_execution_id.slice(0, 8) : "—"}
            </span>
          </div>

          <div className="rounded-lg border border-[#1a2744] bg-[#050914] p-2.5">
            <span className="text-[10px] text-slate-500 block uppercase font-mono">Remediation Plan</span>
            <span className="text-xs font-mono font-medium text-cyan-300 truncate block mt-0.5">
              {execution.remediation_plan_id ? execution.remediation_plan_id.slice(0, 8) : "—"}
            </span>
          </div>

          <div className="rounded-lg border border-[#1a2744] bg-[#050914] p-2.5">
            <span className="text-[10px] text-slate-500 block uppercase font-mono">Approval Req</span>
            <span className="text-xs font-mono font-medium text-cyan-300 truncate block mt-0.5">
              {execution.approval_request_id ? execution.approval_request_id.slice(0, 8) : "—"}
            </span>
          </div>

          <div className="rounded-lg border border-[#1a2744] bg-[#050914] p-2.5">
            <span className="text-[10px] text-slate-500 block uppercase font-mono">Remediation Exec</span>
            <span className="text-xs font-mono font-medium text-cyan-300 truncate block mt-0.5">
              {execution.synthetic_execution_id ? execution.synthetic_execution_id.slice(0, 8) : "—"}
            </span>
          </div>

          <div className="rounded-lg border border-[#1a2744] bg-[#050914] p-2.5">
            <span className="text-[10px] text-slate-500 block uppercase font-mono">Verification ID</span>
            <span className="text-xs font-mono font-medium text-cyan-300 truncate block mt-0.5">
              {execution.verification_id ? execution.verification_id.slice(0, 8) : "—"}
            </span>
          </div>
        </div>
      </div>

      {/* 15 Sequential Stages Grid & Timeline */}
      <div className="rounded-xl border border-[#1a2744] bg-[#070e22] p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-bold text-white tracking-wide">
              15-Stage Platform Orchestration Timeline
            </h2>
            <p className="text-xs text-slate-400">
              Deterministic, real-time stage execution tracked with cryptographic state integrity.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Current: <strong className="text-cyan-300">{execution.current_stage}</strong>
          </span>
        </div>

        <div className="space-y-3">
          {ORDERED_STAGES.map((stage, idx) => {
            const status = getStageStatus(stage.id);
            const metric = execution.stage_metrics?.[stage.id];
            const Icon = stage.icon;

            const isCurrent = execution.current_stage === stage.id;
            const isCompleted = status === "completed";
            const isFailed = status === "failed";
            const isWaiting = status === "waiting_for_approval";
            const isInProgress = status === "in_progress" || isCurrent;

            return (
              <div
                key={stage.id}
                className={`flex flex-col sm:flex-row sm:items-center justify-between p-3.5 rounded-xl border transition-all ${
                  isCompleted
                    ? "border-emerald-500/20 bg-emerald-950/10"
                    : isFailed
                    ? "border-red-500/30 bg-red-950/20"
                    : isWaiting
                    ? "border-amber-500/40 bg-amber-950/20 shadow-md shadow-amber-950/30"
                    : isInProgress
                    ? "border-cyan-500/40 bg-cyan-950/20 shadow-md shadow-cyan-950/30"
                    : "border-[#1a2744]/60 bg-[#060b18]/60 opacity-60"
                }`}
              >
                <div className="flex items-center gap-3.5">
                  <div
                    className={`flex h-8 w-8 items-center justify-center rounded-lg border shrink-0 ${
                      isCompleted
                        ? "border-emerald-500/40 bg-emerald-950 text-emerald-400"
                        : isFailed
                        ? "border-red-500/40 bg-red-950 text-red-400"
                        : isWaiting
                        ? "border-amber-500/40 bg-amber-950 text-amber-400"
                        : isInProgress
                        ? "border-cyan-500/40 bg-cyan-950 text-cyan-400 animate-pulse"
                        : "border-slate-800 bg-slate-900 text-slate-500"
                    }`}
                  >
                    {isCompleted ? (
                      <CheckCircle2 className="h-4 w-4" />
                    ) : isFailed ? (
                      <XCircle className="h-4 w-4" />
                    ) : isInProgress ? (
                      <Clock className="h-4 w-4 animate-spin" />
                    ) : (
                      <Icon className="h-4 w-4" />
                    )}
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-white tracking-wide">{stage.label}</span>
                      <span className="text-[10px] font-mono text-slate-500">[{stage.id}]</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5">{stage.description}</p>
                  </div>
                </div>

                <div className="flex items-center gap-4 mt-2 sm:mt-0 font-mono text-xs">
                  {metric?.duration_seconds !== undefined && (
                    <span className="text-slate-400">
                      Duration: <strong className="text-white">{metric.duration_seconds}s</strong>
                    </span>
                  )}

                  {metric?.completed_at && (
                    <span className="text-slate-500 text-[10px] hidden md:inline">
                      {new Date(metric.completed_at).toLocaleTimeString()}
                    </span>
                  )}

                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border ${
                      isCompleted
                        ? "bg-emerald-950/80 text-emerald-300 border-emerald-800/60"
                        : isFailed
                        ? "bg-red-950/80 text-red-300 border-red-800/60"
                        : isWaiting
                        ? "bg-amber-950/80 text-amber-300 border-amber-800/60"
                        : isInProgress
                        ? "bg-cyan-950/80 text-cyan-300 border-cyan-800/60 animate-pulse"
                        : "bg-slate-900 text-slate-500 border-slate-800"
                    }`}
                  >
                    {status.replace(/_/g, " ")}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

