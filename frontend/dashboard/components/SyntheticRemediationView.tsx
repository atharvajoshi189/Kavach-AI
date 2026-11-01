"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import { SyntheticRemediationExecutionResponse } from "../lib/types";
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  RefreshCw,
  Cpu,
  Layers,
  ArrowRight,
  Info,
} from "lucide-react";

interface SyntheticRemediationViewProps {
  initialExecutionId?: string;
  onNavigateToVerification?: (executionId: string) => void;
}

export const SyntheticRemediationView: React.FC<SyntheticRemediationViewProps> = ({
  initialExecutionId,
  onNavigateToVerification,
}) => {
  const { activeSandbox } = useAuth();
  const [executions, setExecutions] = useState<SyntheticRemediationExecutionResponse[]>([]);
  const [selectedExec, setSelectedExec] = useState<SyntheticRemediationExecutionResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchExecutions = useCallback(async (silent = false) => {
    if (!activeSandbox) {
      setLoading(false);
      return;
    }
    if (!silent) setLoading(true);
    else setRefreshing(true);
    setError(null);

    try {
      const res = await api.approval.listRemediationExecutions({
        sandbox_id: activeSandbox.id,
        page_size: 50,
      });
      setExecutions(res.items || []);
      if (res.items && res.items.length > 0) {
        if (initialExecutionId) {
          const match = res.items.find((e) => e.id === initialExecutionId);
          setSelectedExec(match || res.items[0]);
        } else if (!selectedExec || !res.items.some((e) => e.id === selectedExec.id)) {
          setSelectedExec(res.items[0]);
        } else {
          const updated = res.items.find((e) => e.id === selectedExec.id);
          if (updated) setSelectedExec(updated);
        }
      } else {
        setSelectedExec(null);
      }
    } catch (err: any) {
      console.error("Failed to load remediation executions:", err);
      setError(err?.message || "Failed to load remediation executions.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [activeSandbox, initialExecutionId, selectedExec]);

  useEffect(() => {
    fetchExecutions();
  }, [activeSandbox]);

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case "completed":
        return "bg-emerald-950 text-emerald-300 border-emerald-800";
      case "executing":
        return "bg-cyan-950 text-cyan-300 border-cyan-800 animate-pulse";
      case "verifying":
        return "bg-blue-950 text-blue-300 border-blue-800 animate-pulse";
      case "partial_failure":
        return "bg-orange-950 text-orange-300 border-orange-800";
      case "failed":
        return "bg-red-950 text-red-300 border-red-800";
      default:
        return "bg-slate-900 text-slate-400 border-slate-800";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#1a2744] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white tracking-wide">
              Synthetic Sandbox Remediation Engine
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Deterministic execution of allowlisted synthetic countermeasure handlers in isolated sandboxes.
          </p>
        </div>

        <button
          onClick={() => fetchExecutions(true)}
          disabled={refreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1a2744] bg-[#070e22] text-xs font-semibold text-slate-300 hover:bg-slate-800 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
          <span>Refresh Executions</span>
        </button>
      </div>

      {/* Safety Invariant Notice */}
      <div className="flex items-start gap-3 rounded-xl border border-cyan-500/30 bg-cyan-950/20 p-4 text-xs text-cyan-200">
        <Info className="h-4 w-4 shrink-0 text-cyan-400 mt-0.5" />
        <div>
          <span className="font-bold text-white">Synthetic-Only Execution Guarantee: </span>
          Remediation actions are strictly simulated against synthetic asset state records in PostgreSQL.
          No production servers, endpoints, operating system files, or firewalls are ever contacted or modified.
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-950/40 p-3 text-xs text-red-200">
          <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Content Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left List of Executions */}
        <div className="lg:col-span-4 space-y-3">
          <div className="text-xs font-semibold text-slate-400 px-1">
            REMEDIATION EXECUTIONS ({executions.length})
          </div>

          {loading ? (
            <div className="flex h-64 items-center justify-center rounded-xl border border-[#1a2744] bg-[#070e22]">
              <Clock className="h-6 w-6 animate-spin text-cyan-400" />
            </div>
          ) : executions.length === 0 ? (
            <div className="rounded-xl border border-[#1a2744] bg-[#070e22] p-8 text-center text-xs text-slate-400">
              No synthetic remediation executions found in this sandbox.
            </div>
          ) : (
            <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
              {executions.map((ex) => {
                const isSelected = selectedExec?.id === ex.id;
                return (
                  <button
                    key={ex.id}
                    onClick={() => setSelectedExec(ex)}
                    className={`w-full text-left p-3.5 rounded-xl border transition-all ${
                      isSelected
                        ? "border-cyan-500 bg-cyan-950/30 shadow-md shadow-cyan-950/50"
                        : "border-[#1a2744] bg-[#070e22] hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-white">
                        {ex.id.slice(0, 8)}...
                      </span>
                      <span
                        className={`rounded px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider border font-mono ${getStatusBadge(
                          ex.execution_status
                        )}`}
                      >
                        {ex.execution_status.replace(/_/g, " ")}
                      </span>
                    </div>

                    <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                      <span>Actions: {ex.execution_metadata?.actions_succeeded || 0} / {ex.execution_metadata?.actions_total || 0}</span>
                      <span className="font-mono text-[10px]">
                        {new Date(ex.started_at).toLocaleTimeString()}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Detail Pane */}
        <div className="lg:col-span-8">
          {selectedExec ? (
            <div className="rounded-xl border border-[#1a2744] bg-[#070e22] p-6 space-y-6">
              {/* Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1a2744] pb-4">
                <div>
                  <h3 className="text-sm font-bold text-white">
                    Synthetic Execution: {selectedExec.id}
                  </h3>
                  <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 mt-1 font-mono">
                    <span>Plan ID: {selectedExec.remediation_plan_id.slice(0, 8)}</span>
                    <span>•</span>
                    <span>Approval ID: {selectedExec.approval_request_id.slice(0, 8)}</span>
                    <span>•</span>
                    <span>Started: {new Date(selectedExec.started_at).toLocaleTimeString()}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span
                    className={`rounded px-2.5 py-1 text-xs font-bold font-mono uppercase tracking-wider border ${getStatusBadge(
                      selectedExec.execution_status
                    )}`}
                  >
                    {selectedExec.execution_status.replace(/_/g, " ")}
                  </span>
                </div>
              </div>

              {/* Execution Metrics Summary */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="rounded-lg border border-[#1a2744] bg-[#050914] p-3">
                  <span className="text-[10px] text-slate-500 uppercase block font-mono">Total Actions</span>
                  <span className="text-base font-bold text-white font-mono mt-0.5 block">
                    {selectedExec.execution_metadata?.actions_total || 0}
                  </span>
                </div>

                <div className="rounded-lg border border-emerald-500/20 bg-emerald-950/20 p-3">
                  <span className="text-[10px] text-emerald-400 uppercase block font-mono">Succeeded</span>
                  <span className="text-base font-bold text-emerald-300 font-mono mt-0.5 block">
                    {selectedExec.execution_metadata?.actions_succeeded || 0}
                  </span>
                </div>

                <div className="rounded-lg border border-red-500/20 bg-red-950/20 p-3">
                  <span className="text-[10px] text-red-400 uppercase block font-mono">Failed</span>
                  <span className="text-base font-bold text-red-300 font-mono mt-0.5 block">
                    {selectedExec.execution_metadata?.actions_failed || 0}
                  </span>
                </div>

                <div className="rounded-lg border border-slate-700 bg-slate-900/40 p-3">
                  <span className="text-[10px] text-slate-400 uppercase block font-mono">Skipped</span>
                  <span className="text-base font-bold text-slate-300 font-mono mt-0.5 block">
                    {selectedExec.execution_metadata?.actions_skipped?.length || 0}
                  </span>
                </div>
              </div>

              {/* Action-by-Action Breakdown */}
              <div>
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
                  Allowlisted Handlers Execution Feed
                </h4>

                {selectedExec.execution_metadata?.action_results ? (
                  <div className="space-y-2">
                    {Object.entries(selectedExec.execution_metadata.action_results).map(
                      ([actionCode, res]: [string, any]) => {
                        const isSuccess = res.success === true;
                        const isSkipped = res.skipped === true;

                        return (
                          <div
                            key={actionCode}
                            className={`rounded-lg border p-3.5 text-xs transition-all ${
                              isSuccess
                                ? "border-emerald-500/20 bg-emerald-950/10"
                                : isSkipped
                                ? "border-slate-800 bg-slate-900/30 text-slate-400"
                                : "border-red-500/30 bg-red-950/20"
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2.5">
                                {isSuccess ? (
                                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                                ) : isSkipped ? (
                                  <Clock className="h-4 w-4 text-slate-500 shrink-0" />
                                ) : (
                                  <XCircle className="h-4 w-4 text-red-400 shrink-0" />
                                )}
                                <span className="font-mono font-bold text-white text-xs">
                                  {actionCode}
                                </span>
                              </div>

                              <span
                                className={`rounded px-2 py-0.5 text-[9px] font-bold font-mono uppercase border ${
                                  isSuccess
                                    ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                                    : isSkipped
                                    ? "bg-slate-900 text-slate-400 border-slate-700"
                                    : "bg-red-950 text-red-300 border-red-800"
                                }`}
                              >
                                {isSuccess ? "Applied" : isSkipped ? "Skipped (Deps)" : "Failed"}
                              </span>
                            </div>

                            {/* Applied Changes or Failure Reason */}
                            {res.applied_changes && (
                              <div className="mt-2 text-[11px] font-mono text-emerald-300 bg-emerald-950/30 p-2 rounded border border-emerald-900/40">
                                Applied: {JSON.stringify(res.applied_changes)}
                              </div>
                            )}

                            {res.reason && (
                              <div className="mt-2 text-[11px] text-slate-400 italic">
                                {res.reason}
                              </div>
                            )}

                            {res.error && (
                              <div className="mt-2 text-[11px] font-mono text-red-300 bg-red-950/40 p-2 rounded border border-red-900/50">
                                Error: {res.error}
                              </div>
                            )}
                          </div>
                        );
                      }
                    )}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic">No action results recorded.</p>
                )}
              </div>

              {/* Navigation to Verification */}
              {onNavigateToVerification && (
                <div className="flex justify-end pt-4 border-t border-[#1a2744]">
                  <button
                    onClick={() => onNavigateToVerification(selectedExec.id)}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors shadow-md shadow-cyan-950"
                  >
                    <span>View Before/After Verification & Snapshots</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="flex h-96 items-center justify-center rounded-xl border border-[#1a2744] bg-[#070e22] text-xs text-slate-400">
              Select an execution to inspect action-by-action results.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

