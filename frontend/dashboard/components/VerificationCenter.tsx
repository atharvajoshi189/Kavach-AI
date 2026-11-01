"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import {
  RemediationVerificationSummaryResponse,
  SyntheticSnapshotComparisonResponse,
  SyntheticRemediationExecutionResponse,
} from "../lib/types";
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Layers,
  ShieldCheck,
  RefreshCw,
  FileCheck,
  Hash,
  Database,
  ArrowRight,
  HelpCircle,
} from "lucide-react";

interface VerificationCenterProps {
  initialExecutionId?: string;
}

export const VerificationCenter: React.FC<VerificationCenterProps> = ({ initialExecutionId }) => {
  const { activeSandbox } = useAuth();
  const [executions, setExecutions] = useState<SyntheticRemediationExecutionResponse[]>([]);
  const [selectedExecId, setSelectedExecId] = useState<string | null>(initialExecutionId || null);

  const [verification, setVerification] = useState<RemediationVerificationSummaryResponse | null>(null);
  const [snapshots, setSnapshots] = useState<SyntheticSnapshotComparisonResponse | null>(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 1. Fetch available remediation executions
  const fetchExecutions = useCallback(async () => {
    if (!activeSandbox) {
      setLoading(false);
      return;
    }
    try {
      const res = await api.approval.listRemediationExecutions({
        sandbox_id: activeSandbox.id,
        page_size: 50,
      });
      setExecutions(res.items || []);
      if (res.items && res.items.length > 0) {
        if (!selectedExecId || !res.items.some((e) => e.id === selectedExecId)) {
          setSelectedExecId(res.items[0].id);
        }
      }
    } catch (e: any) {
      console.error("Failed to load executions list for verification:", e);
    }
  }, [activeSandbox, selectedExecId]);

  useEffect(() => {
    fetchExecutions();
  }, [fetchExecutions]);

  // 2. Fetch Verification and Snapshots for selected execution
  const fetchVerificationDetails = useCallback(async (execId: string, silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);
    setError(null);

    try {
      const [vRes, sRes] = await Promise.all([
        api.approval.getRemediationVerification(execId).catch(() => null),
        api.approval.getRemediationSnapshots(execId).catch(() => null),
      ]);
      setVerification(vRes);
      setSnapshots(sRes);
    } catch (err: any) {
      console.error("Failed to fetch verification details:", err);
      setError(err?.message || "Failed to load verification comparison data.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (selectedExecId) {
      fetchVerificationDetails(selectedExecId);
    } else {
      setVerification(null);
      setSnapshots(null);
      setLoading(false);
    }
  }, [selectedExecId, fetchVerificationDetails]);

  const getStatusBadge = (status: string) => {
    switch (status?.toUpperCase()) {
      case "PASSED":
        return "bg-emerald-950 text-emerald-300 border-emerald-800";
      case "PARTIALLY_PASSED":
        return "bg-amber-950 text-amber-300 border-amber-800";
      case "FAILED":
        return "bg-red-950 text-red-300 border-red-800";
      case "INCONCLUSIVE":
        return "bg-purple-950 text-purple-300 border-purple-800";
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
            <FileCheck className="h-5 w-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white tracking-wide">
              Regression Verification & State Snapshot Center
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic BEFORE and AFTER state differentials with deterministic compliance evaluation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {executions.length > 0 && (
            <select
              value={selectedExecId || ""}
              onChange={(e) => setSelectedExecId(e.target.value)}
              className="rounded-lg border border-[#1a2744] bg-[#070e22] px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-cyan-500"
            >
              {executions.map((ex) => (
                <option key={ex.id} value={ex.id}>
                  Exec: {ex.id.slice(0, 8)} ({ex.execution_status})
                </option>
              ))}
            </select>
          )}

          <button
            onClick={() => selectedExecId && fetchVerificationDetails(selectedExecId, true)}
            disabled={refreshing || !selectedExecId}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1a2744] bg-[#070e22] text-xs font-semibold text-slate-300 hover:bg-slate-800 transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-950/40 p-3 text-xs text-red-200">
          <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="flex h-64 items-center justify-center rounded-xl border border-[#1a2744] bg-[#070e22]">
          <Clock className="h-6 w-6 animate-spin text-cyan-400" />
        </div>
      ) : !verification && !snapshots ? (
        <div className="rounded-xl border border-[#1a2744] bg-[#070e22] p-8 text-center text-xs text-slate-400">
          No verification records found for the selected execution.
        </div>
      ) : (
        <div className="space-y-6">
          {/* Overall Verification Status Banner */}
          {verification && (
            <div
              className={`rounded-xl border p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 ${
                verification.overall_status === "PASSED"
                  ? "border-emerald-500/30 bg-emerald-950/20"
                  : verification.overall_status === "PARTIALLY_PASSED"
                  ? "border-amber-500/30 bg-amber-950/20"
                  : verification.overall_status === "INCONCLUSIVE"
                  ? "border-purple-500/30 bg-purple-950/20"
                  : "border-red-500/30 bg-red-950/20"
              }`}
            >
              <div className="flex items-center gap-3.5">
                <div
                  className={`flex h-10 w-10 items-center justify-center rounded-xl border ${
                    verification.overall_status === "PASSED"
                      ? "border-emerald-500/50 bg-emerald-950 text-emerald-400"
                      : verification.overall_status === "PARTIALLY_PASSED"
                      ? "border-amber-500/50 bg-amber-950 text-amber-400"
                      : verification.overall_status === "INCONCLUSIVE"
                      ? "border-purple-500/50 bg-purple-950 text-purple-400"
                      : "border-red-500/50 bg-red-950 text-red-400"
                  }`}
                >
                  {verification.overall_status === "PASSED" ? (
                    <CheckCircle2 className="h-5 w-5" />
                  ) : verification.overall_status === "INCONCLUSIVE" ? (
                    <HelpCircle className="h-5 w-5" />
                  ) : (
                    <XCircle className="h-5 w-5" />
                  )}
                </div>

                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-white tracking-wide">
                      Overall Regression Verification Status:
                    </span>
                    <span
                      className={`rounded px-2.5 py-0.5 text-xs font-mono font-bold uppercase tracking-wider border ${getStatusBadge(
                        verification.overall_status
                      )}`}
                    >
                      {verification.overall_status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-0.5">
                    Evaluated against actual before-and-after state differential evidence.
                  </p>
                </div>
              </div>

              {/* Counts */}
              <div className="flex items-center gap-4 font-mono text-xs">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Passed</span>
                  <span className="text-emerald-400 font-bold text-sm">{verification.passed_checks}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Failed</span>
                  <span className="text-red-400 font-bold text-sm">{verification.failed_checks}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Inconclusive</span>
                  <span className="text-purple-400 font-bold text-sm">{verification.inconclusive_checks}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Total</span>
                  <span className="text-white font-bold text-sm">{verification.total_checks}</span>
                </div>
              </div>
            </div>
          )}

          {/* Cryptographic Snapshots Side-by-Side */}
          {snapshots && (
            <div className="rounded-xl border border-[#1a2744] bg-[#070e22] p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                    <Database className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Cryptographic State Snapshots</span>
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Deterministic SHA-256 state hashing captured immediately before and after execution.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Before Snapshot */}
                <div className="rounded-lg border border-[#1a2744] bg-[#050914] p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-300">BEFORE SNAPSHOT</span>
                    <span className="font-mono text-[10px] text-slate-500">
                      {snapshots.before_snapshot?.captured_at
                        ? new Date(snapshots.before_snapshot.captured_at).toLocaleTimeString()
                        : "N/A"}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px] font-mono text-cyan-400/90 truncate">
                    <Hash className="h-3 w-3 shrink-0 text-cyan-400" />
                    <span className="truncate">
                      SHA: {snapshots.before_snapshot?.sha256_hash || "None recorded"}
                    </span>
                  </div>
                  <pre className="text-[10px] font-mono text-slate-300 bg-[#070c1a] p-2.5 rounded border border-[#1a2744]/70 max-h-36 overflow-y-auto">
                    {JSON.stringify(snapshots.before_snapshot?.asset_states || {}, null, 2)}
                  </pre>
                </div>

                {/* After Snapshot */}
                <div className="rounded-lg border border-[#1a2744] bg-[#050914] p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-300">AFTER SNAPSHOT</span>
                    <span className="font-mono text-[10px] text-slate-500">
                      {snapshots.after_snapshot?.captured_at
                        ? new Date(snapshots.after_snapshot.captured_at).toLocaleTimeString()
                        : "N/A"}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-400/90 truncate">
                    <Hash className="h-3 w-3 shrink-0 text-emerald-400" />
                    <span className="truncate">
                      SHA: {snapshots.after_snapshot?.sha256_hash || "None recorded"}
                    </span>
                  </div>
                  <pre className="text-[10px] font-mono text-slate-300 bg-[#070c1a] p-2.5 rounded border border-[#1a2744]/70 max-h-36 overflow-y-auto">
                    {JSON.stringify(snapshots.after_snapshot?.asset_states || {}, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {/* Verification Criteria Checks Feed */}
          {verification && verification.check_details && (
            <div className="rounded-xl border border-[#1a2744] bg-[#070e22] p-5 space-y-4">
              <div>
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                  Action-by-Action Criteria Verification Details
                </h3>
                <p className="text-[11px] text-slate-400">
                  Each action criteria evaluated against actual state before and after execution.
                </p>
              </div>

              <div className="space-y-3">
                {verification.check_details.map((check, idx) => (
                  <div
                    key={idx}
                    className="rounded-lg border border-[#1a2744] bg-[#050914] p-4 space-y-3 text-xs"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-cyan-400 font-bold">{check.action_code}</span>
                        <span className="text-white font-semibold">{check.title}</span>
                      </div>

                      <span
                        className={`rounded px-2 py-0.5 text-[10px] font-bold font-mono uppercase border ${getStatusBadge(
                          check.status
                        )}`}
                      >
                        {check.status}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                      <div className="rounded bg-[#070c1a] p-2.5 border border-[#1a2744]/60">
                        <span className="text-slate-500 block uppercase text-[9px] font-mono">Expected Condition</span>
                        <span className="text-slate-300 font-mono mt-0.5 block">{check.expected_condition}</span>
                      </div>

                      <div className="rounded bg-[#070c1a] p-2.5 border border-[#1a2744]/60">
                        <span className="text-slate-500 block uppercase text-[9px] font-mono">Actual Condition</span>
                        <span className="text-slate-300 font-mono mt-0.5 block">{check.actual_condition}</span>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-400 font-mono pt-1 border-t border-[#1a2744]/40">
                      <span>Before Value: <strong className="text-slate-300">{JSON.stringify(check.before_value)}</strong></span>
                      <span>•</span>
                      <span>After Value: <strong className="text-emerald-300">{JSON.stringify(check.after_value)}</strong></span>
                    </div>

                    {check.failure_reason && (
                      <div className="text-[11px] text-red-300 bg-red-950/30 p-2 rounded border border-red-900/40">
                        Failure Rationale: {check.failure_reason}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

