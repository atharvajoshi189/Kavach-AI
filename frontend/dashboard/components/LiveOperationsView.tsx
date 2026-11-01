"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import { OrchestrationExecutionResponse } from "../lib/types";
import {
  Activity,
  Play,
  RefreshCw,
  CheckCircle2,
  Clock,
  XCircle,
  AlertTriangle,
  Layers,
  ChevronRight,
  ArrowLeft,
  Cpu,
} from "lucide-react";
import { PipelineExecutionView } from "./PipelineExecutionView";
import { PipelineControlModal } from "./PipelineControlModal";

interface LiveOperationsViewProps {
  onNavigateToTab?: (tab: string) => void;
}

export const LiveOperationsView: React.FC<LiveOperationsViewProps> = ({ onNavigateToTab }) => {
  const { activeSandbox } = useAuth();
  const [pipelines, setPipelines] = useState<OrchestrationExecutionResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [inspectingId, setInspectingId] = useState<string | null>(null);
  const [isStartModalOpen, setIsStartModalOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchPipelines = useCallback(async (silent = false) => {
    if (!activeSandbox) {
      setLoading(false);
      return;
    }
    if (!silent) setLoading(true);
    else setRefreshing(true);
    setError(null);

    try {
      const res = await api.orchestration.listPipelines({
        sandbox_id: activeSandbox.id,
        page_size: 50,
      });
      setPipelines(res.items || []);
    } catch (err: any) {
      setError(err?.message || "Failed to load live pipeline executions");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [activeSandbox]);

  useEffect(() => {
    fetchPipelines();
    const interval = setInterval(() => fetchPipelines(true), 10000);
    return () => clearInterval(interval);
  }, [fetchPipelines]);

  if (inspectingId) {
    return (
      <div className="space-y-4">
        <button
          onClick={() => setInspectingId(null)}
          className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-mono transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to Live Operations Pipeline List</span>
        </button>
        <PipelineExecutionView
          executionId={inspectingId}
          onBackToList={() => setInspectingId(null)}
          onNavigateToTab={onNavigateToTab as any}
        />
      </div>
    );
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "COMPLETED":
        return "bg-emerald-950 text-emerald-300 border-emerald-800";
      case "RUNNING":
        return "bg-cyan-950 text-cyan-300 border-cyan-800 animate-pulse";
      case "WAITING_FOR_APPROVAL":
        return "bg-amber-950 text-amber-300 border-amber-800";
      case "FAILED":
        return "bg-rose-950 text-rose-300 border-rose-800";
      default:
        return "bg-slate-900 text-slate-400 border-slate-800";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between border-b border-[#1a2744] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white tracking-wide">Live Operations Control</h1>
            <span className="rounded bg-cyan-950/80 px-2 py-0.5 text-xs font-mono text-cyan-400 border border-cyan-800/60">
              15-STAGE STATE MACHINE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time multi-agent autonomous security pipeline coordinator across simulation, guardian defense, approvals, and verification.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchPipelines(false)}
            disabled={refreshing || loading}
            className="flex items-center gap-1.5 rounded-lg border border-[#1a2744] bg-[#0c1222] px-3 py-1.5 text-xs text-slate-300 hover:text-white"
          >
            <RefreshCw className={`h-3.5 w-3.5 text-cyan-400 ${refreshing ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={() => setIsStartModalOpen(true)}
            disabled={!activeSandbox}
            className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors shadow-sm disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            <span>Start New Pipeline</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-900/60 bg-rose-950/20 p-4 text-xs text-rose-300 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Pipeline Executions Table */}
      <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-5 space-y-4 shadow-sm">
        <div className="flex items-center justify-between border-b border-[#1a2744] pb-3">
          <span className="text-sm font-bold text-white flex items-center gap-2">
            <Activity className="h-4 w-4 text-cyan-400" />
            <span>Pipeline Execution History ({pipelines.length})</span>
          </span>
          <span className="text-xs text-slate-400 font-mono">
            Scope: {activeSandbox?.name || "Global"}
          </span>
        </div>

        {pipelines.length === 0 ? (
          <div className="py-16 text-center text-xs text-slate-500 space-y-2">
            <Cpu className="h-8 w-8 text-slate-600 mx-auto" />
            <p className="font-semibold text-slate-300">No Pipeline Executions Found</p>
            <p className="text-slate-500">
              Click &quot;Start New Pipeline&quot; above to trigger an autonomous 15-stage security lifecycle run.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#1a2744] text-[10px] font-mono uppercase text-slate-400">
                  <th className="pb-2.5">Execution ID</th>
                  <th className="pb-2.5">Current Stage</th>
                  <th className="pb-2.5">Status</th>
                  <th className="pb-2.5">Started At</th>
                  <th className="pb-2.5">Completed At</th>
                  <th className="pb-2.5 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1a2744]/60">
                {pipelines.map((pipe) => (
                  <tr key={pipe.id} className="hover:bg-[#070a13]/60 transition-colors">
                    <td className="py-3 font-mono text-cyan-400 font-semibold">{pipe.id.slice(0, 8)}...</td>
                    <td className="py-3 font-mono text-slate-300">{pipe.current_stage}</td>
                    <td className="py-3">
                      <span
                        className={`rounded px-2 py-0.5 text-[10px] font-mono font-bold border ${getStatusBadge(
                          pipe.execution_status
                        )}`}
                      >
                        {pipe.execution_status}
                      </span>
                    </td>
                    <td className="py-3 text-slate-400 font-mono text-[11px]">
                      {new Date(pipe.started_at).toLocaleTimeString()}
                    </td>
                    <td className="py-3 text-slate-400 font-mono text-[11px]">
                      {pipe.completed_at ? new Date(pipe.completed_at).toLocaleTimeString() : "In Progress"}
                    </td>
                    <td className="py-3 text-right">
                      <button
                        onClick={() => setInspectingId(pipe.id)}
                        className="inline-flex items-center gap-1 rounded bg-cyan-950 px-2.5 py-1 text-[11px] font-mono text-cyan-300 border border-cyan-800 hover:bg-cyan-900 transition-colors"
                      >
                        <span>Inspect Stepper</span>
                        <ChevronRight className="h-3 w-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pipeline Trigger Modal */}
      {isStartModalOpen && (
        <PipelineControlModal
          isOpen={isStartModalOpen}
          onClose={() => setIsStartModalOpen(false)}
          onPipelineStarted={(exec) => {
            setIsStartModalOpen(false);
            setInspectingId(exec.id);
          }}
        />
      )}
    </div>
  );
};

