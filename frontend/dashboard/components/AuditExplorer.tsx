"use client";

import React, { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import { AuditLogItem } from "../lib/types";
import {
  FileText,
  Hash,
  ShieldCheck,
  RefreshCw,
  Search,
  Clock,
  AlertTriangle,
  User,
  CheckCircle2,
  Lock,
} from "lucide-react";

export const AuditExplorer: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchLogs = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);
    setError(null);

    try {
      const res = await api.audit.listAuditLogs({
        page,
        page_size: 50,
        event_type: eventTypeFilter.trim() || undefined,
      });
      setLogs(res.items || []);
      setTotal(res.total || 0);
    } catch (err: any) {
      console.error("Failed to load audit logs:", err);
      setError(err?.message || "Failed to load audit trail (Requires Administrator permissions).");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [page, eventTypeFilter]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const getDecisionBadge = (decision?: string | null) => {
    if (!decision) return "bg-slate-900 text-slate-400 border-slate-800";
    const d = decision.toUpperCase();
    if (d.includes("ALLOW") || d.includes("COMPLETED") || d.includes("APPROVED") || d.includes("PASSED")) {
      return "bg-emerald-950 text-emerald-300 border-emerald-800";
    }
    if (d.includes("DENY") || d.includes("REJECT") || d.includes("FAILED")) {
      return "bg-red-950 text-red-300 border-red-800";
    }
    if (d.includes("FAIL_CLOSED")) {
      return "bg-amber-950 text-amber-300 border-amber-800";
    }
    return "bg-cyan-950 text-cyan-300 border-cyan-800";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#1a2744] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white tracking-wide">
              Cryptographic Audit Explorer
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Tamper-evident SHA-256 chained audit ledger for all authorization, simulation, and defensive decisions.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Filter by event type..."
              value={eventTypeFilter}
              onChange={(e) => {
                setEventTypeFilter(e.target.value);
                setPage(1);
              }}
              className="rounded-lg border border-[#1a2744] bg-[#070e22] pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-52"
            />
          </div>

          <button
            onClick={() => fetchLogs(true)}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1a2744] bg-[#070e22] text-xs font-semibold text-slate-300 hover:bg-slate-800 transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Hash-Chain Integrity Banner */}
      <div className="flex items-center justify-between rounded-xl border border-emerald-500/20 bg-emerald-950/10 p-3.5 text-xs text-emerald-300">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0" />
          <span>
            <strong>Cryptographic Chain Active:</strong> Every event is hashed with SHA-256 and linked to the previous record hash.
          </span>
        </div>
        <span className="font-mono text-[10px] bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800 text-emerald-300">
          GENESIS LINKED
        </span>
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
      ) : logs.length === 0 ? (
        <div className="rounded-xl border border-[#1a2744] bg-[#070e22] p-8 text-center text-xs text-slate-400">
          No audit records found matching criteria.
        </div>
      ) : (
        <div className="rounded-xl border border-[#1a2744] bg-[#070e22] overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#1a2744] bg-[#050914] text-[10px] uppercase font-mono text-slate-400">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Event Type</th>
                  <th className="px-4 py-3">Actor / Role</th>
                  <th className="px-4 py-3">Resource</th>
                  <th className="px-4 py-3">Decision</th>
                  <th className="px-4 py-3">Cryptographic Proof</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1a2744]/60 font-sans">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-[#09112a] transition-colors">
                    <td className="px-4 py-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {new Date(log.created_at).toLocaleString([], {
                        month: "short",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                      })}
                    </td>

                    <td className="px-4 py-3 font-mono text-xs text-cyan-300 font-bold">
                      {log.event_type}
                    </td>

                    <td className="px-4 py-3 text-xs">
                      <div className="flex items-center gap-1.5">
                        <User className="h-3 w-3 text-slate-500 shrink-0" />
                        <span className="text-white font-medium">
                          {log.actor_id ? log.actor_id.slice(0, 8) : "SYSTEM"}
                        </span>
                        {log.actor_role && (
                          <span className="text-[10px] font-mono text-slate-500">
                            ({log.actor_role})
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="px-4 py-3 font-mono text-[11px] text-slate-300">
                      <span className="text-slate-400">{log.resource_type}:</span>{" "}
                      {log.resource_id ? log.resource_id.slice(0, 8) : "global"}
                    </td>

                    <td className="px-4 py-3">
                      <span
                        className={`rounded px-2 py-0.5 text-[9px] font-bold font-mono uppercase tracking-wider border ${getDecisionBadge(
                          log.decision
                        )}`}
                      >
                        {log.decision || "RECORDED"}
                      </span>
                    </td>

                    <td className="px-4 py-3 font-mono text-[10px] text-slate-500 whitespace-nowrap">
                      <div className="flex items-center gap-1">
                        <Hash className="h-3 w-3 text-cyan-400 shrink-0" />
                        <span className="text-cyan-400/90" title={log.event_hash}>
                          {log.event_hash.slice(0, 10)}...
                        </span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between border-t border-[#1a2744] bg-[#050914] px-4 py-3 text-xs text-slate-400">
            <span>
              Showing Page {page} (Total: {total} events)
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="px-2.5 py-1 rounded border border-[#1a2744] bg-[#070e22] text-xs text-slate-300 disabled:opacity-40"
              >
                Previous
              </button>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={logs.length < 50}
                className="px-2.5 py-1 rounded border border-[#1a2744] bg-[#070e22] text-xs text-slate-300 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

