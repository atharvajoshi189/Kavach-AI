"use client";

import React, { useEffect, useState } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import { AuditLogItem } from "../lib/types";
import {
  History,
  ShieldCheck,
  Lock,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  Hash,
  X,
} from "lucide-react";

export const AuditTrail: React.FC = () => {
  const { user } = useAuth();
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [selectedLog, setSelectedLog] = useState<AuditLogItem | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await api.listAuditLogs(page, 50);
      setLogs(res.items || []);
      setTotal(res.total || 0);
    } catch (err: any) {
      if (err.status === 403) {
        setErrorMsg("Audit log inspection is restricted to the Administrator role (OPA policy requirement). Switch to 'val_admin' using the profile icon to inspect.");
      } else {
        setErrorMsg(err.message || "Failed to load audit trail.");
      }
      setLogs([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page, user?.role]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-[#1a2744] pb-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <span>Cryptographic Audit Trail</span>
            <span className="rounded bg-purple-950 px-2 py-0.5 text-xs font-mono text-purple-400 border border-purple-800/80">
              SHA-256 CHAINED
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Tamper-evident sequential audit log recording security decisions, simulation runs, and identity events.
          </p>
        </div>

        <button
          onClick={fetchLogs}
          disabled={loading}
          className="flex items-center gap-1.5 rounded-lg border border-[#1a2744] bg-[#0c1222] px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:border-cyan-700 transition-all disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          <span>Refresh Logs</span>
        </button>
      </div>

      {errorMsg ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-amber-900/40 bg-amber-950/20 p-8 text-center">
          <Lock className="h-8 w-8 text-amber-400 mb-2" />
          <h3 className="text-sm font-semibold text-white">Administrator Authorization Required</h3>
          <p className="text-xs text-slate-400 max-w-md mt-1">{errorMsg}</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[#1a2744] bg-[#0c1222]">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="border-b border-[#1a2744] bg-[#070a13] text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Event Type</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Actor / Role</th>
                <th className="px-4 py-3">Decision</th>
                <th className="px-4 py-3">SHA-256 Hash</th>
                <th className="px-4 py-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1a2744]/70 font-mono">
              {logs.map((log) => {
                const isAllow =
                  log.decision === "ALLOW" ||
                  log.decision === "allow" ||
                  log.decision === "success";

                return (
                  <tr
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className="hover:bg-cyan-950/20 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3 text-slate-400 text-[11px]">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 font-semibold text-cyan-300">{log.event_type}</td>
                    <td className="px-4 py-3 text-white">{log.action}</td>
                    <td className="px-4 py-3 text-purple-300">
                      {log.actor_role || "system"}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-block rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                          isAllow
                            ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                            : "bg-rose-950 text-rose-400 border border-rose-800"
                        }`}
                      >
                        {log.decision || "LOG"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-[10px]">
                      {log.event_hash.slice(0, 10)}...
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedLog(log);
                        }}
                        className="rounded bg-slate-900 px-2 py-1 text-[10px] text-cyan-400 border border-slate-800 hover:border-cyan-700"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Log Detail Drawer */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-xl rounded-xl border border-cyan-900/60 bg-[#0c1222] p-6 shadow-2xl">
            <button
              onClick={() => setSelectedLog(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white"
            >
              <X className="h-5 w-5" />
            </button>

            <h3 className="text-base font-bold text-white mb-2 flex items-center gap-2">
              <History className="h-4 w-4 text-cyan-400" />
              <span>Audit Log Record: {selectedLog.event_type}</span>
            </h3>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                <div>
                  <span className="text-slate-400">Action:</span> {selectedLog.action}
                </div>
                <div>
                  <span className="text-slate-400">Decision:</span> {selectedLog.decision}
                </div>
                <div>
                  <span className="text-slate-400">Actor Role:</span> {selectedLog.actor_role}
                </div>
                <div>
                  <span className="text-slate-400">Resource:</span> {selectedLog.resource_type}
                </div>
              </div>

              <div>
                <span className="text-slate-400 text-[11px] block mb-1">SHA-256 Current Hash:</span>
                <div className="rounded bg-[#070a13] p-2 font-mono text-[10px] text-cyan-400 border border-[#1a2744] break-all">
                  {selectedLog.event_hash}
                </div>
              </div>

              <div>
                <span className="text-slate-400 text-[11px] block mb-1">Previous Chained Hash:</span>
                <div className="rounded bg-[#070a13] p-2 font-mono text-[10px] text-slate-500 border border-[#1a2744] break-all">
                  {selectedLog.previous_hash}
                </div>
              </div>

              <div>
                <span className="text-slate-400 text-[11px] block mb-1">Raw Event Payload:</span>
                <pre className="rounded bg-[#070a13] p-3 font-mono text-[10px] text-emerald-400 border border-[#1a2744] overflow-x-auto max-h-48">
                  {JSON.stringify(selectedLog.event_data, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

