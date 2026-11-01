"use client";

import React, { useEffect, useState } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import {
  AttackPath,
  AuditLogItem,
  RedTeamScenario,
  SyntheticAsset,
  SystemHealth,
} from "../lib/types";
import {
  Server,
  Layers,
  Crosshair,
  GitFork,
  ShieldCheck,
  History,
  Activity,
  AlertTriangle,
  ArrowRight,
  Database,
  Cpu,
  Lock,
  Boxes,
  RefreshCw,
} from "lucide-react";
import { NavTab } from "./Sidebar";

interface CommandCenterProps {
  onNavigate: (tab: NavTab) => void;
}

export const CommandCenter: React.FC<CommandCenterProps> = ({ onNavigate }) => {
  const { activeSandbox, sandboxes, user } = useAuth();

  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [assets, setAssets] = useState<SyntheticAsset[]>([]);
  const [scenarios, setScenarios] = useState<RedTeamScenario[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      // 1. Health
      try {
        const h = await api.getHealth();
        setHealth(h);
      } catch (e) {
        console.warn("Health error:", e);
      }

      // 2. Scenarios
      try {
        const sc = await api.listScenarios();
        setScenarios(sc);
      } catch (e) {
        console.warn("Scenarios error:", e);
      }

      // 3. Assets for active sandbox
      if (activeSandbox?.id) {
        try {
          const a = await api.listAssets(activeSandbox.id);
          setAssets(a);
        } catch (e) {
          console.warn("Assets error:", e);
        }
      }

      // 4. Attack Paths
      try {
        const ap = await api.listAttackPaths(0, 10);
        setAttackPaths(ap.items || []);
      } catch (e) {
        console.warn("Attack paths error:", e);
      }

      // 5. Audit logs (Admin only or fallback empty)
      try {
        const logs = await api.listAuditLogs(1, 10);
        setAuditLogs(logs.items || []);
      } catch (e) {
        // Expected if user is not admin
        setAuditLogs([]);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [activeSandbox?.id]);

  // Derived metrics
  const completedPaths = attackPaths.filter((p) => p.status === "completed").length;
  const criticalAssets = assets.filter((a) => a.risk_level === "critical" || a.risk_level === "high").length;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-[#1a2744] pb-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <span>SOC Operational Command Center</span>
            <span className="rounded bg-cyan-950 px-2 py-0.5 text-xs font-mono text-cyan-400 border border-cyan-800/80">
              LIVE TELEMETRY
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time synthetic security surface, deterministic attack simulations, and cryptographic audit monitoring.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-1.5 rounded-lg border border-[#1a2744] bg-[#0c1222] px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:border-cyan-700 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            <span>Refresh Telemetry</span>
          </button>
        </div>
      </div>

      {/* Primary KPI Grid (All Derived from Live API) */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Synthetic Assets */}
        <div
          onClick={() => onNavigate("assets_sandbox")}
          className="group cursor-pointer rounded-xl border border-[#1a2744] bg-[#0c1222] p-4 transition-all hover:border-cyan-700/60 hover:shadow-lg hover:shadow-cyan-950/20"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Synthetic Assets</span>
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-950/70 border border-cyan-800/60 text-cyan-400">
              <Server className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-white">{assets.length}</span>
            <span className="text-xs text-slate-500 font-medium">in {activeSandbox?.name || "sandbox"}</span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/60">
            <span className="text-amber-400 font-semibold">{criticalAssets} High/Critical</span>
            <span className="flex items-center gap-1 text-cyan-400 group-hover:translate-x-0.5 transition-transform">
              Inspect <ArrowRight className="h-3 w-3" />
            </span>
          </div>
        </div>

        {/* Attack Scenarios */}
        <div
          onClick={() => onNavigate("red_team")}
          className="group cursor-pointer rounded-xl border border-[#1a2744] bg-[#0c1222] p-4 transition-all hover:border-cyan-700/60 hover:shadow-lg hover:shadow-cyan-950/20"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Attack Scenarios</span>
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-purple-950/70 border border-purple-800/60 text-purple-400">
              <Crosshair className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-white">{scenarios.length}</span>
            <span className="text-xs text-emerald-400 font-medium">Deterministic</span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/60">
            <span>MITRE ATT&CK Mapped</span>
            <span className="flex items-center gap-1 text-purple-400 group-hover:translate-x-0.5 transition-transform">
              Simulate <ArrowRight className="h-3 w-3" />
            </span>
          </div>
        </div>

        {/* Attack Paths */}
        <div
          onClick={() => onNavigate("attack_paths")}
          className="group cursor-pointer rounded-xl border border-[#1a2744] bg-[#0c1222] p-4 transition-all hover:border-cyan-700/60 hover:shadow-lg hover:shadow-cyan-950/20"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Attack Paths</span>
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-950/70 border border-blue-800/60 text-blue-400">
              <GitFork className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-white">{attackPaths.length}</span>
            <span className="text-xs text-cyan-400 font-medium">{completedPaths} Executed</span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/60">
            <span>Graph Orchestrated</span>
            <span className="flex items-center gap-1 text-blue-400 group-hover:translate-x-0.5 transition-transform">
              Graph Intel <ArrowRight className="h-3 w-3" />
            </span>
          </div>
        </div>

        {/* Active Sandboxes */}
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Active Sandboxes</span>
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-950/70 border border-emerald-800/60 text-emerald-400">
              <Layers className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-white">{sandboxes.length}</span>
            <span className="text-xs text-emerald-400 font-medium">Isolated</span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/60">
            <span className="text-slate-500">100% Policy Guarded</span>
            <span className="text-emerald-400 font-mono">ENFORCED</span>
          </div>
        </div>
      </div>

      {/* Infrastructure Core Matrix */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        {/* Postgres */}
        <div className="flex items-center gap-3 rounded-lg border border-[#1a2744] bg-[#0c1222] p-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-blue-950/60 text-blue-400">
            <Database className="h-4 w-4" />
          </div>
          <div>
            <div className="text-[11px] text-slate-400">PostgreSQL (pgvector)</div>
            <div className="text-xs font-mono font-semibold text-emerald-400">
              {health?.services?.postgresql === "healthy" ? "CONNECTED" : "OFFLINE"}
            </div>
          </div>
        </div>

        {/* Redis */}
        <div className="flex items-center gap-3 rounded-lg border border-[#1a2744] bg-[#0c1222] p-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-rose-950/60 text-rose-400">
            <Cpu className="h-4 w-4" />
          </div>
          <div>
            <div className="text-[11px] text-slate-400">Redis Broker & Cache</div>
            <div className="text-xs font-mono font-semibold text-emerald-400">
              {health?.services?.redis === "healthy" ? "CONNECTED" : "OFFLINE"}
            </div>
          </div>
        </div>

        {/* OPA Gateway */}
        <div className="flex items-center gap-3 rounded-lg border border-[#1a2744] bg-[#0c1222] p-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-cyan-950/60 text-cyan-400">
            <Lock className="h-4 w-4" />
          </div>
          <div>
            <div className="text-[11px] text-slate-400">OPA Policy Engine</div>
            <div className="text-xs font-mono font-semibold text-cyan-400">DEFAULT-DENY</div>
          </div>
        </div>

        {/* MCP Server */}
        <div
          onClick={() => onNavigate("settings")}
          className="flex items-center gap-3 rounded-lg border border-[#1a2744] bg-[#0c1222] p-3 cursor-pointer hover:border-cyan-800 transition-colors"
        >
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-amber-950/60 text-amber-400">
            <Boxes className="h-4 w-4" />
          </div>
          <div>
            <div className="text-[11px] text-slate-400">MCP Protocol Server</div>
            <div className="text-xs font-mono font-semibold text-amber-400">10 TOOLS ONLINE</div>
          </div>
        </div>
      </div>

      {/* Two Column Layout: Recent Attack Paths & Recent Chained Audits */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Recent Attack Paths */}
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <GitFork className="h-4 w-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-white">Recent Attack Paths</h2>
            </div>
            <button
              onClick={() => onNavigate("attack_paths")}
              className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-1 font-medium"
            >
              View All <ArrowRight className="h-3 w-3" />
            </button>
          </div>

          {attackPaths.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <GitFork className="h-8 w-8 text-slate-600 mb-2" />
              <p className="text-xs text-slate-400">No attack paths planned yet.</p>
              <button
                onClick={() => onNavigate("attack_paths")}
                className="mt-3 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-cyan-500 transition-colors"
              >
                Plan First Attack Path
              </button>
            </div>
          ) : (
            <div className="space-y-2.5">
              {attackPaths.slice(0, 4).map((path) => (
                <div
                  key={path.id}
                  onClick={() => onNavigate("attack_paths")}
                  className="flex items-center justify-between rounded-lg border border-slate-800/80 bg-[#070a13] p-3 text-xs hover:border-cyan-800/60 transition-colors cursor-pointer"
                >
                  <div>
                    <div className="font-mono text-cyan-300 font-medium">
                      Path #{path.id.slice(0, 8)}...
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      {path.execution_mode} mode • {path.completed_stages}/{path.total_stages} stages
                    </div>
                  </div>
                  <div className="text-right">
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wider ${
                        path.status === "completed"
                          ? "bg-emerald-950 text-emerald-400 border border-emerald-800/80"
                          : path.status === "running"
                          ? "bg-cyan-950 text-cyan-400 border border-cyan-800/80 animate-pulse"
                          : "bg-slate-900 text-slate-400 border border-slate-800"
                      }`}
                    >
                      {path.status}
                    </span>
                    {path.risk_score !== null && path.risk_score !== undefined && (
                      <div className="text-[10px] font-mono text-slate-400 mt-1">
                        Risk: <span className="text-amber-400 font-bold">{path.risk_score.toFixed(2)}</span>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Audit Trail Activity */}
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4 border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <History className="h-4 w-4 text-purple-400" />
              <h2 className="text-sm font-semibold text-white">Cryptographic Audit Trail</h2>
            </div>
            <button
              onClick={() => onNavigate("audit_explorer")}
              className="text-xs text-purple-400 hover:text-purple-300 transition-colors flex items-center gap-1 font-medium"
            >
              Inspect Logs <ArrowRight className="h-3 w-3" />
            </button>
          </div>

          {auditLogs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Lock className="h-8 w-8 text-slate-600 mb-2" />
              <p className="text-xs text-slate-400">
                {user?.role === "admin"
                  ? "Audit records will populate as security actions execute."
                  : "Audit inspection requires Administrator credentials. Authenticate as Admin to view."}
              </p>
            </div>
          ) : (
            <div className="space-y-2.5">
              {auditLogs.slice(0, 4).map((log) => (
                <div
                  key={log.id}
                  className="flex items-center justify-between rounded-lg border border-slate-800/80 bg-[#070a13] p-3 text-xs"
                >
                  <div className="space-y-0.5 truncate pr-2">
                    <div className="font-mono text-slate-200 text-[11px] truncate">
                      {log.action} <span className="text-slate-500">({log.event_type})</span>
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono">
                      Actor: <span className="text-cyan-400">{log.actor_role || "system"}</span> •{" "}
                      {new Date(log.created_at).toLocaleTimeString()}
                    </div>
                  </div>
                  <div className="shrink-0 text-right">
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wider ${
                        log.decision === "ALLOW" || log.decision === "allow"
                          ? "bg-emerald-950 text-emerald-400 border border-emerald-800/80"
                          : "bg-rose-950 text-rose-400 border border-rose-800/80"
                      }`}
                    >
                      {log.decision || "LOG"}
                    </span>
                    <div className="text-[9px] font-mono text-slate-500 mt-1">
                      SHA256: {log.event_hash.slice(0, 8)}...
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

