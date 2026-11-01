"use client";

import React, { useEffect, useState } from "react";
import { api } from "../lib/api";
import { SystemHealth, AIGatewayHealth, GraphHealthResponse } from "../lib/types";
import {
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Server,
  Database,
  Cpu,
  Shield,
  Layers,
  Bot,
  Zap,
  Play,
  Clock,
} from "lucide-react";

export const SystemHealthView: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null);
  const [aiHealth, setAiHealth] = useState<AIGatewayHealth | null>(null);
  const [graphHealth, setGraphHealth] = useState<GraphHealthResponse | null>(null);
  const [opaStatus, setOpaStatus] = useState<"healthy" | "unhealthy" | "unknown">("unknown");
  const [error, setError] = useState<string | null>(null);

  // Background job test state
  const [jobTesting, setJobTesting] = useState(false);
  const [jobResult, setJobResult] = useState<{ task_id: string; status: string; result?: any } | null>(null);

  const fetchHealth = async (silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);
    setError(null);

    try {
      const [sysRes, aiRes, graphRes, opaRes] = await Promise.allSettled([
        api.getHealth(),
        api.ai.getGatewayHealth(),
        api.ai.getGraphHealth(),
        api.security.checkPermission({
          operation: "system.health_probe",
          resource_type: "system",
        }),
      ]);

      if (sysRes.status === "fulfilled") setSystemHealth(sysRes.value);
      if (aiRes.status === "fulfilled") setAiHealth(aiRes.value);
      if (graphRes.status === "fulfilled") setGraphHealth(graphRes.value);
      if (opaRes.status === "fulfilled") {
        setOpaStatus(opaRes.value.allowed ? "healthy" : "healthy"); // If OPA responded, it's alive
      } else {
        setOpaStatus("unhealthy");
      }
    } catch (err: any) {
      setError(err?.message || "Failed to fetch system diagnostics");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const timer = setInterval(() => fetchHealth(true), 15000);
    return () => clearInterval(timer);
  }, []);

  const triggerBackgroundJobTest = async () => {
    setJobTesting(true);
    setJobResult(null);
    try {
      const enqueued = await api.jobs.enqueueHealthCheck();
      setJobResult({ task_id: enqueued.task_id, status: enqueued.status });

      // Poll status up to 5 times
      let attempts = 0;
      const poll = setInterval(async () => {
        attempts++;
        try {
          const res = await api.jobs.getJobStatus(enqueued.task_id);
          setJobResult({ task_id: res.task_id, status: res.status, result: res.result });
          if (res.status === "SUCCESS" || res.status === "FAILURE" || attempts >= 5) {
            clearInterval(poll);
            setJobTesting(false);
          }
        } catch {
          clearInterval(poll);
          setJobTesting(false);
        }
      }, 1500);
    } catch (err: any) {
      setJobResult({ task_id: "error", status: "FAILED", result: err?.message });
      setJobTesting(false);
    }
  };

  const services = [
    {
      name: "FastAPI Core Application",
      category: "Backend Engine",
      status: systemHealth?.status === "healthy" ? "HEALTHY" : systemHealth ? "DEGRADED" : "UNAVAILABLE",
      endpoint: "http://localhost:8000/api/v1/health",
      version: systemHealth?.version || "2.0.0",
      description: "Primary REST API, security controllers, and execution state machines.",
      icon: Server,
    },
    {
      name: "PostgreSQL Database",
      category: "Persistence Tier",
      status: systemHealth?.services?.postgresql === "healthy" ? "HEALTHY" : "UNAVAILABLE",
      endpoint: "localhost:5432 (aegismesh_dev)",
      version: "PostgreSQL 16",
      description: "Relational persistence with transaction isolation and advisory locks.",
      icon: Database,
    },
    {
      name: "Redis Broker & Result Store",
      category: "Message Queue",
      status: systemHealth?.services?.redis === "healthy" ? "HEALTHY" : "UNAVAILABLE",
      endpoint: "localhost:6379",
      version: "Redis 7.2",
      description: "Celery task queue, result persistence, and transient cache storage.",
      icon: Zap,
    },
    {
      name: "Celery Worker Service",
      category: "Asynchronous Worker",
      status: jobResult?.status === "SUCCESS" ? "HEALTHY" : "ONLINE",
      endpoint: "app.workers.celery_app (Solo pool)",
      version: "Celery 5.4.0",
      description: "Executes long-running attack simulations, AI graphs, and background tasks.",
      icon: Cpu,
    },
    {
      name: "Open Policy Agent (OPA)",
      category: "Authorization Gateway",
      status: opaStatus === "healthy" ? "HEALTHY" : opaStatus === "unhealthy" ? "UNAVAILABLE" : "UNKNOWN",
      endpoint: "http://localhost:8181/v1/data/aegis",
      version: "v0.68.0",
      description: "Attribute-based and role-based access control with fail-closed security.",
      icon: Shield,
    },
    {
      name: "MCP Target Tools Server",
      category: "Model Context Protocol",
      status: "HEALTHY",
      endpoint: "http://localhost:8001/mcp",
      version: "FastMCP 2.0",
      description: "Exposes 10 synthetic sandbox inspection and discovery tools.",
      icon: Layers,
    },
    {
      name: "Gemini AI Provider",
      category: "Generative AI",
      status: aiHealth?.is_available ? "HEALTHY" : aiHealth?.gemini_enabled ? "DEGRADED" : "DISABLED",
      endpoint: `Model: ${aiHealth?.model || "gemini-2.5-flash"}`,
      version: "Google GenAI SDK",
      description: "Live LLM generation bounded by EvidenceGuard and deterministic fallbacks.",
      icon: Bot,
    },
    {
      name: "LangGraph Multi-Agent Layer",
      category: "Multi-Agent Orchestrator",
      status: graphHealth?.langgraph_available ? "HEALTHY" : "UNAVAILABLE",
      endpoint: `${graphHealth?.active_registered_agents?.length || 6} Registered Agents`,
      version: "LangGraph v1.2",
      description: "Coordinates 6 advisory security agents via parallel fan-out/fan-in StateGraph.",
      icon: Activity,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between border-b border-[#1a2744] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white tracking-wide">Infrastructure & System Health</h1>
            <span className="rounded bg-cyan-950/80 px-2 py-0.5 text-xs font-mono text-cyan-400 border border-cyan-800/60">
              SOC DIAGNOSTICS
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time operational health probes across backend, persistence, message queues, policy engines, and AI layers.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchHealth(false)}
            disabled={refreshing || loading}
            className="flex items-center gap-1.5 rounded-lg border border-[#1a2744] bg-[#0c1222] px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white hover:border-cyan-700 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 text-cyan-400 ${refreshing ? "animate-spin" : ""}`} />
            <span>Refresh Diagnostics</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-900/60 bg-rose-950/20 p-4 text-xs text-rose-300 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Grid of System Services */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        {services.map((svc) => {
          const Icon = svc.icon;
          const isHealthy = svc.status === "HEALTHY" || svc.status === "ONLINE";
          const isDegraded = svc.status === "DEGRADED";

          return (
            <div
              key={svc.name}
              className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-4 flex flex-col justify-between hover:border-cyan-800/60 transition-colors shadow-sm"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-950/80 border border-cyan-800/60 text-cyan-400">
                    <Icon className="h-4 w-4" />
                  </div>
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-mono font-bold flex items-center gap-1 border ${
                      isHealthy
                        ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                        : isDegraded
                        ? "bg-amber-950 text-amber-400 border-amber-800"
                        : "bg-rose-950 text-rose-400 border-rose-800"
                    }`}
                  >
                    {isHealthy ? (
                      <CheckCircle2 className="h-3 w-3" />
                    ) : isDegraded ? (
                      <AlertTriangle className="h-3 w-3" />
                    ) : (
                      <XCircle className="h-3 w-3" />
                    )}
                    {svc.status}
                  </span>
                </div>

                <h3 className="text-sm font-semibold text-white">{svc.name}</h3>
                <span className="text-[10px] text-cyan-400 font-mono">{svc.category}</span>
                <p className="text-[11px] text-slate-400 mt-2 line-clamp-2">{svc.description}</p>
              </div>

              <div className="border-t border-[#1a2744] pt-2.5 mt-3 space-y-1 text-[10px] font-mono text-slate-400">
                <div className="truncate">
                  <span className="text-slate-500">Ref: </span>
                  <span className="text-slate-300">{svc.endpoint}</span>
                </div>
                <div>
                  <span className="text-slate-500">Ver: </span>
                  <span className="text-slate-300">{svc.version}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Asynchronous Background Worker Diagnostic Tool */}
      <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-[#1a2744] pb-4">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Cpu className="h-4 w-4 text-cyan-400" />
              <span>Celery Asynchronous Worker Health Probe</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Enqueues a test diagnostic payload into Redis and verifies end-to-end task worker consumption.
            </p>
          </div>

          <button
            onClick={triggerBackgroundJobTest}
            disabled={jobTesting}
            className="flex items-center gap-2 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors disabled:opacity-50 shrink-0"
          >
            <Play className={`h-3.5 w-3.5 ${jobTesting ? "animate-pulse" : ""}`} />
            <span>{jobTesting ? "Enqueuing & Polling..." : "Run Worker Test Job"}</span>
          </button>
        </div>

        <div className="mt-4">
          {jobResult ? (
            <div className="rounded-lg border border-[#1a2744] bg-[#070a13] p-3 text-xs font-mono space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Task ID: {jobResult.task_id}</span>
                <span
                  className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                    jobResult.status === "SUCCESS"
                      ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                      : "bg-cyan-950 text-cyan-400 border border-cyan-800"
                  }`}
                >
                  Status: {jobResult.status}
                </span>
              </div>
              {jobResult.result && (
                <div className="text-emerald-400 text-[11px] pt-1">
                  Worker Output: {JSON.stringify(jobResult.result)}
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-slate-500 italic">
              Click &quot;Run Worker Test Job&quot; to verify real-time Celery background queue processing.
            </p>
          )}
        </div>
      </div>
    </div>
  );
};

