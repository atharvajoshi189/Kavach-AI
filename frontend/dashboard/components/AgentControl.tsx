"use client";

import React from "react";
import { Bot, Shield, CheckCircle2, Clock, AlertCircle, Cpu, Zap, Activity } from "lucide-react";

export const AgentControl: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-[#1a2744] pb-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <span>Autonomous Agent Control Center</span>
            <span className="rounded bg-cyan-950 px-2 py-0.5 text-xs font-mono text-cyan-400 border border-cyan-800/80">
              RUNTIME STATUS
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Status, execution interfaces, and operational bounds for implemented and planned platform agents.
          </p>
        </div>
      </div>

      {/* Engineering Clarification Banner */}
      <div className="rounded-lg border border-cyan-900/60 bg-cyan-950/20 p-4 text-xs text-cyan-200">
        <div className="flex items-center gap-2 font-bold text-white mb-1">
          <Cpu className="h-4 w-4 text-cyan-400" />
          <span>Execution Engine Architecture: Deterministic Simulation vs. Autonomous AI</span>
        </div>
        <p className="text-slate-300 leading-relaxed text-[11px]">
          AegisMesh 2.0 Red Team Agent operates via a <strong>deterministic simulation engine</strong> governed strictly by MITRE ATT&CK techniques, PostgreSQL advisory transaction locks, and OPA security boundaries. Autonomous LLM decision-making and Blue Guardian defensive reasoning loops are scheduled for subsequent architectural phases.
        </p>
      </div>

      {/* Agents Matrix */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        {/* Red Team Agent (Implemented) */}
        <div className="rounded-xl border border-cyan-800/80 bg-[#0c1222] p-5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-rose-950/80 border border-rose-700/60 text-rose-400">
                <Bot className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white">Red Team Agent</h3>
                <span className="text-[10px] text-slate-400 font-mono">app.agents.red_team.agent</span>
              </div>
            </div>
            <span className="rounded bg-emerald-950 px-2 py-0.5 text-[10px] font-mono font-bold text-emerald-400 border border-emerald-800">
              ONLINE / ACTIVE
            </span>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Orchestrates deterministic attack scenarios against synthetic assets inside sandbox environments. Features a 9-stage execution lifecycle, fail-closed audit logging, and transactional concurrency control.
          </p>

          <div className="space-y-2 text-xs border-t border-slate-800/80 pt-3">
            <div className="flex justify-between text-[11px]">
              <span className="text-slate-500">Capability:</span>
              <span className="font-mono text-cyan-300">Deterministic Simulation</span>
            </div>
            <div className="flex justify-between text-[11px]">
              <span className="text-slate-500">Engine Type:</span>
              <span className="font-mono text-slate-200">Rule-based MITRE Scenarios (8)</span>
            </div>
            <div className="flex justify-between text-[11px]">
              <span className="text-slate-500">Isolation Boundary:</span>
              <span className="font-mono text-emerald-400">Strict Sandbox Only</span>
            </div>
          </div>
        </div>

        {/* Target Agent & Sandbox Infrastructure (Implemented) */}
        <div className="rounded-xl border border-cyan-800/80 bg-[#0c1222] p-5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-950/80 border border-cyan-700/60 text-cyan-400">
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white">Synthetic Target Agent</h3>
                <span className="text-[10px] text-slate-400 font-mono">app.services.target_agent_service</span>
              </div>
            </div>
            <span className="rounded bg-emerald-950 px-2 py-0.5 text-[10px] font-mono font-bold text-emerald-400 border border-emerald-800">
              ONLINE / ACTIVE
            </span>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Provides simulated target environments and MCP endpoints. Exposes controlled observational tools for asset inspection and simulated finding telemetry.
          </p>

          <div className="space-y-2 text-xs border-t border-slate-800/80 pt-3">
            <div className="flex justify-between text-[11px]">
              <span className="text-slate-500">Capability:</span>
              <span className="font-mono text-cyan-300">Observation & Telemetry</span>
            </div>
            <div className="flex justify-between text-[11px]">
              <span className="text-slate-500">MCP Protocol:</span>
              <span className="font-mono text-slate-200">Streamable HTTP (Port 8001)</span>
            </div>
            <div className="flex justify-between text-[11px]">
              <span className="text-slate-500">Isolation Boundary:</span>
              <span className="font-mono text-emerald-400">Read-Only Synthetic Assets</span>
            </div>
          </div>
        </div>

        {/* Blue Guardian Agent (Planned - Step 10) */}
        <div className="rounded-xl border border-slate-800 bg-[#0c1222]/50 p-5 space-y-4 opacity-75">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-900 border border-slate-800 text-slate-500">
                <Bot className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-300">Blue Guardian Agent</h3>
                <span className="text-[10px] text-slate-500 font-mono">Defensive Detection & Correlation</span>
              </div>
            </div>
            <span className="rounded bg-slate-900 px-2 py-0.5 text-[10px] font-mono font-semibold text-slate-500 border border-slate-800">
              PLANNED (STEP 10)
            </span>
          </div>

          <p className="text-xs text-slate-500 leading-relaxed">
            Autonomous defensive agent designed to detect Red Team simulations, correlate telemetry across attack stages, and compute defensive resilience metrics.
          </p>
        </div>

        {/* Async Worker Subsystem (Implemented) */}
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-amber-950/80 border border-amber-700/60 text-amber-400">
                <Zap className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white">Celery Task Dispatcher</h3>
                <span className="text-[10px] text-slate-400 font-mono">app.workers.celery_app</span>
              </div>
            </div>
            <span className="rounded bg-emerald-950 px-2 py-0.5 text-[10px] font-mono font-bold text-emerald-400 border border-emerald-800">
              RUNNING (SOLO)
            </span>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Asynchronous task queue powered by Redis broker. Dispatches long-running background assessments without blocking HTTP request threads.
          </p>
        </div>
      </div>
    </div>
  );
};

