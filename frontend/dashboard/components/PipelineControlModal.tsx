"use client";

import React, { useState } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import { OrchestrationExecutionResponse } from "../lib/types";
import {
  ShieldAlert,
  Play,
  X,
  Layers,
  Crosshair,
  GitBranch,
  CheckCircle2,
  AlertTriangle,
  Info,
  Clock,
  Sparkles,
} from "lucide-react";

interface PipelineControlModalProps {
  isOpen: boolean;
  onClose: () => void;
  onPipelineStarted: (execution: OrchestrationExecutionResponse) => void;
}

const RED_TEAM_SCENARIOS = [
  {
    id: "simulated_initial_access",
    name: "Simulated Initial Access",
    category: "initial_access",
    description: "Public-facing synthetic exploit targeting perimeter web/API assets.",
    applicableAssets: "Web App, API, Server",
  },
  {
    id: "simulated_privilege_escalation",
    name: "Simulated Privilege Escalation",
    category: "privilege_escalation",
    description: "Sudo/misconfiguration abuse to elevate synthetic session privileges.",
    applicableAssets: "Server, Database, API",
  },
  {
    id: "simulated_lateral_movement",
    name: "Simulated Lateral Movement",
    category: "lateral_movement",
    description: "SSH/SMB pivot across internal synthetic assets in sandbox topology.",
    applicableAssets: "All assets",
  },
  {
    id: "simulated_data_exfiltration",
    name: "Simulated Data Exfiltration",
    category: "exfiltration",
    description: "Extraction of simulated high-value customer/credential database tables.",
    applicableAssets: "Database, Server, API",
  },
  {
    id: "simulated_service_discovery",
    name: "Simulated Service Discovery",
    category: "discovery",
    description: "Port scan and service fingerprinting across sandbox assets.",
    applicableAssets: "All assets",
  },
  {
    id: "simulated_weak_configuration_assessment",
    name: "Weak Configuration Assessment",
    category: "configuration",
    description: "Audit synthetic asset flags for default ports, credentials, and open access.",
    applicableAssets: "All assets",
  },
  {
    id: "simulated_authentication_anomaly",
    name: "Authentication Anomaly",
    category: "credential_access",
    description: "Simulated credential stuffing and brute force against auth services.",
    applicableAssets: "Server, Database, Web App, API",
  },
  {
    id: "simulated_persistence",
    name: "Simulated Persistence",
    category: "persistence",
    description: "Installation of synthetic scheduled job / backdoor telemetry.",
    applicableAssets: "Server, Web App, API",
  },
];

export const PipelineControlModal: React.FC<PipelineControlModalProps> = ({
  isOpen,
  onClose,
  onPipelineStarted,
}) => {
  const { activeSandbox } = useAuth();
  const [executionMode, setExecutionMode] = useState<"scenario" | "attack_path">("scenario");
  const [selectedScenario, setSelectedScenario] = useState("simulated_initial_access");
  const [autoApprove, setAutoApprove] = useState(false);
  const [correlationWindow, setCorrelationWindow] = useState(300);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeSandbox) {
      setError("Please select an active sandbox first.");
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      const execution = await api.orchestration.startPipeline({
        sandbox_id: activeSandbox.id,
        scenario_id: executionMode === "scenario" ? selectedScenario : undefined,
        run_attack_path: executionMode === "attack_path",
        auto_approve: autoApprove,
        correlation_window_seconds: correlationWindow,
        client_metadata: {
          client_agent: "AegisMesh-SOC-Command-Center",
          initiated_at: new Date().toISOString(),
          mode: executionMode,
        },
      });

      onPipelineStarted(execution);
      onClose();
    } catch (err: any) {
      console.error("Failed to start pipeline:", err);
      setError(err?.message || "Failed to start orchestration pipeline.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl rounded-xl border border-cyan-500/30 bg-[#0b1329] shadow-2xl shadow-cyan-950/60 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[#1a2744] bg-[#070a13] px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-950/80 border border-cyan-500/40 text-cyan-400">
              <Play className="h-4 w-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-wide">
                Start Unified Orchestration Pipeline
              </h2>
              <p className="text-xs text-slate-400">
                Executes all 15 platform stages from simulation through remediation and verification.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {error && (
            <div className="flex items-center gap-2.5 rounded-lg border border-red-500/30 bg-red-950/40 p-3 text-xs text-red-300">
              <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          {/* Sandbox Scope Banner */}
          <div className="flex items-center justify-between rounded-lg border border-[#1a2744] bg-[#0d1836] p-3 text-xs">
            <div className="flex items-center gap-2.5">
              <Layers className="h-4 w-4 text-cyan-400" />
              <div>
                <span className="text-slate-400">Target Sandbox: </span>
                <span className="font-semibold text-white">
                  {activeSandbox ? activeSandbox.name : "None Selected"}
                </span>
                <span className="ml-2 font-mono text-[10px] text-slate-500">
                  {activeSandbox ? activeSandbox.id.slice(0, 8) : ""}
                </span>
              </div>
            </div>
            <span className="rounded bg-cyan-950 px-2 py-0.5 text-[10px] font-mono text-cyan-400 border border-cyan-800/60">
              SIMULATION ONLY
            </span>
          </div>

          {/* Execution Mode Selector */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2 uppercase tracking-wider">
              Execution Architecture Mode
            </label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setExecutionMode("scenario")}
                className={`flex flex-col items-start gap-1 p-3 rounded-lg border text-left transition-all ${
                  executionMode === "scenario"
                    ? "border-cyan-500 bg-cyan-950/40 text-cyan-200"
                    : "border-[#1a2744] bg-[#091024] text-slate-400 hover:border-slate-700"
                }`}
              >
                <div className="flex items-center gap-2 font-semibold text-xs text-white">
                  <Crosshair className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Single Scenario Simulation</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Targeted Red Team run mapped to a specific MITRE ATT&CK technique.
                </p>
              </button>

              <button
                type="button"
                onClick={() => setExecutionMode("attack_path")}
                className={`flex flex-col items-start gap-1 p-3 rounded-lg border text-left transition-all ${
                  executionMode === "attack_path"
                    ? "border-cyan-500 bg-cyan-950/40 text-cyan-200"
                    : "border-[#1a2744] bg-[#091024] text-slate-400 hover:border-slate-700"
                }`}
              >
                <div className="flex items-center gap-2 font-semibold text-xs text-white">
                  <GitBranch className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Multi-Stage Attack Path</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Autonomous multi-hop pivot path exploring asset graph dependencies.
                </p>
              </button>
            </div>
          </div>

          {/* Scenario Selection (if in scenario mode) */}
          {executionMode === "scenario" && (
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                Select Synthetic Red Team Scenario
              </label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-48 overflow-y-auto pr-1">
                {RED_TEAM_SCENARIOS.map((sc) => (
                  <button
                    key={sc.id}
                    type="button"
                    onClick={() => setSelectedScenario(sc.id)}
                    className={`flex flex-col text-left p-2.5 rounded-lg border transition-all ${
                      selectedScenario === sc.id
                        ? "border-cyan-500 bg-cyan-950/40 shadow-sm shadow-cyan-950"
                        : "border-[#1a2744] bg-[#070e22] hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-white">{sc.name}</span>
                      <span className="text-[9px] font-mono text-cyan-400 bg-cyan-950 px-1 py-0.2 rounded border border-cyan-800/40">
                        {sc.category}
                      </span>
                    </div>
                    <p className="text-[10px] text-slate-400 mt-0.5 line-clamp-1">{sc.description}</p>
                    <span className="text-[9px] text-slate-500 mt-1">Targets: {sc.applicableAssets}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Approval & Governance Settings */}
          <div className="rounded-lg border border-[#1a2744] bg-[#081028] p-3.5 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs font-semibold text-white">Approval Automation</span>
                <p className="text-[11px] text-slate-400">
                  Allow test auto-approval, or pause pipeline at Stage 12 for Four-Eyes signoff.
                </p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoApprove}
                  onChange={(e) => setAutoApprove(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600"></div>
              </label>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-[#1a2744]/70">
              <span className="text-xs text-slate-300">Guardian Correlation Window</span>
              <div className="flex items-center gap-1.5">
                <input
                  type="number"
                  min={30}
                  max={3600}
                  value={correlationWindow}
                  onChange={(e) => setCorrelationWindow(Number(e.target.value))}
                  className="w-16 rounded border border-[#1a2744] bg-[#050914] px-2 py-1 text-xs text-white text-right font-mono"
                />
                <span className="text-xs text-slate-500">sec</span>
              </div>
            </div>
          </div>

          {/* Safety & Epistemic Boundaries Notice */}
          <div className="flex items-start gap-2.5 rounded-lg border border-cyan-800/30 bg-cyan-950/20 p-3 text-[11px] text-cyan-200">
            <Info className="h-4 w-4 shrink-0 text-cyan-400 mt-0.5" />
            <span>
              <strong>Deterministic Sandbox Boundaries:</strong> Execution modifies only synthetic state
              dictionaries in PostgreSQL. Real operating systems, production networks, and host credentials
              are never accessed or altered.
            </span>
          </div>

          {/* Actions */}
          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="px-4 py-2 rounded-lg border border-[#1a2744] text-xs font-semibold text-slate-300 hover:bg-slate-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !activeSandbox}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-cyan-600 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors disabled:opacity-50 shadow-md shadow-cyan-950"
            >
              {isSubmitting ? (
                <>
                  <Clock className="h-3.5 w-3.5 animate-spin" />
                  <span>Initializing Platform Lifecycle...</span>
                </>
              ) : (
                <>
                  <Play className="h-3.5 w-3.5" />
                  <span>Start 15-Stage Orchestration</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

