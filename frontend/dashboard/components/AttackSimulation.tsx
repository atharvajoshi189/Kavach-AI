"use client";

import React, { useEffect, useState } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import { RedTeamRun, RedTeamScenario, SyntheticAsset } from "../lib/types";
import {
  Crosshair,
  ShieldAlert,
  Play,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Clock,
  RefreshCw,
  X,
  Bug,
  Activity,
  Layers,
  ChevronRight,
} from "lucide-react";

export interface AttackSimulationProps {
  onHandOffToGuardian?: (executionId?: string) => void;
}

export const AttackSimulation: React.FC<AttackSimulationProps> = ({ onHandOffToGuardian }) => {
  const { activeSandbox } = useAuth();
  const [scenarios, setScenarios] = useState<RedTeamScenario[]>([]);
  const [assets, setAssets] = useState<SyntheticAsset[]>([]);
  const [loading, setLoading] = useState(false);

  // Execution Modal state
  const [selectedScenario, setSelectedScenario] = useState<RedTeamScenario | null>(null);
  const [selectedAssetId, setSelectedAssetId] = useState<string>("");
  const [customParams, setCustomParams] = useState<string>("{}");
  const [isExecuting, setIsExecuting] = useState(false);
  const [execResult, setExecResult] = useState<RedTeamRun | null>(null);
  const [execError, setExecError] = useState<string | null>(null);
  const [isGuardianLaunching, setIsGuardianLaunching] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [scList, assetList] = await Promise.all([
        api.listScenarios(),
        activeSandbox?.id ? api.listAssets(activeSandbox.id) : Promise.resolve([]),
      ]);
      setScenarios(scList);
      setAssets(assetList);
    } catch (err) {
      console.error("Failed to load scenario data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [activeSandbox?.id]);

  const handleOpenRunModal = (scenario: RedTeamScenario) => {
    setSelectedScenario(scenario);
    setExecResult(null);
    setExecError(null);

    // Pick first compatible asset
    const compatible = assets.find((a) =>
      scenario.applicable_asset_types.includes(a.asset_type)
    );
    if (compatible) {
      setSelectedAssetId(compatible.id);
    } else if (assets.length > 0) {
      setSelectedAssetId(assets[0].id);
    }
  };

  const handleExecuteSimulation = async () => {
    if (!selectedScenario || !selectedAssetId || !activeSandbox?.id) return;
    setIsExecuting(true);
    setExecError(null);
    setExecResult(null);

    try {
      let params = {};
      try {
        params = JSON.parse(customParams);
      } catch {
        throw new Error("Parameters must be valid JSON.");
      }

      // Create a transient execution campaign for this run
      const campaignId = activeSandbox.id; // or existing campaign
      const runResponse = await api.executeRun(campaignId, {
        scenario: selectedScenario.scenario_id,
        asset_id: selectedAssetId,
        parameters: params,
      });

      // Fetch full details of the execution run
      const detailedRun = await api.getRunDetails(runResponse.run_id);
      setExecResult(detailedRun);
    } catch (err: any) {
      setExecError(err.message || "Failed to execute simulation run.");
    } finally {
      setIsExecuting(false);
    }
  };

  const handleHandOffToGuardian = async () => {
    if (!execResult || !activeSandbox?.id) return;
    setIsGuardianLaunching(true);
    try {
      const guardianEx = await api.guardian.createExecution({
        sandbox_id: activeSandbox.id,
        attack_run_id: execResult.run_id,
      });
      if (onHandOffToGuardian) {
        onHandOffToGuardian(guardianEx.execution_id);
      }
    } catch (err: any) {
      console.error("Failed to launch Blue Guardian for run:", err);
      setExecError(err.message || "Failed to launch Blue Guardian analysis.");
    } finally {
      setIsGuardianLaunching(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-[#1a2744] pb-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <span>Red Team Attack Simulation Engine</span>
            <span className="rounded bg-purple-950 px-2 py-0.5 text-xs font-mono text-purple-400 border border-purple-800/80">
              8 DETERMINISTIC SCENARIOS
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Execute controlled, policy-governed MITRE ATT&CK techniques strictly against isolated sandbox assets.
          </p>
        </div>

        <button
          onClick={fetchData}
          disabled={loading}
          className="flex items-center gap-1.5 rounded-lg border border-[#1a2744] bg-[#0c1222] px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:border-cyan-700 transition-all disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          <span>Refresh Scenarios</span>
        </button>
      </div>

      {/* Safety Invariant Notice */}
      <div className="flex items-center gap-3 rounded-lg border border-cyan-900/60 bg-cyan-950/30 p-3 text-xs text-cyan-200">
        <ShieldAlert className="h-5 w-5 shrink-0 text-cyan-400" />
        <div className="leading-relaxed">
          <strong className="text-white">Synthetic Guardrail Invariant:</strong> All executions use deterministic simulated payloads (`is_simulated=True`, `simulation_only=True`). Real socket exploits, network scans, and destructive commands are prohibited by design.
        </div>
      </div>

      {/* Scenarios Grid */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        {scenarios.map((sc) => (
          <div
            key={sc.scenario_id}
            className="flex flex-col justify-between rounded-xl border border-[#1a2744] bg-[#0c1222] p-5 shadow-sm hover:border-cyan-700/60 transition-all hover:shadow-cyan-950/30"
          >
            <div>
              <div className="flex items-center justify-between">
                <span className="rounded bg-slate-900 px-2 py-0.5 font-mono text-[10px] text-cyan-400 font-bold border border-slate-800">
                  {sc.technique_id}
                </span>
                <span className="rounded bg-emerald-950/80 px-2 py-0.5 text-[9px] font-mono text-emerald-400 border border-emerald-800/80">
                  SIMULATION ONLY
                </span>
              </div>

              <h3 className="mt-3 text-sm font-semibold text-white leading-snug">
                {sc.name}
              </h3>
              <p className="mt-1 text-xs text-slate-400 line-clamp-2">
                {sc.description}
              </p>

              <div className="mt-3 space-y-1.5 pt-3 border-t border-slate-800/60 text-[11px]">
                <div className="flex items-center justify-between text-slate-400">
                  <span>Category:</span>
                  <span className="font-medium text-slate-200 capitalize">{sc.category.replace("_", " ")}</span>
                </div>
                <div className="flex items-center justify-between text-slate-400">
                  <span>Target Assets:</span>
                  <span className="font-mono text-cyan-300 text-[10px] truncate max-w-[140px]">
                    {sc.applicable_asset_types.join(", ")}
                  </span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800/60">
              <button
                onClick={() => handleOpenRunModal(sc)}
                className="w-full flex items-center justify-center gap-1.5 rounded-lg bg-cyan-600/90 py-2 text-xs font-semibold text-white hover:bg-cyan-500 transition-all shadow-sm shadow-cyan-950"
              >
                <Play className="h-3 w-3 fill-white" />
                <span>Configure & Run</span>
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Execution Drawer / Modal */}
      {selectedScenario && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-xl border border-cyan-900/60 bg-[#0c1222] p-6 shadow-2xl">
            <button
              onClick={() => setSelectedScenario(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white transition-colors"
            >
              <X className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-3 border-b border-[#1a2744] pb-4 mb-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-950 border border-cyan-700/60 text-cyan-400">
                <Crosshair className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-base font-bold text-white">{selectedScenario.name}</h2>
                <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mt-0.5">
                  <span className="text-cyan-400 font-semibold">{selectedScenario.scenario_id}</span>
                  <span>•</span>
                  <span>{selectedScenario.technique_id}</span>
                </div>
              </div>
            </div>

            {/* Error Banner */}
            {execError && (
              <div className="mb-4 flex items-center gap-2 rounded-lg border border-rose-900/60 bg-rose-950/40 p-3 text-xs text-rose-300">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span>{execError}</span>
              </div>
            )}

            {/* Form */}
            {!execResult ? (
              <div className="space-y-4 text-xs">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Target Synthetic Asset (Sandbox Scoped)
                  </label>
                  <select
                    value={selectedAssetId}
                    onChange={(e) => setSelectedAssetId(e.target.value)}
                    className="w-full rounded-lg border border-[#1a2744] bg-[#070a13] p-2.5 text-xs text-white focus:border-cyan-500 focus:outline-none"
                  >
                    {assets.map((a) => {
                      const isCompatible = selectedScenario.applicable_asset_types.includes(
                        a.asset_type
                      );
                      return (
                        <option
                          key={a.id}
                          value={a.id}
                          className={isCompatible ? "text-white" : "text-slate-500"}
                        >
                          {a.name} ({a.asset_type}) - {a.ip_address} {isCompatible ? "✓ Compatible" : "⚠ Incompatible"}
                        </option>
                      );
                    })}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Simulation Parameters (JSON)
                  </label>
                  <textarea
                    rows={3}
                    value={customParams}
                    onChange={(e) => setCustomParams(e.target.value)}
                    className="w-full rounded-lg border border-[#1a2744] bg-[#070a13] p-2.5 font-mono text-xs text-cyan-300 focus:border-cyan-500 focus:outline-none"
                  />
                </div>

                <div className="rounded-lg border border-amber-950/80 bg-amber-950/20 p-3 text-amber-300 text-[11px] leading-relaxed">
                  <strong>Notice:</strong> This simulation triggers the Red Team Agent 9-stage lifecycle: OPA gateway validation, SHA-256 chained audit recording, PostgreSQL advisory locking, and synthetic finding generation.
                </div>

                <button
                  onClick={handleExecuteSimulation}
                  disabled={isExecuting || !selectedAssetId}
                  className="w-full rounded-lg bg-cyan-600 py-2.5 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  <Play className="h-4 w-4 fill-white" />
                  <span>{isExecuting ? "Executing Deterministic Simulation..." : "Confirm & Execute Simulation"}</span>
                </button>
              </div>
            ) : (
              /* Execution Results View */
              <div className="space-y-4">
                <div className="flex items-center justify-between rounded-lg border border-emerald-800/80 bg-emerald-950/30 p-3 text-xs">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                    <div>
                      <div className="font-semibold text-emerald-300">Simulation Run Completed</div>
                      <div className="text-[11px] font-mono text-slate-400">
                        Run ID: {execResult.run_id}
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] text-slate-400 block">Calculated Risk</span>
                    <span className="font-mono text-base font-bold text-amber-400">
                      {execResult.risk_score?.toFixed(1) || "N/A"} / 10
                    </span>
                  </div>
                </div>

                {/* Findings List */}
                <div>
                  <h4 className="text-xs font-semibold text-white mb-2 flex items-center gap-1.5">
                    <Bug className="h-4 w-4 text-amber-400" />
                    <span>Generated Synthetic Findings ({execResult.execution_metadata?.findings?.length || 0})</span>
                  </h4>
                  <div className="space-y-2">
                    {execResult.execution_metadata?.findings?.map((f, i) => (
                      <div
                        key={i}
                        className="rounded-lg border border-[#1a2744] bg-[#070a13] p-3 text-xs"
                      >
                        <div className="flex items-center justify-between font-semibold text-white">
                          <span>{f.title}</span>
                          <span className="rounded bg-amber-950 px-2 py-0.5 text-[10px] font-mono uppercase text-amber-400 border border-amber-800">
                            {f.severity}
                          </span>
                        </div>
                        <p className="mt-1 text-slate-400 text-[11px]">{f.description}</p>
                        {f.remediation_recommendation && (
                          <div className="mt-2 rounded bg-cyan-950/30 border border-cyan-900/40 p-2 text-[11px] text-cyan-300">
                            <strong>Remediation:</strong> {f.remediation_recommendation}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Events Timeline */}
                <div>
                  <h4 className="text-xs font-semibold text-white mb-2 flex items-center gap-1.5">
                    <Activity className="h-4 w-4 text-cyan-400" />
                    <span>Telemetry Events ({execResult.execution_metadata?.events?.length || 0})</span>
                  </h4>
                  <div className="rounded-lg border border-[#1a2744] bg-[#070a13] p-3 font-mono text-[11px] space-y-1.5 max-h-40 overflow-y-auto">
                    {execResult.execution_metadata?.events?.map((ev, i) => (
                      <div key={i} className="flex items-center justify-between text-slate-300">
                        <span className="text-cyan-400">{ev.event_type}</span>
                        <span className="text-slate-500 text-[10px]">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex flex-col gap-2 pt-2">
                  <button
                    onClick={handleHandOffToGuardian}
                    disabled={isGuardianLaunching}
                    className="w-full flex items-center justify-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 py-2.5 text-xs font-bold text-white shadow-lg shadow-cyan-950/50 transition-all disabled:opacity-50"
                  >
                    <ShieldAlert className={`h-4 w-4 ${isGuardianLaunching ? "animate-spin" : ""}`} />
                    <span>{isGuardianLaunching ? "Launching Blue Guardian Pipeline..." : "Analyze with Blue Guardian"}</span>
                  </button>

                  <button
                    onClick={() => setExecResult(null)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 text-xs font-medium text-slate-300 hover:text-white transition-colors"
                  >
                    Run Another Simulation
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

