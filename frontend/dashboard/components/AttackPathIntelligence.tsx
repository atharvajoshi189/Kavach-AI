"use client";

import React, { useEffect, useState, useMemo } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import {
  AttackPath,
  AttackPathEdge,
  AttackPathNode,
  AttackPathReport,
  SyntheticAsset,
} from "../lib/types";
import {
  GitFork,
  Play,
  PlusCircle,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Clock,
  ArrowRight,
  RefreshCw,
  X,
  FileText,
  Activity,
  Layers,
  Network,
} from "lucide-react";

export interface AttackPathIntelligenceProps {
  onHandOffToGuardian?: (executionId?: string) => void;
}

export const AttackPathIntelligence: React.FC<AttackPathIntelligenceProps> = ({
  onHandOffToGuardian,
}) => {
  const { activeSandbox } = useAuth();
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null);
  const [graphData, setGraphData] = useState<{ nodes: AttackPathNode[]; edges: AttackPathEdge[] } | null>(null);
  const [report, setReport] = useState<AttackPathReport | null>(null);
  const [assets, setAssets] = useState<SyntheticAsset[]>([]);
  const [loading, setLoading] = useState(false);
  const [isGuardianLaunching, setIsGuardianLaunching] = useState(false);

  // Path Planner Modal State
  const [isPlanModalOpen, setIsPlanModalOpen] = useState(false);
  const [sourceAssetId, setSourceAssetId] = useState("");
  const [destAssetId, setDestAssetId] = useState("");
  const [executionMode, setExecutionMode] = useState<"targeted" | "exploratory">("targeted");
  const [maxStages, setMaxStages] = useState(4);
  const [isPlanning, setIsPlanning] = useState(false);
  const [planError, setPlanError] = useState<string | null>(null);

  // Path Execution State
  const [isExecuting, setIsExecuting] = useState(false);
  const [execStatusMessage, setExecStatusMessage] = useState<string | null>(null);

  // Selected Node in Graph
  const [activeNode, setActiveNode] = useState<AttackPathNode | null>(null);

  const loadPathsAndAssets = async () => {
    setLoading(true);
    try {
      const [pathRes, assetList] = await Promise.all([
        api.listAttackPaths(0, 50),
        activeSandbox?.id ? api.listAssets(activeSandbox.id) : Promise.resolve([]),
      ]);
      setPaths(pathRes.items || []);
      setAssets(assetList);

      if (pathRes.items && pathRes.items.length > 0 && !selectedPath) {
        handleSelectPath(pathRes.items[0]);
      }
    } catch (err) {
      console.error("Failed to load attack paths:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPathsAndAssets();
  }, [activeSandbox?.id]);

  const handleSelectPath = async (p: AttackPath) => {
    setSelectedPath(p);
    setActiveNode(null);
    try {
      const [g, rep] = await Promise.all([
        api.getAttackPathGraph(p.id),
        api.getAttackPathReport(p.id),
      ]);
      setGraphData(g);
      setReport(rep);
    } catch (err) {
      console.error("Failed to load path graph or report:", err);
    }
  };

  const handleCreatePlan = async () => {
    if (!sourceAssetId || !activeSandbox?.id) return;
    setIsPlanning(true);
    setPlanError(null);
    try {
      const campaignId = activeSandbox.id;
      const res = await api.planAttackPath({
        campaign_id: campaignId,
        source_asset_id: sourceAssetId,
        destination_asset_id: destAssetId || undefined,
        execution_mode: executionMode,
        max_stages: maxStages,
      });

      setIsPlanModalOpen(false);
      await loadPathsAndAssets();
      handleSelectPath(res.attack_path);
    } catch (err: any) {
      setPlanError(err.message || "Failed to plan attack path.");
    } finally {
      setIsPlanning(false);
    }
  };

  const handleExecuteSelectedPath = async () => {
    if (!selectedPath) return;
    setIsExecuting(true);
    setExecStatusMessage("Executing sequential attack path stages via Red Team Agent...");
    try {
      const updated = await api.executeAttackPath(selectedPath.id);
      setSelectedPath(updated);
      setExecStatusMessage(`Execution finished with status: ${updated.status}`);
      await handleSelectPath(updated);
    } catch (err: any) {
      setExecStatusMessage(`Execution failed: ${err.message}`);
    } finally {
      setIsExecuting(false);
    }
  };

  const handleHandOffToGuardian = async () => {
    if (!selectedPath || !activeSandbox?.id) return;
    setIsGuardianLaunching(true);
    try {
      const guardianEx = await api.guardian.createExecution({
        sandbox_id: activeSandbox.id,
        attack_path_id: selectedPath.id,
      });
      if (onHandOffToGuardian) {
        onHandOffToGuardian(guardianEx.execution_id);
      }
    } catch (err: any) {
      console.error("Failed to launch Blue Guardian for attack path:", err);
      setExecStatusMessage(`Failed to launch Blue Guardian: ${err.message}`);
    } finally {
      setIsGuardianLaunching(false);
    }
  };

  // Node position layout calculation for interactive SVG graph
  const layoutNodes = useMemo(() => {
    if (!graphData || !graphData.nodes || graphData.nodes.length === 0) return [];
    const count = graphData.nodes.length;
    return graphData.nodes.map((node, idx) => {
      // Horizontal sequential layout with subtle offset
      const x = 120 + idx * 240;
      const y = 140 + (idx % 2 === 0 ? 0 : 50);
      return { ...node, x, y };
    });
  }, [graphData]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-[#1a2744] pb-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <span>Attack Path Intelligence & Graph Engine</span>
            <span className="rounded bg-cyan-950 px-2 py-0.5 text-xs font-mono text-cyan-400 border border-cyan-800/80">
              ORCHESTRATOR
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Multi-stage attack path planning, execution coordination, lateral movement validation, and event correlation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsPlanModalOpen(true)}
            className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500 transition-all shadow-sm shadow-cyan-900/40"
          >
            <PlusCircle className="h-3.5 w-3.5" />
            <span>Plan New Path</span>
          </button>
          <button
            onClick={loadPathsAndAssets}
            disabled={loading}
            className="flex items-center gap-1.5 rounded-lg border border-[#1a2744] bg-[#0c1222] px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:border-cyan-700 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Main Two Column View: Path Selector & Interactive Graph */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Attack Paths List (4 cols) */}
        <div className="lg:col-span-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Orchestrated Paths ({paths.length})
            </span>
          </div>

          {paths.length === 0 ? (
            <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-8 text-center">
              <GitFork className="h-8 w-8 text-slate-600 mx-auto mb-2" />
              <p className="text-xs text-slate-400">No attack paths generated.</p>
              <button
                onClick={() => setIsPlanModalOpen(true)}
                className="mt-3 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-cyan-500 transition-colors"
              >
                Plan First Attack Path
              </button>
            </div>
          ) : (
            <div className="space-y-2 max-h-[75vh] overflow-y-auto pr-1">
              {paths.map((p) => {
                const isSelected = selectedPath?.id === p.id;
                return (
                  <div
                    key={p.id}
                    onClick={() => handleSelectPath(p)}
                    className={`cursor-pointer rounded-xl border p-3.5 transition-all text-xs ${
                      isSelected
                        ? "border-cyan-500 bg-cyan-950/30 shadow-md shadow-cyan-950/40"
                        : "border-[#1a2744] bg-[#0c1222] hover:border-slate-700 text-slate-300"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-cyan-300 font-semibold">
                        Path #{p.id.slice(0, 8)}...
                      </span>
                      <span
                        className={`rounded px-1.5 py-0.5 text-[9px] font-mono font-bold uppercase tracking-wider ${
                          p.status === "completed"
                            ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                            : p.status === "running"
                            ? "bg-cyan-950 text-cyan-400 border border-cyan-800 animate-pulse"
                            : "bg-slate-900 text-slate-400 border border-slate-800"
                        }`}
                      >
                        {p.status}
                      </span>
                    </div>

                    <div className="mt-2 text-[11px] text-slate-400">
                      Mode: <span className="text-white capitalize">{p.execution_mode}</span> •{" "}
                      <span>{p.completed_stages} of {p.total_stages} stages</span>
                    </div>

                    {p.risk_score !== null && p.risk_score !== undefined && (
                      <div className="mt-1 text-[11px] text-slate-400">
                        Risk Score: <span className="font-mono text-amber-400 font-bold">{p.risk_score.toFixed(2)} / 10</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Interactive Graph & Inspector (8 cols) */}
        <div className="lg:col-span-8 space-y-4">
          {selectedPath ? (
            <>
              {/* Path Controls & Actions Banner */}
              <div className="flex items-center justify-between rounded-xl border border-[#1a2744] bg-[#0c1222] p-4">
                <div>
                  <h2 className="text-sm font-bold text-white flex items-center gap-2">
                    <span>Path #{selectedPath.id.slice(0, 8)}...</span>
                    <span className="text-slate-500 font-normal">|</span>
                    <span className="text-cyan-400 text-xs font-mono font-normal">
                      {selectedPath.total_stages} Planned Stages
                    </span>
                  </h2>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Mode: {selectedPath.execution_mode} • Status: {selectedPath.status}
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {selectedPath.status === "planned" || selectedPath.status === "ready" ? (
                    <button
                      onClick={handleExecuteSelectedPath}
                      disabled={isExecuting}
                      className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 transition-colors shadow-sm disabled:opacity-50"
                    >
                      <Play className="h-3.5 w-3.5 fill-white" />
                      <span>{isExecuting ? "Executing Path..." : "Execute Attack Path"}</span>
                    </button>
                  ) : (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleHandOffToGuardian}
                        disabled={isGuardianLaunching}
                        className="flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-3.5 py-1.5 text-xs font-bold text-white shadow-sm shadow-cyan-950/50 transition-all disabled:opacity-50"
                      >
                        <ShieldAlert className={`h-3.5 w-3.5 ${isGuardianLaunching ? "animate-spin" : ""}`} />
                        <span>{isGuardianLaunching ? "Launching Guardian..." : "Analyze with Blue Guardian"}</span>
                      </button>
                      <span className="rounded bg-slate-900 px-2.5 py-1 text-xs font-mono text-slate-400 border border-slate-800">
                        Outcome: {selectedPath.status.toUpperCase()}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {execStatusMessage && (
                <div className="rounded-lg border border-cyan-800/80 bg-cyan-950/40 p-2.5 text-xs text-cyan-300">
                  {execStatusMessage}
                </div>
              )}

              {/* Interactive SVG Attack Graph Canvas */}
              <div className="relative rounded-xl border border-[#1a2744] bg-[#070a13] p-4 min-h-[380px] overflow-hidden">
                <div className="absolute left-4 top-4 z-10 flex items-center gap-2 text-[11px] font-semibold text-slate-400">
                  <Network className="h-4 w-4 text-cyan-400" />
                  <span>TOPOLOGY GRAPH VISUALIZER</span>
                </div>

                {layoutNodes.length === 0 ? (
                  <div className="flex h-64 flex-col items-center justify-center text-center">
                    <Activity className="h-8 w-8 text-slate-600 mb-2" />
                    <p className="text-xs text-slate-400">Loading graph representation...</p>
                  </div>
                ) : (
                  <svg className="w-full h-80">
                    <defs>
                      <marker
                        id="arrow"
                        viewBox="0 0 10 10"
                        refX="22"
                        refY="5"
                        markerWidth="6"
                        markerHeight="6"
                        orient="auto-start-reverse"
                      >
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="#06b6d4" />
                      </marker>
                    </defs>

                    {/* Render Edges */}
                    {layoutNodes.map((source, i) => {
                      if (i === layoutNodes.length - 1) return null;
                      const target = layoutNodes[i + 1];
                      return (
                        <g key={i}>
                          <line
                            x1={source.x}
                            y1={source.y}
                            x2={target.x}
                            y2={target.y}
                            stroke="#06b6d4"
                            strokeWidth="2"
                            strokeDasharray="4 2"
                            markerEnd="url(#arrow)"
                          />
                        </g>
                      );
                    })}

                    {/* Render Nodes */}
                    {layoutNodes.map((n) => {
                      const isNodeActive = activeNode?.asset_id === n.asset_id;
                      return (
                        <g
                          key={n.asset_id}
                          transform={`translate(${n.x}, ${n.y})`}
                          onClick={() => setActiveNode(n)}
                          className="cursor-pointer"
                        >
                          <circle
                            r="24"
                            fill={isNodeActive ? "#0e7490" : "#0c1222"}
                            stroke={isNodeActive ? "#22d3ee" : "#1a2744"}
                            strokeWidth="2.5"
                            className="transition-all hover:stroke-cyan-400"
                          />
                          <text
                            textAnchor="middle"
                            dy="4"
                            fill="#f1f5f9"
                            fontSize="10"
                            fontFamily="monospace"
                            fontWeight="bold"
                          >
                            {n.asset_type.slice(0, 3).toUpperCase()}
                          </text>
                          <text
                            textAnchor="middle"
                            dy="40"
                            fill="#94a3b8"
                            fontSize="10"
                            fontWeight="500"
                          >
                            {n.asset_name.slice(0, 16)}...
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                )}
              </div>

              {/* Node Inspector Drawer */}
              {activeNode && (
                <div className="rounded-xl border border-cyan-900/60 bg-[#0c1222] p-4 text-xs">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2">
                    <span className="font-bold text-white">Inspecting Asset Node: {activeNode.asset_name}</span>
                    <button
                      onClick={() => setActiveNode(null)}
                      className="text-slate-400 hover:text-white"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div>
                      <span className="text-slate-400">Asset ID:</span>{" "}
                      <span className="font-mono text-cyan-300">{activeNode.asset_id}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Type:</span>{" "}
                      <span className="text-white capitalize">{activeNode.asset_type}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Risk Level:</span>{" "}
                      <span className="font-mono text-amber-400 uppercase font-semibold">{activeNode.risk_level}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Status:</span>{" "}
                      <span className="text-emerald-400 font-mono">{activeNode.status}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Stages List & Correlated Telemetry */}
              <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-4">
                <h3 className="text-xs font-bold text-white mb-3 uppercase tracking-wider flex items-center gap-2">
                  <Activity className="h-4 w-4 text-cyan-400" />
                  <span>Sequential Stages ({selectedPath.stages?.length || 0})</span>
                </h3>
                <div className="space-y-2">
                  {selectedPath.stages?.map((stage) => (
                    <div
                      key={stage.id}
                      className="flex items-center justify-between rounded-lg border border-slate-800 bg-[#070a13] p-3 text-xs"
                    >
                      <div className="flex items-center gap-3">
                        <span className="flex h-5 w-5 items-center justify-center rounded bg-slate-900 font-mono text-[10px] text-cyan-400 font-bold border border-slate-800">
                          {stage.sequence_number}
                        </span>
                        <div>
                          <div className="font-semibold text-white font-mono">{stage.scenario_id}</div>
                          <div className="text-[10px] text-slate-500 font-mono">
                            Stage ID: {stage.id.slice(0, 8)}...
                          </div>
                        </div>
                      </div>

                      <div className="text-right">
                        <span
                          className={`rounded px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wider ${
                            stage.status === "completed"
                              ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                              : stage.status === "failed"
                              ? "bg-rose-950 text-rose-400 border border-rose-800"
                              : stage.status === "skipped"
                              ? "bg-slate-900 text-slate-400 border border-slate-800"
                              : "bg-cyan-950 text-cyan-400 border border-cyan-800"
                          }`}
                        >
                          {stage.status}
                        </span>
                        {stage.risk_score !== null && stage.risk_score !== undefined && (
                          <div className="text-[10px] font-mono text-slate-400 mt-1">
                            Risk: <span className="text-amber-400 font-bold">{stage.risk_score.toFixed(1)}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="flex h-96 flex-col items-center justify-center rounded-xl border border-[#1a2744] bg-[#0c1222] p-8 text-center">
              <GitFork className="h-10 w-10 text-slate-600 mb-3" />
              <h3 className="text-sm font-semibold text-slate-300">Select an Attack Path</h3>
              <p className="text-xs text-slate-500 max-w-sm mt-1">
                Choose a planned or executed attack path from the left sidebar to inspect its topology graph, execution state, and correlated telemetry.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Path Planner Modal */}
      {isPlanModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-lg rounded-xl border border-cyan-900/60 bg-[#0c1222] p-6 shadow-2xl">
            <button
              onClick={() => setIsPlanModalOpen(false)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white transition-colors"
            >
              <X className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-3 border-b border-[#1a2744] pb-4 mb-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-950 border border-cyan-700/60 text-cyan-400">
                <GitFork className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-base font-bold text-white">Plan Multi-Stage Attack Path</h2>
                <p className="text-xs text-slate-400">Orchestrates kill-chain stages respecting asset topology</p>
              </div>
            </div>

            {planError && (
              <div className="mb-4 rounded-lg border border-rose-900/60 bg-rose-950/40 p-3 text-xs text-rose-300">
                {planError}
              </div>
            )}

            <div className="space-y-4 text-xs">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Source Synthetic Asset (Entry Point)
                </label>
                <select
                  value={sourceAssetId}
                  onChange={(e) => setSourceAssetId(e.target.value)}
                  className="w-full rounded-lg border border-[#1a2744] bg-[#070a13] p-2.5 text-xs text-white focus:border-cyan-500 focus:outline-none"
                >
                  <option value="">Select Source Asset...</option>
                  {assets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.asset_type}) - {a.ip_address}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Target / Destination Asset (Optional Target)
                </label>
                <select
                  value={destAssetId}
                  onChange={(e) => setDestAssetId(e.target.value)}
                  className="w-full rounded-lg border border-[#1a2744] bg-[#070a13] p-2.5 text-xs text-white focus:border-cyan-500 focus:outline-none"
                >
                  <option value="">None (Exploratory Path)</option>
                  {assets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.asset_type}) - {a.ip_address}
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Execution Mode
                  </label>
                  <select
                    value={executionMode}
                    onChange={(e) => setExecutionMode(e.target.value as any)}
                    className="w-full rounded-lg border border-[#1a2744] bg-[#070a13] p-2.5 text-xs text-white focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="targeted">Targeted Kill-Chain</option>
                    <option value="exploratory">Exploratory Breadth</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Max Stages (1-8)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={8}
                    value={maxStages}
                    onChange={(e) => setMaxStages(Number(e.target.value))}
                    className="w-full rounded-lg border border-[#1a2744] bg-[#070a13] p-2.5 text-xs text-white focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>

              <button
                onClick={handleCreatePlan}
                disabled={isPlanning || !sourceAssetId}
                className="w-full rounded-lg bg-cyan-600 py-2.5 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                <PlusCircle className="h-4 w-4" />
                <span>{isPlanning ? "Generating Graph Plan..." : "Generate & Save Attack Path"}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

