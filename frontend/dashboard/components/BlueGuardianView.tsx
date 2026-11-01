"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import {
  GuardianExecution,
  DefensiveEventRecord,
  CorrelatedEventGroup,
  ThreatDetection,
  ThreatRiskAssessment,
  ThreatAssetImpact,
  RiskSummary,
} from "../lib/types";
import {
  ShieldAlert,
  Activity,
  Layers,
  Database,
  Search,
  CheckCircle2,
  Clock,
  AlertTriangle,
  Flame,
  Network,
  Cpu,
  Hash,
  ChevronRight,
  RefreshCw,
  ExternalLink,
  ShieldCheck,
  Zap,
  Brain,
  Sparkles,
} from "lucide-react";

interface BlueGuardianViewProps {
  initialExecutionId?: string;
  initialTab?: "ingestion" | "detection" | "impact" | "risk";
  onNavigateToResponseCenter?: () => void;
  onNavigateToAI?: () => void;
}

export const BlueGuardianView: React.FC<BlueGuardianViewProps> = ({
  initialExecutionId,
  initialTab = "detection",
  onNavigateToResponseCenter,
  onNavigateToAI,
}) => {
  const { activeSandbox } = useAuth();
  const [activeTab, setActiveTab] = useState<"ingestion" | "detection" | "impact" | "risk">(initialTab);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // AI explanation state
  const [aiExplanation, setAiExplanation] = useState<any>(null);
  const [aiExplaining, setAiExplaining] = useState(false);

  useEffect(() => {
    if (initialTab) {
      setActiveTab(initialTab);
    }
  }, [initialTab]);

  // Execution state
  const [currentExecution, setCurrentExecution] = useState<GuardianExecution | null>(null);
  const [executionIdInput, setExecutionIdInput] = useState(initialExecutionId || "");

  // Pipeline Sub-Data
  const [events, setEvents] = useState<DefensiveEventRecord[]>([]);
  const [groups, setGroups] = useState<CorrelatedEventGroup[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<CorrelatedEventGroup | null>(null);
  const [detections, setDetections] = useState<ThreatDetection[]>([]);
  const [selectedDetection, setSelectedDetection] = useState<ThreatDetection | null>(null);
  const [riskAssessments, setRiskAssessments] = useState<ThreatRiskAssessment[]>([]);
  const [selectedAssessment, setSelectedAssessment] = useState<ThreatRiskAssessment | null>(null);
  const [impactedAssets, setImpactedAssets] = useState<ThreatAssetImpact[]>([]);
  const [riskSummary, setRiskSummary] = useState<RiskSummary | null>(null);

  // Fetch or trigger execution
  const loadExecutionData = useCallback(async (execId?: string) => {
    if (!activeSandbox) return;
    setLoading(true);
    setError(null);

    try {
      let execution: GuardianExecution | null = null;
      if (execId) {
        execution = await api.guardian.getExecution(execId);
        setCurrentExecution(execution);
      } else {
        try {
          const recentExecs = await api.guardian.listExecutions(activeSandbox.id, 1);
          if (recentExecs && recentExecs.length > 0) {
            execution = await api.guardian.getExecution(recentExecs[0].execution_id);
            setCurrentExecution(execution);
          }
        } catch (e) {
          console.warn("Could not list recent executions:", e);
        }
      }

      // Load parallel pipeline data
      const [rSum, dets, assess] = await Promise.all([
        api.guardian.getRiskSummary({ sandbox_id: activeSandbox.id, execution_id: execId }),
        api.guardian.listDetections({ sandbox_id: activeSandbox.id, execution_id: execId, page_size: 50 }),
        api.guardian.listRiskAssessments({ sandbox_id: activeSandbox.id, execution_id: execId, page_size: 50 }),
      ]);

      setRiskSummary(rSum);
      setDetections(dets.items || []);
      if (dets.items && dets.items.length > 0) {
        setSelectedDetection(dets.items[0]);
      }

      setRiskAssessments(assess.items || []);
      if (assess.items && assess.items.length > 0) {
        setSelectedAssessment(assess.items[0]);
        // Also load detailed asset impacts for the first assessment
        try {
          const detail = await api.guardian.getRiskAssessment(assess.items[0].id);
          setImpactedAssets(detail.impacted_assets || []);
        } catch {
          setImpactedAssets([]);
        }
      }

      // If we have an execution, load its events and correlated groups
      if (execution) {
        const [evs, grps] = await Promise.all([
          api.guardian.listExecutionEvents(execution.execution_id, 1, 50),
          api.guardian.listExecutionCorrelatedGroups(execution.execution_id),
        ]);
        setEvents(evs.items || []);
        setGroups(grps.items || []);
        if (grps.items && grps.items.length > 0) {
          setSelectedGroup(grps.items[0]);
        }
      }
    } catch (err: any) {
      console.error("Failed to load Blue Guardian data:", err);
      setError(err?.message || "Failed to load Blue Guardian pipeline telemetry.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [activeSandbox]);

  const handleExplainThreat = async (detectionId: string) => {
    setAiExplaining(true);
    setAiExplanation(null);
    try {
      const res = await api.ai.explainThreat(detectionId);
      setAiExplanation(res);
    } catch (e: any) {
      setAiExplanation({ error: e?.message || "Failed to generate AI threat explanation" });
    } finally {
      setAiExplaining(false);
    }
  };

  useEffect(() => {
    if (initialExecutionId) {
      setExecutionIdInput(initialExecutionId);
      loadExecutionData(initialExecutionId);
    } else {
      loadExecutionData();
    }
  }, [initialExecutionId, loadExecutionData]);

  const handleSelectAssessment = async (ass: ThreatRiskAssessment) => {
    setSelectedAssessment(ass);
    try {
      const detail = await api.guardian.getRiskAssessment(ass.id);
      setImpactedAssets(detail.impacted_assets || []);
    } catch (err) {
      console.error("Failed to fetch assessment detail:", err);
    }
  };

  const [isTriggering, setIsTriggering] = useState(false);
  const handleTriggerGuardian = async () => {
    if (!activeSandbox) return;
    setIsTriggering(true);
    setError(null);
    try {
      let assets = await api.listAssets(activeSandbox.id);
      if (!assets || assets.length === 0) {
        await api.seedDemoSandbox();
        assets = await api.listAssets(activeSandbox.id);
      }
      const targetAsset =
        assets.find((a) => ["web_application", "api", "server"].includes(a.asset_type)) || assets[0];
      const runRes = await api.executeRun(activeSandbox.id, {
        scenario: "simulated_initial_access",
        asset_id: targetAsset.id,
      });
      const gEx = await api.guardian.createExecution({
        sandbox_id: activeSandbox.id,
        attack_run_id: runRes.run_id,
      });
      await loadExecutionData(gEx.execution_id);
    } catch (err: any) {
      console.error("Failed to trigger Guardian:", err);
      setError(err?.message || "Failed to trigger Blue Guardian pipeline.");
    } finally {
      setIsTriggering(false);
    }
  };

  const PIPELINE_STAGES = [
    { key: "ingesting", label: "Ingestion", step: 1 },
    { key: "correlating", label: "Correlation", step: 2 },
    { key: "detecting", label: "Detection", step: 3 },
    { key: "analyzing_risk", label: "Risk Analysis", step: 4 },
    { key: "recommending", label: "Recommendations", step: 5 },
    { key: "planning", label: "Planning", step: 6 },
    { key: "completed", label: "Incident Reporting", step: 7 },
  ];

  const getStageStatus = (stageStep: number) => {
    if (!currentExecution) {
      return detections.length > 0 && stageStep <= 4 ? "completed" : "idle";
    }
    const status = currentExecution.status;
    if (status === "completed") return "completed";
    if (status === "failed") return "failed";

    const stageMap: Record<string, number> = {
      pending: 0,
      ingesting: 1,
      correlating: 2,
      detecting: 3,
      analyzing_risk: 4,
      recommending: 5,
      planning: 6,
      completed: 7,
    };
    const currentStep = stageMap[status] ?? 0;
    if (currentStep > stageStep) return "completed";
    if (currentStep === stageStep) return "active";
    return "pending";
  };

  return (
    <div className="space-y-6">
      {/* Blue Guardian Top Header & Pipeline Progress Tracker */}
      <div className="rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 backdrop-blur-md">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-[#1a2744]">
          <div className="space-y-1">
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-cyan-400" />
              Blue Guardian Defensive Engine
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/40 bg-cyan-950/60 text-cyan-300">
                DETERMINISTIC
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Autonomous defensive correlation, evidence-backed threat detection, and 6-dimensional risk scoring.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleTriggerGuardian}
              disabled={isTriggering || loading}
              className="flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 px-3.5 py-1.5 text-xs font-bold text-white shadow-md shadow-cyan-950 transition-all disabled:opacity-50"
            >
              <Zap className={`h-3.5 w-3.5 ${isTriggering ? "animate-spin" : ""}`} />
              <span>{isTriggering ? "Analyzing..." : "⚡ Run Pipeline Analysis"}</span>
            </button>

            <button
              onClick={() => {
                setRefreshing(true);
                loadExecutionData(currentExecution?.execution_id);
              }}
              disabled={loading || refreshing}
              className="flex items-center gap-1.5 rounded-lg border border-[#1a2744] bg-[#070a13] px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:border-cyan-500/50 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin text-cyan-400" : ""}`} />
              <span>Refresh</span>
            </button>

            {onNavigateToResponseCenter && (
              <button
                onClick={onNavigateToResponseCenter}
                className="flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-3 py-1.5 text-xs font-semibold text-white shadow-sm shadow-cyan-950 transition-all"
              >
                <span>Response Center</span>
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* 7-Stage Pipeline Tracker */}
        <div className="pt-5">
          <div className="text-[11px] font-mono font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center justify-between">
            <span>DEFENSIVE PIPELINE LIFECYCLE (7 STAGES)</span>
            {currentExecution && (
              <span className="text-cyan-400">
                EXECUTION: {currentExecution.execution_id.slice(0, 8)}... ({currentExecution.status.toUpperCase()})
              </span>
            )}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
            {PIPELINE_STAGES.map((stg) => {
              const status = getStageStatus(stg.step);
              return (
                <div
                  key={stg.key}
                  className={`flex flex-col p-2.5 rounded-lg border text-xs transition-all ${
                    status === "completed"
                      ? "border-emerald-800/80 bg-emerald-950/30 text-emerald-300"
                      : status === "active"
                      ? "border-cyan-500/80 bg-cyan-950/40 text-cyan-200 shadow-sm shadow-cyan-950"
                      : "border-[#1a2744] bg-[#070a13]/70 text-slate-500"
                  }`}
                >
                  <div className="flex items-center justify-between font-mono text-[10px]">
                    <span>0{stg.step}</span>
                    {status === "completed" ? (
                      <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                    ) : status === "active" ? (
                      <Activity className="h-3 w-3 text-cyan-400 animate-spin" />
                    ) : (
                      <Clock className="h-3 w-3" />
                    )}
                  </div>
                  <span className="font-semibold mt-1 text-[11px] truncate">{stg.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Sub-tab Navigation */}
      <div className="flex items-center gap-2 border-b border-[#1a2744] pb-2">
        <button
          onClick={() => setActiveTab("detection")}
          className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "detection"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          Threat Detections ({detections.length})
        </button>

        <button
          onClick={() => setActiveTab("impact")}
          className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "impact"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          Asset Impact & Blast Radius ({riskSummary?.directly_affected_assets_count ?? 0} Direct / {riskSummary?.potentially_exposed_assets_count ?? 0} Exposed)
        </button>

        <button
          onClick={() => setActiveTab("risk")}
          className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "risk"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          Multi-Factor Risk Analysis ({riskAssessments.length})
        </button>

        <button
          onClick={() => setActiveTab("ingestion")}
          className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "ingestion"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          Event Ingestion & Correlation ({events.length} Events / {groups.length} Groups)
        </button>
      </div>

      {/* SUB-TAB 1: THREAT DETECTIONS */}
      {activeTab === "detection" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Detections List */}
          <div className="lg:col-span-1 rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-4 space-y-3">
            <h2 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              CORRELATED DETECTIONS ({detections.length})
            </h2>

            {detections.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500">
                No detections found. Run Red Team simulation or check execution ID.
              </div>
            ) : (
              <div className="space-y-2 max-h-[550px] overflow-y-auto pr-1">
                {detections.map((det) => (
                  <div
                    key={det.id}
                    onClick={() => setSelectedDetection(det)}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      selectedDetection?.id === det.id
                        ? "border-cyan-500/80 bg-cyan-950/30"
                        : "border-[#1a2744] bg-[#070a13] hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-[10px] text-cyan-400">{det.detection_code}</span>
                      <span
                        className={`px-1.5 py-0.2 rounded text-[10px] font-mono uppercase ${
                          det.severity === "critical"
                            ? "bg-rose-950 text-rose-300 border border-rose-800"
                            : det.severity === "high"
                            ? "bg-amber-950 text-amber-300 border border-amber-800"
                            : "bg-cyan-950 text-cyan-300 border border-cyan-800"
                        }`}
                      >
                        {det.severity}
                      </span>
                    </div>
                    <div className="font-semibold text-xs text-white mt-1.5 line-clamp-1">
                      {det.title}
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                      <span className="font-mono">{det.classification}</span>
                      <span className="text-cyan-300">{(det.confidence_score * 100).toFixed(0)}% Conf</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Detection Detail Card */}
          <div className="lg:col-span-2 rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 space-y-4">
            {selectedDetection ? (
              <>
                <div className="flex items-start justify-between border-b border-[#1a2744] pb-4">
                  <div>
                    <span className="font-mono text-xs text-cyan-400">{selectedDetection.detection_code}</span>
                    <h2 className="text-base font-bold text-white mt-0.5">{selectedDetection.title}</h2>
                    <div className="flex items-center gap-2 mt-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono border border-cyan-700/60 bg-cyan-950/60 text-cyan-300 uppercase">
                        {selectedDetection.classification}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono border border-slate-700 bg-slate-900 text-slate-300">
                        Rule: {selectedDetection.rule_code} (v{selectedDetection.rule_version})
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono border border-emerald-800 bg-emerald-950 text-emerald-300">
                        Confidence: {(selectedDetection.confidence_score * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-slate-300">Description</h3>
                  <p className="text-xs text-slate-300 leading-relaxed bg-[#070a13] p-3 rounded-lg border border-[#1a2744]">
                    {selectedDetection.description}
                  </p>
                </div>

                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-slate-300">Detection Rationale & Evidence Basis</h3>
                  <p className="text-xs text-slate-300 leading-relaxed bg-[#070a13] p-3 rounded-lg border border-[#1a2744] font-mono">
                    {selectedDetection.detection_rationale}
                  </p>
                </div>

                {/* MITRE ATT&CK Badges */}
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-slate-300">MITRE ATT&CK Mapping</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedDetection.mitre_tactics?.map((tac, idx) => (
                      <span key={idx} className="px-2.5 py-1 rounded bg-[#10192e] text-cyan-300 border border-cyan-800/60 text-xs font-mono">
                        Tactic: {tac}
                      </span>
                    ))}
                    {selectedDetection.mitre_techniques?.map((tech, idx) => (
                      <span key={idx} className="px-2.5 py-1 rounded bg-[#10192e] text-indigo-300 border border-indigo-800/60 text-xs font-mono">
                        Technique: {tech.technique_id || tech.id || "T1078"} - {tech.name || "Technique"}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Affected Assets */}
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-slate-300">Directly Affected Synthetic Assets</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedDetection.affected_asset_ids?.map((aid, idx) => (
                      <span key={idx} className="px-2.5 py-1 rounded bg-rose-950/40 text-rose-300 border border-rose-800/60 text-xs font-mono">
                        {aid}
                      </span>
                    ))}
                  </div>
                </div>

                {/* AI Threat Explanation Action */}
                <div className="pt-3 border-t border-[#1a2744] space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-xs font-semibold text-white flex items-center gap-1.5">
                        <Brain className="h-4 w-4 text-cyan-400" />
                        <span>AI Advisory Reasoning</span>
                      </span>
                      <p className="text-[11px] text-slate-500">
                        EvidenceGuard-bounded synthesis of adversary ingress, technique, and containment.
                      </p>
                    </div>

                    <button
                      onClick={() => handleExplainThreat(selectedDetection.id)}
                      disabled={aiExplaining}
                      className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors disabled:opacity-50"
                    >
                      <Sparkles className={`h-3.5 w-3.5 ${aiExplaining ? "animate-spin" : ""}`} />
                      <span>{aiExplaining ? "Analyzing..." : "Explain with AI"}</span>
                    </button>
                  </div>

                  {aiExplanation && (
                    <div className="rounded-lg border border-cyan-800/60 bg-[#070a13] p-3.5 text-xs space-y-2">
                      <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                        <span className="text-cyan-300 font-semibold">AI Threat Intelligence Dossier</span>
                        <span>{aiExplanation.fallback_used ? "Deterministic Fallback" : "Live Gemini"}</span>
                      </div>
                      {aiExplanation.summary && (
                        <p className="text-slate-200 leading-relaxed">{aiExplanation.summary}</p>
                      )}
                      {aiExplanation.explanation && (
                        <p className="text-slate-200 leading-relaxed">{aiExplanation.explanation}</p>
                      )}
                      {aiExplanation.evidence_references && aiExplanation.evidence_references.length > 0 && (
                        <div className="text-[10px] text-slate-400 font-mono pt-1">
                          <span className="text-slate-500">Cited Evidence: </span>
                          {aiExplanation.evidence_references.join(", ")}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="py-20 text-center text-xs text-slate-500">
                Select a detection to view structured telemetry and evidence.
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUB-TAB 2: ASSET IMPACT & BLAST RADIUS */}
      {activeTab === "impact" && (
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1a2744] pb-4">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <Network className="h-4 w-4 text-cyan-400" />
                Asset Impact & Blast Radius Evaluation
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Evaluates direct compromise vs downstream exposure through topology relationship traversal.
              </p>
            </div>

            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300">
                DIRECTLY AFFECTED: {riskSummary?.directly_affected_assets_count ?? 0}
              </span>
              <span className="px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-amber-300">
                POTENTIALLY EXPOSED: {riskSummary?.potentially_exposed_assets_count ?? 0}
              </span>
            </div>
          </div>

          {impactedAssets.length === 0 ? (
            <div className="py-12 text-center text-xs text-slate-400">
              <CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto mb-2" />
              <p className="font-semibold text-white">No Asset Blast Radius Recorded</p>
              <p className="text-slate-500 mt-1">Select or run an execution with multi-stage attack paths.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#1a2744] text-[11px] text-slate-400 font-mono">
                    <th className="pb-2.5 font-normal">IMPACT TYPE</th>
                    <th className="pb-2.5 font-normal">TARGET ASSET ID</th>
                    <th className="pb-2.5 font-normal">IMPACT SCORE</th>
                    <th className="pb-2.5 font-normal">TRAVERSAL DEPTH</th>
                    <th className="pb-2.5 font-normal">RELATIONSHIP PATH</th>
                    <th className="pb-2.5 font-normal">RATIONALE</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1a2744]/60">
                  {impactedAssets.map((imp) => (
                    <tr key={imp.id} className="hover:bg-[#10192e] transition-colors">
                      <td className="py-3 font-mono">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] border ${
                            imp.impact_type === "DIRECTLY_AFFECTED"
                              ? "bg-rose-950/70 text-rose-300 border-rose-700/60"
                              : "bg-amber-950/70 text-amber-300 border-amber-700/60"
                          }`}
                        >
                          {imp.impact_type}
                        </span>
                      </td>
                      <td className="py-3 font-mono text-cyan-300 font-semibold">{imp.asset_id}</td>
                      <td className="py-3 font-mono font-bold text-white">{imp.impact_score.toFixed(1)} / 10</td>
                      <td className="py-3 font-mono text-slate-300">Hop {imp.traversal_depth}</td>
                      <td className="py-3 font-mono text-[11px] text-slate-400">
                        {imp.relationship_path && imp.relationship_path.length > 0
                          ? imp.relationship_path.join(" → ")
                          : "Root Node (Direct)"}
                      </td>
                      <td className="py-3 text-slate-300 text-[11px] max-w-xs">{imp.impact_rationale}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* SUB-TAB 3: MULTI-FACTOR RISK ANALYSIS */}
      {activeTab === "risk" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Risk Assessments list */}
          <div className="lg:col-span-1 rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-4 space-y-3">
            <h2 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              RISK ASSESSMENTS ({riskAssessments.length})
            </h2>

            <div className="space-y-2 max-h-[550px] overflow-y-auto pr-1">
              {riskAssessments.map((ass) => (
                <div
                  key={ass.id}
                  onClick={() => handleSelectAssessment(ass)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${
                    selectedAssessment?.id === ass.id
                      ? "border-cyan-500/80 bg-cyan-950/30"
                      : "border-[#1a2744] bg-[#070a13] hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-xs font-bold text-white">
                      Risk: {ass.risk_score.toFixed(1)} / 10
                    </span>
                    <span
                      className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                        ass.risk_category === "Critical"
                          ? "bg-rose-950 text-rose-300 border border-rose-800"
                          : ass.risk_category === "High"
                          ? "bg-amber-950 text-amber-300 border border-amber-800"
                          : "bg-cyan-950 text-cyan-300 border border-cyan-800"
                      }`}
                    >
                      {ass.risk_category}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-2 font-mono truncate">
                    Formula: {ass.scoring_formula_version}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Assessment Detail & 6-Dimension Breakdown */}
          <div className="lg:col-span-2 rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 space-y-5">
            {selectedAssessment ? (
              <>
                <div className="flex items-center justify-between border-b border-[#1a2744] pb-4">
                  <div>
                    <h2 className="text-base font-bold text-white flex items-center gap-2">
                      <Flame className="h-5 w-5 text-amber-400" />
                      Multi-Factor Bounded Risk Score: {selectedAssessment.risk_score.toFixed(1)} / 10.0
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Formula Version: {selectedAssessment.scoring_formula_version} • Status: {selectedAssessment.assessment_status}
                    </p>
                  </div>

                  <span
                    className={`px-2.5 py-1 rounded text-xs font-mono font-bold border ${
                      selectedAssessment.risk_category === "Critical"
                        ? "bg-rose-950 text-rose-300 border-rose-700"
                        : "bg-amber-950 text-amber-300 border-amber-700"
                    }`}
                  >
                    {selectedAssessment.risk_category.toUpperCase()}
                  </span>
                </div>

                {/* 5 Component Scoring Gauges */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="rounded-lg border border-[#1a2744] bg-[#070a13] p-3 text-xs">
                    <div className="flex justify-between text-slate-400 mb-1">
                      <span>Asset Criticality Score</span>
                      <span className="font-mono text-cyan-400 font-bold">{selectedAssessment.asset_criticality_score.toFixed(1)} / 10</span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div className="bg-cyan-400 h-full" style={{ width: `${selectedAssessment.asset_criticality_score * 10}%` }} />
                    </div>
                  </div>

                  <div className="rounded-lg border border-[#1a2744] bg-[#070a13] p-3 text-xs">
                    <div className="flex justify-between text-slate-400 mb-1">
                      <span>Direct Impact Score</span>
                      <span className="font-mono text-rose-400 font-bold">{selectedAssessment.direct_impact_score.toFixed(1)} / 10</span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div className="bg-rose-500 h-full" style={{ width: `${selectedAssessment.direct_impact_score * 10}%` }} />
                    </div>
                  </div>

                  <div className="rounded-lg border border-[#1a2744] bg-[#070a13] p-3 text-xs">
                    <div className="flex justify-between text-slate-400 mb-1">
                      <span>Blast Radius Score</span>
                      <span className="font-mono text-amber-400 font-bold">{selectedAssessment.blast_radius_score.toFixed(1)} / 10</span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div className="bg-amber-400 h-full" style={{ width: `${selectedAssessment.blast_radius_score * 10}%` }} />
                    </div>
                  </div>

                  <div className="rounded-lg border border-[#1a2744] bg-[#070a13] p-3 text-xs">
                    <div className="flex justify-between text-slate-400 mb-1">
                      <span>Evidence Confidence Score</span>
                      <span className="font-mono text-emerald-400 font-bold">{selectedAssessment.evidence_confidence_score.toFixed(1)} / 10</span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div className="bg-emerald-400 h-full" style={{ width: `${selectedAssessment.evidence_confidence_score * 10}%` }} />
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-slate-300">Assessment Rationale</h3>
                  <p className="text-xs text-slate-300 leading-relaxed bg-[#070a13] p-3 rounded-lg border border-[#1a2744] font-mono">
                    {selectedAssessment.assessment_rationale}
                  </p>
                </div>
              </>
            ) : (
              <div className="py-20 text-center text-xs text-slate-500">
                Select a risk assessment to view its multi-factor mathematical breakdown.
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUB-TAB 4: EVENT INGESTION & CORRELATION */}
      {activeTab === "ingestion" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Correlated Event Groups */}
          <div className="rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-4 space-y-3">
            <h2 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              CORRELATED EVENT GROUPS ({groups.length})
            </h2>

            {groups.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500">
                No correlated groups in current execution.
              </div>
            ) : (
              <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                {groups.map((grp) => (
                  <div
                    key={grp.id}
                    onClick={() => setSelectedGroup(grp)}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      selectedGroup?.id === grp.id
                        ? "border-cyan-500/80 bg-cyan-950/30"
                        : "border-[#1a2744] bg-[#070a13] hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-white">{grp.title}</span>
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
                        {grp.correlation_basis}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-1 font-mono">
                      Rule: {grp.correlation_rule} • {grp.member_event_ids?.length || 0} events
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Raw Ingested Events Stream */}
          <div className="rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-4 space-y-3">
            <h2 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              INGESTED TELEMETRY STREAM ({events.length})
            </h2>

            {events.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500">
                No defensive events ingested yet.
              </div>
            ) : (
              <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                {events.map((ev) => (
                  <div key={ev.id} className="p-3 rounded-lg border border-[#1a2744] bg-[#070a13] text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-cyan-300 font-mono">{ev.event_type}</span>
                      <span className="font-mono text-[10px] text-slate-500">
                        {new Date(ev.original_timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400">
                      <Hash className="h-3 w-3 text-slate-500" />
                      <span className="truncate">SHA256: {ev.sha256_hash}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

