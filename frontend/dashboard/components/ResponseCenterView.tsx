"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import {
  DefensiveRecommendation,
  Playbook,
  RemediationPlan,
  IncidentReport,
  ExecutiveSummary,
} from "../lib/types";
import {
  ShieldAlert,
  ShieldCheck,
  FileText,
  BookOpen,
  ListOrdered,
  Award,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ArrowRight,
  RefreshCw,
  PlusCircle,
  ExternalLink,
  ChevronRight,
  Flame,
  Activity,
  Layers,
  Sparkles,
  UserCheck,
  FileCheck,
} from "lucide-react";
import { ApprovalCenter } from "./ApprovalCenter";
import { SyntheticRemediationView } from "./SyntheticRemediationView";
import { VerificationCenter } from "./VerificationCenter";
import { AuditExplorer } from "./AuditExplorer";

export type ResponseTab =
  | "approvals"
  | "remediation"
  | "verification"
  | "audit"
  | "recommendations"
  | "playbooks"
  | "plans"
  | "reports"
  | "executive";

export const ResponseCenterView: React.FC = () => {
  const { activeSandbox } = useAuth();
  const [activeTab, setActiveTab] = useState<ResponseTab>("approvals");
  const [activeRemediationExecId, setActiveRemediationExecId] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Data states
  const [recommendations, setRecommendations] = useState<DefensiveRecommendation[]>([]);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);
  const [remediationPlans, setRemediationPlans] = useState<RemediationPlan[]>([]);
  const [selectedPlan, setSelectedPlan] = useState<RemediationPlan | null>(null);
  const [reports, setReports] = useState<IncidentReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<IncidentReport | null>(null);
  const [execSummary, setExecSummary] = useState<ExecutiveSummary | null>(null);

  // Report generation state
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);

  const fetchResponseData = useCallback(async () => {
    if (!activeSandbox) return;
    setLoading(true);
    setError(null);

    try {
      const [recs, pbooks, plans, reps] = await Promise.all([
        api.guardian.listRecommendations({ sandbox_id: activeSandbox.id, page_size: 50 }),
        api.guardian.listPlaybooks(),
        api.guardian.listRemediationPlans({ sandbox_id: activeSandbox.id }),
        api.guardian.listIncidentReports({ sandbox_id: activeSandbox.id }),
      ]);

      setRecommendations(recs.items || []);
      setPlaybooks(pbooks.playbooks || []);
      if (pbooks.playbooks && pbooks.playbooks.length > 0) {
        setSelectedPlaybook(pbooks.playbooks[0]);
      }

      setRemediationPlans(plans.items || []);
      if (plans.items && plans.items.length > 0) {
        // Fetch detailed plan including actions
        try {
          const detPlan = await api.guardian.getRemediationPlan(plans.items[0].id);
          setSelectedPlan(detPlan);
        } catch {
          setSelectedPlan(plans.items[0]);
        }
      }

      setReports(reps.items || []);
      if (reps.items && reps.items.length > 0) {
        try {
          const detRep = await api.guardian.getIncidentReport(reps.items[0].id);
          setSelectedReport(detRep);
          // Also fetch executive summary using the report's guardian_execution_id
          const sum = await api.guardian.getExecutiveSummary(reps.items[0].guardian_execution_id);
          setExecSummary(sum);
        } catch {
          setSelectedReport(reps.items[0]);
        }
      }
    } catch (err: any) {
      console.error("Failed to load response center data:", err);
      setError(err?.message || "Failed to load response center telemetry.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [activeSandbox]);

  useEffect(() => {
    fetchResponseData();
  }, [fetchResponseData]);

  const handleSelectPlan = async (plan: RemediationPlan) => {
    try {
      const detPlan = await api.guardian.getRemediationPlan(plan.id);
      setSelectedPlan(detPlan);
    } catch {
      setSelectedPlan(plan);
    }
  };

  const handleSelectReport = async (rep: IncidentReport) => {
    try {
      const detRep = await api.guardian.getIncidentReport(rep.id);
      setSelectedReport(detRep);
      const sum = await api.guardian.getExecutiveSummary(rep.guardian_execution_id);
      setExecSummary(sum);
    } catch {
      setSelectedReport(rep);
    }
  };

  const handleGenerateReport = async () => {
    if (!selectedPlan?.guardian_execution_id && (!reports.length || !reports[0]?.guardian_execution_id)) {
      return;
    }
    const executionId = selectedPlan?.guardian_execution_id || reports[0]?.guardian_execution_id;
    setIsGeneratingReport(true);
    try {
      const newReport = await api.guardian.generateIncidentReport(executionId, {
        custom_title: `Autonomous Security Incident Assessment (${new Date().toLocaleDateString()})`,
        include_ai_narrative: true,
      });
      await fetchResponseData();
      setSelectedReport(newReport);
    } catch (err: any) {
      console.error("Failed to generate incident report:", err);
      setError(err?.message || "Failed to generate report version.");
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const getPriorityBadge = (p: string) => {
    switch (p) {
      case "P0":
        return "bg-rose-950 text-rose-300 border-rose-700";
      case "P1":
        return "bg-amber-950 text-amber-300 border-amber-700";
      case "P2":
        return "bg-yellow-950 text-yellow-300 border-yellow-700";
      default:
        return "bg-cyan-950 text-cyan-300 border-cyan-700";
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 backdrop-blur-md">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
            Autonomous Response & Remediation Center
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Evidence-backed mitigation playbooks, sequenced remediation plans, and epistemic incident reports.
          </p>
        </div>

        <button
          onClick={() => {
            setRefreshing(true);
            fetchResponseData();
          }}
          disabled={loading || refreshing}
          className="flex items-center gap-1.5 rounded-lg border border-[#1a2744] bg-[#070a13] px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:border-cyan-500/50 transition-all disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin text-cyan-400" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Sub-tab Navigation */}
      <div className="flex flex-wrap items-center gap-2 border-b border-[#1a2744] pb-2">
        <button
          onClick={() => setActiveTab("approvals")}
          className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "approvals"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <UserCheck className="h-3.5 w-3.5 text-cyan-400" />
          <span>Human Approvals & Governance</span>
        </button>

        <button
          onClick={() => setActiveTab("remediation")}
          className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "remediation"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
          <span>Synthetic Remediation</span>
        </button>

        <button
          onClick={() => setActiveTab("verification")}
          className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "verification"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <FileCheck className="h-3.5 w-3.5 text-blue-400" />
          <span>Verification & Snapshots</span>
        </button>

        <button
          onClick={() => setActiveTab("audit")}
          className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "audit"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <FileText className="h-3.5 w-3.5 text-amber-400" />
          <span>Audit Ledger</span>
        </button>

        <button
          onClick={() => setActiveTab("recommendations")}
          className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "recommendations"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <ShieldAlert className="h-3.5 w-3.5" />
          <span>Recommendations ({recommendations.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("playbooks")}
          className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "playbooks"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <BookOpen className="h-3.5 w-3.5" />
          <span>Playbooks ({playbooks.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("plans")}
          className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "plans"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <ListOrdered className="h-3.5 w-3.5" />
          <span>Plans ({remediationPlans.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("reports")}
          className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "reports"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <FileText className="h-3.5 w-3.5" />
          <span>Reports ({reports.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("executive")}
          className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === "executive"
              ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <Award className="h-3.5 w-3.5" />
          <span>Executive Posture</span>
        </button>
      </div>

      {/* TAB 0: HUMAN APPROVALS & FOUR-EYES GOVERNANCE */}
      {activeTab === "approvals" && (
        <ApprovalCenter
          onRemediationExecuted={(execId) => {
            setActiveRemediationExecId(execId);
            setActiveTab("remediation");
          }}
        />
      )}

      {/* TAB 0.5: SYNTHETIC REMEDIATION PROGRESS */}
      {activeTab === "remediation" && (
        <SyntheticRemediationView
          initialExecutionId={activeRemediationExecId}
          onNavigateToVerification={(execId) => {
            setActiveRemediationExecId(execId);
            setActiveTab("verification");
          }}
        />
      )}

      {/* TAB 0.75: VERIFICATION & SNAPSHOTS */}
      {activeTab === "verification" && (
        <VerificationCenter initialExecutionId={activeRemediationExecId} />
      )}

      {/* TAB 0.9: AUDIT LEDGER */}
      {activeTab === "audit" && <AuditExplorer />}

      {/* TAB 1: DEFENSIVE RECOMMENDATIONS */}
      {activeTab === "recommendations" && (
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-[#1a2744] pb-4">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-cyan-400" />
                Evidence-Backed Recommendations
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Targeted mitigation guidance synthesized directly from correlated attack detections.
              </p>
            </div>
            <span className="font-mono text-xs text-cyan-400">
              Total: {recommendations.length}
            </span>
          </div>

          {recommendations.length === 0 ? (
            <div className="py-12 text-center text-xs text-slate-400">
              <CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto mb-2" />
              <p className="font-semibold text-white">No active defensive recommendations.</p>
              <p className="text-slate-500 mt-1">Run a simulation and execute Blue Guardian to generate plans.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {recommendations.map((rec) => (
                <div key={rec.id} className="p-4 rounded-xl border border-[#1a2744] bg-[#070a13] space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getPriorityBadge(rec.priority)}`}>
                          {rec.priority}
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-800">
                          {rec.recommendation_type.toUpperCase()}
                        </span>
                        <span className="text-[10px] font-mono text-slate-400">
                          Playbook: {rec.playbook_id} (v{rec.playbook_version})
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-white mt-1.5">{rec.title}</h3>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-300 border border-slate-700 capitalize">
                      {rec.status}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300">{rec.description}</p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs">
                    <div className="p-2.5 rounded-lg border border-[#1a2744] bg-[#0c1222]">
                      <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">Expected Outcome</span>
                      <p className="text-slate-300 text-[11px]">{rec.expected_outcome}</p>
                    </div>

                    <div className="p-2.5 rounded-lg border border-[#1a2744] bg-[#0c1222]">
                      <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">Verification Criteria</span>
                      <ul className="text-slate-300 text-[11px] space-y-1 list-disc list-inside">
                        {rec.verification_criteria?.map((vc, i) => (
                          <li key={i}>{vc}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: PLAYBOOK LIBRARY */}
      {activeTab === "playbooks" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-4 space-y-3">
            <h2 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              CATALOG ({playbooks.length} PLAYBOOKS)
            </h2>

            <div className="space-y-2 max-h-[550px] overflow-y-auto pr-1">
              {playbooks.map((pb) => (
                <div
                  key={pb.playbook_id}
                  onClick={() => setSelectedPlaybook(pb)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${
                    selectedPlaybook?.playbook_id === pb.playbook_id
                      ? "border-cyan-500/80 bg-cyan-950/30"
                      : "border-[#1a2744] bg-[#070a13] hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-cyan-400 text-[10px]">{pb.playbook_id}</span>
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono border ${getPriorityBadge(pb.default_priority)}`}>
                      {pb.default_priority}
                    </span>
                  </div>
                  <div className="font-semibold text-xs text-white mt-1 line-clamp-1">{pb.title}</div>
                  <div className="text-[11px] text-slate-400 mt-1 capitalize">{pb.recommendation_type}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="lg:col-span-2 rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 space-y-4">
            {selectedPlaybook ? (
              <>
                <div className="border-b border-[#1a2744] pb-4">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-cyan-400">{selectedPlaybook.playbook_id}</span>
                    <span className="text-slate-500 font-mono">v{selectedPlaybook.playbook_version}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getPriorityBadge(selectedPlaybook.default_priority)}`}>
                      Default {selectedPlaybook.default_priority}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 border border-slate-700 text-slate-300">
                      Complexity: {selectedPlaybook.complexity}
                    </span>
                  </div>
                  <h2 className="text-base font-bold text-white mt-1.5">{selectedPlaybook.title}</h2>
                  <p className="text-xs text-slate-300 mt-2 leading-relaxed">{selectedPlaybook.description}</p>
                </div>

                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-slate-300">Rationale & Expected Outcome</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    <div className="bg-[#070a13] p-3 rounded-lg border border-[#1a2744]">
                      <span className="text-[10px] font-mono text-slate-500 block mb-1">RATIONALE</span>
                      <p className="text-slate-300 text-[11px]">{selectedPlaybook.rationale}</p>
                    </div>
                    <div className="bg-[#070a13] p-3 rounded-lg border border-[#1a2744]">
                      <span className="text-[10px] font-mono text-slate-500 block mb-1">EXPECTED OUTCOME</span>
                      <p className="text-slate-300 text-[11px]">{selectedPlaybook.expected_outcome}</p>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-slate-300">
                    Action Templates ({selectedPlaybook.action_templates?.length || 0})
                  </h3>
                  <div className="space-y-2">
                    {selectedPlaybook.action_templates?.map((at, idx) => (
                      <div key={idx} className="p-3 rounded-lg border border-[#1a2744] bg-[#070a13] text-xs space-y-1">
                        <div className="flex items-center justify-between font-semibold text-white">
                          <span>{at.title}</span>
                          <span className="font-mono text-[10px] text-cyan-400">Step {at.sequence_order || idx + 1}</span>
                        </div>
                        <p className="text-slate-400 text-[11px]">{at.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <div className="py-20 text-center text-xs text-slate-500">
                Select a playbook from the catalog to view details.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: REMEDIATION PLANS */}
      {activeTab === "plans" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-4 space-y-3">
            <h2 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              REMEDIATION PLANS ({remediationPlans.length})
            </h2>

            <div className="space-y-2 max-h-[550px] overflow-y-auto pr-1">
              {remediationPlans.map((pln) => (
                <div
                  key={pln.id}
                  onClick={() => handleSelectPlan(pln)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${
                    selectedPlan?.id === pln.id
                      ? "border-cyan-500/80 bg-cyan-950/30"
                      : "border-[#1a2744] bg-[#070a13] hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-white truncate">{pln.title}</span>
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono border ${getPriorityBadge(pln.overall_priority)}`}>
                      {pln.overall_priority}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between font-mono">
                    <span>{pln.action_count} Actions</span>
                    <span className="text-cyan-400 capitalize">{pln.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="lg:col-span-2 rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 space-y-4">
            {selectedPlan ? (
              <>
                <div className="border-b border-[#1a2744] pb-4">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getPriorityBadge(selectedPlan.overall_priority)}`}>
                      Overall {selectedPlan.overall_priority}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 border border-emerald-800 text-emerald-300 uppercase">
                      {selectedPlan.status}
                    </span>
                    <span className="text-slate-400 text-xs font-mono">Plan v{selectedPlan.plan_version}</span>
                  </div>
                  <h2 className="text-base font-bold text-white mt-1.5">{selectedPlan.title}</h2>
                  <p className="text-xs text-slate-300 mt-1">{selectedPlan.description}</p>
                </div>

                <div className="space-y-3">
                  <h3 className="text-xs font-semibold text-slate-300 flex items-center gap-2">
                    <ListOrdered className="h-4 w-4 text-cyan-400" />
                    Ordered Action Sequence ({selectedPlan.actions?.length || selectedPlan.action_count} Actions)
                  </h3>

                  {selectedPlan.actions && selectedPlan.actions.length > 0 ? (
                    <div className="space-y-2">
                      {selectedPlan.actions.map((act) => (
                        <div key={act.id} className="p-3 rounded-lg border border-[#1a2744] bg-[#070a13] text-xs space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs font-bold text-cyan-400">
                                #{act.sequence_order}
                              </span>
                              <span className="font-semibold text-white">{act.title}</span>
                            </div>
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 border border-slate-700 text-slate-300 capitalize">
                              {act.status}
                            </span>
                          </div>

                          <p className="text-slate-400 text-[11px]">{act.description}</p>

                          <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono text-slate-500 pt-1">
                            <span>Type: {act.action_type}</span>
                            {act.depends_on && act.depends_on.length > 0 && (
                              <span className="text-amber-400">
                                Depends on: {act.depends_on.join(", ")}
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500">Actions list generated in execution database.</p>
                  )}
                </div>
              </>
            ) : (
              <div className="py-20 text-center text-xs text-slate-500">
                Select a remediation plan to inspect its ordered actions.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: INCIDENT REPORTS */}
      {activeTab === "reports" && (
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1a2744] pb-4">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <FileText className="h-4 w-4 text-cyan-400" />
                Versioned Incident Reports
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Epistemic forensic reports documenting observed events, derived threats, and advisory remediation.
              </p>
            </div>

            <button
              onClick={handleGenerateReport}
              disabled={isGeneratingReport}
              className="flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-3.5 py-1.5 text-xs font-bold text-white shadow-sm shadow-cyan-950 transition-all disabled:opacity-50"
            >
              <PlusCircle className={`h-3.5 w-3.5 ${isGeneratingReport ? "animate-spin" : ""}`} />
              <span>{isGeneratingReport ? "Synthesizing Report..." : "Generate New Version"}</span>
            </button>
          </div>

          {reports.length === 0 ? (
            <div className="py-12 text-center text-xs text-slate-400">
              <FileText className="h-8 w-8 text-slate-600 mx-auto mb-2" />
              <p className="font-semibold text-white">No incident reports generated yet.</p>
              <p className="text-slate-500 mt-1">Click "Generate New Version" to produce an incident report from latest telemetry.</p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Report Version Selector */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400 font-mono">Available Versions:</span>
                {reports.map((r) => (
                  <button
                    key={r.id}
                    onClick={() => handleSelectReport(r)}
                    className={`px-3 py-1 rounded text-xs font-mono transition-all ${
                      selectedReport?.id === r.id
                        ? "bg-cyan-600 text-white font-bold"
                        : "bg-[#070a13] border border-[#1a2744] text-slate-300 hover:border-slate-600"
                    }`}
                  >
                    v{r.report_version}
                  </button>
                ))}
              </div>

              {selectedReport && (
                <div className="space-y-5 rounded-xl border border-[#1a2744] bg-[#070a13] p-5">
                  <div className="border-b border-[#1a2744] pb-4">
                    <div className="flex items-center gap-2 font-mono text-xs">
                      <span className="text-cyan-400">REPORT VERSION {selectedReport.report_version}</span>
                      <span className="text-slate-600">•</span>
                      <span className="text-rose-400 uppercase font-bold">Severity: {selectedReport.severity}</span>
                      <span className="text-slate-600">•</span>
                      <span className="text-amber-400 font-bold">Max Risk: {selectedReport.max_risk_score.toFixed(1)} / 10 ({selectedReport.risk_category})</span>
                    </div>
                    <h2 className="text-lg font-bold text-white mt-2">{selectedReport.title}</h2>
                  </div>

                  <div>
                    <h3 className="text-xs font-mono uppercase text-slate-400 mb-2">Executive Summary</h3>
                    <div className="p-4 rounded-lg border border-[#1a2744] bg-[#0c1222] text-xs text-slate-200 leading-relaxed font-sans">
                      {selectedReport.executive_summary}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                    <div className="p-3 rounded-lg border border-[#1a2744] bg-[#0c1222]">
                      <span className="text-slate-500 block text-[10px]">AFFECTED ASSETS</span>
                      <span className="text-sm font-bold text-rose-400">
                        {selectedReport.affected_asset_ids?.length || 0} Directly Compromised
                      </span>
                    </div>
                    <div className="p-3 rounded-lg border border-[#1a2744] bg-[#0c1222]">
                      <span className="text-slate-500 block text-[10px]">POTENTIALLY EXPOSED</span>
                      <span className="text-sm font-bold text-amber-400">
                        {selectedReport.potentially_exposed_asset_ids?.length || 0} Blast Radius Nodes
                      </span>
                    </div>
                    <div className="p-3 rounded-lg border border-[#1a2744] bg-[#0c1222]">
                      <span className="text-slate-500 block text-[10px]">STATUS</span>
                      <span className="text-sm font-bold text-emerald-400 uppercase">
                        {selectedReport.report_status}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 5: EXECUTIVE POSTURE SUMMARY */}
      {activeTab === "executive" && (
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 space-y-6">
          <div className="border-b border-[#1a2744] pb-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Award className="h-4 w-4 text-cyan-400" />
              Executive Security Posture Briefing
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              High-level strategic briefing designed for CISO & executive stakeholders.
            </p>
          </div>

          {execSummary ? (
            <div className="space-y-5">
              {/* Posture Rating Card */}
              <div className="p-5 rounded-xl border border-[#1a2744] bg-[#070a13] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                  <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                    COMPREHENSIVE POSTURE RATING
                  </span>
                  <div className="text-2xl font-bold font-mono text-white mt-1 flex items-center gap-2">
                    <span>{execSummary.posture_rating}</span>
                    <span className="text-xs font-normal text-slate-400 font-sans">
                      (Max Risk: {execSummary.max_risk_score.toFixed(1)} / 10 • {execSummary.risk_category})
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {execSummary.ai_enriched && (
                    <span className="flex items-center gap-1 px-2.5 py-1 rounded bg-indigo-950 border border-indigo-800 text-indigo-300 text-xs font-mono">
                      <Sparkles className="h-3 w-3" />
                      AI ENRICHED
                    </span>
                  )}
                  <span className="px-2.5 py-1 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 text-xs font-mono">
                    DETERMINISTIC VERIFIED
                  </span>
                </div>
              </div>

              {/* Executive Summary Narrative */}
              <div>
                <h3 className="text-xs font-mono uppercase text-slate-400 mb-2">Executive Overview</h3>
                <div className="p-4 rounded-xl border border-[#1a2744] bg-[#070a13] text-xs text-slate-200 leading-relaxed font-sans">
                  {execSummary.executive_summary}
                </div>
              </div>

              {/* Immediate Priorities */}
              <div>
                <h3 className="text-xs font-mono uppercase text-rose-400 mb-2">Immediate Response Priorities (P0)</h3>
                <div className="space-y-2">
                  {execSummary.immediate_priorities?.map((prio, idx) => (
                    <div key={idx} className="flex items-start gap-2.5 p-3 rounded-lg border border-rose-900/40 bg-rose-950/20 text-xs text-rose-200">
                      <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
                      <span>{prio}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Residual Risks & Uncertainties */}
              <div>
                <h3 className="text-xs font-mono uppercase text-amber-400 mb-2">Residual Risks & Epistemic Uncertainties</h3>
                <div className="space-y-2">
                  {execSummary.residual_risks_and_uncertainties?.map((unc, idx) => (
                    <div key={idx} className="flex items-start gap-2.5 p-3 rounded-lg border border-amber-900/40 bg-amber-950/20 text-xs text-amber-200">
                      <Clock className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                      <span>{unc}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-slate-500">
              No executive summary generated yet. Generate an incident report to create an executive briefing.
            </div>
          )}
        </div>
      )}
    </div>
  );
};

