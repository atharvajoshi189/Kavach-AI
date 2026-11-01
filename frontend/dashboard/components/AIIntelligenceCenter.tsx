"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import {
  AegisAgentOutput,
  AgentMetadata,
  AIGatewayHealth,
  AIAnalysisRecord,
  AIUsageMetrics,
  GraphExecutionResponse,
  GraphHealthResponse,
  GuardianExecution,
} from "../lib/types";
import {
  Bot,
  Cpu,
  Brain,
  Shield,
  Activity,
  Play,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Sparkles,
  Zap,
  ChevronRight,
  GitBranch,
  Layers,
  Search,
  MessageSquare,
  FileText,
  HelpCircle,
  ExternalLink,
} from "lucide-react";

type AICenterTab = "gateway" | "agents" | "graph" | "history";

interface AIIntelligenceCenterProps {
  initialTab?: AICenterTab;
}

export const AIIntelligenceCenter: React.FC<AIIntelligenceCenterProps> = ({
  initialTab = "gateway",
}) => {
  const { activeSandbox } = useAuth();
  const [activeTab, setActiveTab] = useState<AICenterTab>(initialTab);

  // Common context & executions
  const [executions, setExecutions] = useState<GuardianExecution[]>([]);
  const [selectedExecutionId, setSelectedExecutionId] = useState<string>("");

  // Tab 1: AI Gateway
  const [gatewayHealth, setGatewayHealth] = useState<AIGatewayHealth | null>(null);
  const [usageMetrics, setUsageMetrics] = useState<AIUsageMetrics | null>(null);
  const [qaQuestion, setQaQuestion] = useState("");
  const [qaAnswer, setQaAnswer] = useState<any>(null);
  const [qaLoading, setQaLoading] = useState(false);

  // Tab 2: Specialized AI Agents
  const [agents, setAgents] = useState<AgentMetadata[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [agentOutput, setAgentOutput] = useState<AegisAgentOutput | null>(null);
  const [agentLoading, setAgentLoading] = useState(false);
  const [agentCustomQuery, setAgentCustomQuery] = useState("");

  // Tab 3: Multi-Agent Graph (LangGraph)
  const [graphHealth, setGraphHealth] = useState<GraphHealthResponse | null>(null);
  const [graphRequestType, setGraphRequestType] = useState<string>("full_investigation");
  const [graphQuery, setGraphQuery] = useState("");
  const [graphRunning, setGraphRunning] = useState(false);
  const [graphResult, setGraphResult] = useState<GraphExecutionResponse | null>(null);
  const [activeAgentInspector, setActiveAgentInspector] = useState<string | null>(null);

  // Tab 4: AI Analysis History
  const [historyRecords, setHistoryRecords] = useState<AIAnalysisRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [selectedAnalysis, setSelectedAnalysis] = useState<AIAnalysisRecord | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load executions for the active sandbox
  const loadExecutions = useCallback(async () => {
    if (!activeSandbox) return;
    try {
      const list = await api.guardian.listExecutions(activeSandbox.id, 10);
      setExecutions(list);
      if (list.length > 0 && !selectedExecutionId) {
        setSelectedExecutionId(list[0].execution_id);
      }
    } catch {
      // Ignored if no executions yet
    }
  }, [activeSandbox, selectedExecutionId]);

  // Load Gateway & Graph Health & Agents
  const loadInitialData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [gwRes, useRes, grRes, agRes] = await Promise.allSettled([
        api.ai.getGatewayHealth(),
        api.ai.getUsageMetrics(),
        api.ai.getGraphHealth(),
        api.ai.listAgents(),
      ]);

      if (gwRes.status === "fulfilled") setGatewayHealth(gwRes.value);
      if (useRes.status === "fulfilled") setUsageMetrics(useRes.value);
      if (grRes.status === "fulfilled") setGraphHealth(grRes.value);
      if (agRes.status === "fulfilled") setAgents(agRes.value.agents);
    } catch (err: any) {
      setError(err?.message || "Failed to load AI intelligence components");
    } finally {
      setLoading(false);
    }
  }, []);

  // Load history records
  const loadHistory = useCallback(async () => {
    if (!selectedExecutionId) {
      setHistoryRecords([]);
      return;
    }
    setHistoryLoading(true);
    try {
      const res = await api.ai.listAnalyses(selectedExecutionId);
      setHistoryRecords(res.analyses || []);
    } catch {
      setHistoryRecords([]);
    } finally {
      setHistoryLoading(false);
    }
  }, [selectedExecutionId]);

  useEffect(() => {
    loadExecutions();
    loadInitialData();
  }, [loadExecutions, loadInitialData]);

  useEffect(() => {
    if (activeTab === "history") {
      loadHistory();
    }
  }, [activeTab, loadHistory]);

  // Trigger Contextual Security Q&A
  const handleAskQuestion = async () => {
    if (!qaQuestion.trim() || !selectedExecutionId) return;
    setQaLoading(true);
    setQaAnswer(null);
    try {
      const res = await api.ai.askSecurityQuestion(selectedExecutionId, qaQuestion);
      setQaAnswer(res);
    } catch (err: any) {
      setQaAnswer({ error: err?.message || "Failed to complete security question inquiry." });
    } finally {
      setQaLoading(false);
    }
  };

  // Execute a single specialized agent
  const handleExecuteSingleAgent = async (agentName: string) => {
    if (!activeSandbox) return;
    setSelectedAgent(agentName);
    setAgentLoading(true);
    setAgentOutput(null);
    try {
      const output = await api.ai.executeSingleAgent({
        sandbox_id: activeSandbox.id,
        agent_name: agentName,
        execution_id: selectedExecutionId || undefined,
        user_query: agentCustomQuery.trim() || undefined,
      });
      setAgentOutput(output);
    } catch (err: any) {
      setError(err?.message || `Failed to execute agent ${agentName}`);
    } finally {
      setAgentLoading(false);
    }
  };

  // Execute full or scoped LangGraph multi-agent graph
  const handleExecuteGraph = async () => {
    if (!activeSandbox) return;
    setGraphRunning(true);
    setGraphResult(null);
    setActiveAgentInspector(null);
    try {
      const res = await api.ai.executeGraph({
        sandbox_id: activeSandbox.id,
        execution_id: selectedExecutionId || undefined,
        request_type: graphRequestType,
        user_query: graphQuery.trim() || undefined,
      });
      setGraphResult(res);
      const firstAgent = Object.keys(res.agent_outputs || {})[0];
      if (firstAgent) setActiveAgentInspector(firstAgent);
    } catch (err: any) {
      setError(err?.message || "Multi-agent graph execution failed");
    } finally {
      setGraphRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between border-b border-[#1a2744] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white tracking-wide">AI Security Intelligence Center</h1>
            <span className="rounded bg-cyan-950/80 px-2 py-0.5 text-xs font-mono text-cyan-400 border border-cyan-800/60">
              LANGGRAPH + GEMINI
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Evidence-grounded multi-agent reasoning, specialized advisory agents, and deterministic safety fallbacks.
          </p>
        </div>

        {/* Execution Context Selector */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 font-mono">Execution Context:</span>
          <select
            value={selectedExecutionId}
            onChange={(e) => setSelectedExecutionId(e.target.value)}
            className="rounded-lg border border-[#1a2744] bg-[#0c1222] px-2.5 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            {executions.length === 0 ? (
              <option value="">No executions in sandbox</option>
            ) : (
              executions.map((ex) => (
                <option key={ex.execution_id} value={ex.execution_id}>
                  {ex.execution_id.slice(0, 8)} - {ex.status} ({ex.threat_detections_count || 0} threats)
                </option>
              ))
            )}
          </select>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-900/60 bg-rose-950/20 p-4 text-xs text-rose-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-slate-400 hover:text-white text-xs">
            Dismiss
          </button>
        </div>
      )}

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-2 border-b border-[#1a2744] pb-2 text-xs">
        {[
          { id: "gateway", label: "AI Gateway & Q&A", icon: Brain },
          { id: "agents", label: "Specialized Agents (6)", icon: Bot },
          { id: "graph", label: "Multi-Agent Graph (LangGraph)", icon: GitBranch },
          { id: "history", label: "Analysis History", icon: Clock },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as AICenterTab)}
              className={`flex items-center gap-2 rounded-lg px-3 py-1.5 font-medium transition-all ${
                isActive
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-800"
                  : "text-slate-400 hover:bg-[#0c1222] hover:text-slate-200 border border-transparent"
              }`}
            >
              <Icon className="h-3.5 w-3.5 text-cyan-400" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB 1: AI GATEWAY & CONTEXTUAL Q&A */}
      {activeTab === "gateway" && (
        <div className="space-y-6">
          {/* Status & Usage Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-4">
              <span className="text-[10px] text-slate-500 font-mono uppercase">Provider Status</span>
              <div className="flex items-center gap-2 mt-1">
                <span
                  className={`h-2.5 w-2.5 rounded-full ${
                    gatewayHealth?.is_available ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
                  }`}
                />
                <span className="text-sm font-bold text-white uppercase">
                  {gatewayHealth?.provider || "Gemini"}
                </span>
                <span className="text-[10px] text-cyan-400 font-mono ml-auto">
                  {gatewayHealth?.model || "gemini-2.5-flash"}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-2">
                EvidenceGuard grounding active. Fail-closed deterministic fallback protection enabled.
              </p>
            </div>

            <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-4">
              <span className="text-[10px] text-slate-500 font-mono uppercase">Total Requests</span>
              <div className="text-xl font-bold text-white mt-1">
                {usageMetrics?.total_requests || 0}
              </div>
              <div className="flex items-center gap-2 text-[10px] text-slate-400 mt-2 font-mono">
                <span className="text-emerald-400">{usageMetrics?.successful_requests || 0} Success</span>
                <span>•</span>
                <span className="text-amber-400">{usageMetrics?.fallback_requests || 0} Fallbacks</span>
              </div>
            </div>

            <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-4">
              <span className="text-[10px] text-slate-500 font-mono uppercase">Average Latency</span>
              <div className="text-xl font-bold text-cyan-400 mt-1">
                {usageMetrics?.average_latency_ms ? `${Math.round(usageMetrics.average_latency_ms)} ms` : "—"}
              </div>
              <p className="text-[11px] text-slate-400 mt-2">
                Cached responses: {usageMetrics?.cached_requests || 0} hits
              </p>
            </div>

            <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-4">
              <span className="text-[10px] text-slate-500 font-mono uppercase">Token Consumption</span>
              <div className="text-xl font-bold text-white mt-1">
                {((usageMetrics?.total_input_tokens || 0) + (usageMetrics?.total_output_tokens || 0)).toLocaleString()}
              </div>
              <p className="text-[11px] text-slate-400 mt-2 font-mono">
                In: {(usageMetrics?.total_input_tokens || 0).toLocaleString()} | Out: {(usageMetrics?.total_output_tokens || 0).toLocaleString()}
              </p>
            </div>
          </div>

          {/* Contextual Security Q&A Assistant */}
          <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-5 space-y-4">
            <div className="flex items-center gap-2 border-b border-[#1a2744] pb-3">
              <MessageSquare className="h-4 w-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white">Contextual Security Q&A Assistant</h3>
              <span className="text-[10px] text-slate-400 font-mono ml-auto">
                Evidence-Grounded in Current Execution Telemetry
              </span>
            </div>

            <p className="text-xs text-slate-400">
              Ask questions about observed attack vectors, MITRE ATT&CK techniques, risk drivers, or recommended playbooks. All responses strictly cite verified database records.
            </p>

            <div className="flex gap-2">
              <input
                type="text"
                value={qaQuestion}
                onChange={(e) => setQaQuestion(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleAskQuestion()}
                placeholder="e.g. Which synthetic asset was compromised first, and what mitigation is proposed?"
                className="flex-1 rounded-lg border border-[#1a2744] bg-[#070a13] px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
              />
              <button
                onClick={handleAskQuestion}
                disabled={qaLoading || !qaQuestion.trim() || !selectedExecutionId}
                className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors disabled:opacity-50 shrink-0"
              >
                <Sparkles className={`h-3.5 w-3.5 ${qaLoading ? "animate-spin" : ""}`} />
                <span>{qaLoading ? "Analyzing..." : "Ask Assistant"}</span>
              </button>
            </div>

            {/* Q&A Output Display */}
            {qaAnswer && (
              <div className="rounded-lg border border-cyan-800/60 bg-[#070a13] p-4 text-xs space-y-3 mt-4">
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                  <span className="font-semibold text-cyan-300">Grounded Security Intelligence</span>
                  <span className="text-[10px] text-slate-500 font-mono">
                    {qaAnswer.fallback_used ? "Deterministic Fallback" : "Live Gemini"}
                  </span>
                </div>

                {qaAnswer.summary && <p className="text-slate-200 leading-relaxed">{qaAnswer.summary}</p>}
                {qaAnswer.answer && <p className="text-slate-200 leading-relaxed">{qaAnswer.answer}</p>}
                {qaAnswer.explanation && <p className="text-slate-200 leading-relaxed">{qaAnswer.explanation}</p>}

                {qaAnswer.evidence_references && qaAnswer.evidence_references.length > 0 && (
                  <div className="text-[10px] text-slate-400 font-mono">
                    <span className="text-slate-500">Cited Evidence IDs: </span>
                    {qaAnswer.evidence_references.join(", ")}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: SPECIALIZED AI AGENTS */}
      {activeTab === "agents" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {agents.map((ag) => {
              const agentId = ag.agent_name || ag.name || "";
              return (
                <div
                  key={agentId}
                  className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-4 flex flex-col justify-between hover:border-cyan-800/60 transition-colors shadow-sm"
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-950/80 border border-cyan-800/60 text-cyan-400">
                        <Bot className="h-4 w-4" />
                      </div>
                      <span className="rounded bg-emerald-950 px-2 py-0.5 text-[10px] font-mono text-emerald-400 border border-emerald-800">
                        ADVISORY
                      </span>
                    </div>

                    <h3 className="text-sm font-bold text-white">{ag.display_name}</h3>
                    <span className="text-[10px] text-cyan-400 font-mono">{agentId}</span>
                    <p className="text-xs text-slate-300 mt-2 leading-relaxed">{ag.description}</p>

                    <div className="mt-3 space-y-1">
                      <span className="text-[10px] font-semibold text-slate-400 uppercase">Key Responsibilities:</span>
                      <ul className="text-[11px] text-slate-400 list-disc list-inside space-y-0.5">
                        {ag.responsibilities.slice(0, 3).map((r, i) => (
                          <li key={i} className="truncate">{r}</li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  <div className="border-t border-[#1a2744] pt-3 mt-4">
                    <button
                      onClick={() => handleExecuteSingleAgent(agentId)}
                      disabled={agentLoading || !activeSandbox}
                      className="w-full flex items-center justify-center gap-1.5 rounded-lg bg-cyan-600/90 hover:bg-cyan-500 py-1.5 text-xs font-semibold text-white transition-colors disabled:opacity-50"
                    >
                      <Play className="h-3 w-3" />
                      <span>{agentLoading && selectedAgent === agentId ? "Executing..." : "Execute Agent"}</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Agent Output Drawer / Box */}
          {agentOutput && (
            <div className="rounded-xl border border-cyan-800/80 bg-[#0c1222] p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[#1a2744] pb-3">
                <div className="flex items-center gap-2">
                  <Bot className="h-4 w-4 text-cyan-400" />
                  <h3 className="text-sm font-bold text-white">Agent Output: {agentOutput.agent_name}</h3>
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-mono uppercase font-bold border ${
                      agentOutput.fallback_used
                        ? "bg-amber-950 text-amber-400 border-amber-800"
                        : "bg-emerald-950 text-emerald-400 border-emerald-800"
                    }`}
                  >
                    {agentOutput.fallback_used ? "Deterministic Fallback" : "Live GenAI"}
                  </span>
                </div>
                <span className="text-xs font-mono text-cyan-400">
                  Confidence: {Math.round(agentOutput.confidence * 100)}%
                </span>
              </div>

              <div>
                <span className="text-[10px] font-semibold text-slate-400 uppercase font-mono">Executive Synthesis</span>
                <p className="text-xs text-slate-200 mt-1 leading-relaxed">{agentOutput.summary}</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="rounded-lg border border-[#1a2744] bg-[#070a13] p-3 space-y-1.5">
                  <span className="text-[10px] font-semibold text-cyan-400 uppercase font-mono">Observations (Facts)</span>
                  <ul className="list-disc list-inside space-y-1 text-slate-300">
                    {agentOutput.observations.map((obs, i) => (
                      <li key={i}>{obs}</li>
                    ))}
                  </ul>
                </div>

                <div className="rounded-lg border border-[#1a2744] bg-[#070a13] p-3 space-y-1.5">
                  <span className="text-[10px] font-semibold text-emerald-400 uppercase font-mono">Derived Deductions</span>
                  <ul className="list-disc list-inside space-y-1 text-slate-300">
                    {agentOutput.derived_conclusions.map((conc, i) => (
                      <li key={i}>{conc}</li>
                    ))}
                  </ul>
                </div>
              </div>

              {agentOutput.advisory_recommendations.length > 0 && (
                <div className="rounded-lg border border-[#1a2744] bg-[#070a13] p-3 text-xs space-y-1.5">
                  <span className="text-[10px] font-semibold text-amber-400 uppercase font-mono">Advisory Recommendations</span>
                  <ul className="list-disc list-inside space-y-1 text-slate-300">
                    {agentOutput.advisory_recommendations.map((rec, i) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: MULTI-AGENT GRAPH (LANGGRAPH) */}
      {activeTab === "graph" && (
        <div className="space-y-6">
          {/* Controls Bar */}
          <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">Investigation Scope:</span>
              <select
                value={graphRequestType}
                onChange={(e) => setGraphRequestType(e.target.value)}
                className="rounded-lg border border-[#1a2744] bg-[#070a13] px-2.5 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
              >
                <option value="full_investigation">Full Multi-Agent Investigation (All 6 Agents)</option>
                <option value="threat_focus">Threat Intelligence Focus</option>
                <option value="attack_path_focus">Attack Path Analysis Focus</option>
                <option value="risk_focus">Risk Assessment Focus</option>
                <option value="incident_focus">Incident Narrative Focus</option>
                <option value="defense_focus">Defensive Strategy Focus</option>
                <option value="executive_briefing">Executive Briefing Focus</option>
              </select>
            </div>

            <button
              onClick={handleExecuteGraph}
              disabled={graphRunning || !activeSandbox}
              className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors disabled:opacity-50 shrink-0"
            >
              <GitBranch className={`h-3.5 w-3.5 ${graphRunning ? "animate-spin" : ""}`} />
              <span>{graphRunning ? "Coordinating Multi-Agent Graph..." : "Run Multi-Agent Investigation"}</span>
            </button>
          </div>

          {/* Visual StateGraph Stepper Flow */}
          <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1a2744] pb-2 text-xs">
              <span className="font-semibold text-white flex items-center gap-2">
                <GitBranch className="h-4 w-4 text-cyan-400" />
                <span>LangGraph StateGraph Execution Pipeline</span>
              </span>
              <span className="text-[10px] text-slate-400 font-mono">
                Fan-out / Fan-in Parallel Coordination
              </span>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono py-2 overflow-x-auto">
              {[
                { name: "Context Init", desc: "Sandbox Bounds" },
                { name: "Evidence Retrieval", desc: "Telemetry & State" },
                { name: "Input Validation", desc: "Injection Defense" },
                { name: "Agent Router", desc: "Fan-out Edge" },
                { name: "Parallel Agents", desc: "Specialized Analysis" },
                { name: "Result Aggregation", desc: "Synthesis & Health" },
                { name: "Final Persistence", desc: "Audit Record" },
              ].map((step, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <div className="flex flex-col items-center rounded-lg border border-[#1a2744] bg-[#070a13] px-3 py-2 text-center min-w-[110px]">
                    <span className="text-[11px] font-bold text-slate-200">{step.name}</span>
                    <span className="text-[9px] text-slate-500">{step.desc}</span>
                  </div>
                  {idx < 6 && <ChevronRight className="h-3.5 w-3.5 text-slate-600 shrink-0" />}
                </div>
              ))}
            </div>
          </div>

          {/* Graph Execution Results */}
          {graphResult && (
            <div className="rounded-xl border border-cyan-800/80 bg-[#0c1222] p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1a2744] pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    <h3 className="text-sm font-bold text-white">Graph Execution Completed</h3>
                    <span className="rounded bg-emerald-950 px-2 py-0.5 text-[10px] font-mono text-emerald-400 border border-emerald-800 uppercase">
                      {graphResult.execution_status || graphResult.status || "completed"}
                    </span>
                  </div>
                  <span className="text-[10px] text-slate-400 font-mono mt-0.5 block">
                    Execution ID: {graphResult.graph_execution_id} | Latency: {Math.round(graphResult.total_latency_ms || graphResult.duration_ms || 0)} ms
                  </span>
                </div>

                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="text-emerald-400">
                    {Object.keys(graphResult.agent_outputs || {}).length} Agents Coordinated
                  </span>
                  <span>•</span>
                  <span className="text-cyan-400">
                    Confidence: {Math.round((graphResult.overall_confidence || 0.9) * 100)}%
                  </span>
                </div>
              </div>

              {/* Agent Tabs Inspector */}
              <div className="space-y-3">
                <div className="flex items-center gap-2 overflow-x-auto border-b border-[#1a2744] pb-2">
                  {Object.keys(graphResult.agent_outputs || {}).map((agName) => {
                    const isSelected = activeAgentInspector === agName;
                    return (
                      <button
                        key={agName}
                        onClick={() => setActiveAgentInspector(agName)}
                        className={`rounded-lg px-3 py-1 text-xs font-mono transition-colors shrink-0 ${
                          isSelected
                            ? "bg-cyan-950 text-cyan-300 border border-cyan-800"
                            : "text-slate-400 hover:text-white"
                        }`}
                      >
                        {agName}
                      </button>
                    );
                  })}
                </div>

                {activeAgentInspector && graphResult.agent_outputs[activeAgentInspector] && (
                  <div className="rounded-lg border border-[#1a2744] bg-[#070a13] p-4 text-xs space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white text-sm">
                        {graphResult.agent_outputs[activeAgentInspector].agent_name}
                      </span>
                      <span className="text-cyan-400 font-mono text-xs">
                        Confidence: {Math.round(graphResult.agent_outputs[activeAgentInspector].confidence * 100)}%
                      </span>
                    </div>

                    <p className="text-slate-200 leading-relaxed">
                      {graphResult.agent_outputs[activeAgentInspector].summary}
                    </p>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                      <div className="space-y-1">
                        <span className="text-[10px] font-mono text-slate-500 uppercase">Observed Facts:</span>
                        <ul className="list-disc list-inside text-slate-300 space-y-0.5">
                          {graphResult.agent_outputs[activeAgentInspector].observations.map((obs, i) => (
                            <li key={i}>{obs}</li>
                          ))}
                        </ul>
                      </div>

                      <div className="space-y-1">
                        <span className="text-[10px] font-mono text-slate-500 uppercase">Derived Conclusions:</span>
                        <ul className="list-disc list-inside text-slate-300 space-y-0.5">
                          {graphResult.agent_outputs[activeAgentInspector].derived_conclusions.map((c, i) => (
                            <li key={i}>{c}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: AI ANALYSIS HISTORY */}
      {activeTab === "history" && (
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-[#1a2744] pb-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Clock className="h-4 w-4 text-cyan-400" />
                <span>Persisted AI Analysis Records</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Audit trail of all generative inferences, token usage, latency metrics, and EvidenceGuard sanitization results.
              </p>
            </div>

            <button
              onClick={loadHistory}
              disabled={historyLoading}
              className="flex items-center gap-1.5 rounded-lg border border-[#1a2744] bg-[#070a13] px-3 py-1.5 text-xs text-slate-300 hover:text-white"
            >
              <RefreshCw className={`h-3.5 w-3.5 text-cyan-400 ${historyLoading ? "animate-spin" : ""}`} />
              <span>Refresh History</span>
            </button>
          </div>

          {historyRecords.length === 0 ? (
            <p className="text-xs text-slate-500 italic py-6 text-center">
              No persisted AI analyses found for execution context &apos;{selectedExecutionId || "None"}&apos;. Execute an agent or multi-agent graph to populate records.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#1a2744] text-[10px] font-mono uppercase text-slate-400">
                    <th className="pb-2">Capability</th>
                    <th className="pb-2">Model</th>
                    <th className="pb-2">Tokens</th>
                    <th className="pb-2">Latency</th>
                    <th className="pb-2">Status</th>
                    <th className="pb-2">Timestamp</th>
                    <th className="pb-2 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1a2744]/50">
                  {historyRecords.map((rec) => (
                    <tr key={rec.id} className="hover:bg-[#070a13]/60 transition-colors">
                      <td className="py-2.5 font-mono text-cyan-400">{rec.capability}</td>
                      <td className="py-2.5 text-slate-300">{rec.model_name}</td>
                      <td className="py-2.5 font-mono text-slate-400">{rec.total_tokens || "—"}</td>
                      <td className="py-2.5 font-mono text-slate-400">
                        {rec.latency_ms ? `${Math.round(rec.latency_ms)} ms` : "—"}
                      </td>
                      <td className="py-2.5">
                        <span
                          className={`rounded px-2 py-0.5 text-[10px] font-mono font-bold ${
                            rec.fallback_used
                              ? "bg-amber-950 text-amber-400 border border-amber-800"
                              : "bg-emerald-950 text-emerald-400 border border-emerald-800"
                          }`}
                        >
                          {rec.fallback_used ? "Fallback" : "Live"}
                        </span>
                      </td>
                      <td className="py-2.5 text-slate-400 font-mono text-[11px]">
                        {new Date(rec.created_at).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 text-right">
                        <button
                          onClick={() => setSelectedAnalysis(rec)}
                          className="rounded px-2 py-1 text-[11px] text-cyan-400 hover:bg-cyan-950 transition-colors font-mono"
                        >
                          View Output
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Modal / Inspector for Analysis JSON */}
          {selectedAnalysis && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
              <div className="w-full max-w-2xl rounded-xl border border-cyan-800/80 bg-[#0c1222] p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-[#1a2744] pb-2">
                  <h3 className="text-sm font-bold text-white font-mono">
                    Analysis Record: {selectedAnalysis.capability}
                  </h3>
                  <button
                    onClick={() => setSelectedAnalysis(null)}
                    className="text-slate-400 hover:text-white text-xs font-mono"
                  >
                    Close
                  </button>
                </div>

                <div className="rounded-lg border border-[#1a2744] bg-[#070a13] p-3 max-h-96 overflow-y-auto text-xs font-mono text-slate-300">
                  <pre>{JSON.stringify(selectedAnalysis.content, null, 2)}</pre>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

