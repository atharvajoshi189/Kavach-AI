"use client";

import React, { useState } from "react";
import {
  Compass,
  CheckCircle2,
  ChevronRight,
  ChevronLeft,
  X,
  Play,
  ArrowRight,
  Sparkles,
  ShieldCheck,
  HelpCircle,
} from "lucide-react";

export interface GuidedStep {
  id: number;
  title: string;
  targetTab: string;
  description: string;
  context: string;
  actionLabel: string;
}

export const GUIDED_STEPS: GuidedStep[] = [
  {
    id: 1,
    title: "1. Verify Infrastructure & System Health",
    targetTab: "system_health",
    description: "Check the operational status of FastAPI, PostgreSQL, Redis, Celery, and OPA engines.",
    context: "Before launching security operations, confirm all background workers, database transactions, and authorization systems are healthy.",
    actionLabel: "Open System Health",
  },
  {
    id: 2,
    title: "2. Verify Active Synthetic Sandbox",
    targetTab: "assets_sandbox",
    description: "Ensure an active synthetic sandbox is selected in the top navigation bar or seed a demo environment.",
    context: "All simulation and defense activities are strictly bound to isolated synthetic sandbox environments (is_simulated = True).",
    actionLabel: "Inspect Sandboxes",
  },
  {
    id: 3,
    title: "3. Review Synthetic Asset Inventory",
    targetTab: "assets_sandbox",
    description: "Examine synthetic host servers, databases, web applications, and network topologies.",
    context: "Assets have defined risk levels, service configurations, and simulated vulnerabilities that guide adversary modeling.",
    actionLabel: "View Asset Inventory",
  },
  {
    id: 4,
    title: "4. Launch Red Team Simulation",
    targetTab: "red_team",
    description: "Select a synthetic scenario (e.g., Web Shell Ingress) and run a deterministic attack simulation.",
    context: "The Red Team simulation engine deterministically exercises attack vectors within the synthetic sandbox boundary.",
    actionLabel: "Launch Simulation",
  },
  {
    id: 5,
    title: "5. Inspect Multi-Stage Attack Path",
    targetTab: "attack_paths",
    description: "Plan or inspect a multi-hop lateral movement attack path and examine the visual attack graph.",
    context: "Attack Path Orchestration traces adversary kill-chains across connected assets with stage prerequisites.",
    actionLabel: "Inspect Attack Paths",
  },
  {
    id: 6,
    title: "6. Review Blue Guardian Threat Detections",
    targetTab: "blue_guardian",
    description: "Inspect ingested security events, correlated event groups, and triggered detection rules.",
    context: "Blue Guardian automatically correlates raw telemetry into high-fidelity detections mapped to MITRE ATT&CK techniques.",
    actionLabel: "Review Detections",
  },
  {
    id: 7,
    title: "7. Examine Asset Risk & Blast Radius",
    targetTab: "blue_guardian",
    description: "Review calculated composite risk scores, asset criticality ratings, and potential blast radiuses.",
    context: "Authoritative deterministic risk calculations prioritize critical threats without stochastic AI distortion.",
    actionLabel: "Examine Risk Scores",
  },
  {
    id: 8,
    title: "8. Generate AI Security Intelligence",
    targetTab: "ai_center",
    description: "Execute specialized advisory AI agents or coordinate the LangGraph multi-agent investigation graph.",
    context: "AI agents provide advisory synthesis, separating observed telemetry from deductions, backed by EvidenceGuard grounding.",
    actionLabel: "Open AI Intelligence Center",
  },
  {
    id: 9,
    title: "9. Review Defensive Recommendations",
    targetTab: "response_center",
    description: "Evaluate prioritized countermeasure recommendations and bundled remediation action plans.",
    context: "Defensive recommendations reference pre-approved playbooks (e.g., host isolation, firewall rules, service patch).",
    actionLabel: "Review Recommendations",
  },
  {
    id: 10,
    title: "10. Complete Four-Eyes Human Approval",
    targetTab: "response_center",
    description: "Perform authorized dual human-in-the-loop review and record cryptographic approval decisions.",
    context: "AegisMesh governance strictly mandates Four-Eyes quorum before any countermeasure plan can be executed.",
    actionLabel: "Review Approval Queue",
  },
  {
    id: 11,
    title: "11. Run Synthetic Remediation Execution",
    targetTab: "response_center",
    description: "Execute the approved remediation plan in synthetic mode and observe before/after state snapshots.",
    context: "Synthetic Remediation safely isolates target containers and applies configuration diffs with rollback snapshots.",
    actionLabel: "Execute Remediation",
  },
  {
    id: 12,
    title: "12. Inspect Regression Verification",
    targetTab: "response_center",
    description: "Verify that defensive countermeasures successfully neutralized threats and preserved service integrity.",
    context: "The Verification Engine runs automated deterministic checks comparing pre-remediation and post-remediation states.",
    actionLabel: "Inspect Verification",
  },
  {
    id: 13,
    title: "13. Review SHA-256 Audit Trail",
    targetTab: "audit_explorer",
    description: "Inspect cryptographically chained immutable audit records documenting the full investigation lifecycle.",
    context: "Every operator action, approval decision, synthetic change, and verification check is signed with SHA-256 hashes.",
    actionLabel: "Explore Audit Logs",
  },
];

interface GuidedOperationsBannerProps {
  currentStepIndex: number;
  onSelectStepIndex: (index: number) => void;
  onNavigateToTab: (tab: string) => void;
  onClose: () => void;
}

export const GuidedOperationsBanner: React.FC<GuidedOperationsBannerProps> = ({
  currentStepIndex,
  onSelectStepIndex,
  onNavigateToTab,
  onClose,
}) => {
  const currentStep = GUIDED_STEPS[currentStepIndex] || GUIDED_STEPS[0];
  const progressPercent = Math.round(((currentStepIndex + 1) / GUIDED_STEPS.length) * 100);

  const handleNext = () => {
    if (currentStepIndex < GUIDED_STEPS.length - 1) {
      const nextIndex = currentStepIndex + 1;
      onSelectStepIndex(nextIndex);
      onNavigateToTab(GUIDED_STEPS[nextIndex].targetTab);
    }
  };

  const handlePrev = () => {
    if (currentStepIndex > 0) {
      const prevIndex = currentStepIndex - 1;
      onSelectStepIndex(prevIndex);
      onNavigateToTab(GUIDED_STEPS[prevIndex].targetTab);
    }
  };

  const handleActionClick = () => {
    onNavigateToTab(currentStep.targetTab);
  };

  return (
    <div className="relative mb-5 rounded-xl border border-cyan-800/80 bg-gradient-to-r from-cyan-950/40 via-[#0c1222] to-[#070a13] p-4 shadow-lg backdrop-blur-md">
      {/* Top Banner Row */}
      <div className="flex items-center justify-between border-b border-[#1a2744] pb-2.5">
        <div className="flex items-center gap-2">
          <div className="flex h-6 w-6 items-center justify-center rounded-full bg-cyan-950 border border-cyan-700/80 text-cyan-400">
            <Compass className="h-3.5 w-3.5" />
          </div>
          <span className="text-xs font-bold uppercase tracking-wider text-white">
            Guided Operations Mode
          </span>
          <span className="rounded bg-cyan-950/80 px-2 py-0.5 text-[10px] font-mono text-cyan-400 border border-cyan-800/60">
            Step {currentStepIndex + 1} of {GUIDED_STEPS.length} ({progressPercent}%)
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="hidden sm:flex w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="bg-cyan-400 h-full transition-all duration-300"
              style={{ width: `${progressPercent}%` }}
            />
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded transition-colors"
            title="Exit Guided Mode"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pt-3">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold text-white">{currentStep.title}</span>
            <span className="text-[10px] text-cyan-400 font-mono">[{currentStep.targetTab}]</span>
          </div>
          <p className="text-xs text-slate-300">{currentStep.description}</p>
          <p className="text-[11px] text-slate-500 italic">{currentStep.context}</p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={handlePrev}
            disabled={currentStepIndex === 0}
            className="rounded-lg border border-[#1a2744] bg-[#070a13] p-1.5 text-xs text-slate-400 hover:text-white hover:border-cyan-700 disabled:opacity-30 transition-colors"
            title="Previous Step"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>

          <button
            onClick={handleActionClick}
            className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors shadow-sm"
          >
            <span>{currentStep.actionLabel}</span>
            <ArrowRight className="h-3 w-3" />
          </button>

          <button
            onClick={handleNext}
            disabled={currentStepIndex === GUIDED_STEPS.length - 1}
            className="rounded-lg border border-[#1a2744] bg-[#070a13] p-1.5 text-xs text-slate-400 hover:text-white hover:border-cyan-700 disabled:opacity-30 transition-colors"
            title="Next Step"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
};

