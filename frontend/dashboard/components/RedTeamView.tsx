"use client";

import React, { useState } from "react";
import { AttackPathIntelligence } from "./AttackPathIntelligence";
import { AttackSimulation } from "./AttackSimulation";
import { Crosshair, GitFork } from "lucide-react";

interface RedTeamViewProps {
  onNavigateToGuardian?: (executionId?: string) => void;
}

export const RedTeamView: React.FC<RedTeamViewProps> = ({ onNavigateToGuardian }) => {
  const [activeSubTab, setActiveSubTab] = useState<"paths" | "scenarios">("paths");

  return (
    <div className="space-y-6">
      {/* Sub-navigation Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-[#1a2744] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Crosshair className="h-5 w-5 text-cyan-400" />
            Red Team Autonomous Simulation Engine
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Plan multi-stage attack paths across synthetic topology or execute targeted individual scenarios.
          </p>
        </div>

        {/* Sub-tab pills */}
        <div className="flex items-center rounded-lg border border-[#1a2744] bg-[#0c1222] p-1">
          <button
            onClick={() => setActiveSubTab("paths")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
              activeSubTab === "paths"
                ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <GitFork className="h-3.5 w-3.5" />
            <span>Attack Paths (Multi-Stage)</span>
          </button>

          <button
            onClick={() => setActiveSubTab("scenarios")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
              activeSubTab === "scenarios"
                ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm shadow-cyan-950"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Crosshair className="h-3.5 w-3.5" />
            <span>Single Scenario Runner</span>
          </button>
        </div>
      </div>

      {/* Render Selected Engine View */}
      {activeSubTab === "paths" ? (
        <AttackPathIntelligence onHandOffToGuardian={onNavigateToGuardian} />
      ) : (
        <AttackSimulation onHandOffToGuardian={onNavigateToGuardian} />
      )}
    </div>
  );
};

