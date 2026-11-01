"use client";

import React, { useState } from "react";
import {
  Swords,
  FlaskConical,
  Clock,
  Server,
  Activity,
  Settings,
  ChevronLeft,
  ChevronRight,
  Sparkles,
} from "lucide-react";

export type NavTab =
  // AGENT ARENA
  | "agent_arena"
  | "experiments"
  | "arena_reports"
  // INFRASTRUCTURE
  | "assets_sandbox"
  | "system_health"
  | "settings"
  // Legacy Tab IDs (preserved for type compatibility across components)
  | "overview"
  | "live_operations"
  | "red_team"
  | "attack_paths"
  | "blue_guardian"
  | "threat_intelligence"
  | "risk_intelligence"
  | "ai_center"
  | "ai_agents"
  | "ai_graph"
  | "ai_history"
  | "response_center"
  | "approval_center"
  | "synthetic_remediation"
  | "verification_center"
  | "audit_explorer"
  | (string & {});

interface NavGroup {
  title: string;
  items: Array<{
    id: NavTab;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string;
    hasDot?: boolean;
  }>;
}

const NAV_GROUPS: NavGroup[] = [
  {
    title: "AGENT ARENA",
    items: [
      { id: "agent_arena", label: "Agent Arena", icon: Swords },
      { id: "experiments", label: "Experiments", icon: FlaskConical },
      { id: "arena_reports", label: "History & Reports", icon: Clock },
    ],
  },
  {
    title: "INFRASTRUCTURE",
    items: [
      { id: "assets_sandbox", label: "Assets & Sandbox", icon: Server },
      { id: "system_health", label: "System Health", icon: Activity, hasDot: true },
      { id: "settings", label: "Settings", icon: Settings },
    ],
  },
];

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  isGuidedModeActive?: boolean;
  onToggleGuidedMode?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
}) => {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={`relative flex flex-col border-r border-white/[0.06] bg-[#050813]/85 backdrop-blur-2xl transition-all duration-300 ease-in-out select-none shadow-[4px_0_30px_rgba(0,0,0,0.5)] z-20 ${
        collapsed ? "w-16" : "w-56"
      }`}
    >
      {/* Ambient glass background glow */}
      <div className="absolute top-0 left-0 w-full h-40 bg-gradient-to-b from-cyan-500/[0.04] to-transparent pointer-events-none" />
      <div className="absolute bottom-0 left-0 w-full h-40 bg-gradient-to-t from-blue-600/[0.03] to-transparent pointer-events-none" />

      {/* Collapse Toggle Button with Glassmorphism */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="absolute -right-3 top-5 z-30 flex h-6 w-6 items-center justify-center rounded-full border border-cyan-500/30 bg-[#090f1d]/90 backdrop-blur-xl text-slate-300 hover:text-cyan-300 hover:border-cyan-400 hover:scale-110 transition-all shadow-[0_0_12px_rgba(0,0,0,0.8)] cursor-pointer"
        title={collapsed ? "Expand Sidebar" : "Collapse Sidebar"}
      >
        {collapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronLeft className="h-3 w-3" />}
      </button>

      {/* Navigation Groups */}
      <div className="flex-1 overflow-y-auto px-2.5 py-5 space-y-6 scrollbar-none relative z-10">
        {NAV_GROUPS.map((group, groupIdx) => (
          <div key={groupIdx} className="space-y-1.5">
            {!collapsed && (
              <p className="px-2.5 text-[9px] font-bold tracking-widest text-cyan-400/60 uppercase font-mono">
                {group.title}
              </p>
            )}

            <div className="space-y-1">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive =
                  activeTab === item.id ||
                  ((item.id === "experiments" || item.id === "arena_reports") &&
                    activeTab === "agent_arena");

                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      if (item.id === "experiments" || item.id === "arena_reports") {
                        onSelectTab("agent_arena");
                      } else {
                        onSelectTab(item.id);
                      }
                    }}
                    title={collapsed ? item.label : undefined}
                    className={`group relative flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-xs font-medium transition-all cursor-pointer ${
                      isActive
                        ? "bg-gradient-to-r from-cyan-500/20 via-cyan-500/10 to-transparent text-cyan-300 border border-cyan-400/40 shadow-[0_0_18px_rgba(6,182,212,0.25)] ring-1 ring-cyan-400/20 font-semibold backdrop-blur-md"
                        : "text-slate-400 hover:bg-white/[0.04] hover:text-slate-200 border border-transparent hover:border-white/[0.06]"
                    } ${collapsed ? "justify-center px-0 py-2.5" : ""}`}
                  >
                    {/* Glowing Left Indicator for Active Tab */}
                    {isActive && (
                      <span className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 rounded-r bg-cyan-400 shadow-[0_0_10px_rgba(6,182,212,0.9)]" />
                    )}

                    <Icon
                      className={`h-4 w-4 shrink-0 transition-transform duration-200 group-hover:scale-110 ${
                        isActive
                          ? "text-cyan-400 drop-shadow-[0_0_8px_rgba(6,182,212,0.6)]"
                          : "text-slate-400 group-hover:text-slate-200"
                      }`}
                    />

                    {!collapsed && (
                      <span className="truncate flex-1 text-left text-[11px] tracking-wide font-sans">
                        {item.label}
                      </span>
                    )}

                    {!collapsed && item.badge && (
                      <span className="rounded-full bg-cyan-950/80 px-1.5 py-0.2 text-[9px] font-mono font-bold text-cyan-300 border border-cyan-700/60 shadow-sm">
                        {item.badge}
                      </span>
                    )}

                    {!collapsed && item.hasDot && (
                      <span className="relative flex h-2 w-2">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Bottom Glass Footer info */}
      {!collapsed && (
        <div className="p-3 m-2.5 rounded-xl bg-white/[0.02] border border-white/[0.05] backdrop-blur-md">
          <div className="flex items-center gap-2 text-[10px] text-slate-400 font-mono">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="truncate">RL Policy: Q-Learning</span>
          </div>
          <div className="mt-1 flex items-center justify-between text-[9px] text-slate-500 font-mono">
            <span>Adaptive Engine</span>
            <span className="text-emerald-400 font-bold">ONLINE</span>
          </div>
        </div>
      )}
    </aside>
  );
};
