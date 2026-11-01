"use client";

import React, { useEffect, useState } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import { SystemHealth } from "../lib/types";
import { NavTab } from "./Sidebar";
import {
  ShieldAlert,
  Shield,
  Layers,
  Activity,
  PlusCircle,
  RefreshCw,
  LogOut,
  ChevronDown,
  User,
  Swords,
  FlaskConical,
  Clock,
  Server,
  Radio,
} from "lucide-react";

interface HeaderProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  isGuidedModeActive?: boolean;
  onToggleGuidedMode?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onSelectTab,
}) => {
  const {
    user,
    activeSandbox,
    sandboxes,
    setActiveSandbox,
    setIsAuthModalOpen,
    logout,
  } = useAuth();

  const [health, setHealth] = useState<SystemHealth | null>(null);

  useEffect(() => {
    api.getHealth().then(setHealth).catch(() => setHealth(null));
  }, []);

  return (
    <header className="sticky top-0 z-40 flex h-14 w-full items-center justify-between border-b border-white/[0.06] bg-[#050813]/85 px-4 backdrop-blur-2xl shadow-[0_4px_30px_rgba(0,0,0,0.4)]">
      {/* LEFT: BRAND */}
      <div className="flex items-center gap-3 shrink-0">
        <div
          onClick={() => onSelectTab("agent_arena")}
          className="flex items-center gap-2.5 cursor-pointer group"
        >
          {/* Hexagonal Green Shield Logo */}
          <div className="relative flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-950/80 border border-emerald-500/70 text-emerald-400 shadow-md shadow-emerald-950">
            <Shield className="h-5 w-5 fill-emerald-500/20 text-emerald-400" />
            <span className="absolute inset-0 rounded-lg ring-1 ring-emerald-400/30 animate-pulse pointer-events-none" />
          </div>
          <div>
            <div className="flex items-center gap-1 font-bold tracking-wider text-sm text-white">
              <span>AEGISMESH</span>
              <span className="text-white font-black">2.0</span>
            </div>
            <p className="text-[10px] text-slate-400 tracking-wide font-normal -mt-0.5">
              SOC Command Center
            </p>
          </div>
        </div>
      </div>

      {/* CENTER: TOP NAVIGATION PILLS (GLASSMORPHISM) */}
      <div className="hidden md:flex items-center gap-2">
        {/* 1. Agent Arena (Active Glow Pill) */}
        <button
          onClick={() => onSelectTab("agent_arena")}
          className={`flex items-center gap-1.5 rounded-full px-4 py-1.5 text-xs font-medium transition-all cursor-pointer ${
            activeTab === "agent_arena"
              ? "bg-gradient-to-r from-cyan-500/25 via-cyan-500/15 to-transparent text-cyan-300 border border-cyan-400/60 shadow-[0_0_15px_rgba(6,182,212,0.3)] ring-1 ring-cyan-400/30 font-semibold backdrop-blur-md"
              : "bg-white/[0.03] text-slate-400 border border-white/[0.06] hover:text-slate-200 hover:border-white/[0.12] hover:bg-white/[0.06]"
          }`}
        >
          <Swords className="h-3.5 w-3.5 text-cyan-400" />
          <span>Agent Arena</span>
        </button>

        {/* 2. Experiments */}
        <button
          onClick={() => onSelectTab("experiments")}
          className={`flex items-center gap-1.5 rounded-full px-4 py-1.5 text-xs font-medium transition-all cursor-pointer ${
            activeTab === "experiments"
              ? "bg-gradient-to-r from-cyan-500/25 via-cyan-500/15 to-transparent text-cyan-300 border border-cyan-400/60 shadow-[0_0_15px_rgba(6,182,212,0.3)] font-semibold backdrop-blur-md"
              : "bg-white/[0.03] text-slate-400 border border-white/[0.06] hover:text-slate-200 hover:border-white/[0.12] hover:bg-white/[0.06]"
          }`}
        >
          <FlaskConical className="h-3.5 w-3.5 text-slate-400" />
          <span>Experiments</span>
        </button>

        {/* 3. Assets & Sandbox */}
        <button
          onClick={() => onSelectTab("assets_sandbox")}
          className={`flex items-center gap-1.5 rounded-full px-4 py-1.5 text-xs font-medium transition-all cursor-pointer ${
            activeTab === "assets_sandbox"
              ? "bg-gradient-to-r from-cyan-500/25 via-cyan-500/15 to-transparent text-cyan-300 border border-cyan-400/60 shadow-[0_0_15px_rgba(6,182,212,0.3)] font-semibold backdrop-blur-md"
              : "bg-white/[0.03] text-slate-400 border border-white/[0.06] hover:text-slate-200 hover:border-white/[0.12] hover:bg-white/[0.06]"
          }`}
        >
          <Server className="h-3.5 w-3.5 text-slate-400" />
          <span>Sandboxes & Assets</span>
        </button>

        {/* 4. System Health */}
        <button
          onClick={() => onSelectTab("system_health")}
          className={`flex items-center gap-1.5 rounded-full px-4 py-1.5 text-xs font-medium transition-all cursor-pointer ${
            activeTab === "system_health"
              ? "bg-gradient-to-r from-cyan-500/25 via-cyan-500/15 to-transparent text-cyan-300 border border-cyan-400/60 shadow-[0_0_15px_rgba(6,182,212,0.3)] font-semibold backdrop-blur-md"
              : "bg-white/[0.03] text-slate-400 border border-white/[0.06] hover:text-slate-200 hover:border-white/[0.12] hover:bg-white/[0.06]"
          }`}
        >
          <Activity className="h-3.5 w-3.5 text-slate-400" />
          <span>System Health</span>
        </button>
      </div>

      {/* RIGHT: LIVE SIMULATION STATUS, SANDBOX SELECTOR & OPERATOR PROFILE */}
      <div className="flex items-center gap-3 shrink-0">
        {/* Live Simulation Pill with Glass Effect */}
        <div className="flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-950/40 px-3 py-1 text-xs text-emerald-300 font-medium backdrop-blur-md shadow-sm">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
          </span>
          <span className="text-[11px] font-mono tracking-tight">Live Simulation</span>
        </div>

        {/* Sandbox Scope Selector with Glass Styling */}
        <div className="hidden sm:flex items-center gap-1.5 rounded-xl border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 text-xs text-slate-300 backdrop-blur-md">
          <span className="text-slate-400 text-[11px]">Sandbox:</span>
          {sandboxes.length > 0 ? (
            <select
              value={activeSandbox?.id || ""}
              onChange={(e) => {
                const selected = sandboxes.find((s) => s.id === e.target.value);
                if (selected) setActiveSandbox(selected);
              }}
              className="bg-transparent font-medium text-slate-200 focus:outline-none cursor-pointer pr-1 text-xs max-w-[130px] truncate"
            >
              {sandboxes.map((sb) => (
                <option key={sb.id} value={sb.id} className="bg-[#0c1422] text-white">
                  {sb.name}
                </option>
              ))}
            </select>
          ) : (
            <span className="text-slate-200 font-mono text-[11px]">isolated-sandbox-2780e9</span>
          )}
        </div>

        {/* Operator Profile with Glass Styling */}
        <button
          onClick={() => setIsAuthModalOpen(true)}
          className="flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 text-xs hover:border-cyan-500/40 hover:bg-white/[0.06] transition-all backdrop-blur-md cursor-pointer"
        >
          <div className="flex h-6 w-6 items-center justify-center rounded-full bg-cyan-950/90 text-cyan-300 border border-cyan-400/70 text-[11px] font-bold shadow-sm shadow-cyan-900">
            {user ? user.username.charAt(0).toUpperCase() : "V"}
          </div>
          <div className="text-left hidden sm:block leading-tight">
            <p className="font-semibold text-white text-[11px]">
              {user ? user.username : "val_operator"}
            </p>
            <p className="text-[9px] text-slate-400">Security Operator</p>
          </div>
          <ChevronDown className="h-3.5 w-3.5 text-slate-400 ml-0.5" />
        </button>
      </div>
    </header>
  );
};
