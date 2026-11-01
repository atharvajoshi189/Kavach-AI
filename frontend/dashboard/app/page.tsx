"use client";

import React, { useState } from "react";
import { Header } from "../components/Header";
import { Sidebar, NavTab } from "../components/Sidebar";
import { AssetsSandboxView } from "../components/AssetsSandboxView";
import { SystemHealthView } from "../components/SystemHealthView";
import { SettingsView } from "../components/SettingsView";
import { AuthModal } from "../components/AuthModal";
import { AgentArenaView } from "../components/AgentArenaView";

export default function SOCDashboard() {
  const [activeTab, setActiveTab] = useState<NavTab>("agent_arena");

  const renderActiveTab = () => {
    switch (activeTab) {
      case "agent_arena":
      case "experiments":
      case "arena_reports":
        return <AgentArenaView />;
      case "assets_sandbox":
        return <AssetsSandboxView />;
      case "system_health":
        return <SystemHealthView />;
      case "settings":
        return <SettingsView />;
      default:
        return <AgentArenaView />;
    }
  };

  return (
    <div className="flex h-screen w-full flex-col bg-[#040711] text-slate-100 overflow-hidden font-sans relative selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Ambient background lighting & glows for glassmorphism depth */}
      <div className="fixed top-0 left-1/4 w-[600px] h-[350px] bg-cyan-600/[0.04] rounded-full blur-[140px] pointer-events-none -z-0" />
      <div className="fixed bottom-0 right-1/4 w-[600px] h-[350px] bg-blue-600/[0.04] rounded-full blur-[140px] pointer-events-none -z-0" />
      <div className="fixed top-1/2 left-0 w-[400px] h-[400px] bg-indigo-600/[0.03] rounded-full blur-[120px] pointer-events-none -z-0" />

      {/* Top Glass Navigation Bar */}
      <Header activeTab={activeTab} onSelectTab={setActiveTab} />

      {/* Main Workspace with Glassmorphic Sidebar & Viewport */}
      <div className="flex flex-1 overflow-hidden relative z-10">
        <Sidebar activeTab={activeTab} onSelectTab={setActiveTab} />

        <main className="flex-1 overflow-y-auto bg-transparent p-4 md:p-6 scrollbar-thin scrollbar-thumb-slate-800 scrollbar-track-transparent">
          <div className="mx-auto max-w-7xl">
            {renderActiveTab()}
          </div>
        </main>
      </div>

      <AuthModal />
    </div>
  );
}
