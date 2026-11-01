"use client";

import React, { useState } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import { AssetIntelligence } from "./AssetIntelligence";
import { Layers, Server, PlusCircle, RefreshCw, Shield, Globe } from "lucide-react";

export const AssetsSandboxView: React.FC = () => {
  const { activeSandbox, sandboxes, setActiveSandbox, refreshSandboxes } = useAuth();
  const [isSeeding, setIsSeeding] = useState(false);
  const [seedMessage, setSeedMessage] = useState<string | null>(null);

  const handleSeedDemo = async () => {
    setIsSeeding(true);
    setSeedMessage(null);
    try {
      const res = await api.seedDemoSandbox();
      setSeedMessage(`Successfully seeded ${res.seeded_assets_count} enterprise synthetic assets!`);
      await refreshSandboxes();
    } catch (err: any) {
      setSeedMessage(`Failed to seed: ${err.message}`);
    } finally {
      setIsSeeding(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Sandbox Scope Header & Status Card */}
      <div className="rounded-xl border border-[#1a2744] bg-[#0c1222]/80 p-5 backdrop-blur-md">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-[#1a2744]">
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              <Layers className="h-5 w-5 text-cyan-400" />
              Synthetic Asset Registry & Sandbox Topology
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Strictly isolated synthetic infrastructure with authentic service metadata and deterministic lateral links.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleSeedDemo}
              disabled={isSeeding}
              className="flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm shadow-cyan-950 transition-all disabled:opacity-50"
            >
              <PlusCircle className={`h-3.5 w-3.5 ${isSeeding ? "animate-spin" : ""}`} />
              <span>{isSeeding ? "Seeding Assets..." : "Seed 10 Demo Assets"}</span>
            </button>
          </div>
        </div>

        {seedMessage && (
          <div className="mt-4 p-2.5 rounded-lg border border-cyan-800/80 bg-cyan-950/40 text-xs text-cyan-300">
            {seedMessage}
          </div>
        )}

        {/* Sandbox Inventory Details Row */}
        {activeSandbox && (
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 pt-4 text-xs font-mono">
            <div className="p-3 rounded-lg border border-[#1a2744] bg-[#070a13]">
              <span className="text-slate-500 text-[10px] block">ACTIVE SANDBOX</span>
              <span className="text-white font-bold">{activeSandbox.name}</span>
            </div>

            <div className="p-3 rounded-lg border border-[#1a2744] bg-[#070a13]">
              <span className="text-slate-500 text-[10px] block">ISOLATION MODE</span>
              <span className="text-emerald-400 font-bold uppercase">{activeSandbox.isolation_mode} (ZERO REAL-WORLD IMPACT)</span>
            </div>

            <div className="p-3 rounded-lg border border-[#1a2744] bg-[#070a13]">
              <span className="text-slate-500 text-[10px] block">SANDBOX STATUS</span>
              <span className="text-cyan-400 font-bold uppercase">{activeSandbox.status}</span>
            </div>

            <div className="p-3 rounded-lg border border-[#1a2744] bg-[#070a13]">
              <span className="text-slate-500 text-[10px] block">CREATED AT</span>
              <span className="text-slate-300 font-bold">
                {new Date(activeSandbox.created_at).toLocaleDateString()}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Asset Intelligence Component */}
      <AssetIntelligence />
    </div>
  );
};

