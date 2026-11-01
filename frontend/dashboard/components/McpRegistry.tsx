"use client";

import React from "react";
import { Boxes, ShieldCheck, Lock, CheckCircle2, Server, Globe, Radio } from "lucide-react";

interface ToolCard {
  name: string;
  category: string;
  description: string;
  capability: string;
  resource: string;
}

const MCP_TOOLS: ToolCard[] = [
  {
    name: "system_health",
    category: "Diagnostics",
    description: "Evaluates operational health across PostgreSQL, Redis, and OPA policy engine.",
    capability: "read",
    resource: "system",
  },
  {
    name: "list_agents",
    category: "Agent Infrastructure",
    description: "Enumerates registered platform agents and capabilities.",
    capability: "read",
    resource: "agent",
  },
  {
    name: "get_agent",
    category: "Agent Infrastructure",
    description: "Retrieves complete configuration and state of a registered agent.",
    capability: "read",
    resource: "agent",
  },
  {
    name: "list_campaigns",
    category: "Campaign Operations",
    description: "Lists active and completed security assessment campaigns.",
    capability: "read",
    resource: "campaign",
  },
  {
    name: "get_campaign",
    category: "Campaign Operations",
    description: "Retrieves execution configuration and status for a specific campaign.",
    capability: "read",
    resource: "campaign",
  },
  {
    name: "list_incidents",
    category: "Incident Management",
    description: "Enumerates simulated forensic incidents and alert records.",
    capability: "read",
    resource: "incident",
  },
  {
    name: "get_incident",
    category: "Incident Management",
    description: "Retrieves granular forensic incident telemetry and indicators.",
    capability: "read",
    resource: "incident",
  },
  {
    name: "target_list_assets",
    category: "Target Environment",
    description: "Lists synthetic target assets within an isolated sandbox environment.",
    capability: "read",
    resource: "target",
  },
  {
    name: "target_inspect_asset",
    category: "Target Environment",
    description: "Performs observational inspection of a synthetic asset in a sandbox.",
    capability: "read",
    resource: "target",
  },
  {
    name: "target_get_simulated_findings",
    category: "Target Environment",
    description: "Queries simulated finding telemetry associated with a target asset.",
    capability: "read",
    resource: "target",
  },
];

export const McpRegistry: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-[#1a2744] pb-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <span>Model Context Protocol (MCP) Tool Registry</span>
            <span className="rounded bg-amber-950 px-2 py-0.5 text-xs font-mono text-amber-400 border border-amber-800/80">
              10 VERIFIED TOOLS
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Standardized, process-isolated Streamable HTTP tool layer governing AI agent access to platform services.
          </p>
        </div>
      </div>

      {/* Protocol Architecture Card */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-4 space-y-1">
          <div className="text-[11px] font-semibold text-slate-400">Transport Layer</div>
          <div className="font-mono text-xs font-bold text-cyan-400">Streamable HTTP (Port 8001)</div>
          <p className="text-[10px] text-slate-500">Official Python MCP SDK standard at `http://127.0.0.1:8001/mcp`</p>
        </div>

        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-4 space-y-1">
          <div className="text-[11px] font-semibold text-slate-400">Transport-Level Auth</div>
          <div className="font-mono text-xs font-bold text-emerald-400">Authorization: Bearer &lt;JWT&gt;</div>
          <p className="text-[10px] text-slate-500">Tool schemas contain zero credentials; tokens stay at transport layer</p>
        </div>

        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-4 space-y-1">
          <div className="text-[11px] font-semibold text-slate-400">Parameter Security</div>
          <div className="font-mono text-xs font-bold text-purple-400">extra = &quot;forbid&quot; (Strict)</div>
          <p className="text-[10px] text-slate-500">Rejects undeclared parameters to block prompt injection</p>
        </div>
      </div>

      {/* Tools Table */}
      <div className="overflow-x-auto rounded-xl border border-[#1a2744] bg-[#0c1222]">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="border-b border-[#1a2744] bg-[#070a13] text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            <tr>
              <th className="px-4 py-3">Tool Name</th>
              <th className="px-4 py-3">Category</th>
              <th className="px-4 py-3">Description</th>
              <th className="px-4 py-3">Required Capability</th>
              <th className="px-4 py-3">Resource</th>
              <th className="px-4 py-3 text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1a2744]/70">
            {MCP_TOOLS.map((t) => (
              <tr key={t.name} className="hover:bg-cyan-950/20 transition-colors">
                <td className="px-4 py-3 font-mono font-semibold text-cyan-300">{t.name}</td>
                <td className="px-4 py-3 text-slate-400">{t.category}</td>
                <td className="px-4 py-3 text-slate-300 max-w-sm">{t.description}</td>
                <td className="px-4 py-3 font-mono text-[10px] text-purple-400 uppercase">
                  {t.capability}
                </td>
                <td className="px-4 py-3 font-mono text-[10px] text-slate-400">{t.resource}</td>
                <td className="px-4 py-3 text-right">
                  <span className="inline-flex items-center gap-1 rounded bg-emerald-950 px-2 py-0.5 text-[9px] font-mono font-bold text-emerald-400 border border-emerald-800">
                    <CheckCircle2 className="h-2.5 w-2.5" /> VERIFIED
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

