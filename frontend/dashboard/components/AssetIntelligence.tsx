"use client";

import React, { useEffect, useState, useMemo } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import { SyntheticAsset } from "../lib/types";
import {
  Server,
  Database,
  Globe,
  Radio,
  Router,
  Search,
  Filter,
  ShieldAlert,
  ArrowRight,
  RefreshCw,
  ExternalLink,
  X,
  Bug,
  Network,
  Cpu,
} from "lucide-react";

export const AssetIntelligence: React.FC = () => {
  const { activeSandbox } = useAuth();
  const [assets, setAssets] = useState<SyntheticAsset[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [riskFilter, setRiskFilter] = useState("all");
  const [selectedAsset, setSelectedAsset] = useState<SyntheticAsset | null>(null);

  const fetchAssets = async () => {
    if (!activeSandbox?.id) return;
    setLoading(true);
    try {
      const data = await api.listAssets(activeSandbox.id);
      setAssets(data);
    } catch (err) {
      console.error("Failed to load assets:", err);
      setAssets([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, [activeSandbox?.id]);

  // Asset type icon helper
  const getAssetIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case "database":
        return <Database className="h-4 w-4 text-emerald-400" />;
      case "web_application":
        return <Globe className="h-4 w-4 text-cyan-400" />;
      case "api":
        return <Radio className="h-4 w-4 text-purple-400" />;
      case "network_device":
        return <Router className="h-4 w-4 text-amber-400" />;
      default:
        return <Server className="h-4 w-4 text-blue-400" />;
    }
  };

  const getRiskBadge = (risk: string) => {
    switch (risk.toLowerCase()) {
      case "critical":
        return (
          <span className="rounded bg-rose-950 px-2 py-0.5 text-[10px] font-mono font-bold text-rose-400 border border-rose-800/80">
            CRITICAL
          </span>
        );
      case "high":
        return (
          <span className="rounded bg-orange-950 px-2 py-0.5 text-[10px] font-mono font-bold text-orange-400 border border-orange-800/80">
            HIGH
          </span>
        );
      case "medium":
        return (
          <span className="rounded bg-amber-950 px-2 py-0.5 text-[10px] font-mono font-bold text-amber-400 border border-amber-800/80">
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="rounded bg-emerald-950 px-2 py-0.5 text-[10px] font-mono font-bold text-emerald-400 border border-emerald-800/80">
            LOW
          </span>
        );
    }
  };

  // Filtered Assets
  const filteredAssets = useMemo(() => {
    return assets.filter((asset) => {
      const matchSearch =
        asset.name.toLowerCase().includes(search.toLowerCase()) ||
        asset.hostname.toLowerCase().includes(search.toLowerCase()) ||
        asset.ip_address.toLowerCase().includes(search.toLowerCase()) ||
        asset.asset_type.toLowerCase().includes(search.toLowerCase());

      const matchType = typeFilter === "all" || asset.asset_type === typeFilter;
      const matchRisk = riskFilter === "all" || asset.risk_level === riskFilter;

      return matchSearch && matchType && matchRisk;
    });
  }, [assets, search, typeFilter, riskFilter]);

  return (
    <div className="space-y-6">
      {/* Top Controls & Header */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-[#1a2744] pb-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <span>Synthetic Asset Intelligence</span>
            <span className="rounded bg-cyan-950 px-2 py-0.5 text-xs font-mono text-cyan-400 border border-cyan-800/80">
              {assets.length} ASSETS
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Sandbox network topology, service configurations, vulnerability posture, and lateral movement relationships.
          </p>
        </div>

        <button
          onClick={fetchAssets}
          disabled={loading}
          className="flex items-center gap-1.5 rounded-lg border border-[#1a2744] bg-[#0c1222] px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:border-cyan-700 transition-all disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          <span>Refresh Inventory</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by asset name, IP address, hostname..."
            className="w-full rounded-lg border border-[#1a2744] bg-[#0c1222] py-2 pl-9 pr-3 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          {/* Asset Type Filter */}
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="rounded-lg border border-[#1a2744] bg-[#0c1222] px-3 py-2 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none cursor-pointer"
          >
            <option value="all">All Asset Types</option>
            <option value="server">Servers</option>
            <option value="database">Databases</option>
            <option value="web_application">Web Applications</option>
            <option value="api">APIs & Microservices</option>
            <option value="network_device">Network Devices</option>
          </select>

          {/* Risk Level Filter */}
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="rounded-lg border border-[#1a2744] bg-[#0c1222] px-3 py-2 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none cursor-pointer"
          >
            <option value="all">All Risk Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Asset Grid / Table */}
      {filteredAssets.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-[#1a2744] bg-[#0c1222] py-16 text-center">
          <Server className="h-10 w-10 text-slate-600 mb-3" />
          <h3 className="text-sm font-semibold text-slate-300">No Synthetic Assets Found</h3>
          <p className="text-xs text-slate-500 max-w-sm mt-1">
            {search || typeFilter !== "all" || riskFilter !== "all"
              ? "No assets match your search or filter criteria."
              : "Seed the sandbox using the 'Seed Assets' button in the top navigation bar."}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[#1a2744] bg-[#0c1222]">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="border-b border-[#1a2744] bg-[#070a13] text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3">Asset</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Network IP / Hostname</th>
                <th className="px-4 py-3">Risk Level</th>
                <th className="px-4 py-3">Vulnerabilities</th>
                <th className="px-4 py-3">Connections</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1a2744]/70">
              {filteredAssets.map((asset) => (
                <tr
                  key={asset.id}
                  onClick={() => setSelectedAsset(asset)}
                  className="hover:bg-cyan-950/20 cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-[#070a13] border border-slate-800">
                        {getAssetIcon(asset.asset_type)}
                      </div>
                      <div>
                        <div className="font-semibold text-white truncate max-w-[220px]">
                          {asset.name}
                        </div>
                        <div className="font-mono text-[10px] text-slate-500">
                          ID: {asset.id.slice(0, 8)}...
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-[11px] text-cyan-300">
                    {asset.asset_type}
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-mono text-slate-200">{asset.ip_address}</div>
                    <div className="text-[10px] text-slate-500 font-mono truncate max-w-[180px]">
                      {asset.hostname}
                    </div>
                  </td>
                  <td className="px-4 py-3">{getRiskBadge(asset.risk_level)}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5 font-mono text-xs">
                      <Bug className="h-3.5 w-3.5 text-amber-400" />
                      <span>{asset.simulated_vulnerabilities?.length || 0}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5 font-mono text-xs text-slate-400">
                      <Network className="h-3.5 w-3.5 text-cyan-400" />
                      <span>{asset.connected_asset_ids?.length || 0} link(s)</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedAsset(asset);
                      }}
                      className="rounded bg-cyan-950/80 px-2 py-1 text-[11px] font-medium text-cyan-400 hover:bg-cyan-900 transition-colors border border-cyan-800/60"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Asset Deep Inspection Drawer/Modal */}
      {selectedAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-2xl max-h-[85vh] overflow-y-auto rounded-xl border border-cyan-900/50 bg-[#0c1222] p-6 shadow-2xl">
            <button
              onClick={() => setSelectedAsset(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white transition-colors"
            >
              <X className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-3 border-b border-[#1a2744] pb-4 mb-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[#070a13] border border-cyan-800 text-cyan-400">
                {getAssetIcon(selectedAsset.asset_type)}
              </div>
              <div>
                <h2 className="text-base font-bold text-white">{selectedAsset.name}</h2>
                <div className="flex items-center gap-2 mt-0.5 text-xs text-slate-400 font-mono">
                  <span>{selectedAsset.ip_address}</span>
                  <span>•</span>
                  <span>{selectedAsset.hostname}</span>
                  <span>•</span>
                  {getRiskBadge(selectedAsset.risk_level)}
                </div>
              </div>
            </div>

            <div className="space-y-4 text-xs">
              {/* Description */}
              {selectedAsset.description && (
                <div>
                  <h3 className="text-slate-400 text-[11px] uppercase font-semibold mb-1">Description</h3>
                  <p className="rounded-lg bg-[#070a13] p-3 text-slate-300 border border-[#1a2744]">
                    {selectedAsset.description}
                  </p>
                </div>
              )}

              {/* Connected Asset IDs */}
              <div>
                <h3 className="text-slate-400 text-[11px] uppercase font-semibold mb-1">
                  Connected Assets (Lateral Movement Edges)
                </h3>
                {selectedAsset.connected_asset_ids?.length === 0 ? (
                  <p className="text-slate-500 italic">No direct lateral connections defined.</p>
                ) : (
                  <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                    {selectedAsset.connected_asset_ids.map((targetId) => {
                      const targetObj = assets.find((a) => a.id === targetId);
                      return (
                        <div
                          key={targetId}
                          onClick={() => {
                            if (targetObj) setSelectedAsset(targetObj);
                          }}
                          className="flex items-center justify-between rounded border border-slate-800 bg-[#070a13] p-2 hover:border-cyan-700 cursor-pointer transition-colors"
                        >
                          <span className="font-medium text-cyan-300 truncate">
                            {targetObj ? targetObj.name : `Asset ${targetId.slice(0, 8)}...`}
                          </span>
                          <ArrowRight className="h-3 w-3 text-slate-500 shrink-0" />
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Simulated Vulnerabilities */}
              <div>
                <h3 className="text-slate-400 text-[11px] uppercase font-semibold mb-1">
                  Simulated Vulnerability Catalog
                </h3>
                {selectedAsset.simulated_vulnerabilities?.length === 0 ? (
                  <p className="text-slate-500 italic">No simulated vulnerabilities configured.</p>
                ) : (
                  <div className="space-y-2">
                    {selectedAsset.simulated_vulnerabilities.map((vuln, idx) => (
                      <div
                        key={idx}
                        className="rounded border border-rose-950 bg-rose-950/20 p-2.5 text-xs text-rose-200"
                      >
                        <div className="flex items-center justify-between font-mono font-semibold">
                          <span>{vuln.cve || vuln.name || "UNNAMED-VULN"}</span>
                          <span className="text-[10px] uppercase text-rose-400">
                            {vuln.severity || "HIGH"}
                          </span>
                        </div>
                        {vuln.description && (
                          <p className="mt-1 text-[11px] text-slate-400">{vuln.description}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Configuration Metadata */}
              <div>
                <h3 className="text-slate-400 text-[11px] uppercase font-semibold mb-1">
                  Configuration & Service Metadata
                </h3>
                <pre className="rounded-lg bg-[#070a13] p-3 text-[11px] font-mono text-cyan-300 border border-[#1a2744] overflow-x-auto max-h-48">
                  {JSON.stringify(
                    {
                      configuration: selectedAsset.configuration,
                      service_metadata: selectedAsset.service_metadata,
                      os_metadata: selectedAsset.os_metadata,
                    },
                    null,
                    2
                  )}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

