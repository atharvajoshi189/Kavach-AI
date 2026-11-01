"use client";

import React, { useEffect, useState, useMemo } from "react";
import { useAuth } from "../lib/auth-context";
import { api } from "../lib/api";
import { AttackPath, SimulationFinding } from "../lib/types";
import {
  FileSearch,
  ShieldCheck,
  Bug,
  Search,
  Filter,
  CheckCircle2,
  ExternalLink,
  Layers,
  ChevronDown,
} from "lucide-react";

export const EvidenceVault: React.FC = () => {
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [findings, setFindings] = useState<SimulationFinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<SimulationFinding | null>(null);

  useEffect(() => {
    const fetchFindings = async () => {
      setLoading(true);
      try {
        const pathList = await api.listAttackPaths(0, 20);
        setPaths(pathList.items || []);

        // Collect findings across all reports
        const allFindings: SimulationFinding[] = [];
        for (const p of (pathList.items || []).slice(0, 5)) {
          try {
            const rep = await api.getAttackPathReport(p.id);
            // Scan through correlated events or stage metadata
            if (rep && rep.correlated_events) {
              for (const ev of rep.correlated_events) {
                if (ev.details && ev.details.findings) {
                  allFindings.push(...ev.details.findings);
                }
              }
            }
          } catch (e) {
            // ignore
          }
        }

        // If no findings from reports, generate sample structured finding evidence from live assets
        setFindings(allFindings);
      } catch (err) {
        console.error("Failed to load evidence findings:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchFindings();
  }, []);

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const matchSeverity = severityFilter === "all" || f.severity === severityFilter;
      const matchSearch =
        f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.technique.toLowerCase().includes(searchTerm.toLowerCase());
      return matchSeverity && matchSearch;
    });
  }, [findings, severityFilter, searchTerm]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-[#1a2744] pb-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <span>Evidence Vault & Findings Registry</span>
            <span className="rounded bg-cyan-950 px-2 py-0.5 text-xs font-mono text-cyan-400 border border-cyan-800/80">
              AUDITED EVIDENCE
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Forensic artifacts, simulated security findings, and mitigation rationales generated during simulation runs.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search findings by title, technique, or vulnerability..."
            className="w-full rounded-lg border border-[#1a2744] bg-[#0c1222] py-2 pl-9 pr-3 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-lg border border-[#1a2744] bg-[#0c1222] px-3 py-2 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none cursor-pointer"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical Severity</option>
          <option value="high">High Severity</option>
          <option value="medium">Medium Severity</option>
          <option value="low">Low Severity</option>
        </select>
      </div>

      {/* Findings Table */}
      {filteredFindings.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-[#1a2744] bg-[#0c1222] py-16 text-center">
          <FileSearch className="h-10 w-10 text-slate-600 mb-3" />
          <h3 className="text-sm font-semibold text-slate-300">No Security Findings Discovered Yet</h3>
          <p className="text-xs text-slate-500 max-w-sm mt-1">
            Execute a Red Team simulation run or Attack Path to automatically populate forensic findings and evidence in this vault.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {filteredFindings.map((f, i) => (
            <div
              key={f.finding_id || i}
              className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-5 shadow-sm space-y-3"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-cyan-400 font-bold text-xs">{f.technique}</span>
                <span
                  className={`rounded px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wider ${
                    f.severity === "critical"
                      ? "bg-rose-950 text-rose-400 border border-rose-800"
                      : f.severity === "high"
                      ? "bg-orange-950 text-orange-400 border border-orange-800"
                      : "bg-amber-950 text-amber-400 border border-amber-800"
                  }`}
                >
                  {f.severity}
                </span>
              </div>

              <h3 className="text-sm font-bold text-white">{f.title}</h3>
              <p className="text-xs text-slate-400 leading-relaxed">{f.description}</p>

              {f.remediation_recommendation && (
                <div className="rounded-lg bg-[#070a13] border border-cyan-950 p-2.5 text-xs text-cyan-300">
                  <div className="font-semibold text-[11px] text-cyan-400 mb-0.5">Recommended Remediation:</div>
                  <p className="text-[11px] text-slate-300">{f.remediation_recommendation}</p>
                </div>
              )}

              <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-[10px] text-slate-500 font-mono">
                <span>Synthetic Target: {f.asset_id.slice(0, 8)}...</span>
                <span className="text-emerald-400">is_simulated=True</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

