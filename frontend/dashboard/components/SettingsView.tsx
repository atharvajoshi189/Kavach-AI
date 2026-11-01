"use client";

import React from "react";
import { useAuth } from "../lib/auth-context";
import { Settings, Shield, Lock, Database, Cpu, User, CheckCircle2 } from "lucide-react";

export const SettingsView: React.FC = () => {
  const { user } = useAuth();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-[#1a2744] pb-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
            <span>System Settings & Architecture Diagnostics</span>
            <span className="rounded bg-slate-900 px-2 py-0.5 text-xs font-mono text-slate-400 border border-slate-800">
              ENVIRONMENT CONFIG
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Active security policies, authentication configurations, and runtime database properties.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        {/* User Identity Details */}
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-5 space-y-4">
          <div className="flex items-center gap-2 font-bold text-white text-sm">
            <User className="h-4 w-4 text-cyan-400" />
            <span>Active Session Identity</span>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Username:</span>
              <span className="text-cyan-300 font-semibold">{user?.username || "Anonymous"}</span>
            </div>
            <div className="flex justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Email Address:</span>
              <span className="text-slate-300">{user?.email || "N/A"}</span>
            </div>
            <div className="flex justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Platform Role:</span>
              <span className="rounded bg-cyan-950 px-2 py-0.5 text-[10px] text-cyan-400 font-bold uppercase border border-cyan-800">
                {user?.role || "GUEST"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Account Verified:</span>
              <span className="text-emerald-400">
                {user?.is_verified ? "True (Argon2id)" : "Active Session"}
              </span>
            </div>
          </div>
        </div>

        {/* Security & OPA Gateway Specs */}
        <div className="rounded-xl border border-[#1a2744] bg-[#0c1222] p-5 space-y-4">
          <div className="flex items-center gap-2 font-bold text-white text-sm">
            <Lock className="h-4 w-4 text-purple-400" />
            <span>Security Gateway & OPA Configuration</span>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Authorization Model:</span>
              <span className="text-emerald-400 font-semibold">Open Policy Agent (Default-Deny)</span>
            </div>
            <div className="flex justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Policy Package:</span>
              <span className="text-cyan-300">package aegis (v1.0.0)</span>
            </div>
            <div className="flex justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">JWT Algorithm:</span>
              <span className="text-slate-300">HS256 (30-min Access / 7-day Refresh)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Audit Storage:</span>
              <span className="text-purple-300">Sequential SHA-256 Chained Hash</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

