"use client";

import React, { useState } from "react";
import { useAuth } from "../lib/auth-context";
import { Shield, Lock, User, AlertCircle, X, CheckCircle2 } from "lucide-react";

export const AuthModal: React.FC = () => {
  const { isAuthModalOpen, setIsAuthModalOpen, login, user, logout } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  if (!isAuthModalOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(username, password);
    } catch (err: any) {
      setError(err.message || "Authentication failed. Check credentials.");
    } finally {
      setLoading(false);
    }
  };

  const handleQuickLogin = async (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
    setError(null);
    setLoading(true);
    try {
      await login(u, p);
    } catch (err: any) {
      setError(err.message || "Authentication failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-md rounded-xl border border-cyan-900/40 bg-[#0c1222] p-6 shadow-2xl shadow-cyan-950/50">
        <button
          onClick={() => setIsAuthModalOpen(false)}
          className="absolute right-4 top-4 text-slate-400 hover:text-white transition-colors"
        >
          <X className="h-5 w-5" />
        </button>

        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-950/80 border border-cyan-700/50 text-cyan-400">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-white tracking-wide">SOC Identity Verification</h2>
            <p className="text-xs text-slate-400">Authenticate session to execute security operations</p>
          </div>
        </div>

        {user ? (
          <div className="space-y-4">
            <div className="rounded-lg border border-slate-800 bg-[#070a13] p-4 text-sm">
              <div className="flex items-center justify-between mb-2">
                <span className="text-slate-400">Active User:</span>
                <span className="font-mono text-cyan-300 font-semibold">{user.username}</span>
              </div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-slate-400">Role Capability:</span>
                <span className="rounded bg-cyan-950 px-2 py-0.5 text-xs font-semibold text-cyan-400 uppercase tracking-wider border border-cyan-800/60">
                  {user.role}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Status:</span>
                <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Authenticated & Token Active
                </span>
              </div>
            </div>

            <div className="flex gap-2">
              <button
                type="button"
                onClick={logout}
                className="w-full rounded-lg border border-rose-900/60 bg-rose-950/30 py-2.5 text-xs font-medium text-rose-300 hover:bg-rose-900/40 transition-colors"
              >
                Sign Out
              </button>
              <button
                type="button"
                onClick={() => setIsAuthModalOpen(false)}
                className="w-full rounded-lg bg-cyan-600 py-2.5 text-xs font-medium text-white hover:bg-cyan-500 transition-colors"
              >
                Return to Dashboard
              </button>
            </div>
          </div>
        ) : (
          <>
            {error && (
              <div className="mb-4 flex items-center gap-2 rounded-lg border border-rose-900/50 bg-rose-950/40 p-3 text-xs text-rose-300">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Username or Email</label>
                <div className="relative">
                  <User className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    placeholder="e.g. val_operator"
                    className="w-full rounded-lg border border-slate-800 bg-[#070a13] py-2 pl-9 pr-3 text-xs text-white placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    placeholder="••••••••••••"
                    className="w-full rounded-lg border border-slate-800 bg-[#070a13] py-2 pl-9 pr-3 text-xs text-white placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full rounded-lg bg-cyan-600 py-2.5 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors disabled:opacity-50"
              >
                {loading ? "Verifying Credentials..." : "Authenticate Session"}
              </button>
            </form>

            <div className="mt-6 border-t border-slate-800/80 pt-4">
              <p className="text-[11px] font-medium text-slate-400 mb-2.5 uppercase tracking-wider">
                1-Click Preset Roles (Testing Accounts)
              </p>
              <div className="grid grid-cols-3 gap-2">
                <button
                  type="button"
                  onClick={() => handleQuickLogin("val_operator", "AegisOperator2026!")}
                  className="rounded-lg border border-slate-800 bg-[#070a13] p-2 text-center hover:border-cyan-700/60 transition-all hover:bg-cyan-950/20"
                >
                  <div className="text-xs font-semibold text-cyan-400">Operator</div>
                  <div className="text-[10px] text-slate-500">Scan & Run</div>
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickLogin("val_admin", "AegisAdmin2026!")}
                  className="rounded-lg border border-slate-800 bg-[#070a13] p-2 text-center hover:border-purple-700/60 transition-all hover:bg-purple-950/20"
                >
                  <div className="text-xs font-semibold text-purple-400">Admin</div>
                  <div className="text-[10px] text-slate-500">Full Access</div>
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickLogin("val_viewer", "AegisViewer2026!")}
                  className="rounded-lg border border-slate-800 bg-[#070a13] p-2 text-center hover:border-amber-700/60 transition-all hover:bg-amber-950/20"
                >
                  <div className="text-xs font-semibold text-amber-400">Viewer</div>
                  <div className="text-[10px] text-slate-500">Read-Only</div>
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

