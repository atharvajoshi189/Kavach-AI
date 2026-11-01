"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { api, clearStoredTokens, getStoredToken } from "./api";
import { SandboxEnvironment, User } from "./types";

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  activeSandbox: SandboxEnvironment | null;
  sandboxes: SandboxEnvironment[];
  isAuthModalOpen: boolean;
  setIsAuthModalOpen: (open: boolean) => void;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  setActiveSandbox: (sandbox: SandboxEnvironment) => void;
  refreshSandboxes: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [sandboxes, setSandboxes] = useState<SandboxEnvironment[]>([]);
  const [activeSandbox, setActiveSandbox] = useState<SandboxEnvironment | null>(null);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);

  const fetchSandboxes = useCallback(async () => {
    try {
      let sbList = await api.listSandboxes();
      if (!sbList || sbList.length === 0) {
        // Automatically seed demo sandbox if none exists
        try {
          await api.seedDemoSandbox();
          sbList = await api.listSandboxes();
        } catch (e) {
          console.warn("Could not auto-seed sandbox:", e);
        }
      }
      
      // Prioritize demo-enterprise-sandbox at the top of the list
      const demoSb = sbList.find((s) => s.name === "demo-enterprise-sandbox");
      if (demoSb) {
        sbList = [demoSb, ...sbList.filter((s) => s.id !== demoSb.id)];
      }

      setSandboxes(sbList);
      if (sbList.length > 0) {
        setActiveSandbox(demoSb || sbList[0]);
      }
    } catch (err) {
      console.error("Failed to load sandboxes:", err);
    }
  }, []);

  const initAuth = useCallback(async () => {
    setIsLoading(true);
    let currentToken = getStoredToken();

    // If no token exists in localStorage, automatically sign in with operator for instant SOC preview
    if (!currentToken) {
      try {
        const tokens = await api.login("val_operator", "AegisOperator2026!");
        currentToken = tokens.access_token;
      } catch (err) {
        console.warn("Auto-login fallback failed:", err);
      }
    }

    if (currentToken) {
      setToken(currentToken);
      try {
        const profile = await api.getMe();
        setUser(profile);
        await fetchSandboxes();
      } catch (err) {
        console.warn("Stored token invalid or expired. Clearing.", err);
        clearStoredTokens();
        setToken(null);
        setUser(null);
      }
    }
    setIsLoading(false);
  }, [fetchSandboxes]);

  useEffect(() => {
    initAuth();
  }, [initAuth]);

  const login = async (username: string, password: string) => {
    setIsLoading(true);
    try {
      const tokens = await api.login(username, password);
      setToken(tokens.access_token);
      const profile = await api.getMe();
      setUser(profile);
      await fetchSandboxes();
      setIsAuthModalOpen(false);
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    api.logout();
    setToken(null);
    setUser(null);
    setActiveSandbox(null);
    setSandboxes([]);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        activeSandbox,
        sandboxes,
        isAuthModalOpen,
        setIsAuthModalOpen,
        login,
        logout,
        setActiveSandbox,
        refreshSandboxes: fetchSandboxes,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

