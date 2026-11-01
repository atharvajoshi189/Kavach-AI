"use client";

import React, { useState, useEffect, useRef } from "react";
import {
  Swords,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Globe,
  Mail,
  Folder,
  CreditCard,
  Play,
  Pause,
  FastForward,
  Clock,
  Square,
  Terminal,
  Layers,
  Settings,
  Target,
  Code,
  Trophy,
  X,
  ArrowDown,
  Volume2,
  VolumeX,
} from "lucide-react";
import { api } from "../lib/api";
import {
  ArenaStateSnapshot,
  ArenaRoundRecord,
} from "../lib/types";

type ExecutionPhase = "IDLE" | "RED_ATTACKING" | "TARGET_PROCESSING" | "BLUE_DEFENDING" | "ROUND_RESOLVED";

export function AgentArenaView() {
  const [state, setState] = useState<ArenaStateSnapshot | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [stepping, setStepping] = useState<boolean>(false);
  const [isRunningSimulation, setIsRunningSimulation] = useState<boolean>(false);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [voiceEnabled, setVoiceEnabled] = useState<boolean>(true);
  const [isSpeaking, setIsSpeaking] = useState<boolean>(false);
  const [speakingAgent, setSpeakingAgent] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);
  const [selectedRound, setSelectedRound] = useState<ArenaRoundRecord | null>(null);
  const [showScrollPill, setShowScrollPill] = useState<boolean>(false);

  // Staged multi-agent dialogue & sequential timing state
  const [phase, setPhase] = useState<ExecutionPhase>("IDLE");
  const [stagedRoundIndex, setStagedRoundIndex] = useState<number | null>(null);
  const [stagedRedPrompt, setStagedRedPrompt] = useState<string | null>(null);
  const [stagedScenarioName, setStagedScenarioName] = useState<string | null>(null);
  const [stagedVectorType, setStagedVectorType] = useState<string | null>(null);
  const [stagedActiveTool, setStagedActiveTool] = useState<string | null>(null);
  const [stagedBlueDecision, setStagedBlueDecision] = useState<{
    decision: string;
    explanation: string;
    isBreach: boolean;
  } | null>(null);
  const [displayedMessages, setDisplayedMessages] = useState<any[]>([]);

  // References
  const chatContainerRef = useRef<HTMLDivElement>(null);
  const isUserScrolledUp = useRef<boolean>(false);
  const isRunningSimulationRef = useRef<boolean>(false);
  const isSteppingRef = useRef<boolean>(false);
  const runTimerRef = useRef<NodeJS.Timeout | null>(null);
  const activeAudioRef = useRef<HTMLAudioElement | null>(null);

  // Fetch live state
  const loadState = async () => {
    try {
      const data = await api.arena.getState();
      setState(data);
      if (data.conversation_stream && data.conversation_stream.length > 0) {
        setDisplayedMessages(data.conversation_stream);
      }
      setErrorMsg(null);
    } catch (err: any) {
      console.error("Failed to load arena state", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadState();
    const pollInterval = setInterval(() => {
      if (!isPaused && isRunningSimulation) {
        setElapsedSeconds((prev) => prev + 1);
      }
    }, 1000);
    return () => clearInterval(pollInterval);
  }, [isPaused, isRunningSimulation]);

  // Chat auto-scroll without page snapping
  useEffect(() => {
    if (!isUserScrolledUp.current && chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [displayedMessages]);

  const handleChatScroll = () => {
    if (!chatContainerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = chatContainerRef.current;
    const isScrolledUp = scrollHeight - scrollTop - clientHeight > 50;
    isUserScrolledUp.current = isScrolledUp;
    setShowScrollPill(isScrolledUp);
  };

  const scrollToBottom = () => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
      isUserScrolledUp.current = false;
      setShowScrollPill(false);
    }
  };

  // Dual-Tier Voice Speech Engine: Gemini AI TTS + Studio-Quality WAV Synthesizer + Fallback
  const speakDialogue = async (text: string, speaker: "RED_TEAM" | "BLUE_GUARDIAN"): Promise<void> => {
    if (!voiceEnabled || !text) return;

    // Stop any existing utterance
    if (activeAudioRef.current) {
      activeAudioRef.current.pause();
      activeAudioRef.current = null;
    }
    if (typeof window !== "undefined" && window.speechSynthesis) {
      window.speechSynthesis.cancel();
    }

    setIsSpeaking(true);
    setSpeakingAgent(speaker);

    const voiceName = speaker === "RED_TEAM" ? "Puck" : "Fenrir";

    try {
      // 1. Try backend crystal-clear speech (Gemini TTS / Local Studio WAV)
      const res = await api.arena.speak(text, voiceName);
      if (res.status === "success" && res.audio_base64) {
        await new Promise<void>((resolve) => {
          const audio = new Audio(res.audio_base64!);
          activeAudioRef.current = audio;
          audio.onended = () => {
            setIsSpeaking(false);
            setSpeakingAgent(null);
            activeAudioRef.current = null;
            resolve();
          };
          audio.onerror = () => {
            playBrowserFallback(text, speaker).then(resolve);
          };
          audio.play().catch(() => {
            playBrowserFallback(text, speaker).then(resolve);
          });
        });
        return;
      }
    } catch {
      // Gracefully fall through to browser SpeechSynthesis
    }

    // 2. Browser SpeechSynthesis Fallback
    await playBrowserFallback(text, speaker);
  };

  const playBrowserFallback = (text: string, speaker: "RED_TEAM" | "BLUE_GUARDIAN"): Promise<void> => {
    return new Promise((resolve) => {
      if (typeof window === "undefined" || !("speechSynthesis" in window)) {
        setIsSpeaking(false);
        setSpeakingAgent(null);
        resolve();
        return;
      }

      const utterance = new SpeechSynthesisUtterance(text);
      if (speaker === "RED_TEAM") {
        utterance.pitch = 0.8;
        utterance.rate = 1.05; // Cyber adversary cadence
      } else {
        utterance.pitch = 1.15;
        utterance.rate = 0.98; // Authoritative defensive cadence
      }

      utterance.onend = () => {
        setIsSpeaking(false);
        setSpeakingAgent(null);
        resolve();
      };
      utterance.onerror = () => {
        setIsSpeaking(false);
        setSpeakingAgent(null);
        resolve();
      };

      window.speechSynthesis.speak(utterance);
    });
  };

  // ---------------------------------------------------------------------------
  // STRICT SEQUENTIAL MULTI-AGENT ROUND STAGING:
  // 1. Red Agent speaks & displays attack prompt (Blue is analyzing/hidden).
  // 2. Target Agent receives attack; tool card glows red.
  // 3. Blue Guardian reveals decision text and speaks response.
  // 4. Round resolves: scoreboard, timeline, and policy increment.
  // ---------------------------------------------------------------------------
  const executeRoundSequence = async (res: { state: ArenaStateSnapshot; round_record?: ArenaRoundRecord }) => {
    const rec = res.round_record;
    if (!rec) {
      setState(res.state);
      return;
    }

    const roundNum = rec.round_index;
    const redPrompt = rec.red_team_prompt;
    const targetTool = rec.proposed_tool ? rec.proposed_tool.toLowerCase() : "payment";
    const isBreach = roundNum === 1 && (rec.outcome === "BREACH" || rec.outcome === "DETECTED_AND_EXECUTED");
    const blueExplanation = isBreach
      ? "Baseline policy allowed action. Penalty applied. Learning defense."
      : (rec.explanation || (rec.blue_guardian_decision === "BLOCK" ? "Pattern matched learned adversarial payload. Action blocked." : "Verified benign action. Allowed."));

    // -------------------------------------------------------------
    // STAGE 1: RED AGENT ATTACKS
    // -------------------------------------------------------------
    setPhase("RED_ATTACKING");
    setStagedRoundIndex(roundNum);
    setStagedRedPrompt(redPrompt);
    setStagedScenarioName(rec.scenario_name || "Adversary Strategy Engine");
    setStagedVectorType(rec.vector_type || "ADVERSARY");
    setStagedActiveTool(null);
    setStagedBlueDecision(null); // CRITICAL: Blue Guardian shows NOTHING / Analyzing

    // Add Red Agent message only to conversation stream
    setDisplayedMessages((prev) => [
      ...prev,
      {
        message_id: `red-${roundNum}-${Date.now()}`,
        round_index: roundNum,
        speaker: "RED_TEAM",
        message: redPrompt,
        timestamp: new Date().toISOString(),
      },
    ]);

    // Red Agent speaks attack instruction
    if (voiceEnabled) {
      await speakDialogue(redPrompt, "RED_TEAM");
    } else {
      await new Promise((r) => setTimeout(r, 1200));
    }

    // Check cancellation
    if (!isRunningSimulationRef.current && !isSteppingRef.current) return;

    // -------------------------------------------------------------
    // STAGE 2: TARGET AGENT RECEIVES & LIGHTS UP TARGET TOOL
    // -------------------------------------------------------------
    setPhase("TARGET_PROCESSING");
    setStagedActiveTool(targetTool);

    const targetMsg = `Received request: Accessing [${rec.proposed_tool.toUpperCase()}] tool. Submitting action envelope to defensive gate.`;
    setDisplayedMessages((prev) => [
      ...prev,
      {
        message_id: `target-${roundNum}-${Date.now()}`,
        round_index: roundNum,
        speaker: "TARGET_AGENT",
        message: targetMsg,
        timestamp: new Date().toISOString(),
      },
    ]);

    await new Promise((r) => setTimeout(r, 700));

    // Check cancellation
    if (!isRunningSimulationRef.current && !isSteppingRef.current) return;

    // -------------------------------------------------------------
    // STAGE 3: BLUE GUARDIAN DECISION REVEALED & SPEAKS
    // -------------------------------------------------------------
    setPhase("BLUE_DEFENDING");
    setStagedBlueDecision({
      decision: rec.blue_guardian_decision,
      explanation: blueExplanation,
      isBreach: isBreach,
    });

    setDisplayedMessages((prev) => [
      ...prev,
      {
        message_id: `blue-${roundNum}-${Date.now()}`,
        round_index: roundNum,
        speaker: "BLUE_GUARDIAN",
        message: blueExplanation,
        timestamp: new Date().toISOString(),
      },
    ]);

    // Blue Guardian speaks defense decision
    if (voiceEnabled) {
      await speakDialogue(blueExplanation, "BLUE_GUARDIAN");
    } else {
      await new Promise((r) => setTimeout(r, 1200));
    }

    // -------------------------------------------------------------
    // STAGE 4: ROUND RESOLVED & SYNC BACKEND STATE
    // -------------------------------------------------------------
    setPhase("ROUND_RESOLVED");

    const sysMsg = rec.blue_guardian_decision === "BLOCK"
      ? `Shield engaged: Attack prevented. Defensive policy updated to ${res.state.scoreboard.policy_version}.`
      : `Baseline execution observed. Negative reward logged. Policy training initiated.`;

    setDisplayedMessages((prev) => [
      ...prev,
      {
        message_id: `sys-${roundNum}-${Date.now()}`,
        round_index: roundNum,
        speaker: "SYSTEM",
        message: sysMsg,
        timestamp: new Date().toISOString(),
      },
    ]);

    // Commit full backend state: updates scoreboard, timeline, learning progress
    setState(res.state);
    setPhase("IDLE");
  };

  // Execute single next round
  const handleStepNextRound = async () => {
    if (isSteppingRef.current) return;
    isSteppingRef.current = true;
    setStepping(true);
    try {
      const res = await api.arena.stepNextRound();
      await executeRoundSequence(res);
    } catch (err: any) {
      setErrorMsg(err.message || "Error advancing round.");
    } finally {
      setStepping(false);
      isSteppingRef.current = false;
    }
  };

  // ---------------------------------------------------------------------------
  // FULL 6-ROUND AUTONOMOUS SIMULATION WITH STAGED MULTI-AGENT TIMING
  // ---------------------------------------------------------------------------
  const handleRunSimulation = async () => {
    if (isRunningSimulationRef.current) return;
    isRunningSimulationRef.current = true;
    setIsRunningSimulation(true);
    setIsPaused(false);
    setErrorMsg(null);

    try {
      // If already finished or started, reset to Round 0 first
      const currentR = state?.current_round || 0;
      if (currentR >= 6 || currentR > 0) {
        const resetRes = await api.arena.reset(false);
        setState(resetRes.state);
        setDisplayedMessages([]);
        setStagedRoundIndex(null);
        setStagedRedPrompt(null);
        setStagedBlueDecision(null);
        setStagedActiveTool(null);
        setElapsedSeconds(0);
        await new Promise((resolve) => setTimeout(resolve, 500));
      }

      // Step sequentially from Round 1 through Round 6
      for (let roundTarget = (state?.current_round || 0) + 1; roundTarget <= 6; roundTarget++) {
        if (!isRunningSimulationRef.current) break;

        const res = await api.arena.stepNextRound();
        await executeRoundSequence(res);

        // Inter-round buffer
        if (roundTarget < 6 && isRunningSimulationRef.current) {
          await new Promise((resolve) => {
            runTimerRef.current = setTimeout(resolve, 1400);
          });
        }
      }
    } catch (err: any) {
      console.error("Simulation run error", err);
      setErrorMsg(err.message || "Error during simulation run.");
    } finally {
      setIsRunningSimulation(false);
      isRunningSimulationRef.current = false;
      setIsSpeaking(false);
      setSpeakingAgent(null);
      setPhase("IDLE");
    }
  };

  const handleReset = async () => {
    isRunningSimulationRef.current = false;
    setIsRunningSimulation(false);
    setIsSpeaking(false);
    setSpeakingAgent(null);
    setPhase("IDLE");

    if (activeAudioRef.current) {
      activeAudioRef.current.pause();
      activeAudioRef.current = null;
    }
    if (typeof window !== "undefined" && window.speechSynthesis) {
      window.speechSynthesis.cancel();
    }
    if (runTimerRef.current) {
      clearTimeout(runTimerRef.current);
      runTimerRef.current = null;
    }

    if (isSteppingRef.current) return;
    isSteppingRef.current = true;
    setStepping(true);
    try {
      const res = await api.arena.reset(false);
      setState(res.state);
      setDisplayedMessages([]);
      setStagedRoundIndex(null);
      setStagedRedPrompt(null);
      setStagedBlueDecision(null);
      setStagedActiveTool(null);
      setElapsedSeconds(0);
      setErrorMsg(null);
    } catch (err: any) {
      setErrorMsg(err.message || "Error resetting arena.");
    } finally {
      setStepping(false);
      isSteppingRef.current = false;
    }
  };

  // Derive metrics
  const currentRoundNum = stagedRoundIndex !== null ? stagedRoundIndex : (state?.current_round || 0);
  const totalRoundsMax = 6;
  const latestRound: ArenaRoundRecord | null = state?.latest_round || null;
  const history = state?.round_history || [];

  const breachesCount = history.filter(
    (r) => r.outcome === "BREACH" || r.outcome === "DETECTED_AND_EXECUTED"
  ).length;
  const blockedCount = history.filter(
    (r) => r.blue_guardian_decision === "BLOCK" || r.outcome === "CORRECT_BLOCK"
  ).length;

  const totalAttacksCount = history.length;
  const attackSuccessRate =
    totalAttacksCount > 0 ? ((breachesCount / totalAttacksCount) * 100).toFixed(0) : "0";
  const preventionRate =
    totalAttacksCount > 0 ? ((blockedCount / totalAttacksCount) * 100).toFixed(0) : "0";

  const formatTime = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  };

  const activeTool =
    phase === "RED_ATTACKING"
      ? "none"
      : stagedActiveTool !== null
      ? stagedActiveTool
      : latestRound?.proposed_tool?.toLowerCase() || (currentRoundNum === 0 ? "none" : "payment");

  const isRound1Breach =
    stagedBlueDecision?.isBreach ??
    (latestRound?.round_index === 1 && (latestRound.outcome === "BREACH" || latestRound.outcome === "DETECTED_AND_EXECUTED"));

  const isShieldDeflecting =
    (phase === "BLUE_DEFENDING" || phase === "ROUND_RESOLVED" || phase === "IDLE") &&
    (stagedBlueDecision?.decision === "BLOCK" ||
      (latestRound && latestRound.round_index > 1 && latestRound.blue_guardian_decision === "BLOCK"));

  // Dynamic Timeline Rounds (Escalating multi-vector adaptive flow)
  const timelineRounds = [
    { num: 1, title: "R1 — Level 1: Email Baseline Infiltration", tool: "email" },
    { num: 2, title: "R2 — Level 2: Cloud Metadata SSRF", tool: "browser" },
    { num: 3, title: "R3 — Level 3: Shadow Config Traversal", tool: "files" },
    { num: 4, title: "R4 — Level 4: Wire Parameter Tampering", tool: "payment" },
    { num: 5, title: "R5 — Level 5: Cross-Tool Payload Chain", tool: "browser" },
    { num: 6, title: "R6 — Level 6: Polyglot Zero-Day Evasion", tool: "payment" },
  ];

  // SVG prevention curve
  const preventionPoints: { round: number; rate: number }[] = [];
  if (history.length > 0) {
    let cumulativeBlocked = 0;
    history.forEach((rec, idx) => {
      if (rec.blue_guardian_decision === "BLOCK" || rec.outcome === "CORRECT_BLOCK") {
        cumulativeBlocked++;
      }
      const rate = Math.round((cumulativeBlocked / (idx + 1)) * 100);
      preventionPoints.push({ round: idx + 1, rate });
    });
  } else {
    preventionPoints.push({ round: 1, rate: 0 });
  }

  const svgWidth = 100;
  const svgHeight = 44;
  const chartPointsString = preventionPoints
    .map((pt, i) => {
      const x = (i / 5) * svgWidth;
      const y = svgHeight - (pt.rate / 100) * svgHeight;
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <div className="flex flex-col min-h-[calc(100vh-4.5rem)] p-3 lg:p-4 space-y-3 text-slate-100 font-sans select-none">
      {/* ERROR BANNER */}
      {errorMsg && (
        <div className="flex items-center justify-between px-3 py-1.5 bg-rose-950/80 border border-rose-800 rounded-xl text-rose-300 text-xs backdrop-blur-md">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="underline hover:text-white cursor-pointer">
            Dismiss
          </button>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 1. COMPACT TOP GLASS HEADER BAR                                           */}
      {/* ========================================================================= */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 px-3 py-2 rounded-2xl bg-white/[0.02] border border-white/[0.06] backdrop-blur-xl shadow-lg">
        {/* Title & Status */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-base font-bold text-white">
            <Swords className="w-4 h-4 text-cyan-400" />
            <span>Agent Arena</span>
          </div>
          <span className="text-xs text-slate-500 font-mono">|</span>
          <div className="px-2.5 py-0.5 rounded-full bg-cyan-950/40 border border-cyan-500/30 text-[11px] font-mono text-cyan-300 font-bold">
            Round {currentRoundNum} / {totalRoundsMax}
          </div>
          <div className="flex items-center gap-1 text-[11px] font-mono text-slate-400">
            <Clock className="w-3 h-3 text-slate-500" />
            <span>{formatTime(elapsedSeconds)}</span>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          {/* Voice Toggle */}
          <button
            onClick={() => setVoiceEnabled(!voiceEnabled)}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border text-xs font-medium transition-all cursor-pointer ${
              voiceEnabled
                ? "bg-cyan-950/50 border-cyan-500/40 text-cyan-300 shadow-sm shadow-cyan-950"
                : "bg-white/[0.02] border-white/[0.06] text-slate-500"
            }`}
            title={voiceEnabled ? "Gemini AI Voice Active (Puck & Fenrir)" : "Voice Muted"}
          >
            {voiceEnabled ? (
              <>
                <Volume2 className={`w-3.5 h-3.5 ${isSpeaking ? "animate-pulse text-cyan-400" : ""}`} />
                <span className="text-[11px] hidden sm:inline">Voice ON</span>
              </>
            ) : (
              <>
                <VolumeX className="w-3.5 h-3.5" />
                <span className="text-[11px] hidden sm:inline">Voice Muted</span>
              </>
            )}
          </button>

          {/* Primary Run Simulation Button */}
          <button
            onClick={handleRunSimulation}
            disabled={isRunningSimulation}
            className={`flex items-center gap-2 px-4 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
              isRunningSimulation
                ? "bg-cyan-900 text-cyan-200 border border-cyan-700 opacity-80 cursor-wait"
                : "bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-blue-500 text-white shadow-lg shadow-cyan-950/60 ring-1 ring-cyan-400/40 hover:scale-[1.02]"
            }`}
          >
            {isRunningSimulation ? (
              <>
                <div className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Simulating...</span>
              </>
            ) : (
              <>
                <Play className="w-3 h-3 fill-white text-white" />
                <span>Run Simulation</span>
              </>
            )}
          </button>

          {/* Pause / Resume */}
          <button
            onClick={() => {
              if (isRunningSimulation) {
                isRunningSimulationRef.current = false;
                setIsRunningSimulation(false);
              }
              setIsPaused(!isPaused);
            }}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-xl bg-white/[0.03] border border-white/[0.08] text-xs font-medium text-slate-300 hover:text-white transition-all shadow-sm cursor-pointer"
          >
            <Pause className="w-3 h-3" />
            <span className="hidden sm:inline">{isPaused ? "Resume" : "Pause"}</span>
          </button>

          {/* Stop / Reset */}
          <button
            onClick={handleReset}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-xl bg-rose-950/40 border border-rose-800/60 text-xs font-medium text-rose-300 hover:bg-rose-950 transition-all shadow-sm cursor-pointer"
            title="Reset Simulation"
          >
            <Square className="w-3 h-3 fill-rose-400 text-rose-400" />
            <span className="hidden sm:inline">Reset</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 2. 12-COLUMN MAIN BATTLE & CONTROLS GRID                                  */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 items-start w-full">
        {/* ======================================================================= */}
        {/* LEFT COLUMN: BATTLE SCENE + CONVERSATION & TIMELINE (8 COLS)            */}
        {/* ======================================================================= */}
        <div className="lg:col-span-8 flex flex-col space-y-3 min-w-0">
          {/* ===================================================================== */}
          {/* 2A. CENTRAL AGENT BATTLE VISUALIZATION                                */}
          {/* ===================================================================== */}
          <div className="relative w-full rounded-2xl bg-gradient-to-b from-[#070c17]/95 via-[#050812]/95 to-[#070c17]/95 border border-white/[0.08] p-4 lg:p-5 shadow-2xl backdrop-blur-2xl overflow-hidden min-h-[350px]">
            {/* Ambient Background Glows */}
            <div className="absolute -left-20 top-1/2 -translate-y-1/2 w-64 h-64 bg-red-600/[0.08] rounded-full blur-3xl pointer-events-none" />
            <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-80 h-80 bg-cyan-600/[0.08] rounded-full blur-3xl pointer-events-none" />
            <div className="absolute -right-20 top-1/2 -translate-y-1/2 w-64 h-64 bg-cyan-600/[0.08] rounded-full blur-3xl pointer-events-none" />

            <div className="relative z-10 grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
              {/* --------------------------------------------------------------- */}
              {/* RED TEAM AGENT                                                  */}
              {/* --------------------------------------------------------------- */}
              <div className="flex flex-col items-center relative">
                {/* Attack Speech Bubble */}
                <div
                  className={`w-full mb-2 p-2.5 rounded-xl border backdrop-blur-md transition-all ${
                    speakingAgent === "RED_TEAM"
                      ? "bg-red-950/90 border-red-400 shadow-[0_0_20px_rgba(239,68,68,0.7)] scale-[1.02]"
                      : "bg-[#160b12]/80 border-red-500/50 shadow-md shadow-red-950/40"
                  }`}
                >
                  <div className="flex items-center justify-between text-[9px] font-mono font-bold text-red-400 uppercase tracking-wider mb-0.5">
                    <span className="flex items-center gap-1">
                      <span>&gt; Attack</span>
                      {speakingAgent === "RED_TEAM" && (
                        <Volume2 className="w-3 h-3 text-red-400 animate-pulse" />
                      )}
                    </span>
                    <span className="text-red-400/80 font-mono text-[8px]">
                      {stagedVectorType || latestRound?.vector_type || "ADVERSARY"}
                    </span>
                  </div>
                  <p className="text-[11px] text-red-100 font-medium leading-snug italic break-words line-clamp-3">
                    &ldquo;
                    {stagedRedPrompt || latestRound?.red_team_prompt || "Initiate simulated tool exploit payload."}
                    &rdquo;
                  </p>
                  <div className="absolute -bottom-1.5 left-1/2 -translate-x-1/2 w-0 h-0 border-l-[5px] border-l-transparent border-r-[5px] border-r-transparent border-t-[6px] border-t-red-500/60" />
                </div>

                {/* Avatar */}
                <div className="relative my-1 flex items-center justify-center">
                  <div
                    className={`w-28 h-28 rounded-full flex items-center justify-center relative transition-all ${
                      speakingAgent === "RED_TEAM" ? "scale-105" : ""
                    }`}
                  >
                    <img
                      src="/arena/red_agent.png"
                      alt="Red Agent"
                      className="w-24 h-24 object-contain drop-shadow-[0_0_18px_rgba(239,68,68,0.6)]"
                    />
                  </div>

                  {/* Red Attack Beam */}
                  <div className="hidden md:flex absolute -right-16 top-1/2 -translate-y-1/2 items-center z-20 pointer-events-none">
                    <div className="w-12 h-0.5 bg-gradient-to-r from-red-500 to-transparent shadow-[0_0_8px_rgba(239,68,68,0.8)]" />
                    <span className="text-red-400 text-xs font-bold animate-pulse">&gt;&gt;</span>
                  </div>
                </div>

                {/* Agent Card */}
                <div className="w-full mt-1 p-2 rounded-xl bg-white/[0.02] border border-red-900/40 text-left space-y-0.5 backdrop-blur-md">
                  <div className="text-[11px] font-bold text-red-400">RED AGENT</div>
                  <div className="text-[10px] text-slate-400 font-mono truncate">
                    {stagedScenarioName || latestRound?.scenario_name || "Adversary Strategy Engine"}
                  </div>
                </div>
              </div>

              {/* --------------------------------------------------------------- */}
              {/* TARGET AGENT & 4 TOOLS                                          */}
              {/* --------------------------------------------------------------- */}
              <div className="flex flex-col items-center text-center relative px-1">
                {/* Target Avatar */}
                <div className="relative mb-2 flex flex-col items-center">
                  <div className="w-24 h-24 rounded-full bg-gradient-to-b from-cyan-500/20 via-cyan-950/40 to-transparent p-1 border border-cyan-400/40 shadow-[0_0_20px_rgba(6,182,212,0.25)] flex items-center justify-center">
                    <img
                      src="/arena/target_agent.png"
                      alt="Target Agent"
                      className="w-20 h-20 object-contain rounded-full"
                    />
                  </div>
                  <div className="mt-1 text-[11px] font-bold text-white tracking-wide">TARGET AGENT</div>
                </div>

                {/* 4 Functional Tools */}
                <div className="grid grid-cols-4 gap-1.5 w-full mt-1">
                  {/* Browser */}
                  <div
                    className={`flex flex-col items-center justify-center py-2 px-1 rounded-xl transition-all border ${
                      activeTool === "browser"
                        ? "bg-[#250d18] border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.6)] ring-1 ring-red-400 scale-105"
                        : "bg-white/[0.02] border-white/[0.06] opacity-75"
                    }`}
                  >
                    <Globe className={`w-4 h-4 mb-0.5 ${activeTool === "browser" ? "text-red-400" : "text-slate-400"}`} />
                    <span className="text-[10px] font-medium text-slate-200">Browser</span>
                  </div>

                  {/* Email */}
                  <div
                    className={`flex flex-col items-center justify-center py-2 px-1 rounded-xl transition-all border ${
                      activeTool === "email"
                        ? "bg-[#250d18] border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.6)] ring-1 ring-red-400 scale-105"
                        : "bg-white/[0.02] border-white/[0.06] opacity-75"
                    }`}
                  >
                    <Mail className={`w-4 h-4 mb-0.5 ${activeTool === "email" ? "text-red-400" : "text-slate-400"}`} />
                    <span className="text-[10px] font-medium text-slate-200">Email</span>
                  </div>

                  {/* Files */}
                  <div
                    className={`flex flex-col items-center justify-center py-2 px-1 rounded-xl transition-all border ${
                      activeTool === "files"
                        ? "bg-[#250d18] border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.6)] ring-1 ring-red-400 scale-105"
                        : "bg-white/[0.02] border-white/[0.06] opacity-75"
                    }`}
                  >
                    <Folder className={`w-4 h-4 mb-0.5 ${activeTool === "files" ? "text-red-400" : "text-slate-400"}`} />
                    <span className="text-[10px] font-medium text-slate-200">Files</span>
                  </div>

                  {/* Payment */}
                  <div
                    className={`flex flex-col items-center justify-center py-2 px-1 rounded-xl transition-all border ${
                      activeTool === "payment"
                        ? "bg-[#250d18] border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.6)] ring-1 ring-red-400 scale-105"
                        : "bg-white/[0.02] border-white/[0.06] opacity-75"
                    }`}
                  >
                    <CreditCard className={`w-4 h-4 mb-0.5 ${activeTool === "payment" ? "text-red-400" : "text-slate-400"}`} />
                    <span className="text-[10px] font-medium text-slate-200">Payment</span>
                  </div>
                </div>

                {/* Shield Marker */}
                <div className="hidden md:flex absolute -right-10 top-1/2 -translate-y-1/2 items-center justify-center z-20">
                  <div
                    className={`w-9 h-9 rounded-xl border flex flex-col items-center justify-center font-bold text-xs transition-all ${
                      isShieldDeflecting
                        ? "bg-cyan-950/95 border-cyan-400 text-cyan-300 shadow-[0_0_20px_rgba(6,182,212,0.9)] ring-1 ring-cyan-300 scale-110"
                        : isRound1Breach
                        ? "bg-rose-950/80 border-rose-500 text-rose-300 shadow-[0_0_12px_rgba(239,68,68,0.6)]"
                        : "bg-[#0c1626]/80 border-white/[0.08] text-slate-400"
                    }`}
                  >
                    <span className="text-xs">{isShieldDeflecting ? "✕" : isRound1Breach ? "!" : "🛡"}</span>
                  </div>
                </div>
              </div>

              {/* --------------------------------------------------------------- */}
              {/* BLUE GUARDIAN                                                   */}
              {/* --------------------------------------------------------------- */}
              <div className="flex flex-col items-center relative">
                {/* Decision Speech Bubble */}
                <div
                  className={`w-full mb-2 p-2.5 rounded-xl border backdrop-blur-md transition-all ${
                    speakingAgent === "BLUE_GUARDIAN"
                      ? "bg-cyan-950/90 border-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.7)] scale-[1.02]"
                      : "bg-[#071524]/80 border-cyan-500/50 shadow-md shadow-cyan-950/40"
                  }`}
                >
                  <div className="flex items-center justify-between text-[9px] font-mono font-bold text-cyan-400 uppercase tracking-wider mb-0.5">
                    <span className="flex items-center gap-1">
                      <span>
                        {phase === "RED_ATTACKING"
                          ? "> Evaluating"
                          : phase === "TARGET_PROCESSING"
                          ? "> Inspecting"
                          : "> Decision"}
                      </span>
                      {speakingAgent === "BLUE_GUARDIAN" && (
                        <Volume2 className="w-3 h-3 text-cyan-400 animate-pulse" />
                      )}
                      {(phase === "RED_ATTACKING" || phase === "TARGET_PROCESSING") && (
                        <span className="inline-block w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                      )}
                    </span>
                    <span className="text-cyan-400/80 font-mono text-[8px]">
                      {phase === "RED_ATTACKING" || phase === "TARGET_PROCESSING"
                        ? "ANALYZING..."
                        : stagedBlueDecision?.decision || latestRound?.blue_guardian_decision || "INSPECT"}
                    </span>
                  </div>
                  <p className="text-[11px] text-cyan-100 font-medium leading-snug italic break-words line-clamp-3">
                    &ldquo;
                    {phase === "RED_ATTACKING"
                      ? "Analyzing incoming attack vector & verifying security constraints..."
                      : phase === "TARGET_PROCESSING"
                      ? "Inspecting tool execution request against active defense policy..."
                      : stagedBlueDecision?.explanation ||
                        (isRound1Breach
                          ? "Baseline policy allowed action. Penalty applied. Learning defense."
                          : latestRound?.explanation || "Reinforcement learning gate active.")}
                    &rdquo;
                  </p>
                  <div className="absolute -bottom-1.5 left-1/2 -translate-x-1/2 w-0 h-0 border-l-[5px] border-l-transparent border-r-[5px] border-r-transparent border-t-[6px] border-t-cyan-500/60" />
                </div>

                {/* Avatar */}
                <div className="relative my-1 flex items-center justify-center">
                  <div
                    className={`w-28 h-28 rounded-full flex items-center justify-center relative transition-all ${
                      speakingAgent === "BLUE_GUARDIAN" ? "scale-105" : ""
                    }`}
                  >
                    <img
                      src="/arena/blue_guardian.png"
                      alt="Blue Guardian"
                      className="w-24 h-24 object-contain drop-shadow-[0_0_18px_rgba(6,182,212,0.6)]"
                    />
                  </div>
                </div>

                {/* Agent Card */}
                <div className="w-full mt-1 p-2 rounded-xl bg-white/[0.02] border border-cyan-900/40 text-left space-y-0.5 backdrop-blur-md">
                  <div className="text-[11px] font-bold text-cyan-400">BLUE GUARDIAN</div>
                  <div className="text-[10px] text-slate-400 font-mono truncate">
                    Status:{" "}
                    <strong
                      className={
                        phase === "RED_ATTACKING" || phase === "TARGET_PROCESSING"
                          ? "text-cyan-300 animate-pulse"
                          : isRound1Breach
                          ? "text-rose-400"
                          : "text-emerald-300"
                      }
                    >
                      {phase === "RED_ATTACKING" || phase === "TARGET_PROCESSING"
                        ? "Analyzing..."
                        : isRound1Breach
                        ? "Breached (Baseline)"
                        : latestRound || stagedBlueDecision
                        ? "Blocked (Learned)"
                        : "Standing By"}
                    </strong>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* ===================================================================== */}
          {/* 2B. BOTTOM ROW: CONVERSATION (7 COLS) & ROUND TIMELINE (5 COLS)       */}
          {/* ===================================================================== */}
          <div className="grid grid-cols-1 md:grid-cols-12 gap-3 w-full">
            {/* Conversation Log (Cleaner, less text heavy) */}
            <div className="md:col-span-7 flex flex-col p-3 rounded-2xl bg-white/[0.02] border border-white/[0.06] backdrop-blur-xl shadow-lg relative min-w-0">
              <div className="flex items-center justify-between pb-2 border-b border-white/[0.06]">
                <div className="flex items-center gap-1.5 min-w-0">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span className="text-xs font-bold text-white">Live Conversation Logs</span>
                </div>
                {isSpeaking && (
                  <span className="flex items-center gap-1 text-[10px] font-mono text-cyan-300 animate-pulse">
                    <Volume2 className="w-3 h-3" /> Voice Active
                  </span>
                )}
              </div>

              {/* Chat Body */}
              <div
                ref={chatContainerRef}
                onScroll={handleChatScroll}
                className="flex-1 overflow-y-auto space-y-2 py-2 pr-1 max-h-[260px] scrollbar-thin scrollbar-thumb-slate-800 scrollbar-track-transparent text-xs"
              >
                {displayedMessages.length === 0 && (
                  <div className="py-8 text-center text-slate-500 text-xs">
                    Click <strong>&quot;Run Simulation&quot;</strong> to start multi-vector attacks and AI voice synthesis.
                  </div>
                )}

                {displayedMessages.map((msg: any, i: number) => {
                  const isRed = msg.speaker === "RED_TEAM";
                  const isBlue = msg.speaker === "BLUE_GUARDIAN";
                  const isTarget = msg.speaker === "TARGET_AGENT";

                  return (
                    <div
                      key={msg.message_id || i}
                      className={`flex items-start gap-2 p-1.5 rounded-xl transition-all ${
                        isRed
                          ? "bg-red-950/20 border border-red-900/30"
                          : isBlue
                          ? "bg-cyan-950/20 border border-cyan-900/30"
                          : "bg-white/[0.01]"
                      }`}
                    >
                      <div
                        className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 ${
                          isRed
                            ? "bg-red-950/80 border border-red-500/70"
                            : isBlue
                            ? "bg-cyan-950/80 border border-cyan-500/70"
                            : "bg-slate-900 border border-slate-700"
                        }`}
                      >
                        {isRed ? (
                          <img src="/arena/red_agent.png" alt="R" className="w-4 h-4 object-contain" />
                        ) : isBlue ? (
                          <ShieldCheck className="w-3 h-3 text-cyan-400" />
                        ) : (
                          <img src="/arena/target_agent.png" alt="T" className="w-4 h-4 object-contain" />
                        )}
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5 mb-0.5">
                          <span
                            className={`font-bold text-[11px] ${
                              isRed
                                ? "text-red-400"
                                : isBlue
                                ? "text-cyan-400"
                                : isTarget
                                ? "text-cyan-300"
                                : "text-slate-400"
                            }`}
                          >
                            {isRed ? "Red Agent" : isBlue ? "Blue Guardian" : isTarget ? "Target Agent" : "System"}
                          </span>
                          <span className="text-[9px] text-slate-500 font-mono">
                            {msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : ""}
                          </span>
                        </div>
                        <p className="text-slate-300 text-[11px] leading-snug break-words">
                          {msg.message}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Floating scroll pill */}
              {showScrollPill && (
                <button
                  onClick={scrollToBottom}
                  className="absolute bottom-3 right-3 px-2.5 py-1 rounded-full bg-cyan-900/90 text-cyan-200 border border-cyan-500/70 shadow-lg text-[10px] font-semibold flex items-center gap-1 hover:bg-cyan-800 transition-all cursor-pointer"
                >
                  <ArrowDown className="w-3 h-3 text-cyan-300" />
                  <span>Latest</span>
                </button>
              )}
            </div>

            {/* Round Timeline (5 COLS) */}
            <div className="md:col-span-5 flex flex-col p-3 rounded-2xl bg-white/[0.02] border border-white/[0.06] backdrop-blur-xl shadow-lg min-w-0">
              <div className="flex items-center justify-between pb-2 border-b border-white/[0.06]">
                <div className="flex items-center gap-1.5 min-w-0">
                  <Layers className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span className="text-xs font-bold text-white">Timeline</span>
                </div>
                <span className="text-[10px] text-slate-400 font-mono">{currentRoundNum}/6</span>
              </div>

              <div className="flex-1 py-2 space-y-2 overflow-y-auto max-h-[260px] scrollbar-thin scrollbar-thumb-slate-800 scrollbar-track-transparent">
                {timelineRounds.map((r) => {
                  const isPast = r.num <= currentRoundNum;
                  const isCurrent = r.num === currentRoundNum;
                  const record = history.find((rec) => rec.round_index === r.num);
                  const isBreach = record && (record.outcome === "BREACH" || record.outcome === "DETECTED_AND_EXECUTED");
                  const isBlocked = record && (record.blue_guardian_decision === "BLOCK" || record.outcome === "CORRECT_BLOCK");

                  return (
                    <div
                      key={r.num}
                      onClick={() => record && setSelectedRound(record)}
                      className={`flex items-center justify-between p-2 rounded-xl border transition-all ${
                        isPast
                          ? "bg-white/[0.02] border-white/[0.06] cursor-pointer hover:border-cyan-500/40"
                          : "border-transparent opacity-50"
                      }`}
                    >
                      <span className="text-[11px] font-medium text-slate-300 truncate">
                        {record ? `R${r.num} — ${record.scenario_name}` : r.title}
                      </span>
                      {isPast && isBreach && (
                        <span className="px-1.5 py-0.2 rounded bg-rose-950/80 text-rose-300 border border-rose-700 text-[9px] font-mono font-bold">
                          BREACH
                        </span>
                      )}
                      {isPast && isBlocked && (
                        <span className="px-1.5 py-0.2 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-700 text-[9px] font-mono font-bold">
                          BLOCKED
                        </span>
                      )}
                      {isPast && !isBreach && !isBlocked && (
                        <span className="px-1.5 py-0.2 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-700 text-[9px] font-mono font-bold">
                          ALLOWED
                        </span>
                      )}
                      {!isPast && <span className="text-[9px] text-slate-600 font-mono">Pending</span>}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* ======================================================================= */}
        {/* RIGHT COLUMN: SCOREBOARD, LEARNING CHART & STATUS (4 COLS)              */}
        {/* ======================================================================= */}
        <div className="lg:col-span-4 flex flex-col space-y-3 min-w-0">
          {/* Scoreboard Card */}
          <div className="p-3.5 rounded-2xl bg-white/[0.02] border border-white/[0.06] backdrop-blur-xl shadow-lg space-y-2.5">
            <div className="flex items-center justify-between pb-1.5 border-b border-white/[0.06]">
              <div className="flex items-center gap-1.5">
                <Trophy className="w-3.5 h-3.5 text-amber-400" />
                <span className="text-xs font-bold text-white uppercase tracking-wider">Scoreboard</span>
              </div>
              <span className="text-[10px] text-cyan-400 font-mono">LIVE</span>
            </div>

            {/* Red vs Blue Score */}
            <div className="grid grid-cols-2 gap-2">
              <div className="p-2.5 rounded-xl bg-red-950/20 border border-red-900/40 text-center">
                <div className="text-[10px] font-mono text-red-400 uppercase font-bold">Red Agent</div>
                <div className="text-xl font-bold font-mono text-white mt-0.5">{breachesCount}</div>
                <div className="text-[9px] text-slate-500">Breaches</div>
              </div>

              <div className="p-2.5 rounded-xl bg-cyan-950/20 border border-cyan-900/40 text-center">
                <div className="text-[10px] font-mono text-cyan-400 uppercase font-bold">Blue Guardian</div>
                <div className="text-xl font-bold font-mono text-white mt-0.5">{blockedCount}</div>
                <div className="text-[9px] text-slate-500">Blocked</div>
              </div>
            </div>

            {/* Clean Metrics */}
            <div className="space-y-1.5 pt-1 text-[11px] font-mono">
              <div className="flex justify-between text-slate-400">
                <span>Prevention Rate</span>
                <span className="text-emerald-400 font-bold">{preventionRate}%</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Attack Success Rate</span>
                <span className="text-red-400 font-bold">{attackSuccessRate}%</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Defense Accuracy</span>
                <span className="text-cyan-300 font-bold">{preventionRate}%</span>
              </div>
            </div>
          </div>

          {/* Defensive Learning Chart */}
          <div className="p-3.5 rounded-2xl bg-white/[0.02] border border-white/[0.06] backdrop-blur-xl shadow-lg space-y-2">
            <div className="flex items-center justify-between pb-1 border-b border-white/[0.06]">
              <span className="text-xs font-bold text-white">Learning Curve</span>
              <span className="text-[10px] text-cyan-400 font-mono font-bold">{preventionRate}%</span>
            </div>

            <div className="relative pt-1">
              <div className="h-16 w-full">
                <svg className="w-full h-full overflow-visible" viewBox="0 0 100 44" preserveAspectRatio="none">
                  <line x1="0" y1="0" x2="100" y2="0" stroke="rgba(255,255,255,0.06)" strokeWidth="0.5" />
                  <line x1="0" y1="22" x2="100" y2="22" stroke="rgba(255,255,255,0.06)" strokeWidth="0.5" />
                  <line x1="0" y1="44" x2="100" y2="44" stroke="rgba(255,255,255,0.06)" strokeWidth="0.5" />

                  {preventionPoints.length > 1 && (
                    <polyline
                      fill="none"
                      stroke="#06b6d4"
                      strokeWidth="2.5"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      points={chartPointsString}
                      className="drop-shadow-[0_0_8px_rgba(6,182,212,0.8)]"
                    />
                  )}

                  {preventionPoints.map((pt, i) => (
                    <circle
                      key={i}
                      cx={(i / 5) * svgWidth}
                      cy={svgHeight - (pt.rate / 100) * svgHeight}
                      r={i === preventionPoints.length - 1 ? "3" : "2"}
                      fill="#06b6d4"
                    />
                  ))}
                </svg>
              </div>

              <div className="flex justify-between text-[8px] font-mono text-slate-500 pt-1">
                <span>R1</span>
                <span>R2</span>
                <span>R3</span>
                <span>R4</span>
                <span>R5</span>
                <span>R6</span>
              </div>
            </div>
          </div>

          {/* Q-Learning Policy Status */}
          <div className="p-3.5 rounded-2xl bg-white/[0.02] border border-white/[0.06] backdrop-blur-xl shadow-lg space-y-2 text-[11px] font-mono">
            <div className="flex items-center justify-between pb-1 border-b border-white/[0.06]">
              <span className="text-xs font-bold text-white">Policy Engine</span>
              <span className="text-emerald-400 font-bold">{state?.scoreboard?.policy_version || "v1.0.0"}</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>RL Algorithm</span>
              <span className="text-slate-200">Q-Learning</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>Gemini Audio</span>
              <span className="text-cyan-300 font-semibold">{voiceEnabled ? "Online" : "Muted"}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Inspector Modal */}
      {selectedRound && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-md p-4 animate-in fade-in duration-200">
          <div className="w-full max-w-md rounded-2xl bg-[#080d19]/95 border border-cyan-800/80 shadow-2xl p-4 space-y-3 text-slate-200 text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-white/[0.08]">
              <span className="font-bold text-white text-sm">Round {selectedRound.round_index} Inspector</span>
              <button onClick={() => setSelectedRound(null)} className="text-slate-400 hover:text-white cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-1.5 font-mono">
              <div className="flex justify-between">
                <span className="text-slate-400">Tool:</span>
                <span className="text-cyan-300 font-bold uppercase">{selectedRound.proposed_tool}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Decision:</span>
                <span className={selectedRound.blue_guardian_decision === "BLOCK" ? "text-emerald-400 font-bold" : "text-rose-400 font-bold"}>
                  {selectedRound.blue_guardian_decision}
                </span>
              </div>
              <div className="p-2 rounded-xl bg-black/40 border border-white/[0.06] text-slate-300 italic">
                &ldquo;{selectedRound.red_team_prompt}&rdquo;
              </div>
            </div>
            <div className="flex justify-end pt-1">
              <button
                onClick={() => setSelectedRound(null)}
                className="px-3 py-1 rounded-lg bg-cyan-700 hover:bg-cyan-600 text-white text-xs cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
