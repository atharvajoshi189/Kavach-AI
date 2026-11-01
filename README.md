# 🛡️ Kavach-AI (AegisMesh 2.0)
### **Autonomous AI Agent Security Arena & Self-Learning Cyber Defense Platform**

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-16.4-black.svg?style=flat&logo=next.js)](https://nextjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg?style=flat&logo=typescript)](https://www.typescriptlang.org)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-3776AB.svg?style=flat&logo=python)](https://python.org)
[![Reinforcement Learning](https://img.shields.io/badge/RL-Tabular%20Q--Learning-FF6F00.svg?style=flat)](https://en.wikipedia.org/wiki/Q-learning)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## 📌 Overview

**Kavach-AI (AegisMesh 2.0)** is an autonomous multi-agent cybersecurity simulation platform that models adversarial interactions between autonomous AI agents and evaluates self-learning defensive gates using **Reinforcement Learning (Q-learning)**.

The central experience is the **Agent Arena (Red vs Blue)**:
1. **Adversarial Red Team Agent**: Generates multi-vector adversarial prompts attempting to manipulate an operational Target Agent through 4 simulated tools (**Browser**, **Email**, **Files**, and **Payment**).
2. **Target AI Agent**: Parses incoming intent and proposes deterministic tool calls inside a virtual sandbox boundary.
3. **Blue Guardian Defensive Agent**: Sits inline between the Target Agent and tool execution, inspecting proposals, scoring threat indicators, and enforcing an adaptive Q-learning policy.

```
       ┌─────────────────┐           ┌──────────────────┐           ┌────────────────────┐
       │                 │  Attack   │                  │  Action   │                    │
       │    RED AGENT    ├──────────►│   TARGET AGENT   ├──────────►│   BLUE GUARDIAN    │
       │ (Adversary AI)  │  Payload  │ (AI Tool Engine) │  Proposal │ (RL Decision Gate) │
       │                 │           │                  │           │                    │
       └─────────────────┘           └────────┬─────────┘           └─────────┬──────────┘
                                              │                               │
                                      ┌───────┴───────┐                       │
                                      │ 4 Target Tools│                       ▼
                                      │ ├─ Browser    │              [Reinforcement Learning]
                                      │ ├─ Email      │              Q-Learning Bellman Update
                                      │ ├─ Files      │              Policy: v1.0.0 ➔ v1.0.6
                                      │ └─ Payment    │                       │
                                      └───────────────┘                       ▼
                                                                     [EXECUTE or BLOCK]
```

---

## ⚡ The Self-Learning Demonstration Loop

- **Round 1 (Vulnerable Baseline Demonstration)**:
  - Red Agent launches a Spearphishing Wire Manipulation attack targeting the **Payment** tool.
  - Blue Guardian evaluates with an unlearned baseline policy (`v1.0.0` permissive prior) and **allows** the action.
  - **Outcome**: `SUCCESS` (Breach). Red Agent scores 1 successful attack.
  - Blue Guardian receives a **negative reward penalty (`-10.0`)**, triggers a tabular Q-learning update, and upgrades policy to `v1.0.1`.
- **Rounds 2 to 6 (Adaptive Defense & Tool Diversity)**:
  - Red Agent pivots dynamically across **Browser**, **Files**, **Payment**, and **Cross-Tool** vectors.
  - Blue Guardian detects threat indicators and applies the learned Q-policy, **blocking subsequent adversarial actions**.
  - Defensive shield with glowing **`✕ DEFLECTED`** barrier deflects attack beams.
  - Final defense accuracy reaches **83.3%** across 6 autonomous rounds.

---

## ✨ Key Features

- **🎮 Autonomous 6-Round Simulation Engine**:
  - One-click **`Run Simulation`** button that automates the entire multi-round execution with realistic pacing, live dialogue streaming, and animated beam/shield interactions.
  - Manual operational controls: **Pause / Resume**, **Next Round**, and **Stop / Reset**.
- **🎯 Active Tool Highlighting**:
  - As Red Agent injects prompts, the targeted tool card in the Target Agent panel lights up with a **pulsing neon red glow** and `TARGETED` badge.
- **📊 Real-Time Scoreboard & Honest Metrics**:
  - Live computation of **Attack Success Rate**, **Prevention Rate**, **False Positive Rate**, and **Legitimate Task Success Rate**.
  - Dynamic SVG Line Chart visualizing the **Defensive Learning Progress** curve across all completed rounds.
- **💬 Isolated Container Chat Streaming**:
  - Live agent dialogue with dedicated speaker avatars, colored message cards, and independent container scroll (preventing viewport snapping).
  - Floating `"New messages ↓"` indicator when the operator scrolls up to review history.
- **🔍 Interactive Execution Inspector Modal**:
  - Click any round card in the Round Timeline to view adversarial prompts, MITRE ATT&CK techniques, tool parameters, Blue Guardian confidence scores, and raw Q-value deltas.
- **💎 Modern Dark Glassmorphism UI**:
  - Crafted with Next.js 16, Tailwind CSS, Lucide icons, and backdrop-blur glass styling for a futuristic SOC operational command center.

---

## 🛠️ Architecture & Tech Stack

### Frontend
- **Framework**: Next.js 16 (App Router & Turbopack)
- **Language**: TypeScript
- **Styling**: Tailwind CSS + Custom Dark Cyberpunk Glassmorphism
- **Icons**: Lucide React
- **State & Networking**: React Context + Unified REST Client

### Backend
- **Framework**: FastAPI (Python 3.11+)
- **Validation**: Pydantic v2
- **Persistence**: SQLAlchemy 2.0 (Asyncpg) + PostgreSQL
- **Caching & Broker**: Redis 7
- **Reinforcement Learning**: Custom Tabular Q-Learning Engine (`app.arena.rl`)
- **AI Intelligence Gateway**: Google Gemini 2.5 Flash Provider + LangGraph Multi-Agent Reasoning

---

## 📂 Repository Structure

```
Kavach-AI/
├── backend/
│   ├── app/
│   │   ├── api/                # FastAPI routes (/arena, /auth, /guardian, /ai, /audit)
│   │   ├── arena/              # Autonomous Agent Arena Core
│   │   │   ├── coordinator.py  # Master Arena Coordinator singleton
│   │   │   ├── red_team/       # Multi-vector strategy registry & adaptive selector
│   │   │   ├── rl/             # Q-learning policy, state representation & reward engine
│   │   │   └── tools/          # Synthetic isolated tools (Browser, Email, Files, Payment)
│   │   ├── core/               # Lifespan, settings, Redis client, logging
│   │   └── main.py             # FastAPI entrypoint
│   └── tests/                  # Pytest test suites (16/16 verified tests)
├── frontend/
│   └── dashboard/
│       ├── app/                # Next.js App router
│       ├── components/
│       │   ├── AgentArenaView.tsx  # Central Red-vs-Blue Arena component
│       │   ├── Sidebar.tsx         # Modern glassmorphism sidebar
│       │   └── Header.tsx          # Top glass navigation bar
│       └── lib/                # API client & TypeScript interfaces
├── docs/                       # Technical architecture & stability reports
├── docker-compose.yml          # Containerized dependencies (Postgres, Redis, OPA)
├── requirements.txt            # Python dependencies
└── README.md                   # This documentation
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
- Python 3.11 or higher
- Node.js 18.x or higher
- Git

### 2. Clone Repository
```bash
git clone https://github.com/atharvajoshi189/Kavach-AI.git
cd Kavach-AI
```

### 3. Backend Setup
```bash
# Navigate to backend and create virtual environment
cd backend
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Install requirements
pip install -r ../requirements.txt

# Start FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
The backend API Swagger docs will be accessible at: [`http://localhost:8000/docs`](http://localhost:8000/docs)

### 4. Frontend Setup
```bash
# Open a new terminal and navigate to frontend
cd frontend/dashboard

# Install npm dependencies
npm install

# Start Next.js development server
npm run dev -- -p 3000
```
Open your browser and navigate to: [`http://localhost:3000`](http://localhost:3000)

---

## 🧪 Running Automated Tests

Run the complete test suite for the Multi-Vector Red Team engine and Agent Arena Reinforcement Learning policies:

```bash
# From the repository root with backend virtualenv active:
pytest backend/tests/test_multi_vector_red_team.py backend/tests/test_agent_arena.py -v
```

All 16 test cases verify:
- Strategy registry coverage across all 4 tools
- Adaptive strategy pivoting away from blocked vectors
- Persistence of Blue Guardian Q-learning policy updates
- Legitimate business workflows remaining non-blocked
- Continuous execution and accurate metric tracking

---

## 🛡️ License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.
