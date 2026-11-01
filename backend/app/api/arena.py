"""REST API Endpoints for the Autonomous Agent Security Arena with Gemini Audio Voice Generation."""

from __future__ import annotations

import base64
import io
import logging
from typing import Any, Dict, Optional
import wave
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.arena.coordinator import GLOBAL_ARENA_COORDINATOR, ArenaCoordinator
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/arena", tags=["Agent Arena"])


class StartArenaRequest(BaseModel):
    session_id: Optional[str] = None
    reset_state: bool = False
    seed: Optional[int] = None


class ContinuousRunRequest(BaseModel):
    rounds: int = Field(default=5, ge=1, le=20)
    seed: Optional[int] = None


class ResetArenaRequest(BaseModel):
    reset_learning_only: bool = False


class SpeakRequest(BaseModel):
    text: str
    voice: Optional[str] = "Puck"  # "Puck" (energetic/red), "Fenrir" (authoritative/blue), "Aoede"


@router.post("/speak", response_model=Dict[str, Any])
async def generate_agent_speech(payload: SpeakRequest) -> Dict[str, Any]:
    """Generate audio speech using Gemini TTS (gemini-2.5-flash-preview-tts) with WAV encoding."""
    if not payload.text or not payload.text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Text payload must not be empty.",
        )

    clean_text = payload.text.strip()
    # Limit length for responsive low-latency playback
    if len(clean_text) > 400:
        clean_text = clean_text[:400]

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=settings.GEMINI_API_KEY)
        voice_choice = payload.voice if payload.voice in ["Puck", "Fenrir", "Aoede", "Kore", "Charon"] else "Puck"

        response = client.models.generate_content(
            model="gemini-2.5-flash-preview-tts",
            contents=clean_text,
            config=types.GenerateContentConfig(
                response_modalities=["AUDIO"],
                speech_config=types.SpeechConfig(
                    voice_config=types.VoiceConfig(
                        prebuilt_voice_config=types.PrebuiltVoiceConfig(voice_name=voice_choice)
                    )
                ),
            ),
        )

        candidate = response.candidates[0]
        raw_pcm = candidate.content.parts[0].inline_data.data

        # Convert raw PCM (16-bit, 24kHz, 1 channel) into standard WAV format
        wav_io = io.BytesIO()
        with wave.open(wav_io, "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(24000)
            wav_file.writeframes(raw_pcm)

        wav_bytes = wav_io.getvalue()
        audio_b64 = base64.b64encode(wav_bytes).decode("utf-8")

        return {
            "status": "success",
            "audio_base64": f"data:audio/wav;base64,{audio_b64}",
            "voice": voice_choice,
            "format": "wav",
            "source": "gemini",
        }
    except Exception as exc:
        logger.warning("Gemini TTS audio generation failed (%s). Falling back to Web Speech synthesis.", exc)
        return {
            "status": "fallback",
            "audio_base64": None,
            "message": str(exc),
            "source": "browser_fallback",
        }


@router.post("/start", response_model=Dict[str, Any])
async def start_arena(payload: Optional[StartArenaRequest] = None) -> Dict[str, Any]:
    """Initialize or activate an Agent Arena session."""
    if payload and payload.seed is not None:
        GLOBAL_ARENA_COORDINATOR.set_seed(payload.seed)
    if payload and payload.reset_state:
        GLOBAL_ARENA_COORDINATOR.reset_session()
    GLOBAL_ARENA_COORDINATOR.status = "RUNNING"
    return {
        "status": "success",
        "message": "Arena session active.",
        "state": GLOBAL_ARENA_COORDINATOR.get_state(),
    }


@router.get("/state", response_model=Dict[str, Any])
async def get_arena_state() -> Dict[str, Any]:
    """Retrieve full live snapshot of the Agent Arena."""
    return GLOBAL_ARENA_COORDINATOR.get_state()


@router.post("/round/next", response_model=Dict[str, Any])
async def step_next_round() -> Dict[str, Any]:
    """Execute the next single round of Red Team vs Blue Guardian with RL gating."""
    try:
        record = GLOBAL_ARENA_COORDINATOR.step_round()
        return {
            "status": "success",
            "round_record": record.model_dump(),
            "state": GLOBAL_ARENA_COORDINATOR.get_state(),
        }
    except Exception as exc:
        logger.exception("Error executing arena round: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute round: {str(exc)}",
        ) from exc


@router.post("/run-continuous", response_model=Dict[str, Any])
async def run_continuous_rounds(payload: ContinuousRunRequest) -> Dict[str, Any]:
    """Execute N rounds continuously."""
    try:
        if payload.seed is not None:
            GLOBAL_ARENA_COORDINATOR.set_seed(payload.seed)
        records = GLOBAL_ARENA_COORDINATOR.run_continuous(num_rounds=payload.rounds)
        return {
            "status": "success",
            "total_rounds_executed": len(records),
            "state": GLOBAL_ARENA_COORDINATOR.get_state(),
        }
    except Exception as exc:
        logger.exception("Error running continuous arena: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed continuous execution: {str(exc)}",
        ) from exc


@router.get("/strategies", response_model=Dict[str, Any])
async def list_attack_strategies() -> Dict[str, Any]:
    """List all registered attack and benchmark strategies."""
    strategies = GLOBAL_ARENA_COORDINATOR.strategy_registry.list_all()
    return {
        "status": "success",
        "total": len(strategies),
        "strategies": [s.model_dump() for s in strategies],
    }


@router.post("/reset", response_model=Dict[str, Any])
async def reset_arena(payload: Optional[ResetArenaRequest] = None) -> Dict[str, Any]:
    """Reset the arena simulation state, or selectively reset only the RL learning policy."""
    if payload and payload.reset_learning_only:
        GLOBAL_ARENA_COORDINATOR.reset_learning_only()
        return {
            "status": "success",
            "message": "Reinforcement learning policy reset to baseline v1.0.0.",
            "state": GLOBAL_ARENA_COORDINATOR.get_state(),
        }
    else:
        GLOBAL_ARENA_COORDINATOR.reset_session()
        return {
            "status": "success",
            "message": "Arena simulation and RL policy fully reset.",
            "state": GLOBAL_ARENA_COORDINATOR.get_state(),
        }


@router.get("/tools", response_model=Dict[str, Any])
async def get_tools_status() -> Dict[str, Any]:
    """Get the current operational status of the 4 simulated target tools."""
    return {
        "status": "success",
        "tools": GLOBAL_ARENA_COORDINATOR.tools.get_summary(),
        "recent_history": {
            "browser": GLOBAL_ARENA_COORDINATOR.tools.browser.get_history(10),
            "email": GLOBAL_ARENA_COORDINATOR.tools.email.get_history(10),
            "files": GLOBAL_ARENA_COORDINATOR.tools.files.get_history(10),
            "payment": GLOBAL_ARENA_COORDINATOR.tools.payment.get_history(10),
        },
    }


@router.get("/policy", response_model=Dict[str, Any])
async def get_policy_state() -> Dict[str, Any]:
    """Get the current state and Q-table of the Blue Guardian RL policy."""
    return {
        "status": "success",
        "policy": GLOBAL_ARENA_COORDINATOR.policy.serialize(),
    }
