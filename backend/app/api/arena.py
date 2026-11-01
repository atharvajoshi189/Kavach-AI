"""REST API Endpoints for the Autonomous Agent Security Arena with Multi-Tier TTS Voice Engine."""

from __future__ import annotations

import base64
import io
import logging
import os
import tempfile
import uuid
import wave
from typing import Any, Dict, Optional
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
    voice: Optional[str] = "Puck"  # "Puck" (Red Agent) or "Fenrir" / "Aoede" (Blue Guardian)


def _generate_offline_high_quality_wav(clean_text: str, is_red: bool) -> Optional[str]:
    """Generates crystal-clear 16-bit WAV audio using local pyttsx3/SAPI5 synthesizer."""
    try:
        try:
            import pythoncom
            pythoncom.CoInitialize()
        except Exception:
            pass

        import pyttsx3

        engine = pyttsx3.init()
        voices = engine.getProperty("voices")

        # Pick distinct voice for Red Agent vs Blue Guardian
        # Red Agent: Male / David (adversarial cyber tone)
        # Blue Guardian: Female / Zira (crystal-clear, authoritative defense tone)
        if voices:
            if is_red:
                male_v = next((v.id for v in voices if "david" in v.name.lower() or "male" in v.name.lower()), voices[0].id)
                engine.setProperty("voice", male_v)
                engine.setProperty("rate", 175)
                engine.setProperty("volume", 1.0)
            else:
                female_v = next((v.id for v in voices if "zira" in v.name.lower() or "female" in v.name.lower()), voices[-1].id)
                engine.setProperty("voice", female_v)
                engine.setProperty("rate", 165)
                engine.setProperty("volume", 1.0)

        temp_wav_path = os.path.join(tempfile.gettempdir(), f"kavach_voice_{uuid.uuid4().hex}.wav")
        engine.save_to_file(clean_text, temp_wav_path)
        engine.runAndWait()
        engine.stop()

        if os.path.exists(temp_wav_path):
            with open(temp_wav_path, "rb") as f:
                wav_bytes = f.read()
            try:
                os.remove(temp_wav_path)
            except Exception:
                pass
            return f"data:audio/wav;base64,{base64.b64encode(wav_bytes).decode('utf-8')}"
    except Exception as exc:
        logger.warning("pyttsx3 offline audio generation failed: %s", exc)
    return None


@router.post("/speak", response_model=Dict[str, Any])
async def generate_agent_speech(payload: SpeakRequest) -> Dict[str, Any]:
    """Generate crystal-clear speech using Gemini AI TTS or offline crystal-clear audio engine."""
    import re

    if not payload.text or not payload.text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Text payload must not be empty.",
        )

    clean_text = payload.text.strip()
    # Format dollars for natural audio output
    clean_text = re.sub(r"\$(\d+(?:,\d+)*)", r"\1 dollars", clean_text)
    # Strip distracting markdown fences, curly brackets, quotes and formatting
    clean_text = re.sub(r'[{}\[\]"\'`*_#<>]', ' ', clean_text)
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()
    if len(clean_text) > 350:
        clean_text = clean_text[:350]

    is_red = payload.voice in ["Puck", "Charon"]

    # 1. Attempt Gemini TTS first if quota is available
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
        logger.info("Gemini TTS quota hit or unavailable (%s). Switching to crystal-clear offline studio TTS.", exc)

    # 2. Offline Studio Quality WAV Synthesizer (Crystal Clear Audio)
    offline_audio = _generate_offline_high_quality_wav(clean_text, is_red=is_red)
    if offline_audio:
        return {
            "status": "success",
            "audio_base64": offline_audio,
            "voice": "David" if is_red else "Zira",
            "format": "wav",
            "source": "studio_wav",
        }

    # 3. Fallback to client-side browser synthesis
    return {
        "status": "fallback",
        "audio_base64": None,
        "message": "Web speech fallback",
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
