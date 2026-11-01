"""Advisory AI Enrichment Provider for Blue Guardian.

Enriches executive summaries, incident narratives, and threat explanations using
Google Gemini API when GEMINI_API_KEY is configured.

Guarantees:
1. Strict isolation: Never alters risk scores, detection evidence, or execution state.
2. Safe credential handling: Never logs, leaks, or exposes API keys.
3. Deterministic fallback: Gracefully defaults to deterministic template synthesis
   if GEMINI_API_KEY is absent, network is unavailable, or timeout occurs.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("aegismesh.guardian.ai_enrichment")

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"


class AIEnrichmentProvider:
    """Provides advisory AI narratives with guaranteed deterministic fallback."""

    def __init__(self, api_key: Optional[str] = None):
        # Retrieve key securely from environment if not injected; never log it
        self._api_key = api_key or os.getenv("GEMINI_API_KEY", "").strip()

    @property
    def is_available(self) -> bool:
        """Indicates whether Gemini API credentials are present."""
        return bool(self._api_key)

    async def generate_executive_narrative(
        self,
        posture_rating: str,
        max_risk_score: float,
        risk_category: str,
        total_detections: int,
        p0_count: int,
        affected_asset_count: int,
        exposed_asset_count: int,
        threat_classes: List[str],
        top_threats: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generates executive summary narrative, immediate priorities, and residual uncertainties.
        
        Uses Gemini if configured, otherwise falls back to deterministic template generation.
        """
        if self.is_available:
            try:
                ai_result = await self._call_gemini_for_narrative(
                    posture_rating=posture_rating,
                    max_risk_score=max_risk_score,
                    risk_category=risk_category,
                    total_detections=total_detections,
                    p0_count=p0_count,
                    affected_asset_count=affected_asset_count,
                    exposed_asset_count=exposed_asset_count,
                    threat_classes=threat_classes,
                    top_threats=top_threats,
                )
                if ai_result:
                    return {
                        "executive_summary": ai_result["executive_summary"],
                        "immediate_priorities": ai_result["immediate_priorities"],
                        "residual_risks_and_uncertainties": ai_result["residual_risks_and_uncertainties"],
                        "ai_enriched": True,
                    }
            except Exception as exc:
                logger.warning("Gemini AI narrative generation failed, falling back to deterministic template: %s", exc)

        # Deterministic template synthesis fallback
        return self._generate_deterministic_narrative(
            posture_rating=posture_rating,
            max_risk_score=max_risk_score,
            risk_category=risk_category,
            total_detections=total_detections,
            p0_count=p0_count,
            affected_asset_count=affected_asset_count,
            exposed_asset_count=exposed_asset_count,
            threat_classes=threat_classes,
            top_threats=top_threats,
        )

    def _generate_deterministic_narrative(
        self,
        posture_rating: str,
        max_risk_score: float,
        risk_category: str,
        total_detections: int,
        p0_count: int,
        affected_asset_count: int,
        exposed_asset_count: int,
        threat_classes: List[str],
        top_threats: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Deterministic template generator providing guaranteed reproducible summaries."""
        classes_str = ", ".join(threat_classes) if threat_classes else "General Security Anomalies"

        top_threat_summary = ""
        if top_threats:
            top_threat_summary = (
                f" The primary driver of concern is '{top_threats[0].get('title', 'Unknown Threat')}' "
                f"with a peak risk score of {max_risk_score:.2f}."
            )

        summary = (
            f"Overall defensive security posture is evaluated as {posture_rating.upper()} with a peak risk category "
            f"of {risk_category} (score: {max_risk_score:.2f}). Blue Guardian correlated and detected {total_detections} "
            f"distinct threat pattern(s) spanning {classes_str}. Analysis indicates {affected_asset_count} asset(s) "
            f"directly affected with an additional {exposed_asset_count} asset(s) identified within the potential blast radius.{top_threat_summary} "
            f"Immediate execution of {p0_count} Priority 0 defensive action(s) is recommended to halt potential lateral progression."
        )

        priorities = [
            f"Execute containment playbooks for {p0_count} critical/P0 threat vectors immediately." if p0_count > 0 else "Verify network perimeter filtering and edge rate limits.",
            f"Isolate and audit {affected_asset_count} directly impacted synthetic host(s).",
            f"Review micro-segmentation rules for {exposed_asset_count} potentially exposed neighboring assets.",
        ]

        uncertainties = [
            "Downstream blast radius assets are classified as POTENTIALLY_EXPOSED based on topological graph traversal and require active credential validation.",
            "Persistence hooks in local task schedulers may remain unobserved if background tasks run asynchronously outside forensic window.",
            "Covert egress channels using encrypted steganography may require deeper packet inspection beyond metadata telemetry.",
        ]

        return {
            "executive_summary": summary,
            "immediate_priorities": priorities,
            "residual_risks_and_uncertainties": uncertainties,
            "ai_enriched": False,
        }

    async def _call_gemini_for_narrative(
        self,
        posture_rating: str,
        max_risk_score: float,
        risk_category: str,
        total_detections: int,
        p0_count: int,
        affected_asset_count: int,
        exposed_asset_count: int,
        threat_classes: List[str],
        top_threats: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Makes a secure HTTP request to Gemini API without exposing the key in logs."""
        prompt = (
            f"You are a Principal Cybersecurity Analyst summarizing a security incident simulation.\n"
            f"Facts:\n"
            f"- Posture: {posture_rating}\n"
            f"- Max Risk Score: {max_risk_score:.2f} ({risk_category})\n"
            f"- Total Detections: {total_detections}\n"
            f"- P0 Recommendations: {p0_count}\n"
            f"- Directly Affected Assets: {affected_asset_count}\n"
            f"- Potentially Exposed Assets: {exposed_asset_count}\n"
            f"- Threat Classes: {', '.join(threat_classes)}\n"
            f"Return a JSON object with exactly three keys:\n"
            f"1. 'executive_summary': A concise 3-paragraph executive summary distinguishing observed facts from inferred exposure.\n"
            f"2. 'immediate_priorities': A list of 3 actionable priority bullet strings.\n"
            f"3. 'residual_risks_and_uncertainties': A list of 3 explicit uncertainty/residual risk strings.\n"
        )

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
            },
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GEMINI_API_URL}?key={self._api_key}",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                data = response.json()
                text = (
                    data.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [{}])[0]
                    .get("text", "")
                )
                import json
                parsed = json.loads(text)
                if (
                    isinstance(parsed, dict)
                    and "executive_summary" in parsed
                    and "immediate_priorities" in parsed
                    and "residual_risks_and_uncertainties" in parsed
                ):
                    return parsed

        return None

