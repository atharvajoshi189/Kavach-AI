"""MITRE ATT&CK Mapping Module for Blue Guardian Threat Detection.

Grounds ATT&CK technique and tactic classifications directly in defensive event evidence
rather than purely relying on scenario titles or high-level labels.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger("aegismesh.guardian.mitre")

# Authoritative catalog of supported MITRE ATT&CK techniques
MITRE_TECHNIQUE_CATALOG: Dict[str, Dict[str, str]] = {
    "T1046": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "default_rationale": "Event evidence demonstrates active network or port scanning against asset endpoints.",
    },
    "T1110": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "default_rationale": "Event evidence demonstrates repeated authentication failures or password spraying attempts.",
    },
    "T1190": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "default_rationale": "Event evidence indicates payload delivery or exploit attempts targeting an externally exposed service or web application.",
    },
    "T1068": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "default_rationale": "Event evidence reveals unauthorized elevation of process privileges, SUID exploitation, or token impersonation.",
    },
    "T1021": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "default_rationale": "Event evidence demonstrates pivot attempts across internal network boundaries using remote services (e.g. SSH, SMB, WinRM).",
    },
    "T1053": {
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "default_rationale": "Event evidence indicates modification or registration of cron jobs, systemd timers, or scheduled tasks to maintain access.",
    },
    "T1048": {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "default_rationale": "Event evidence shows sensitive data transmission across non-standard or alternative egress protocols.",
    },
}


class MitreMapper:
    """Evaluates and maps observed telemetry to verified MITRE ATT&CK techniques."""

    @staticmethod
    def map_technique(
        technique_id: str,
        custom_rationale: Optional[str] = None,
        evidence_clues: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Constructs a validated MITRE technique mapping dictionary."""
        entry = MITRE_TECHNIQUE_CATALOG.get(technique_id)
        if not entry:
            return {
                "technique_id": technique_id,
                "technique_name": "Custom Technique",
                "tactic": "General",
                "mapping_rationale": custom_rationale or f"Evidence mapped to technique '{technique_id}'.",
            }

        rationale = custom_rationale or entry["default_rationale"]
        if evidence_clues:
            rationale = f"{rationale} Corroborating indicators: {', '.join(evidence_clues)}."

        return {
            "technique_id": entry["technique_id"],
            "technique_name": entry["technique_name"],
            "tactic": entry["tactic"],
            "tactic_id": entry.get("tactic_id"),
            "mapping_rationale": rationale,
        }

    @staticmethod
    def extract_tactics(techniques: List[Dict[str, Any]]) -> List[str]:
        """Extracts unique tactic names preserving deterministic order."""
        seen = set()
        tactics = []
        for t in techniques:
            tac = t.get("tactic")
            if tac and tac not in seen:
                seen.add(tac)
                tactics.append(tac)
        return tactics

