"""Allowlisted registry of deterministic synthetic-only remediation action handlers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Any, Callable, Dict, List, Optional
import uuid

from app.models.guardian import RemediationPlanAction
from app.models.synthetic_asset import SyntheticAsset

logger = logging.getLogger("aegismesh.guardian.action_registry")


@dataclass(frozen=True)
class ActionResult:
    """Outcome of an allowlisted synthetic action handler execution."""
    success: bool
    action_code: str
    target_asset_ids: List[str]
    applied_changes: Dict[str, Any]
    error_message: Optional[str] = None
    is_simulated: bool = True
    simulation_only: bool = True


# =============================================================================
# Allowlisted Synthetic Handlers (Strictly modifies synthetic records in DB)
# =============================================================================

def handle_session_revocation(action: RemediationPlanAction, assets: List[SyntheticAsset]) -> ActionResult:
    now = datetime.now(timezone.utc).isoformat()
    changes = {}
    for a in assets:
        cfg = dict(a.configuration or {})
        cfg["active_sessions_revoked_at"] = now
        cfg["active_bearer_tokens_valid"] = False
        a.configuration = cfg
        changes[str(a.id)] = {"sessions_revoked": True, "timestamp": now}
    return ActionResult(success=True, action_code=action.action_code, target_asset_ids=[str(a.id) for a in assets], applied_changes=changes)


def handle_credential_rotation(action: RemediationPlanAction, assets: List[SyntheticAsset]) -> ActionResult:
    now = datetime.now(timezone.utc).isoformat()
    changes = {}
    for a in assets:
        cfg = dict(a.configuration or {})
        cfg["credential_rotation"] = {
            "last_rotated": now,
            "mfa_enforced": True,
            "password_policy_version": "2.0.0",
        }
        cfg["mfa_enforced"] = True
        a.configuration = cfg
        changes[str(a.id)] = {"mfa_enforced": True, "rotated_at": now}
    return ActionResult(success=True, action_code=action.action_code, target_asset_ids=[str(a.id) for a in assets], applied_changes=changes)


def handle_account_lockout(action: RemediationPlanAction, assets: List[SyntheticAsset]) -> ActionResult:
    changes = {}
    for a in assets:
        cfg = dict(a.configuration or {})
        cfg["account_lockout_policy"] = {
            "enabled": True,
            "failed_attempts_allowed": 3,
            "lockout_duration_minutes": 30,
        }
        a.configuration = cfg
        changes[str(a.id)] = {"lockout_policy_enabled": True}
    return ActionResult(success=True, action_code=action.action_code, target_asset_ids=[str(a.id) for a in assets], applied_changes=changes)


def handle_rate_limiting(action: RemediationPlanAction, assets: List[SyntheticAsset]) -> ActionResult:
    changes = {}
    for a in assets:
        cfg = dict(a.configuration or {})
        cfg["rate_limiting"] = {
            "enabled": True,
            "max_requests_per_minute": 60,
            "signature_verification": True,
        }
        a.configuration = cfg
        changes[str(a.id)] = {"rate_limiting_enabled": True}
    return ActionResult(success=True, action_code=action.action_code, target_asset_ids=[str(a.id) for a in assets], applied_changes=changes)


def handle_application_isolation(action: RemediationPlanAction, assets: List[SyntheticAsset]) -> ActionResult:
    changes = {}
    for a in assets:
        cfg = dict(a.configuration or {})
        cfg["isolated_mode"] = True
        cfg["strict_input_validation"] = True
        a.configuration = cfg
        changes[str(a.id)] = {"isolated_mode": True}
    return ActionResult(success=True, action_code=action.action_code, target_asset_ids=[str(a.id) for a in assets], applied_changes=changes)


def handle_privilege_restriction(action: RemediationPlanAction, assets: List[SyntheticAsset]) -> ActionResult:
    changes = {}
    for a in assets:
        cfg = dict(a.configuration or {})
        cfg["least_privilege_enforced"] = True
        cfg["unauthorized_sudo_rules_removed"] = True
        cfg["privileged_accounts"] = [p for p in cfg.get("privileged_accounts", []) if p in ["root", "admin", "system"]]
        a.configuration = cfg
        changes[str(a.id)] = {"least_privilege_enforced": True}
    return ActionResult(success=True, action_code=action.action_code, target_asset_ids=[str(a.id) for a in assets], applied_changes=changes)


def handle_network_segmentation(action: RemediationPlanAction, assets: List[SyntheticAsset]) -> ActionResult:
    changes = {}
    for a in assets:
        cfg = dict(a.configuration or {})
        cfg["network_segmentation"] = {
            "segmented": True,
            "isolated_vlan": True,
            "unauthorized_lateral_traffic_blocked": True,
        }
        # Filter down lateral connected assets to authorized list
        if a.connected_asset_ids and len(a.connected_asset_ids) > 1:
            a.connected_asset_ids = a.connected_asset_ids[:1]
        a.configuration = cfg
        changes[str(a.id)] = {"network_segmentation": True}
    return ActionResult(success=True, action_code=action.action_code, target_asset_ids=[str(a.id) for a in assets], applied_changes=changes)


def handle_persistence_removal(action: RemediationPlanAction, assets: List[SyntheticAsset]) -> ActionResult:
    changes = {}
    for a in assets:
        cfg = dict(a.configuration or {})
        cfg["persistence_artifacts_removed"] = True
        cfg["simulated_cron_jobs"] = []
        cfg["unauthorized_startup_scripts"] = []
        a.configuration = cfg
        changes[str(a.id)] = {"persistence_artifacts_removed": True}
    return ActionResult(success=True, action_code=action.action_code, target_asset_ids=[str(a.id) for a in assets], applied_changes=changes)


def handle_egress_restriction(action: RemediationPlanAction, assets: List[SyntheticAsset]) -> ActionResult:
    changes = {}
    for a in assets:
        cfg = dict(a.configuration or {})
        cfg["egress_filtering"] = {
            "restricted": True,
            "external_destinations_blocked": True,
            "dlp_monitoring_active": True,
        }
        a.configuration = cfg
        changes[str(a.id)] = {"egress_filtering_active": True}
    return ActionResult(success=True, action_code=action.action_code, target_asset_ids=[str(a.id) for a in assets], applied_changes=changes)


def handle_service_hardening(action: RemediationPlanAction, assets: List[SyntheticAsset]) -> ActionResult:
    changes = {}
    for a in assets:
        cfg = dict(a.configuration or {})
        cfg["service_hardening"] = {
            "debug_ports_closed": True,
            "default_credentials_disabled": True,
            "tls_enforced": True,
        }
        a.configuration = cfg
        changes[str(a.id)] = {"service_hardened": True}
    return ActionResult(success=True, action_code=action.action_code, target_asset_ids=[str(a.id) for a in assets], applied_changes=changes)


def handle_configuration_hardening(action: RemediationPlanAction, assets: List[SyntheticAsset]) -> ActionResult:
    changes = {}
    for a in assets:
        cfg = dict(a.configuration or {})
        cfg["baseline_hardened"] = True
        cfg["insecure_protocols_disabled"] = True
        # Mark matching vulnerabilities resolved
        if a.simulated_vulnerabilities:
            # Remediate critical/high vulnerabilities
            remaining = [v for v in a.simulated_vulnerabilities if str(v.get("severity", "")).lower() not in ["critical", "high"]]
            a.simulated_vulnerabilities = remaining
        # Lower risk level if high or critical
        if a.risk_level in ["critical", "high"]:
            a.risk_level = "medium"
        a.configuration = cfg
        changes[str(a.id)] = {"baseline_hardened": True, "risk_level": a.risk_level}
    return ActionResult(success=True, action_code=action.action_code, target_asset_ids=[str(a.id) for a in assets], applied_changes=changes)


# Registry mapping action codes and action types to strict handlers
SYNTHETIC_ACTION_HANDLERS: Dict[str, Callable[[RemediationPlanAction, List[SyntheticAsset]], ActionResult]] = {
    # Playbook 1: Credential Access
    "ACT-PB-001-01": handle_session_revocation,
    "ACT-PB-001-02": handle_credential_rotation,
    "ACT-PB-001-03": handle_service_hardening,
    # Playbook 2: Initial Access & API
    "ACT-PB-002-01": handle_rate_limiting,
    "ACT-PB-002-02": handle_application_isolation,
    "ACT-PB-002-03": handle_configuration_hardening,
    # Playbook 3: Privilege Escalation
    "ACT-PB-003-01": handle_privilege_restriction,
    "ACT-PB-003-02": handle_credential_rotation,
    "ACT-PB-003-03": handle_configuration_hardening,
    # Playbook 4: Lateral Movement
    "ACT-PB-004-01": handle_network_segmentation,
    "ACT-PB-004-02": handle_privilege_restriction,
    "ACT-PB-004-03": handle_service_hardening,
    # Playbook 5: Persistence
    "ACT-PB-005-01": handle_persistence_removal,
    "ACT-PB-005-02": handle_credential_rotation,
    "ACT-PB-005-03": handle_service_hardening,
    # Playbook 6: Exfiltration
    "ACT-PB-006-01": handle_egress_restriction,
    "ACT-PB-006-02": handle_network_segmentation,
    "ACT-PB-006-03": handle_service_hardening,
    # Playbook 7: Reconnaissance
    "ACT-PB-007-01": handle_network_segmentation,
    "ACT-PB-007-02": handle_rate_limiting,
    "ACT-PB-007-03": handle_service_hardening,
    # Playbook 8: Weak Configuration
    "ACT-PB-008-01": handle_configuration_hardening,
    "ACT-PB-008-02": handle_credential_rotation,
    "ACT-PB-008-03": handle_service_hardening,

    # Canonical aliases
    "SIMULATE_ACCOUNT_LOCKOUT": handle_account_lockout,
    "SIMULATE_CREDENTIAL_ROTATION": handle_credential_rotation,
    "SIMULATE_RATE_LIMIT": handle_rate_limiting,
    "SIMULATE_APPLICATION_ISOLATION": handle_application_isolation,
    "SIMULATE_PRIVILEGE_RESTRICTION": handle_privilege_restriction,
    "SIMULATE_NETWORK_SEGMENTATION": handle_network_segmentation,
    "SIMULATE_PERSISTENCE_REMOVAL": handle_persistence_removal,
    "SIMULATE_EGRESS_RESTRICTION": handle_egress_restriction,
    "SIMULATE_SERVICE_HARDENING": handle_service_hardening,
    "SIMULATE_CONFIGURATION_HARDENING": handle_configuration_hardening,
}


class SyntheticActionRegistry:
    """Dispatches execution to allowlisted synthetic handlers; fails closed on unknown actions."""

    @classmethod
    def get_handler(cls, action_code: str, action_type: str) -> Optional[Callable[[RemediationPlanAction, List[SyntheticAsset]], ActionResult]]:
        # 1. Match by exact action_code
        if action_code in SYNTHETIC_ACTION_HANDLERS:
            return SYNTHETIC_ACTION_HANDLERS[action_code]
        # 2. Match by normalized action_code
        norm = action_code.upper().replace("-", "_")
        if norm in SYNTHETIC_ACTION_HANDLERS:
            return SYNTHETIC_ACTION_HANDLERS[norm]
        # 3. Match substring playbook code in action_code (e.g., ACT-PB-004-01 in ACT-01-ACT-PB-004-01)
        for key, handler in SYNTHETIC_ACTION_HANDLERS.items():
            if key in action_code:
                return handler
        # 4. Match by action_type
        type_norm = f"SIMULATE_{action_type.upper().replace('-', '_')}"
        if type_norm in SYNTHETIC_ACTION_HANDLERS:
            return SYNTHETIC_ACTION_HANDLERS[type_norm]
        for key, handler in SYNTHETIC_ACTION_HANDLERS.items():
            if key.replace("SIMULATE_", "") in action_type.upper() or action_type.upper() in key:
                return handler

        return None

