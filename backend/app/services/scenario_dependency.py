"""Scenario dependency and transition validation for attack path orchestration."""
from dataclasses import dataclass, field
from typing import Optional

SCENARIO_DEPENDENCY_MAP: dict[str, dict] = {
    "simulated_service_discovery": {
        "category": "discovery",
        "prerequisites": [],
        "allowed_transitions": [
            "simulated_weak_configuration_assessment",
            "simulated_authentication_anomaly",
            "simulated_initial_access",
        ],
        "supported_asset_types": ["server", "web_application", "api", "network_device"],
        "requires_destination": False,
    },
    "simulated_weak_configuration_assessment": {
        "category": "discovery",
        "prerequisites": [],
        "allowed_transitions": [
            "simulated_authentication_anomaly",
            "simulated_initial_access",
        ],
        "supported_asset_types": ["server", "database", "web_application", "api", "network_device"],
        "requires_destination": False,
    },
    "simulated_authentication_anomaly": {
        "category": "credential_access",
        "prerequisites": [],
        "allowed_transitions": [
            "simulated_privilege_escalation",
            "simulated_lateral_movement",
        ],
        "supported_asset_types": ["server", "database", "web_application", "api"],
        "requires_destination": False,
    },
    "simulated_initial_access": {
        "category": "initial_access",
        "prerequisites": [],
        "allowed_transitions": [
            "simulated_privilege_escalation",
            "simulated_lateral_movement",
            "simulated_persistence",
            "simulated_data_exfiltration",
        ],
        "supported_asset_types": ["server", "web_application", "api", "network_device"],
        "requires_destination": False,
    },
    "simulated_privilege_escalation": {
        "category": "privilege_escalation",
        "prerequisites": [],
        "allowed_transitions": [
            "simulated_lateral_movement",
            "simulated_persistence",
            "simulated_data_exfiltration",
        ],
        "supported_asset_types": ["server", "workstation", "database"],
        "requires_destination": False,
    },
    "simulated_lateral_movement": {
        "category": "lateral_movement",
        "prerequisites": [],
        "allowed_transitions": [
            "simulated_privilege_escalation",
            "simulated_persistence",
            "simulated_data_exfiltration",
            "simulated_service_discovery",
        ],
        "supported_asset_types": ["server", "workstation", "database"],
        "requires_destination": True,
    },
    "simulated_persistence": {
        "category": "persistence",
        "prerequisites": [],
        "allowed_transitions": [
            "simulated_data_exfiltration",
        ],
        "supported_asset_types": ["server", "workstation", "network_device"],
        "requires_destination": False,
    },
    "simulated_data_exfiltration": {
        "category": "exfiltration",
        "prerequisites": [],
        "allowed_transitions": [],  # Terminal
        "supported_asset_types": ["server", "database", "api"],
        "requires_destination": False,
    },
}

# MITRE ATT&CK kill-chain ordering for planning preference
KILL_CHAIN_ORDER = [
    "simulated_service_discovery",
    "simulated_weak_configuration_assessment",
    "simulated_authentication_anomaly",
    "simulated_initial_access",
    "simulated_privilege_escalation",
    "simulated_lateral_movement",
    "simulated_persistence",
    "simulated_data_exfiltration",
]


@dataclass
class ValidationResult:
    valid: bool
    reason: str = ""
    missing_prerequisites: list[str] = field(default_factory=list)


class ScenarioDependencyEngine:
    """Validates scenario transitions and prerequisites for attack path planning."""

    def is_compatible(self, scenario_id: str, asset_type: str) -> bool:
        """Returns True if the scenario can target the given asset type."""
        info = SCENARIO_DEPENDENCY_MAP.get(scenario_id)
        if not info:
            return False
        return asset_type in info["supported_asset_types"]

    def can_transition(self, from_scenario: str, to_scenario: str) -> bool:
        """Returns True if to_scenario can follow from_scenario."""
        info = SCENARIO_DEPENDENCY_MAP.get(from_scenario)
        if not info:
            return False
        return to_scenario in info["allowed_transitions"]

    def requires_destination(self, scenario_id: str) -> bool:
        """Returns True if the scenario requires a destination asset."""
        info = SCENARIO_DEPENDENCY_MAP.get(scenario_id)
        if not info:
            return False
        return info.get("requires_destination", False)

    def validate_prerequisite_stages(
        self,
        completed_stage_ids: list[str],
        required_prereqs: list[str],
    ) -> ValidationResult:
        """Validates that all required prerequisite stages have been completed."""
        completed_set = set(completed_stage_ids)
        missing = [p for p in required_prereqs if p not in completed_set]
        if missing:
            return ValidationResult(valid=False, reason="Missing prerequisites", missing_prerequisites=missing)
        return ValidationResult(valid=True)

    def get_candidate_next_scenarios(
        self,
        current_scenario: str,
        asset_type: str,
    ) -> list[str]:
        """Returns candidate next scenarios compatible with the asset type."""
        info = SCENARIO_DEPENDENCY_MAP.get(current_scenario, {})
        transitions = info.get("allowed_transitions", [])
        return [s for s in transitions if self.is_compatible(s, asset_type)]

    def get_supported_scenarios_for_asset_type(self, asset_type: str) -> list[str]:
        """Returns all scenarios that support the given asset type, in kill-chain order."""
        result = []
        for scenario_id in KILL_CHAIN_ORDER:
            info = SCENARIO_DEPENDENCY_MAP.get(scenario_id, {})
            if asset_type in info.get("supported_asset_types", []):
                result.append(scenario_id)
        return result


dependency_engine = ScenarioDependencyEngine()

