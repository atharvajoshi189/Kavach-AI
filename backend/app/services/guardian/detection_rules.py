"""Deterministic Threat Detection Rule Definitions and Registry for Blue Guardian.

Defines the initial library of 8 rules corresponding to the AegisMesh synthetic scenario suite.
Uses safe, bounded conditional evaluators (no dynamic python exec or eval).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
import uuid

from app.models.guardian import CorrelatedEventGroup, DefensiveEventRecord
from app.services.guardian.mitre_mapper import MitreMapper


@dataclass(frozen=True)
class RuleEvaluationResult:
    """Outcome payload when a detection rule matches forensic evidence."""
    matched: bool
    title: str
    description: str
    classification: str
    base_severity: str
    base_confidence: float
    mitre_techniques: List[Dict[str, Any]]
    mitre_tactics: List[str]
    affected_asset_ids: List[str]
    evidence_references: Dict[str, Any]
    detection_rationale: str
    is_compromised: bool = False
    multi_host_scope: bool = False
    has_rich_payload: bool = False


@dataclass
class DetectionRule:
    """Descriptor and bounded evaluation logic for a detection rule."""
    rule_code: str
    rule_version: str
    rule_name: str
    description: str
    enabled: bool
    severity: str
    confidence: float
    classification: str
    mitre_tactics: List[str]
    mitre_techniques: List[Dict[str, Any]]
    required_event_types: List[str]
    min_event_count: int
    false_positive_conditions: List[str]
    evaluator: Callable[[CorrelatedEventGroup, List[DefensiveEventRecord]], Optional[RuleEvaluationResult]]

    def evaluate(
        self,
        group: CorrelatedEventGroup,
        events: List[DefensiveEventRecord],
    ) -> Optional[RuleEvaluationResult]:
        """Executes the safe condition evaluator if the rule is enabled."""
        if not self.enabled:
            return None
        return self.evaluator(group, events)


# =============================================================================
# Helper Extraction Functions
# =============================================================================

def _extract_assets(group: CorrelatedEventGroup, events: List[DefensiveEventRecord]) -> List[str]:
    """Collects unique asset UUID strings involved in the event group."""
    asset_ids: set[str] = set()
    if group.root_cause_asset_id:
        asset_ids.add(str(group.root_cause_asset_id))
    for aid in (group.impacted_asset_ids or []):
        asset_ids.add(str(aid))
    for ev in events:
        if ev.source_asset_id:
            asset_ids.add(str(ev.source_asset_id))
        if ev.destination_asset_id:
            asset_ids.add(str(ev.destination_asset_id))
    return sorted(list(asset_ids))


def _extract_source_event_ids(events: List[DefensiveEventRecord]) -> List[str]:
    return [ev.source_event_id for ev in events]


# =============================================================================
# Initial 8 Detection Rule Evaluators
# =============================================================================

# 1. BGD-RULE-001: Network Service Discovery (T1046)
def _eval_service_discovery(group: CorrelatedEventGroup, events: List[DefensiveEventRecord]) -> Optional[RuleEvaluationResult]:
    valid_types = {"port_scan", "service_enumeration", "network_sweep", "service_discovery"}
    matching_events = [
        e for e in events
        if e.event_type.lower() in valid_types
        or (e.scenario_id and "service_discovery" in e.scenario_id.lower())
    ]
    if len(matching_events) < 1 and "reconnaissance" not in group.stage.lower():
        return None

    affected = _extract_assets(group, matching_events or events)
    tech = MitreMapper.map_technique("T1046", evidence_clues=[f"{len(matching_events)} discovery events observed"])
    
    return RuleEvaluationResult(
        matched=True,
        title="Network Service Discovery Activity Detected",
        description="Observed sequential or coordinated service and port discovery targeting sandbox assets.",
        classification="Reconnaissance",
        base_severity="Low",
        base_confidence=0.75,
        mitre_techniques=[tech],
        mitre_tactics=MitreMapper.extract_tactics([tech]),
        affected_asset_ids=affected,
        evidence_references={
            "source_event_ids": _extract_source_event_ids(matching_events or events),
            "correlation_basis": group.correlation_basis,
            "stage": group.stage,
        },
        detection_rationale=f"Telemetry indicates scanning probes across assets: {', '.join(affected[:3])}.",
        has_rich_payload=any("port" in str(e.raw_payload) for e in events),
    )


# 2. BGD-RULE-002: Repeated Authentication Failures / Brute Force (T1110)
def _eval_brute_force(group: CorrelatedEventGroup, events: List[DefensiveEventRecord]) -> Optional[RuleEvaluationResult]:
    valid_types = {"auth_failure", "failed_login", "brute_force_attempt", "credential_stuffing", "authentication_anomaly"}
    matching_events = [
        e for e in events
        if e.event_type.lower() in valid_types
        or (e.scenario_id and "authentication_anomaly" in e.scenario_id.lower())
    ]
    if len(matching_events) < 1 and "credential_access" not in group.stage.lower():
        return None

    affected = _extract_assets(group, matching_events or events)
    tech = MitreMapper.map_technique("T1110", evidence_clues=[f"{len(matching_events)} anomalous authentication events"])

    return RuleEvaluationResult(
        matched=True,
        title="Repeated Authentication Failures / Potential Brute Force",
        description="Defensive telemetry recorded rapid authentication anomalies or credential spraying attempts.",
        classification="Credential Access",
        base_severity="Medium",
        base_confidence=0.80,
        mitre_techniques=[tech],
        mitre_tactics=MitreMapper.extract_tactics([tech]),
        affected_asset_ids=affected,
        evidence_references={
            "source_event_ids": _extract_source_event_ids(matching_events or events),
            "correlation_basis": group.correlation_basis,
            "stage": group.stage,
        },
        detection_rationale="Clustered authentication anomalies indicate active credential access attempt.",
        has_rich_payload=any("user" in str(e.raw_payload).lower() for e in events),
    )


# 3. BGD-RULE-003: Exploit Public-Facing Application (T1190)
def _eval_initial_access(group: CorrelatedEventGroup, events: List[DefensiveEventRecord]) -> Optional[RuleEvaluationResult]:
    valid_types = {"exploit_attempt", "web_attack", "injection_attempt", "auth_bypass", "initial_access"}
    matching_events = [
        e for e in events
        if e.event_type.lower() in valid_types
        or (e.scenario_id and "initial_access" in e.scenario_id.lower())
        or (e.scenario_id and "auth_bypass" in e.scenario_id.lower())
    ]
    if len(matching_events) < 1 and "initial_access" not in group.stage.lower():
        return None

    affected = _extract_assets(group, matching_events or events)
    is_compromised = any(
        "success" in str(e.raw_payload).lower() or "bypass" in e.event_type.lower()
        for e in (matching_events or events)
    )
    tech = MitreMapper.map_technique("T1190", evidence_clues=["Application endpoint targeted with exploit or bypass payload"])

    return RuleEvaluationResult(
        matched=True,
        title="Exploit Attempt on Public-Facing Application",
        description="Detected application-layer exploit or authorization bypass telemetry on synthetic service.",
        classification="Initial Access",
        base_severity="High",
        base_confidence=0.85,
        mitre_techniques=[tech],
        mitre_tactics=MitreMapper.extract_tactics([tech]),
        affected_asset_ids=affected,
        evidence_references={
            "source_event_ids": _extract_source_event_ids(matching_events or events),
            "correlation_basis": group.correlation_basis,
            "stage": group.stage,
        },
        detection_rationale="Exploitation or authorization bypass behavior confirmed in defensive telemetry stream.",
        is_compromised=is_compromised,
        has_rich_payload=True,
    )


# 4. BGD-RULE-004: Exploitation for Privilege Escalation (T1068)
def _eval_privilege_escalation(group: CorrelatedEventGroup, events: List[DefensiveEventRecord]) -> Optional[RuleEvaluationResult]:
    valid_types = {"privilege_escalation", "suid_exec", "token_impersonation", "sudo_abuse", "privilege_escalation_attempt"}
    matching_events = [
        e for e in events
        if e.event_type.lower() in valid_types
        or (e.scenario_id and "privilege_escalation" in e.scenario_id.lower())
    ]
    if len(matching_events) < 1 and "privilege_escalation" not in group.stage.lower():
        return None

    affected = _extract_assets(group, matching_events or events)
    is_compromised = any(
        "root" in str(e.raw_payload).lower() or "admin" in str(e.raw_payload).lower() or e.severity.upper() == "CRITICAL"
        for e in (matching_events or events)
    )
    tech = MitreMapper.map_technique("T1068", evidence_clues=["Unauthorized elevation of process privileges"])

    return RuleEvaluationResult(
        matched=True,
        title="Privilege Escalation Exploitation Detected",
        description="Observed local privilege elevation or SUID/sudo permission abuse on host asset.",
        classification="Privilege Escalation",
        base_severity="High",
        base_confidence=0.85,
        mitre_techniques=[tech],
        mitre_tactics=MitreMapper.extract_tactics([tech]),
        affected_asset_ids=affected,
        evidence_references={
            "source_event_ids": _extract_source_event_ids(matching_events or events),
            "correlation_basis": group.correlation_basis,
            "stage": group.stage,
        },
        detection_rationale="Execution of privileged elevation primitives identified in host audit events.",
        is_compromised=is_compromised,
        has_rich_payload=True,
    )


# 5. BGD-RULE-005: Unauthorized Lateral Movement via Remote Services (T1021)
def _eval_lateral_movement(group: CorrelatedEventGroup, events: List[DefensiveEventRecord]) -> Optional[RuleEvaluationResult]:
    valid_types = {"lateral_movement", "remote_service_access", "smb_exec", "ssh_pivot", "network_pivot"}
    matching_events = [
        e for e in events
        if e.event_type.lower() in valid_types
        or (e.scenario_id and "lateral_movement" in e.scenario_id.lower())
    ]
    if len(matching_events) < 1 and "lateral_movement" not in group.stage.lower():
        return None

    affected = _extract_assets(group, matching_events or events)
    tech = MitreMapper.map_technique("T1021", evidence_clues=["Remote service pivot across internal assets"])

    return RuleEvaluationResult(
        matched=True,
        title="Unauthorized Lateral Movement via Remote Services",
        description="Detected pivoting or remote service connection traversing internal asset boundary.",
        classification="Lateral Movement",
        base_severity="High",
        base_confidence=0.85,
        mitre_techniques=[tech],
        mitre_tactics=MitreMapper.extract_tactics([tech]),
        affected_asset_ids=affected,
        evidence_references={
            "source_event_ids": _extract_source_event_ids(matching_events or events),
            "correlation_basis": group.correlation_basis,
            "stage": group.stage,
        },
        detection_rationale="Cross-asset network traversal observed between source and destination targets.",
        multi_host_scope=len(affected) >= 2,
        has_rich_payload=True,
    )


# 6. BGD-RULE-006: Scheduled Task / Cron Persistence (T1053)
def _eval_persistence(group: CorrelatedEventGroup, events: List[DefensiveEventRecord]) -> Optional[RuleEvaluationResult]:
    valid_types = {"scheduled_task_created", "cron_job_added", "persistence_mechanism", "service_installed", "persistence"}
    matching_events = [
        e for e in events
        if e.event_type.lower() in valid_types
        or (e.scenario_id and "persistence" in e.scenario_id.lower())
    ]
    if len(matching_events) < 1 and "persistence" not in group.stage.lower():
        return None

    affected = _extract_assets(group, matching_events or events)
    tech = MitreMapper.map_technique("T1053", evidence_clues=["Persistence established via task scheduling"])

    return RuleEvaluationResult(
        matched=True,
        title="Scheduled Task / Cron Persistence Mechanism",
        description="Identified creation or modification of system task/cron persistence mechanisms.",
        classification="Persistence",
        base_severity="Medium",
        base_confidence=0.80,
        mitre_techniques=[tech],
        mitre_tactics=MitreMapper.extract_tactics([tech]),
        affected_asset_ids=affected,
        evidence_references={
            "source_event_ids": _extract_source_event_ids(matching_events or events),
            "correlation_basis": group.correlation_basis,
            "stage": group.stage,
        },
        detection_rationale="Recurring execution scheduler artifact registered on target asset.",
        has_rich_payload=True,
    )


# 7. BGD-RULE-007: Suspicious Data Exfiltration via Alternative Protocol (T1048)
def _eval_data_exfiltration(group: CorrelatedEventGroup, events: List[DefensiveEventRecord]) -> Optional[RuleEvaluationResult]:
    valid_types = {"data_exfiltration", "outbound_transfer", "covert_channel", "egress_anomaly", "exfiltration"}
    matching_events = [
        e for e in events
        if e.event_type.lower() in valid_types
        or (e.scenario_id and "data_exfiltration" in e.scenario_id.lower())
    ]
    if len(matching_events) < 1 and "exfiltration" not in group.stage.lower():
        return None

    affected = _extract_assets(group, matching_events or events)
    tech = MitreMapper.map_technique("T1048", evidence_clues=["Data transmission through alternative egress protocol"])

    return RuleEvaluationResult(
        matched=True,
        title="Suspicious Data Exfiltration via Alternative Protocol",
        description="Detected unauthorized egress of synthetic data payloads across alternative communication channels.",
        classification="Exfiltration",
        base_severity="Critical",
        base_confidence=0.90,
        mitre_techniques=[tech],
        mitre_tactics=MitreMapper.extract_tactics([tech]),
        affected_asset_ids=affected,
        evidence_references={
            "source_event_ids": _extract_source_event_ids(matching_events or events),
            "correlation_basis": group.correlation_basis,
            "stage": group.stage,
        },
        detection_rationale="Defensive sensor detected sensitive data package transmitted outbound.",
        is_compromised=True,
        has_rich_payload=True,
    )


# 8. BGD-RULE-008: Insecure Configuration Finding (T1190 / Weak Configuration)
def _eval_weak_configuration(group: CorrelatedEventGroup, events: List[DefensiveEventRecord]) -> Optional[RuleEvaluationResult]:
    valid_types = {"config_audit_finding", "misconfiguration_detected", "weak_ciphers", "default_credentials", "weak_configuration"}
    
    # Check for genuine configuration evidence in events or payloads
    matching_events = [
        e for e in events
        if e.event_type.lower() in valid_types
        or (e.scenario_id and "weak_configuration" in e.scenario_id.lower())
        or any(k in str(e.raw_payload).lower() for k in ["finding", "misconfiguration", "vulnerability", "insecure"])
    ]

    # Condition: Rule ONLY triggers when actual configuration evidence is present
    if not matching_events:
        return None

    affected = _extract_assets(group, matching_events)
    tech = MitreMapper.map_technique("T1190", custom_rationale="Insecure configuration exposes host or application to exploitation")

    return RuleEvaluationResult(
        matched=True,
        title="Insecure Configuration / Weak Security Posture",
        description="Identified high-risk configuration flaw, default credentials, or vulnerable service setting.",
        classification="Suspicious Configuration",
        base_severity="Low",
        base_confidence=0.70,
        mitre_techniques=[tech],
        mitre_tactics=MitreMapper.extract_tactics([tech]),
        affected_asset_ids=affected,
        evidence_references={
            "source_event_ids": _extract_source_event_ids(matching_events),
            "correlation_basis": group.correlation_basis,
            "stage": group.stage,
        },
        detection_rationale="Audit verification identified actionable misconfiguration evidence in target profile.",
        has_rich_payload=True,
    )


# =============================================================================
# Detection Rule Registry
# =============================================================================

INITIAL_DETECTION_RULES: List[DetectionRule] = [
    DetectionRule(
        rule_code="BGD-RULE-001",
        rule_version="1.0.0",
        rule_name="Network Service Discovery Activity",
        description="Detects active scanning, port enumeration, or discovery probes on synthetic assets.",
        enabled=True,
        severity="Low",
        confidence=0.75,
        classification="Reconnaissance",
        mitre_tactics=["Reconnaissance"],
        mitre_techniques=[MitreMapper.map_technique("T1046")],
        required_event_types=["port_scan", "service_enumeration", "network_sweep", "service_discovery"],
        min_event_count=1,
        false_positive_conditions=["Legitimate vulnerability scanner or health check probe"],
        evaluator=_eval_service_discovery,
    ),
    DetectionRule(
        rule_code="BGD-RULE-002",
        rule_version="1.0.0",
        rule_name="Repeated Authentication Failures",
        description="Detects high-frequency authentication failures or password spraying attempts.",
        enabled=True,
        severity="Medium",
        confidence=0.80,
        classification="Credential Access",
        mitre_tactics=["Credential Access"],
        mitre_techniques=[MitreMapper.map_technique("T1110")],
        required_event_types=["auth_failure", "failed_login", "brute_force_attempt", "credential_stuffing", "authentication_anomaly"],
        min_event_count=1,
        false_positive_conditions=["User password expiration or misconfigured service account"],
        evaluator=_eval_brute_force,
    ),
    DetectionRule(
        rule_code="BGD-RULE-003",
        rule_version="1.0.0",
        rule_name="Exploit Public-Facing Application",
        description="Detects application exploit payloads or authorization bypass attempts on exposed services.",
        enabled=True,
        severity="High",
        confidence=0.85,
        classification="Initial Access",
        mitre_tactics=["Initial Access"],
        mitre_techniques=[MitreMapper.map_technique("T1190")],
        required_event_types=["exploit_attempt", "web_attack", "injection_attempt", "auth_bypass", "initial_access"],
        min_event_count=1,
        false_positive_conditions=["Web application firewall signature false alarm"],
        evaluator=_eval_initial_access,
    ),
    DetectionRule(
        rule_code="BGD-RULE-004",
        rule_version="1.0.0",
        rule_name="Privilege Escalation Exploitation",
        description="Detects unauthorized elevation to root or administrative context.",
        enabled=True,
        severity="High",
        confidence=0.85,
        classification="Privilege Escalation",
        mitre_tactics=["Privilege Escalation"],
        mitre_techniques=[MitreMapper.map_technique("T1068")],
        required_event_types=["privilege_escalation", "suid_exec", "token_impersonation", "sudo_abuse"],
        min_event_count=1,
        false_positive_conditions=["Legitimate administrative maintenance script or automated package upgrade"],
        evaluator=_eval_privilege_escalation,
    ),
    DetectionRule(
        rule_code="BGD-RULE-005",
        rule_version="1.0.0",
        rule_name="Unauthorized Lateral Movement via Remote Services",
        description="Detects network pivoting and remote execution across sandbox internal asset boundaries.",
        enabled=True,
        severity="High",
        confidence=0.85,
        classification="Lateral Movement",
        mitre_tactics=["Lateral Movement"],
        mitre_techniques=[MitreMapper.map_technique("T1021")],
        required_event_types=["lateral_movement", "remote_service_access", "smb_exec", "ssh_pivot", "network_pivot"],
        min_event_count=1,
        false_positive_conditions=["Internal orchestration tool or cross-node synchronization daemon"],
        evaluator=_eval_lateral_movement,
    ),
    DetectionRule(
        rule_code="BGD-RULE-006",
        rule_version="1.0.0",
        rule_name="Scheduled Task and Cron Persistence",
        description="Detects creation or modification of persistent cron jobs or system scheduling services.",
        enabled=True,
        severity="Medium",
        confidence=0.80,
        classification="Persistence",
        mitre_tactics=["Persistence"],
        mitre_techniques=[MitreMapper.map_technique("T1053")],
        required_event_types=["scheduled_task_created", "cron_job_added", "persistence_mechanism", "service_installed", "persistence"],
        min_event_count=1,
        false_positive_conditions=["Legitimate cron job deployment during configuration management"],
        evaluator=_eval_persistence,
    ),
    DetectionRule(
        rule_code="BGD-RULE-007",
        rule_version="1.0.0",
        rule_name="Suspicious Data Exfiltration via Alternative Protocol",
        description="Detects exfiltration of sensitive telemetry data through non-standard egress protocols.",
        enabled=True,
        severity="Critical",
        confidence=0.90,
        classification="Exfiltration",
        mitre_tactics=["Exfiltration"],
        mitre_techniques=[MitreMapper.map_technique("T1048")],
        required_event_types=["data_exfiltration", "outbound_transfer", "covert_channel", "egress_anomaly", "exfiltration"],
        min_event_count=1,
        false_positive_conditions=["Authorized off-site backup transfer"],
        evaluator=_eval_data_exfiltration,
    ),
    DetectionRule(
        rule_code="BGD-RULE-008",
        rule_version="1.0.0",
        rule_name="Insecure Configuration Finding",
        description="Detects confirmed misconfigurations, weak credentials, or vulnerable service parameters.",
        enabled=True,
        severity="Low",
        confidence=0.70,
        classification="Suspicious Configuration",
        mitre_tactics=["Initial Access"],
        mitre_techniques=[MitreMapper.map_technique("T1190", custom_rationale="Insecure configuration creates exploitable exposure")],
        required_event_types=["config_audit_finding", "misconfiguration_detected", "weak_ciphers", "default_credentials", "weak_configuration"],
        min_event_count=1,
        false_positive_conditions=["Intentional debug configuration in isolated staging environment"],
        evaluator=_eval_weak_configuration,
    ),
]


class DetectionRuleRegistry:
    """Manages active detection rules and provides immutable access."""

    def __init__(self, rules: Optional[List[DetectionRule]] = None):
        self._rules: Dict[str, DetectionRule] = {}
        for r in (rules or INITIAL_DETECTION_RULES):
            self._rules[r.rule_code] = r

    def get_all_rules(self) -> List[DetectionRule]:
        """Returns sorted list of registered rules."""
        return sorted(list(self._rules.values()), key=lambda r: r.rule_code)

    def get_rule(self, rule_code: str) -> Optional[DetectionRule]:
        return self._rules.get(rule_code)

