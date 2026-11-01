"""Scenario registry and deterministic handlers for the Red Team Simulation Engine."""

from datetime import datetime, timezone
import logging
from typing import Any, Callable, Coroutine, Optional
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.red_team.schemas import (
    ScenarioMetadataResponse,
    SimulationEvent,
    SimulationEvidence,
    SimulationFinding,
    SimulationResult,
)
from app.models.synthetic_asset import SyntheticAsset
from app.services.sandbox_service import get_asset_by_id

logger = logging.getLogger("aegismesh.scenario_registry")


class RedTeamScenarioNotFoundError(ValueError):
    """Raised when an unrecognized scenario identifier is requested."""
    pass


class ScenarioAssetIncompatibleError(ValueError):
    """Raised when the target asset type is incompatible with the requested scenario."""
    pass


# Type definition for simulation handler functions
SimulationHandler = Callable[
    ...,
    Coroutine[Any, Any, SimulationResult],
]


class ScenarioDefinition:
    """Descriptor and executable handler binding for a Red Team attack scenario."""

    def __init__(
        self,
        scenario_id: str,
        name: str,
        description: str,
        technique: str,
        technique_id: str,
        applicable_asset_types: list[str],
        handler: SimulationHandler,
        parameters: Optional[dict[str, Any]] = None,
        category: str = "general",
        mapping_type: str = "conceptual_scenario",
        is_synthetic: bool = True,
        risk_classification: str = "medium",
    ):
        self.scenario_id = scenario_id
        self.name = name
        self.description = description
        self.technique = technique
        self.technique_id = technique_id
        self.applicable_asset_types = applicable_asset_types
        self.handler = handler
        self.parameters = parameters or {}
        self.category = category
        self.mapping_type = mapping_type
        self.is_synthetic = is_synthetic
        self.risk_classification = risk_classification

    def to_metadata(self) -> ScenarioMetadataResponse:
        """Converts definition into user-facing API schema."""
        return ScenarioMetadataResponse(
            scenario_id=self.scenario_id,
            name=self.name,
            description=self.description,
            category=self.category,
            technique=self.technique,
            technique_id=self.technique_id,
            applicable_asset_types=self.applicable_asset_types,
            parameters=self.parameters,
            mapping_type=self.mapping_type,
            is_synthetic=self.is_synthetic,
            risk_classification=self.risk_classification,
        )


# =====================================================================
# Scenario Handlers (100% Synthetic, Zero Sockets, Zero Subprocesses)
# =====================================================================

# ---------------------------------------------------------------------
# 1. Simulated Service Discovery (Existing)
# ---------------------------------------------------------------------
async def handle_simulated_service_discovery(
    asset: SyntheticAsset,
    parameters: Optional[dict[str, Any]] = None,
    **kwargs: Any,
) -> SimulationResult:
    """Executes deterministic simulated service and port discovery.

    Evaluates synthetic asset service_metadata and configuration. No network sockets
    or external connections are ever opened.
    """
    started_at = datetime.now(timezone.utc)
    events: list[SimulationEvent] = []
    findings: list[SimulationFinding] = []

    events.append(
        SimulationEvent(
            timestamp=started_at,
            event_type="simulation_started",
            scenario_id="simulated_service_discovery",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Initiated simulated network service discovery on synthetic asset '{asset.name}' ({asset.ip_address})",
            details={
                "scenario": "simulated_service_discovery",
                "asset_id": str(asset.id),
                "asset_type": asset.asset_type,
                "ip_address": asset.ip_address,
            },
            event_metadata={"asset_id": str(asset.id), "scenario": "simulated_service_discovery"},
        )
    )

    services_data = asset.service_metadata or {}
    config_data = asset.configuration or {}
    discovered_services: list[dict[str, Any]] = []

    if "services" in services_data and isinstance(services_data["services"], list):
        for svc in services_data["services"]:
            if isinstance(svc, dict):
                discovered_services.append(svc)
    elif "ports" in services_data and isinstance(services_data["ports"], list):
        for port_info in services_data["ports"]:
            if isinstance(port_info, dict):
                discovered_services.append(port_info)
            elif isinstance(port_info, int):
                discovered_services.append({"port": port_info, "protocol": "tcp", "service": "unknown"})
    elif "running_services" in config_data and isinstance(config_data["running_services"], list):
        for svc in config_data["running_services"]:
            if isinstance(svc, dict):
                discovered_services.append(svc)

    if not discovered_services:
        if asset.asset_type == "web_application":
            discovered_services = [
                {"port": 80, "protocol": "tcp", "service": "http", "banner": "nginx/1.24.0 (simulated)"},
                {"port": 443, "protocol": "tcp", "service": "https", "banner": "nginx/1.24.0 (simulated)"},
            ]
        elif asset.asset_type == "api":
            discovered_services = [
                {"port": 8080, "protocol": "tcp", "service": "http-alt", "banner": "uvicorn/0.30.0 (simulated)"},
                {"port": 443, "protocol": "tcp", "service": "https", "banner": "envoy/1.28.0 (simulated)"},
            ]
        elif asset.asset_type == "database":
            discovered_services = [
                {"port": 5432, "protocol": "tcp", "service": "postgresql", "banner": "PostgreSQL 16.2 (simulated)"},
            ]
        elif asset.asset_type == "network_device":
            discovered_services = [
                {"port": 22, "protocol": "tcp", "service": "ssh", "banner": "OpenSSH_8.9p1 (simulated)"},
                {"port": 161, "protocol": "udp", "service": "snmp", "banner": "net-snmp 5.9.1 (simulated)"},
            ]
        else:
            discovered_services = [
                {"port": 22, "protocol": "tcp", "service": "ssh", "banner": "OpenSSH_8.9p1 (simulated)"},
                {"port": 80, "protocol": "tcp", "service": "http", "banner": "Apache/2.4.52 (simulated)"},
            ]

    for svc in discovered_services:
        port = svc.get("port", "unknown")
        proto = svc.get("protocol", "tcp")
        name = svc.get("service", "unknown")
        banner = svc.get("banner", "simulated-service")

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="service_enumerated",
                scenario_id="simulated_service_discovery",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="info",
                message=f"Discovered simulated listener: {proto}/{port} ({name})",
                details={
                    "port": port,
                    "protocol": proto,
                    "service": name,
                    "banner": banner,
                    "is_simulated": True,
                },
                event_metadata={"port": port, "service": name, "protocol": proto},
            )
        )

    base_risk = 2.0
    for svc in discovered_services:
        port = svc.get("port")
        name = str(svc.get("service", "")).lower()
        if port in [21, 23] or name in ["ftp", "telnet"]:
            base_risk += 3.0
            findings.append(
                SimulationFinding(
                    title=f"Insecure Legacy Protocol Exposed: {name.upper()}",
                    description=f"Synthetic asset exposes legacy unencrypted {name.upper()} service on port {port}.",
                    severity="high",
                    technique="T1046 - Network Service Discovery (Synthetic Simulation)",
                    asset_id=str(asset.id),
                    details={"port": port, "service": name, "protocol": svc.get("protocol")},
                    evidence=SimulationEvidence(
                        scenario_id="simulated_service_discovery",
                        evidence_type="exposed_legacy_service",
                        synthetic_asset_references=[str(asset.id)],
                        finding_description=f"Legacy unencrypted listener {proto}/{port} discovered",
                        severity="high",
                        confidence="high",
                        supporting_synthetic_metadata=svc,
                    ),
                    remediation_recommendation=f"Disable legacy service '{name}' and transition to encrypted protocols.",
                )
            )

    findings.append(
        SimulationFinding(
            title="Synthetic Attack Surface Enumerated",
            description=f"Simulated discovery identified {len(discovered_services)} active network service listener(s).",
            severity="medium" if len(discovered_services) > 2 else "low",
            technique="T1046 - Network Service Discovery (Synthetic Simulation)",
            asset_id=str(asset.id),
            details={"service_count": len(discovered_services), "services": discovered_services},
            evidence=SimulationEvidence(
                scenario_id="simulated_service_discovery",
                evidence_type="network_surface_enumeration",
                synthetic_asset_references=[str(asset.id)],
                finding_description=f"Identified {len(discovered_services)} active service listeners",
                severity="medium" if len(discovered_services) > 2 else "low",
                confidence="high",
                supporting_synthetic_metadata={"count": len(discovered_services)},
            ),
            remediation_recommendation="Restrict unnecessary listening ports and implement network segmentation.",
        )
    )

    risk_score = min(round(base_risk + (0.5 * len(discovered_services)), 1), 10.0)
    completed_at = datetime.now(timezone.utc)

    events.append(
        SimulationEvent(
            timestamp=completed_at,
            event_type="simulation_completed",
            scenario_id="simulated_service_discovery",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Simulated service discovery complete. Discovered {len(discovered_services)} services.",
            details={"services_discovered": len(discovered_services), "risk_score": risk_score},
            event_metadata={"services_count": len(discovered_services), "risk_score": risk_score},
        )
    )

    return SimulationResult(
        scenario="simulated_service_discovery",
        technique="T1046 - Network Service Discovery (Synthetic Simulation)",
        asset_id=str(asset.id),
        sandbox_id=str(asset.sandbox_id),
        status="completed",
        risk_score=risk_score,
        events=events,
        findings=findings,
        started_at=started_at,
        completed_at=completed_at,
        simulation_only=True,
    )


# ---------------------------------------------------------------------
# 2. Simulated Weak Configuration Assessment (Existing)
# ---------------------------------------------------------------------
async def handle_simulated_weak_configuration_assessment(
    asset: SyntheticAsset,
    parameters: Optional[dict[str, Any]] = None,
    **kwargs: Any,
) -> SimulationResult:
    """Executes deterministic assessment of simulated weak configurations and vulnerabilities."""
    started_at = datetime.now(timezone.utc)
    events: list[SimulationEvent] = []
    findings: list[SimulationFinding] = []

    events.append(
        SimulationEvent(
            timestamp=started_at,
            event_type="simulation_started",
            scenario_id="simulated_weak_configuration_assessment",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Initiated weak configuration assessment on synthetic asset '{asset.name}'",
            details={
                "scenario": "simulated_weak_configuration_assessment",
                "asset_id": str(asset.id),
                "asset_type": asset.asset_type,
            },
            event_metadata={"asset_id": str(asset.id)},
        )
    )

    config = asset.configuration or {}
    sim_vulns = asset.simulated_vulnerabilities or []
    base_risk = 1.0

    if config.get("debug") is True or config.get("debug_mode") is True:
        base_risk += 2.5
        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="misconfiguration_detected",
                scenario_id="simulated_weak_configuration_assessment",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="warning",
                message="Debug mode detected in synthetic configuration.",
                details={"setting": "debug_mode", "value": True},
                event_metadata={"setting": "debug_mode"},
            )
        )
        findings.append(
            SimulationFinding(
                title="Debug Mode Enabled in Simulated Asset Configuration",
                description="Simulated asset has debug/verbose mode active, exposing internal stack traces and environment states.",
                severity="medium",
                technique="Synthetic Assessment (Insecure Debug Mode)",
                asset_id=str(asset.id),
                details={"configuration_key": "debug_mode"},
                evidence=SimulationEvidence(
                    scenario_id="simulated_weak_configuration_assessment",
                    evidence_type="debug_mode_flag",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description="debug_mode: true located in synthetic configuration",
                    severity="medium",
                    confidence="high",
                    supporting_synthetic_metadata={"debug_mode": True},
                ),
                remediation_recommendation="Disable debug mode and enforce production-grade telemetry controls.",
            )
        )

    if (
        config.get("default_credentials") is True
        or config.get("allow_anonymous") is True
        or config.get("auth_required") is False
    ):
        base_risk += 4.5
        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="misconfiguration_detected",
                scenario_id="simulated_weak_configuration_assessment",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="high",
                message="Default credentials or unauthenticated access mode detected.",
                details={"default_credentials": config.get("default_credentials"), "allow_anonymous": config.get("allow_anonymous")},
                event_metadata={"insecure_auth": True},
            )
        )
        findings.append(
            SimulationFinding(
                title="Default Credentials / Unauthenticated Access Permitted",
                description="Synthetic asset allows unauthenticated or default-credential access.",
                severity="critical",
                technique="Synthetic Assessment (Default Credentials Exposure)",
                asset_id=str(asset.id),
                details={"misconfiguration": "insecure_access_policy"},
                evidence=SimulationEvidence(
                    scenario_id="simulated_weak_configuration_assessment",
                    evidence_type="insecure_access_policy",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description="Asset allows default credentials or anonymous access",
                    severity="critical",
                    confidence="high",
                    supporting_synthetic_metadata={"default_credentials": config.get("default_credentials")},
                ),
                remediation_recommendation="Enforce mandatory multi-factor authentication and rotate all default credentials.",
            )
        )

    tls_version = str(config.get("tls_version", "")).lower()
    if tls_version in ["1.0", "1.1", "tls1.0", "tls1.1"]:
        base_risk += 2.0
        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="misconfiguration_detected",
                scenario_id="simulated_weak_configuration_assessment",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="warning",
                message=f"Deprecated TLS version detected: {tls_version}",
                details={"tls_version": tls_version},
                event_metadata={"tls_version": tls_version},
            )
        )
        findings.append(
            SimulationFinding(
                title=f"Deprecated Transport Layer Security ({tls_version.upper()})",
                description=f"Synthetic asset configuration specifies obsolete {tls_version.upper()} protocol.",
                severity="medium",
                technique="Synthetic Assessment (Deprecated Cryptographic Protocol)",
                asset_id=str(asset.id),
                details={"tls_version": tls_version},
                evidence=SimulationEvidence(
                    scenario_id="simulated_weak_configuration_assessment",
                    evidence_type="deprecated_tls",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description=f"Deprecated {tls_version.upper()} cipher configuration identified",
                    severity="medium",
                    confidence="high",
                    supporting_synthetic_metadata={"tls_version": tls_version},
                ),
                remediation_recommendation="Upgrade minimum TLS cipher suite to TLS 1.3.",
            )
        )

    for vuln in sim_vulns:
        if isinstance(vuln, dict):
            cve = vuln.get("cve_id", vuln.get("id", "VULN-SIM-001"))
            title = vuln.get("title", vuln.get("name", f"Simulated Vulnerability {cve}"))
            severity = str(vuln.get("severity", "medium")).lower()
            if severity not in ["low", "medium", "high", "critical"]:
                severity = "medium"

            risk_add = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}.get(severity, 2.0)
            base_risk += risk_add

            events.append(
                SimulationEvent(
                    timestamp=datetime.now(timezone.utc),
                    event_type="vulnerability_identified",
                    scenario_id="simulated_weak_configuration_assessment",
                    source_asset_id=str(asset.id),
                    sandbox_id=str(asset.sandbox_id),
                    severity=severity,
                    message=f"Simulated vulnerability identified: {cve} ({title})",
                    details=vuln,
                    event_metadata={"cve": cve, "severity": severity},
                )
            )
            findings.append(
                SimulationFinding(
                    title=f"Synthetic Vulnerability: {cve} - {title}",
                    description=vuln.get("description", "Identified simulated vulnerability in synthetic asset profile."),
                    severity=severity,
                    technique="Synthetic Assessment (Simulated CVE Vulnerability)",
                    asset_id=str(asset.id),
                    details=vuln,
                    evidence=SimulationEvidence(
                        scenario_id="simulated_weak_configuration_assessment",
                        evidence_type="simulated_vulnerability_entry",
                        synthetic_asset_references=[str(asset.id)],
                        finding_description=f"{cve}: {title}",
                        severity=severity,
                        confidence="high",
                        supporting_synthetic_metadata=vuln,
                    ),
                    remediation_recommendation=vuln.get("remediation", "Apply vendor security patch and re-evaluate."),
                )
            )

    if not findings:
        findings.append(
            SimulationFinding(
                title="Synthetic Asset Baseline Configuration Secure",
                description="Deterministic assessment did not identify any known simulated misconfigurations or vulnerabilities.",
                severity="low",
                technique="Synthetic Assessment (Baseline Configuration)",
                asset_id=str(asset.id),
                details={"status": "hardened_baseline"},
                remediation_recommendation="Maintain continuous compliance monitoring.",
            )
        )

    risk_score = min(round(base_risk, 1), 10.0)
    completed_at = datetime.now(timezone.utc)

    events.append(
        SimulationEvent(
            timestamp=completed_at,
            event_type="simulation_completed",
            scenario_id="simulated_weak_configuration_assessment",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Weak configuration assessment complete. {len(findings)} finding(s) generated.",
            details={"findings_count": len(findings), "risk_score": risk_score},
            event_metadata={"findings_count": len(findings), "risk_score": risk_score},
        )
    )

    return SimulationResult(
        scenario="simulated_weak_configuration_assessment",
        technique="Synthetic Configuration Audit (Conceptual)",
        asset_id=str(asset.id),
        sandbox_id=str(asset.sandbox_id),
        status="completed",
        risk_score=risk_score,
        events=events,
        findings=findings,
        started_at=started_at,
        completed_at=completed_at,
        simulation_only=True,
    )


# ---------------------------------------------------------------------
# 3. Simulated Authentication Anomaly (Existing)
# ---------------------------------------------------------------------
async def handle_simulated_authentication_anomaly(
    asset: SyntheticAsset,
    parameters: Optional[dict[str, Any]] = None,
    **kwargs: Any,
) -> SimulationResult:
    """Executes deterministic simulation of authentication anomaly patterns."""
    started_at = datetime.now(timezone.utc)
    events: list[SimulationEvent] = []
    findings: list[SimulationFinding] = []

    params = parameters or {}
    attempt_count = int(params.get("attempt_count", 50))
    source_ip = str(params.get("simulated_source_ip", "198.51.100.42"))
    target_user = str(params.get("target_username", "admin"))

    events.append(
        SimulationEvent(
            timestamp=started_at,
            event_type="simulation_started",
            scenario_id="simulated_authentication_anomaly",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Simulating credential brute-force attack stream against '{asset.name}' targeting '{target_user}'",
            details={
                "scenario": "simulated_authentication_anomaly",
                "asset_id": str(asset.id),
                "attempt_count": attempt_count,
                "simulated_source_ip": source_ip,
                "target_username": target_user,
            },
            event_metadata={"attempt_count": attempt_count, "source_ip": source_ip},
        )
    )

    events.append(
        SimulationEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="synthetic_auth_stream_generated",
            scenario_id="simulated_authentication_anomaly",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="warning",
            message=f"Generated {attempt_count} synthetic authentication requests from {source_ip}",
            details={
                "total_attempts": attempt_count,
                "source_ip": source_ip,
                "target_account": target_user,
                "interval_ms": 100,
            },
            event_metadata={"total_attempts": attempt_count, "source_ip": source_ip},
        )
    )

    config = asset.configuration or {}
    has_weak_auth = config.get("default_credentials") is True or config.get("allow_anonymous") is True

    if attempt_count >= 20:
        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="threshold_exceeded",
                scenario_id="simulated_authentication_anomaly",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="high",
                message=f"Synthetic authentication failure threshold exceeded: {attempt_count} failures in short window",
                details={
                    "threshold": 10,
                    "observed": attempt_count,
                    "target_account": target_user,
                    "source_ip": source_ip,
                },
                event_metadata={"observed_failures": attempt_count, "threshold": 10},
            )
        )

    compromise_simulated = has_weak_auth and attempt_count >= 10

    if compromise_simulated:
        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="anomaly_compromise_simulated",
                scenario_id="simulated_authentication_anomaly",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="critical",
                message=f"Simulated successful authentication following brute-force stream on account '{target_user}'",
                details={
                    "compromised_account": target_user,
                    "source_ip": source_ip,
                    "simulated_credential": "default_credential_hit",
                },
                event_metadata={"compromised": True, "account": target_user},
            )
        )
        findings.append(
            SimulationFinding(
                title=f"Synthetic Credential Compromise: Account '{target_user}'",
                description=f"Simulated brute-force attack from RFC 5737 IP {source_ip} succeeded due to default/weak credentials.",
                severity="critical",
                technique="T1110.001 - Password Guessing (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "account": target_user,
                    "attempts": attempt_count,
                    "source_ip": source_ip,
                    "compromise_result": "success",
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_authentication_anomaly",
                    evidence_type="synthetic_auth_compromise",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description=f"Synthetic default credentials compromised via brute-force stream from {source_ip}",
                    severity="critical",
                    confidence="high",
                    supporting_synthetic_metadata={"account": target_user, "source_ip": source_ip},
                ),
                remediation_recommendation="Implement aggressive rate limiting, account lockout policies, and disable default accounts.",
            )
        )
        risk_score = 8.5
    else:
        findings.append(
            SimulationFinding(
                title="Synthetic Brute-Force Authentication Anomaly Detected",
                description=f"Detected simulated anomalous high-volume authentication pattern ({attempt_count} attempts) targeting '{target_user}'.",
                severity="high" if attempt_count >= 50 else "medium",
                technique="T1110 - Brute Force (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "account": target_user,
                    "attempts": attempt_count,
                    "source_ip": source_ip,
                    "compromise_result": "blocked_or_exhausted",
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_authentication_anomaly",
                    evidence_type="synthetic_auth_anomaly",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description=f"Observed {attempt_count} anomalous authentication attempts",
                    severity="high" if attempt_count >= 50 else "medium",
                    confidence="high",
                    supporting_synthetic_metadata={"attempts": attempt_count, "source_ip": source_ip},
                ),
                remediation_recommendation="Deploy automated IP throttling, fail2ban integration, and adaptive anomaly detection.",
            )
        )
        risk_score = 6.5 if attempt_count < 50 else 7.5

    completed_at = datetime.now(timezone.utc)
    events.append(
        SimulationEvent(
            timestamp=completed_at,
            event_type="simulation_completed",
            scenario_id="simulated_authentication_anomaly",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Authentication anomaly simulation finished with risk score {risk_score}",
            details={"risk_score": risk_score, "compromised": compromise_simulated},
            event_metadata={"risk_score": risk_score, "compromised": compromise_simulated},
        )
    )

    return SimulationResult(
        scenario="simulated_authentication_anomaly",
        technique="T1110 - Brute Force (Synthetic Simulation)",
        asset_id=str(asset.id),
        sandbox_id=str(asset.sandbox_id),
        status="completed",
        risk_score=risk_score,
        events=events,
        findings=findings,
        started_at=started_at,
        completed_at=completed_at,
        simulation_only=True,
    )


# ---------------------------------------------------------------------
# 4. Scenario A: Simulated Initial Access (New)
# ---------------------------------------------------------------------
async def handle_simulated_initial_access(
    asset: SyntheticAsset,
    parameters: Optional[dict[str, Any]] = None,
    **kwargs: Any,
) -> SimulationResult:
    """Executes deterministic initial access simulation on synthetic asset entry points.

    Evaluates synthetic exposed services, weak API configs, or simulated vulnerabilities.
    Never establishes a real session, contacts the network, or claims real compromise.
    """
    started_at = datetime.now(timezone.utc)
    events: list[SimulationEvent] = []
    findings: list[SimulationFinding] = []

    params = parameters or {}
    vector_requested = params.get("vector", "public_facing_exploit")

    events.append(
        SimulationEvent(
            timestamp=started_at,
            event_type="simulation_started",
            scenario_id="simulated_initial_access",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Initiated synthetic initial access simulation on asset '{asset.name}' ({asset.asset_type})",
            details={
                "scenario": "simulated_initial_access",
                "asset_id": str(asset.id),
                "asset_type": asset.asset_type,
                "vector": vector_requested,
            },
            event_metadata={"scenario": "simulated_initial_access", "vector": vector_requested},
        )
    )

    config = asset.configuration or {}
    services = asset.service_metadata or {}
    vulns = asset.simulated_vulnerabilities or []

    # Check synthetic preconditions
    has_exposed_service = (
        bool(services.get("services"))
        or bool(services.get("ports"))
        or config.get("public_facing") is True
    )
    has_weak_api = (
        config.get("auth_required") is False
        or config.get("allow_anonymous") is True
        or config.get("api_key_required") is False
        or bool(config.get("unauthenticated_endpoints"))
    )
    has_initial_vuln = any(
        v.get("category") in ["initial_access", "rce", "injection", "web", "public_exploit"]
        or v.get("severity") in ["high", "critical"]
        for v in vulns
        if isinstance(v, dict)
    )
    has_insecure_config = config.get("default_credentials") is True or config.get("debug_mode") is True

    precondition_satisfied = (
        has_exposed_service or has_weak_api or has_initial_vuln or has_insecure_config
    )

    events.append(
        SimulationEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="simulated_access_attempt",
            scenario_id="simulated_initial_access",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="warning" if precondition_satisfied else "info",
            message=f"Evaluating synthetic entry-point precondition for vector '{vector_requested}'",
            details={
                "has_exposed_service": has_exposed_service,
                "has_weak_api": has_weak_api,
                "has_initial_vuln": has_initial_vuln,
                "has_insecure_config": has_insecure_config,
                "precondition_satisfied": precondition_satisfied,
                "actual_compromise": False,
            },
            event_metadata={"precondition_satisfied": precondition_satisfied, "actual_compromise": False},
        )
    )

    if precondition_satisfied:
        simulated_access_outcome = "success"
        risk_score = 8.0

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_access_succeeded",
                scenario_id="simulated_initial_access",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="high",
                message=f"Synthetic initial access precondition met via satisfied asset profile",
                details={
                    "simulated_access_outcome": "success",
                    "precondition_satisfied": True,
                    "actual_compromise": False,
                },
                event_metadata={"outcome": "success", "actual_compromise": False},
            )
        )

        findings.append(
            SimulationFinding(
                title="Synthetic Initial Access Vector Identified",
                description="Synthetic entry point evaluates as viable based on asset configuration, simulated vulnerability, or exposed services.",
                severity="high",
                technique="T1190 - Exploit Public-Facing Application (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "precondition_satisfied": True,
                    "simulated_access_outcome": "success",
                    "actual_compromise": False,
                    "identified_preconditions": {
                        "exposed_service": has_exposed_service,
                        "weak_api": has_weak_api,
                        "vulnerability": has_initial_vuln,
                        "insecure_config": has_insecure_config,
                    },
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_initial_access",
                    evidence_type="synthetic_entry_point",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description="Synthetic asset configuration satisfies initial access entry criteria",
                    severity="high",
                    confidence="high",
                    supporting_synthetic_metadata={"precondition_satisfied": True, "vector": vector_requested},
                ),
                remediation_recommendation="Implement network segmentation, enforce strict API authentication, and patch exposed service vulnerabilities.",
            )
        )
    else:
        simulated_access_outcome = "blocked_or_ineligible"
        risk_score = 2.0

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_access_blocked",
                scenario_id="simulated_initial_access",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="info",
                message="Synthetic initial access blocked: no matching simulated entry point found in asset metadata",
                details={
                    "simulated_access_outcome": "blocked_or_ineligible",
                    "precondition_satisfied": False,
                    "actual_compromise": False,
                },
                event_metadata={"outcome": "blocked", "actual_compromise": False},
            )
        )

        findings.append(
            SimulationFinding(
                title="Synthetic Initial Access Precondition Unmet",
                description="Asset does not expose required synthetic preconditions (open services, weak API configs, or known vulnerabilities).",
                severity="low",
                technique="T1190 - Exploit Public-Facing Application (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "precondition_satisfied": False,
                    "simulated_access_outcome": "blocked_or_ineligible",
                    "actual_compromise": False,
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_initial_access",
                    evidence_type="hardened_entry_point",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description="No exposed entry point metadata satisfied initial access criteria",
                    severity="low",
                    confidence="high",
                    supporting_synthetic_metadata={"precondition_satisfied": False},
                ),
                remediation_recommendation="Maintain hardened baseline perimeter controls.",
            )
        )

    completed_at = datetime.now(timezone.utc)
    events.append(
        SimulationEvent(
            timestamp=completed_at,
            event_type="simulation_completed",
            scenario_id="simulated_initial_access",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Initial access simulation complete. Outcome: {simulated_access_outcome}",
            details={
                "precondition_satisfied": precondition_satisfied,
                "simulated_access_outcome": simulated_access_outcome,
                "actual_compromise": False,
                "risk_score": risk_score,
            },
            event_metadata={"outcome": simulated_access_outcome, "risk_score": risk_score},
        )
    )

    return SimulationResult(
        scenario="simulated_initial_access",
        technique="T1190 - Exploit Public-Facing Application (Synthetic Simulation)",
        asset_id=str(asset.id),
        sandbox_id=str(asset.sandbox_id),
        status="completed",
        risk_score=risk_score,
        events=events,
        findings=findings,
        started_at=started_at,
        completed_at=completed_at,
        simulation_only=True,
    )


# ---------------------------------------------------------------------
# 5. Scenario B: Simulated Privilege Escalation (New)
# ---------------------------------------------------------------------
async def handle_simulated_privilege_escalation(
    asset: SyntheticAsset,
    parameters: Optional[dict[str, Any]] = None,
    **kwargs: Any,
) -> SimulationResult:
    """Evaluates fictional excessive permissions and privilege boundary weaknesses.

    Does not modify real application, operating system, or database permissions.
    """
    started_at = datetime.now(timezone.utc)
    events: list[SimulationEvent] = []
    findings: list[SimulationFinding] = []

    params = parameters or {}
    source_priv = str(params.get("source_privilege", "standard_user"))
    target_priv = str(params.get("target_privilege", "root"))

    events.append(
        SimulationEvent(
            timestamp=started_at,
            event_type="simulation_started",
            scenario_id="simulated_privilege_escalation",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Evaluating synthetic privilege escalation boundaries on asset '{asset.name}'",
            details={
                "source_privilege": source_priv,
                "target_privilege": target_priv,
                "asset_type": asset.asset_type,
            },
            event_metadata={"source_privilege": source_priv, "target_privilege": target_priv},
        )
    )

    config = asset.configuration or {}
    vulns = asset.simulated_vulnerabilities or []

    # Check synthetic privilege preconditions
    mock_perms = [str(p).lower() for p in config.get("mock_permissions", [])]
    if config.get("sudo_nopasswd") is True:
        mock_perms.append("sudo_nopasswd")
    if config.get("root_access") is True:
        mock_perms.append("root_access")
    if config.get("superuser") is True:
        mock_perms.append("superuser")
    excessive_perms = [
        p for p in mock_perms
        if p in ["sudo_nopasswd", "root_access", "superuser", "admin", "db_owner", "all_privileges", "wheel"]
    ]
    roles = [str(r).lower() for r in (config.get("assigned_roles") or [config.get("role") or ""])]
    has_admin_role = any(r in ["admin", "sysadmin", "dba", "root"] for r in roles)
    has_weak_boundary = (
        config.get("privilege_boundary") in ["weak", "permissive"]
        or config.get("allow_privilege_escalation") is True
        or config.get("sudoers_misconfigured") is True
    )
    has_lpe_vuln = any(
        "privilege_escalation" in str(v.get("category", "")).lower()
        or "privilege escalation" in str(v.get("title", "")).lower()
        or "lpe" in str(v.get("title", "")).lower()
        for v in vulns
        if isinstance(v, dict)
    )

    precondition_satisfied = bool(excessive_perms or has_admin_role or has_weak_boundary or has_lpe_vuln)

    events.append(
        SimulationEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="privilege_check_simulated",
            scenario_id="simulated_privilege_escalation",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="warning" if precondition_satisfied else "info",
            message=f"Evaluated synthetic permission rules from '{source_priv}' to '{target_priv}'",
            details={
                "excessive_permissions": excessive_perms,
                "has_admin_role": has_admin_role,
                "has_weak_boundary": has_weak_boundary,
                "has_lpe_vuln": has_lpe_vuln,
                "actual_privilege_change": False,
            },
            event_metadata={"precondition_satisfied": precondition_satisfied, "actual_privilege_change": False},
        )
    )

    if precondition_satisfied:
        simulated_escalation_outcome = "success"
        risk_score = 8.5

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_privilege_transition",
                scenario_id="simulated_privilege_escalation",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="high",
                message=f"Simulated privilege escalation transition from '{source_priv}' to '{target_priv}' verified",
                details={
                    "source_privilege": source_priv,
                    "target_privilege": target_priv,
                    "simulated_outcome": "success",
                    "actual_privilege_change": False,
                },
                event_metadata={"source": source_priv, "target": target_priv, "actual_privilege_change": False},
            )
        )

        findings.append(
            SimulationFinding(
                title="Synthetic Privilege Boundary Weakness Identified",
                description=f"Synthetic asset configuration contains excessive permissions or mock administrative mappings allowing simulated transition to '{target_priv}'.",
                severity="high",
                technique="T1068 - Exploitation for Privilege Escalation (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "source_privilege": source_priv,
                    "target_privilege": target_priv,
                    "precondition_satisfied": True,
                    "simulated_escalation_outcome": "success",
                    "actual_privilege_change": False,
                    "excessive_permissions": excessive_perms,
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_privilege_escalation",
                    evidence_type="excessive_permissions_grant",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description=f"Excessive mock permissions {excessive_perms or ['admin_role']} permit escalation",
                    severity="high",
                    confidence="high",
                    supporting_synthetic_metadata={"mock_permissions": excessive_perms, "roles": roles},
                ),
                remediation_recommendation="Enforce strict principle of least privilege and eliminate passwordless administrative sudo delegations.",
            )
        )
    else:
        simulated_escalation_outcome = "denied_least_privilege_enforced"
        risk_score = 2.0

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_privilege_denied",
                scenario_id="simulated_privilege_escalation",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="info",
                message=f"Privilege escalation denied: least privilege boundaries enforced for '{source_priv}'",
                details={
                    "source_privilege": source_priv,
                    "target_privilege": target_priv,
                    "simulated_outcome": "denied",
                    "actual_privilege_change": False,
                },
                event_metadata={"outcome": "denied", "actual_privilege_change": False},
            )
        )

        findings.append(
            SimulationFinding(
                title="Least Privilege Enforced - No Synthetic Escalation Path",
                description="Synthetic asset configuration properly confines privileges; no simulated escalation path exists.",
                severity="low",
                technique="T1068 - Exploitation for Privilege Escalation (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "source_privilege": source_priv,
                    "target_privilege": target_priv,
                    "precondition_satisfied": False,
                    "simulated_escalation_outcome": "denied_least_privilege_enforced",
                    "actual_privilege_change": False,
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_privilege_escalation",
                    evidence_type="least_privilege_enforced",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description="Permissions confined without excessive administrative grants",
                    severity="low",
                    confidence="high",
                    supporting_synthetic_metadata={"precondition_satisfied": False},
                ),
                remediation_recommendation="Continue periodic role and sudo permission reviews.",
            )
        )

    completed_at = datetime.now(timezone.utc)
    events.append(
        SimulationEvent(
            timestamp=completed_at,
            event_type="simulation_completed",
            scenario_id="simulated_privilege_escalation",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Privilege escalation simulation finished. Outcome: {simulated_escalation_outcome}",
            details={
                "precondition_satisfied": precondition_satisfied,
                "simulated_escalation_outcome": simulated_escalation_outcome,
                "actual_privilege_change": False,
                "risk_score": risk_score,
            },
            event_metadata={"outcome": simulated_escalation_outcome, "risk_score": risk_score},
        )
    )

    return SimulationResult(
        scenario="simulated_privilege_escalation",
        technique="T1068 - Exploitation for Privilege Escalation (Synthetic Simulation)",
        asset_id=str(asset.id),
        sandbox_id=str(asset.sandbox_id),
        status="completed",
        risk_score=risk_score,
        events=events,
        findings=findings,
        started_at=started_at,
        completed_at=completed_at,
        simulation_only=True,
    )


# ---------------------------------------------------------------------
# 6. Scenario C: Simulated Lateral Movement (New)
# ---------------------------------------------------------------------
async def handle_simulated_lateral_movement(
    asset: SyntheticAsset,
    parameters: Optional[dict[str, Any]] = None,
    session: Optional[AsyncSession] = None,
    **kwargs: Any,
) -> SimulationResult:
    """Simulates lateral movement between related synthetic assets within the same sandbox.

    Validates explicit synthetic relationships stored in asset registry.
    Rejects missing, unrelated, archived, or cross-sandbox destination assets.
    Never establishes actual network connections or contacts destination IPs.
    """
    started_at = datetime.now(timezone.utc)
    events: list[SimulationEvent] = []
    findings: list[SimulationFinding] = []

    params = parameters or {}
    dest_asset_id_raw = params.get("destination_asset_id")

    events.append(
        SimulationEvent(
            timestamp=started_at,
            event_type="simulation_started",
            scenario_id="simulated_lateral_movement",
            source_asset_id=str(asset.id),
            destination_asset_id=str(dest_asset_id_raw) if dest_asset_id_raw else None,
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Initiated synthetic lateral movement simulation from asset '{asset.name}'",
            details={
                "source_asset_id": str(asset.id),
                "destination_asset_id": str(dest_asset_id_raw) if dest_asset_id_raw else None,
            },
            event_metadata={"source_asset_id": str(asset.id), "destination_asset_id": str(dest_asset_id_raw)},
        )
    )

    # 1. Validate destination parameter
    if not dest_asset_id_raw:
        simulated_outcome = "missing_destination_asset_parameter"
        risk_score = 1.0

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_movement_blocked",
                scenario_id="simulated_lateral_movement",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="warning",
                message="Lateral movement simulation rejected: missing required 'destination_asset_id' parameter",
                details={"reason": "missing_destination_asset_parameter"},
                event_metadata={"outcome": simulated_outcome},
            )
        )
        findings.append(
            SimulationFinding(
                title="Synthetic Lateral Movement Precondition Missing",
                description="Simulation requires an explicit destination_asset_id parameter to evaluate lateral movement relationships.",
                severity="low",
                technique="T1021 - Remote Services (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={"simulated_outcome": simulated_outcome, "actual_network_movement": False},
                remediation_recommendation="Specify a valid synthetic destination asset ID.",
            )
        )
        return SimulationResult(
            scenario="simulated_lateral_movement",
            technique="T1021 - Remote Services (Synthetic Simulation)",
            asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            status="completed",
            risk_score=risk_score,
            events=events,
            findings=findings,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            simulation_only=True,
        )

    try:
        dest_uuid = uuid.UUID(str(dest_asset_id_raw))
    except (ValueError, TypeError):
        simulated_outcome = "invalid_destination_asset_id"
        risk_score = 1.0

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_movement_blocked",
                scenario_id="simulated_lateral_movement",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="warning",
                message=f"Lateral movement simulation rejected: invalid UUID format for destination '{dest_asset_id_raw}'",
                details={"reason": "invalid_destination_asset_id"},
                event_metadata={"outcome": simulated_outcome},
            )
        )
        findings.append(
            SimulationFinding(
                title="Invalid Destination Asset Identifier",
                description="The destination_asset_id parameter is not a valid UUID format.",
                severity="low",
                technique="T1021 - Remote Services (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={"simulated_outcome": simulated_outcome, "actual_network_movement": False},
                remediation_recommendation="Ensure destination_asset_id conforms to UUID standard.",
            )
        )
        return SimulationResult(
            scenario="simulated_lateral_movement",
            technique="T1021 - Remote Services (Synthetic Simulation)",
            asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            status="completed",
            risk_score=risk_score,
            events=events,
            findings=findings,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            simulation_only=True,
        )

    # 2. Lookup destination asset if session provided
    dest_asset: Optional[SyntheticAsset] = None
    if session is not None:
        dest_asset = await get_asset_by_id(session, dest_uuid)

    if dest_asset is None:
        simulated_outcome = "destination_asset_not_found"
        risk_score = 1.0

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_movement_blocked",
                scenario_id="simulated_lateral_movement",
                source_asset_id=str(asset.id),
                destination_asset_id=str(dest_uuid),
                sandbox_id=str(asset.sandbox_id),
                severity="warning",
                message=f"Lateral movement destination asset '{dest_uuid}' does not exist in registry",
                details={"reason": "destination_asset_not_found"},
                event_metadata={"outcome": simulated_outcome},
            )
        )
        findings.append(
            SimulationFinding(
                title="Synthetic Destination Asset Not Found",
                description="The specified destination asset does not exist in the active synthetic registry.",
                severity="low",
                technique="T1021 - Remote Services (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={"simulated_outcome": simulated_outcome, "actual_network_movement": False},
                remediation_recommendation="Register destination asset prior to lateral path evaluation.",
            )
        )
        return SimulationResult(
            scenario="simulated_lateral_movement",
            technique="T1021 - Remote Services (Synthetic Simulation)",
            asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            status="completed",
            risk_score=risk_score,
            events=events,
            findings=findings,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            simulation_only=True,
        )

    # 3. Verify same sandbox boundary (cross-sandbox destination rejection)
    if dest_asset.sandbox_id != asset.sandbox_id:
        simulated_outcome = "cross_sandbox_destination_rejected"
        risk_score = 2.0

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_movement_blocked",
                scenario_id="simulated_lateral_movement",
                source_asset_id=str(asset.id),
                destination_asset_id=str(dest_asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="high",
                message="Cross-sandbox lateral movement strictly rejected: assets belong to different sandboxes",
                details={
                    "source_sandbox_id": str(asset.sandbox_id),
                    "destination_sandbox_id": str(dest_asset.sandbox_id),
                    "reason": "cross_sandbox_boundary_violation",
                },
                event_metadata={"outcome": simulated_outcome, "reason": "cross_sandbox_boundary_violation"},
            )
        )
        findings.append(
            SimulationFinding(
                title="Cross-Sandbox Lateral Movement Boundary Enforced",
                description="Synthetic lateral movement is strictly confined to assets within the same sandbox environment.",
                severity="medium",
                technique="T1021 - Remote Services (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "simulated_outcome": simulated_outcome,
                    "source_sandbox_id": str(asset.sandbox_id),
                    "dest_sandbox_id": str(dest_asset.sandbox_id),
                    "actual_network_movement": False,
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_lateral_movement",
                    evidence_type="sandbox_isolation_boundary",
                    synthetic_asset_references=[str(asset.id), str(dest_asset.id)],
                    finding_description="Cross-sandbox access rejected by isolation boundary",
                    severity="medium",
                    confidence="high",
                    supporting_synthetic_metadata={"cross_sandbox": True},
                ),
                remediation_recommendation="Ensure lateral movement paths are evaluated strictly within an isolated sandbox.",
            )
        )
        return SimulationResult(
            scenario="simulated_lateral_movement",
            technique="T1021 - Remote Services (Synthetic Simulation)",
            asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            status="completed",
            risk_score=risk_score,
            events=events,
            findings=findings,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            simulation_only=True,
        )

    # 4. Verify destination status is not archived
    if dest_asset.status == "archived":
        simulated_outcome = "archived_destination_rejected"
        risk_score = 1.0

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_movement_blocked",
                scenario_id="simulated_lateral_movement",
                source_asset_id=str(asset.id),
                destination_asset_id=str(dest_asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="warning",
                message=f"Destination asset '{dest_asset.name}' is archived. Cannot move to archived asset.",
                details={"reason": "archived_destination_rejected"},
                event_metadata={"outcome": simulated_outcome},
            )
        )
        findings.append(
            SimulationFinding(
                title="Archived Destination Asset Rejected",
                description="Cannot evaluate lateral movement to an archived asset.",
                severity="low",
                technique="T1021 - Remote Services (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={"simulated_outcome": simulated_outcome, "actual_network_movement": False},
                remediation_recommendation="Restore asset or select active target.",
            )
        )
        return SimulationResult(
            scenario="simulated_lateral_movement",
            technique="T1021 - Remote Services (Synthetic Simulation)",
            asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            status="completed",
            risk_score=risk_score,
            events=events,
            findings=findings,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            simulation_only=True,
        )

    # 5. Validate explicit synthetic relationship in connected_asset_ids
    connected_ids = [str(cid).strip().lower() for cid in (asset.connected_asset_ids or [])]
    is_related = str(dest_asset.id).lower() in connected_ids

    events.append(
        SimulationEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="relationship_validation_simulated",
            scenario_id="simulated_lateral_movement",
            source_asset_id=str(asset.id),
            destination_asset_id=str(dest_asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Evaluated synthetic relationship between '{asset.name}' and '{dest_asset.name}'",
            details={
                "source_asset_id": str(asset.id),
                "destination_asset_id": str(dest_asset.id),
                "relationship_found": is_related,
                "connected_asset_ids": connected_ids,
            },
            event_metadata={"relationship_found": is_related},
        )
    )

    if is_related:
        precondition_satisfied = True
        simulated_outcome = "success"
        risk_score = 7.5

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_lateral_transition",
                scenario_id="simulated_lateral_movement",
                source_asset_id=str(asset.id),
                destination_asset_id=str(dest_asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="high",
                message=f"Simulated lateral movement path validated: '{asset.name}' -> '{dest_asset.name}'",
                details={
                    "source_asset_id": str(asset.id),
                    "destination_asset_id": str(dest_asset.id),
                    "relationship_type": "connected_asset",
                    "actual_network_movement": False,
                },
                event_metadata={"source": str(asset.id), "destination": str(dest_asset.id), "actual_network_movement": False},
            )
        )

        findings.append(
            SimulationFinding(
                title="Synthetic Lateral Movement Path Validated",
                description=f"Explicit synthetic relationship confirmed between '{asset.name}' and '{dest_asset.name}' inside sandbox.",
                severity="high",
                technique="T1021 - Remote Services (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "source_asset_id": str(asset.id),
                    "destination_asset_id": str(dest_asset.id),
                    "precondition_satisfied": True,
                    "simulated_outcome": "success",
                    "actual_network_movement": False,
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_lateral_movement",
                    evidence_type="connected_asset_relationship",
                    synthetic_asset_references=[str(asset.id), str(dest_asset.id)],
                    finding_description="Explicit relationship registered in connected_asset_ids",
                    severity="high",
                    confidence="high",
                    supporting_synthetic_metadata={"connected_ids": connected_ids},
                ),
                remediation_recommendation="Implement zero-trust microsegmentation and restrict peer-to-peer synthetic routes.",
            )
        )
    else:
        precondition_satisfied = False
        simulated_outcome = "unrelated_target_rejected"
        risk_score = 2.0

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_movement_blocked",
                scenario_id="simulated_lateral_movement",
                source_asset_id=str(asset.id),
                destination_asset_id=str(dest_asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="info",
                message="Lateral movement path rejected: destination asset is not in source connected_asset_ids",
                details={
                    "source_asset_id": str(asset.id),
                    "destination_asset_id": str(dest_asset.id),
                    "precondition_satisfied": False,
                    "actual_network_movement": False,
                },
                event_metadata={"outcome": "rejected", "actual_network_movement": False},
            )
        )

        findings.append(
            SimulationFinding(
                title="Synthetic Segmentation Enforced - Unrelated Target Rejected",
                description=f"Destination asset '{dest_asset.name}' is not registered as a connected peer of '{asset.name}'.",
                severity="low",
                technique="T1021 - Remote Services (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "source_asset_id": str(asset.id),
                    "destination_asset_id": str(dest_asset.id),
                    "precondition_satisfied": False,
                    "simulated_outcome": "unrelated_target_rejected",
                    "actual_network_movement": False,
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_lateral_movement",
                    evidence_type="segmentation_enforced",
                    synthetic_asset_references=[str(asset.id), str(dest_asset.id)],
                    finding_description="No explicit relationship declared between assets",
                    severity="low",
                    confidence="high",
                    supporting_synthetic_metadata={"connected_ids": connected_ids},
                ),
                remediation_recommendation="Maintain current asset network isolation policy.",
            )
        )

    completed_at = datetime.now(timezone.utc)
    events.append(
        SimulationEvent(
            timestamp=completed_at,
            event_type="simulation_completed",
            scenario_id="simulated_lateral_movement",
            source_asset_id=str(asset.id),
            destination_asset_id=str(dest_asset.id) if dest_asset else None,
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Lateral movement simulation completed. Outcome: {simulated_outcome}",
            details={
                "precondition_satisfied": precondition_satisfied,
                "simulated_movement_outcome": simulated_outcome,
                "actual_network_movement": False,
                "risk_score": risk_score,
            },
            event_metadata={"outcome": simulated_outcome, "risk_score": risk_score},
        )
    )

    return SimulationResult(
        scenario="simulated_lateral_movement",
        technique="T1021 - Remote Services (Synthetic Simulation)",
        asset_id=str(asset.id),
        sandbox_id=str(asset.sandbox_id),
        status="completed",
        risk_score=risk_score,
        events=events,
        findings=findings,
        started_at=started_at,
        completed_at=completed_at,
        simulation_only=True,
    )


# ---------------------------------------------------------------------
# 7. Scenario D: Simulated Persistence (New)
# ---------------------------------------------------------------------
async def handle_simulated_persistence(
    asset: SyntheticAsset,
    parameters: Optional[dict[str, Any]] = None,
    **kwargs: Any,
) -> SimulationResult:
    """Generates fictional persistence indicators based on synthetic asset configuration.

    Never creates actual scheduled tasks, services, cron entries, or background processes.
    """
    started_at = datetime.now(timezone.utc)
    events: list[SimulationEvent] = []
    findings: list[SimulationFinding] = []

    events.append(
        SimulationEvent(
            timestamp=started_at,
            event_type="simulation_started",
            scenario_id="simulated_persistence",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Evaluating synthetic persistence indicators on asset '{asset.name}'",
            details={"asset_id": str(asset.id), "asset_type": asset.asset_type},
            event_metadata={"scenario": "simulated_persistence"},
        )
    )

    config = asset.configuration or {}
    vulns = asset.simulated_vulnerabilities or []

    # Check synthetic persistence indicators
    tasks = config.get("scheduled_tasks") or config.get("cron_jobs") or []
    startup_services = config.get("startup_services") or config.get("persistence_indicators") or []
    has_unauthorized_persistence = (
        config.get("unauthorized_persistence") is True
        or config.get("mock_backdoor_service") is True
    )
    has_persist_vuln = any(
        "persistence" in str(v.get("category", "")).lower()
        or "backdoor" in str(v.get("title", "")).lower()
        or "cron" in str(v.get("title", "")).lower()
        for v in vulns
        if isinstance(v, dict)
    )

    precondition_satisfied = bool(tasks or startup_services or has_unauthorized_persistence or has_persist_vuln)

    events.append(
        SimulationEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="persistence_scan_simulated",
            scenario_id="simulated_persistence",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="warning" if precondition_satisfied else "info",
            message="Scanned synthetic startup entries and task schedules for mock persistence anomalies",
            details={
                "scheduled_tasks_count": len(tasks),
                "startup_services_count": len(startup_services),
                "has_unauthorized_persistence": has_unauthorized_persistence,
                "actual_persistence_established": False,
            },
            event_metadata={"precondition_satisfied": precondition_satisfied, "actual_persistence_established": False},
        )
    )

    if precondition_satisfied:
        simulated_persistence_outcome = "indicator_identified"
        risk_score = 7.5

        indicator_sample = tasks[0] if tasks else (startup_services[0] if startup_services else "mock_recurring_daemon")

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_persistence_indicator_flagged",
                scenario_id="simulated_persistence",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="high",
                message=f"Simulated persistence anomaly flagged: '{indicator_sample}' (descriptive metadata)",
                details={
                    "indicator": indicator_sample,
                    "simulated_mechanism": "scheduled_task_or_service",
                    "actual_persistence_established": False,
                },
                event_metadata={"indicator": indicator_sample, "actual_persistence_established": False},
            )
        )

        findings.append(
            SimulationFinding(
                title="Synthetic Persistence Mechanism Identified",
                description="Synthetic asset configuration exhibits suspicious scheduled tasks or recurring startup services.",
                severity="high",
                technique="T1053 - Scheduled Task/Job (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "precondition_satisfied": True,
                    "simulated_persistence_outcome": "indicator_identified",
                    "actual_persistence_established": False,
                    "tasks": tasks,
                    "services": startup_services,
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_persistence",
                    evidence_type="synthetic_persistence_indicator",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description="Suspicious synthetic task or service registration identified in metadata",
                    severity="high",
                    confidence="high",
                    supporting_synthetic_metadata={"indicator": indicator_sample},
                ),
                remediation_recommendation="Audit recurring scheduled tasks, lock down startup directories, and enforce service integrity monitoring.",
            )
        )
    else:
        simulated_persistence_outcome = "no_persistence_indicators_found"
        risk_score = 1.5

        findings.append(
            SimulationFinding(
                title="No Synthetic Persistence Indicators Identified",
                description="Synthetic asset configuration shows normal scheduled tasks and startup profiles.",
                severity="low",
                technique="T1053 - Scheduled Task/Job (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "precondition_satisfied": False,
                    "simulated_persistence_outcome": "no_persistence_indicators_found",
                    "actual_persistence_established": False,
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_persistence",
                    evidence_type="clean_persistence_profile",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description="Clean startup profile without unauthorized scheduled tasks",
                    severity="low",
                    confidence="high",
                    supporting_synthetic_metadata={"precondition_satisfied": False},
                ),
                remediation_recommendation="Maintain periodic scheduled-task auditing.",
            )
        )

    completed_at = datetime.now(timezone.utc)
    events.append(
        SimulationEvent(
            timestamp=completed_at,
            event_type="simulation_completed",
            scenario_id="simulated_persistence",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Persistence simulation completed with outcome: {simulated_persistence_outcome}",
            details={
                "precondition_satisfied": precondition_satisfied,
                "simulated_persistence_outcome": simulated_persistence_outcome,
                "actual_persistence_established": False,
                "risk_score": risk_score,
            },
            event_metadata={"outcome": simulated_persistence_outcome, "risk_score": risk_score},
        )
    )

    return SimulationResult(
        scenario="simulated_persistence",
        technique="T1053 - Scheduled Task/Job (Synthetic Simulation)",
        asset_id=str(asset.id),
        sandbox_id=str(asset.sandbox_id),
        status="completed",
        risk_score=risk_score,
        events=events,
        findings=findings,
        started_at=started_at,
        completed_at=completed_at,
        simulation_only=True,
    )


# ---------------------------------------------------------------------
# 8. Scenario E: Simulated Data Exfiltration (New)
# ---------------------------------------------------------------------
async def handle_simulated_data_exfiltration(
    asset: SyntheticAsset,
    parameters: Optional[dict[str, Any]] = None,
    **kwargs: Any,
) -> SimulationResult:
    """Simulates suspicious access and movement of fictional sensitive data.

    Never accesses production data, transfers real bytes, or issues outbound network connections.
    """
    started_at = datetime.now(timezone.utc)
    events: list[SimulationEvent] = []
    findings: list[SimulationFinding] = []

    params = parameters or {}
    records_requested = int(params.get("simulated_records_requested", 5000))
    target_dataset = str(params.get("target_dataset", "fictional_customer_pii"))

    events.append(
        SimulationEvent(
            timestamp=started_at,
            event_type="simulation_started",
            scenario_id="simulated_data_exfiltration",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Initiated synthetic data exfiltration simulation against dataset '{target_dataset}' on '{asset.name}'",
            details={
                "target_dataset": target_dataset,
                "records_requested": records_requested,
                "actual_data_transferred": False,
            },
            event_metadata={"target_dataset": target_dataset, "records": records_requested},
        )
    )

    config = asset.configuration or {}

    # Check synthetic sensitive data classifications & policies
    classification = str(config.get("data_classification", "internal")).lower()
    has_sensitive_classification = (
        classification in ["confidential", "restricted", "pii", "pci", "hipaa", "secret"]
        or config.get("has_sensitive_data") is True
    )
    mock_datasets = config.get("mock_datasets") or []
    allows_bulk_export = (
        config.get("data_access_policy") == "unrestricted"
        or config.get("allow_bulk_export") is True
    )

    precondition_satisfied = bool(has_sensitive_classification or mock_datasets or allows_bulk_export)

    events.append(
        SimulationEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="simulated_data_access_query",
            scenario_id="simulated_data_exfiltration",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="warning" if precondition_satisfied else "info",
            message=f"Queried synthetic data repository for dataset '{target_dataset}' ({records_requested} records)",
            details={
                "target_dataset": target_dataset,
                "records_requested": records_requested,
                "data_classification": classification,
                "allows_bulk_export": allows_bulk_export,
                "actual_bytes_read": 0,
            },
            event_metadata={"dataset": target_dataset, "classification": classification},
        )
    )

    if precondition_satisfied:
        simulated_exfil_outcome = "simulated_data_staged_and_transferred"
        simulated_mb = round(records_requested * 0.0025, 2)
        simulated_volume_str = f"{simulated_mb} MB (simulated metric, no real bytes)"
        risk_score = 9.0

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_exfiltration_stream",
                scenario_id="simulated_data_exfiltration",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="critical",
                message=f"Simulated exfiltration stream generated for {records_requested} synthetic records ({simulated_volume_str})",
                details={
                    "dataset": target_dataset,
                    "simulated_record_count": records_requested,
                    "simulated_transfer_volume": simulated_volume_str,
                    "simulated_destination": "RFC 5737 198.51.100.99 (fictional destination)",
                    "actual_data_transferred": False,
                    "actual_bytes_transferred": 0,
                },
                event_metadata={
                    "simulated_records": records_requested,
                    "simulated_volume": simulated_volume_str,
                    "actual_data_transferred": False,
                },
            )
        )

        findings.append(
            SimulationFinding(
                title="Synthetic Data Staging and Exfiltration Detected",
                description=f"Synthetic sensitive dataset '{target_dataset}' (classification: {classification.upper()}) was staged for simulated transfer ({records_requested} records).",
                severity="critical",
                technique="T1048 - Exfiltration Over Alternative Protocol (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "target_dataset": target_dataset,
                    "data_classification": classification,
                    "simulated_record_count": records_requested,
                    "simulated_transfer_volume": simulated_volume_str,
                    "precondition_satisfied": True,
                    "simulated_exfiltration_outcome": simulated_exfil_outcome,
                    "actual_data_transferred": False,
                    "actual_bytes_transferred": 0,
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_data_exfiltration",
                    evidence_type="synthetic_data_movement",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description=f"Synthetic bulk access to {classification.upper()} dataset: {records_requested} simulated records",
                    severity="critical",
                    confidence="high",
                    supporting_synthetic_metadata={
                        "dataset": target_dataset,
                        "classification": classification,
                        "simulated_records": records_requested,
                        "simulated_volume": simulated_volume_str,
                    },
                ),
                remediation_recommendation="Implement automated egress filtering, enforce DLP policies, and restrict bulk dataset queries.",
            )
        )
    else:
        simulated_exfil_outcome = "data_access_blocked_or_non_sensitive"
        risk_score = 2.0

        events.append(
            SimulationEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="simulated_exfiltration_blocked",
                scenario_id="simulated_data_exfiltration",
                source_asset_id=str(asset.id),
                sandbox_id=str(asset.sandbox_id),
                severity="info",
                message="Data exfiltration blocked: no synthetic sensitive data classification or unrestricted export policy",
                details={
                    "data_classification": classification,
                    "actual_data_transferred": False,
                    "actual_bytes_transferred": 0,
                },
                event_metadata={"outcome": "blocked", "actual_data_transferred": False},
            )
        )

        findings.append(
            SimulationFinding(
                title="Synthetic Data Protection Enforced - Access Denied",
                description="Synthetic asset configuration enforces strict data access controls or contains non-sensitive data.",
                severity="low",
                technique="T1048 - Exfiltration Over Alternative Protocol (Synthetic Simulation)",
                asset_id=str(asset.id),
                details={
                    "precondition_satisfied": False,
                    "simulated_exfiltration_outcome": simulated_exfil_outcome,
                    "actual_data_transferred": False,
                    "actual_bytes_transferred": 0,
                },
                evidence=SimulationEvidence(
                    scenario_id="simulated_data_exfiltration",
                    evidence_type="data_access_restricted",
                    synthetic_asset_references=[str(asset.id)],
                    finding_description="Data protection policies prevented unauthorized simulated bulk extraction",
                    severity="low",
                    confidence="high",
                    supporting_synthetic_metadata={"data_classification": classification},
                ),
                remediation_recommendation="Maintain continuous DLP monitoring.",
            )
        )

    completed_at = datetime.now(timezone.utc)
    events.append(
        SimulationEvent(
            timestamp=completed_at,
            event_type="simulation_completed",
            scenario_id="simulated_data_exfiltration",
            source_asset_id=str(asset.id),
            sandbox_id=str(asset.sandbox_id),
            severity="info",
            message=f"Data exfiltration simulation complete. Outcome: {simulated_exfil_outcome}",
            details={
                "precondition_satisfied": precondition_satisfied,
                "simulated_exfiltration_outcome": simulated_exfil_outcome,
                "actual_data_transferred": False,
                "actual_bytes_transferred": 0,
                "risk_score": risk_score,
            },
            event_metadata={"outcome": simulated_exfil_outcome, "risk_score": risk_score},
        )
    )

    return SimulationResult(
        scenario="simulated_data_exfiltration",
        technique="T1048 - Exfiltration Over Alternative Protocol (Synthetic Simulation)",
        asset_id=str(asset.id),
        sandbox_id=str(asset.sandbox_id),
        status="completed",
        risk_score=risk_score,
        events=events,
        findings=findings,
        started_at=started_at,
        completed_at=completed_at,
        simulation_only=True,
    )


# =====================================================================
# Scenario Registry Definition
# =====================================================================

class ScenarioRegistry:
    """Central registry maintaining all supported Red Team attack simulation scenarios."""

    def __init__(self) -> None:
        self._scenarios: dict[str, ScenarioDefinition] = {}

    def register(self, definition: ScenarioDefinition) -> None:
        """Registers a scenario definition."""
        self._scenarios[definition.scenario_id] = definition

    def get(self, scenario_id: str) -> ScenarioDefinition:
        """Retrieves a scenario definition by identifier. Raises RedTeamScenarioNotFoundError if not found."""
        if scenario_id not in self._scenarios:
            raise RedTeamScenarioNotFoundError(
                f"Scenario '{scenario_id}' is not recognized. "
                f"Valid scenarios are: {list(self._scenarios.keys())}"
            )
        return self._scenarios[scenario_id]

    def list_all(self) -> list[ScenarioDefinition]:
        """Lists all registered scenario definitions."""
        return list(self._scenarios.values())

    def validate_asset_compatibility(self, scenario_id: str, asset_type: str) -> None:
        """Validates that the scenario is compatible with the target asset type."""
        scenario = self.get(scenario_id)
        if asset_type not in scenario.applicable_asset_types:
            raise ScenarioAssetIncompatibleError(
                f"Scenario '{scenario_id}' is not applicable to asset type '{asset_type}'. "
                f"Applicable types are: {scenario.applicable_asset_types}"
            )


# Initialize global registry instance with all 8 scenarios
registry = ScenarioRegistry()

# 1. Simulated Service Discovery
registry.register(
    ScenarioDefinition(
        scenario_id="simulated_service_discovery",
        name="Simulated Service Discovery",
        description="Generates synthetic service enumeration events and discovers simulated open network ports on synthetic targets from asset metadata. Corresponds conceptually to MITRE ATT&CK T1046 (Network Service Discovery) without performing real network probing or socket operations.",
        technique="T1046 - Network Service Discovery (Synthetic Simulation)",
        technique_id="T1046",
        applicable_asset_types=["server", "web_application", "api", "network_device"],
        handler=handle_simulated_service_discovery,
        parameters={},
        category="discovery",
        mapping_type="technique_emulation",
        is_synthetic=True,
        risk_classification="low",
    )
)

# 2. Simulated Weak Configuration Assessment
registry.register(
    ScenarioDefinition(
        scenario_id="simulated_weak_configuration_assessment",
        name="Simulated Weak Configuration Assessment",
        description="Performs deterministic evaluation of synthetic asset configurations and simulated vulnerabilities for security misconfigurations (such as debug mode, deprecated TLS, or insecure defaults). Note: MITRE ATT&CK Enterprise does not define a standalone technique for passive configuration assessment; this scenario represents a conceptual security posture assessment rather than adversary technique emulation.",
        technique="Synthetic Configuration Audit (Conceptual)",
        technique_id="N/A (Conceptual Assessment)",
        applicable_asset_types=["server", "database", "web_application", "api", "network_device"],
        handler=handle_simulated_weak_configuration_assessment,
        parameters={},
        category="configuration",
        mapping_type="conceptual_scenario",
        is_synthetic=True,
        risk_classification="medium",
    )
)

# 3. Simulated Authentication Anomaly
registry.register(
    ScenarioDefinition(
        scenario_id="simulated_authentication_anomaly",
        name="Simulated Authentication Anomaly",
        description="Simulates synthetic high-frequency authentication attempts and anomaly patterns against synthetic targets without initiating actual network traffic. Corresponds conceptually to MITRE ATT&CK T1110 (Brute Force).",
        technique="T1110 - Brute Force (Synthetic Simulation)",
        technique_id="T1110",
        applicable_asset_types=["server", "database", "web_application", "api"],
        handler=handle_simulated_authentication_anomaly,
        parameters={
            "attempt_count": "int (default: 50)",
            "simulated_source_ip": "str (default: 198.51.100.42)",
            "target_username": "str (default: admin)",
        },
        category="credential_access",
        mapping_type="technique_emulation",
        is_synthetic=True,
        risk_classification="high",
    )
)

# 4. Scenario A: Simulated Initial Access
registry.register(
    ScenarioDefinition(
        scenario_id="simulated_initial_access",
        name="Simulated Initial Access",
        description="Simulates fictional initial access events against synthetic entry points based on exposed services, weak API configs, or simulated vulnerabilities. Corresponds conceptually to MITRE ATT&CK T1190 (Exploit Public-Facing Application) without establishing real sessions or external traffic.",
        technique="T1190 - Exploit Public-Facing Application (Synthetic Simulation)",
        technique_id="T1190",
        applicable_asset_types=["web_application", "api", "server"],
        handler=handle_simulated_initial_access,
        parameters={"vector": "str (default: public_facing_exploit)"},
        category="initial_access",
        mapping_type="technique_emulation",
        is_synthetic=True,
        risk_classification="high",
    )
)

# 5. Scenario B: Simulated Privilege Escalation
registry.register(
    ScenarioDefinition(
        scenario_id="simulated_privilege_escalation",
        name="Simulated Privilege Escalation",
        description="Evaluates fictional excessive permissions and privilege boundary weaknesses in synthetic asset configurations. Corresponds conceptually to MITRE ATT&CK T1068 (Exploitation for Privilege Escalation) without granting actual OS or database permissions.",
        technique="T1068 - Exploitation for Privilege Escalation (Synthetic Simulation)",
        technique_id="T1068",
        applicable_asset_types=["server", "database", "api"],
        handler=handle_simulated_privilege_escalation,
        parameters={
            "source_privilege": "str (default: standard_user)",
            "target_privilege": "str (default: root)",
        },
        category="privilege_escalation",
        mapping_type="technique_emulation",
        is_synthetic=True,
        risk_classification="high",
    )
)

# 6. Scenario C: Simulated Lateral Movement
registry.register(
    ScenarioDefinition(
        scenario_id="simulated_lateral_movement",
        name="Simulated Lateral Movement",
        description="Simulates lateral movement between related synthetic assets within the same sandbox environment based on explicit connected_asset_ids relationships. Corresponds conceptually to MITRE ATT&CK T1021 (Remote Services) without opening network sockets or contacting destination IPs.",
        technique="T1021 - Remote Services (Synthetic Simulation)",
        technique_id="T1021",
        applicable_asset_types=["server", "database", "web_application", "api", "network_device"],
        handler=handle_simulated_lateral_movement,
        parameters={"destination_asset_id": "uuid.UUID (required)"},
        category="lateral_movement",
        mapping_type="technique_emulation",
        is_synthetic=True,
        risk_classification="high",
    )
)

# 7. Scenario D: Simulated Persistence
registry.register(
    ScenarioDefinition(
        scenario_id="simulated_persistence",
        name="Simulated Persistence",
        description="Generates fictional persistence indicators based on synthetic task or startup configurations. Corresponds conceptually to MITRE ATT&CK T1053 (Scheduled Task/Job) without creating real scheduled tasks, services, or OS processes.",
        technique="T1053 - Scheduled Task/Job (Synthetic Simulation)",
        technique_id="T1053",
        applicable_asset_types=["server", "web_application", "api"],
        handler=handle_simulated_persistence,
        parameters={},
        category="persistence",
        mapping_type="technique_emulation",
        is_synthetic=True,
        risk_classification="medium",
    )
)

# 8. Scenario E: Simulated Data Exfiltration
registry.register(
    ScenarioDefinition(
        scenario_id="simulated_data_exfiltration",
        name="Simulated Data Exfiltration",
        description="Simulates suspicious access and movement of fictional sensitive datasets. Corresponds conceptually to MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol) without accessing production records or transferring real bytes.",
        technique="T1048 - Exfiltration Over Alternative Protocol (Synthetic Simulation)",
        technique_id="T1048",
        applicable_asset_types=["database", "server", "api"],
        handler=handle_simulated_data_exfiltration,
        parameters={
            "simulated_records_requested": "int (default: 5000)",
            "target_dataset": "str (default: fictional_customer_pii)",
        },
        category="exfiltration",
        mapping_type="technique_emulation",
        is_synthetic=True,
        risk_classification="critical",
    )
)
