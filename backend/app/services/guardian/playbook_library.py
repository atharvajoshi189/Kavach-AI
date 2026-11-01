"""Deterministic Playbook Catalog and Library for Blue Guardian Remediation.

Provides structured, evidence-backed defensive playbooks across 8 threat classes:
- Credential Access
- Initial Access
- Privilege Escalation
- Lateral Movement
- Persistence
- Exfiltration
- Reconnaissance
- Weak Configuration
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.agents.blue_guardian.schemas import (
    PlaybookResponse,
    RecommendationPriority,
    RecommendationType,
)


@dataclass(frozen=True)
class PlaybookActionTemplate:
    """Action step blueprint within a defensive playbook."""
    action_code: str
    title: str
    description: str
    action_type: str
    sequence_order: int
    depends_on: List[str]
    expected_outcome: str
    verification_criteria: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_code": self.action_code,
            "title": self.title,
            "description": self.description,
            "action_type": self.action_type,
            "sequence_order": self.sequence_order,
            "depends_on": list(self.depends_on),
            "expected_outcome": self.expected_outcome,
            "verification_criteria": list(self.verification_criteria),
        }


@dataclass(frozen=True)
class Playbook:
    """Defensive mitigation playbook blueprint."""
    playbook_id: str
    playbook_version: str
    title: str
    description: str
    category: str
    recommendation_type: RecommendationType
    target_threat_classes: List[str]
    mitre_techniques: List[str]
    default_priority: RecommendationPriority
    complexity: str  # low, medium, high
    rationale: str
    expected_outcome: str
    verification_criteria: List[str]
    action_templates: List[PlaybookActionTemplate]

    def to_response(self) -> PlaybookResponse:
        return PlaybookResponse(
            playbook_id=self.playbook_id,
            playbook_version=self.playbook_version,
            title=self.title,
            description=self.description,
            category=self.category,
            recommendation_type=self.recommendation_type,
            target_threat_classes=list(self.target_threat_classes),
            mitre_techniques=list(self.mitre_techniques),
            default_priority=self.default_priority,
            complexity=self.complexity,
            rationale=self.rationale,
            expected_outcome=self.expected_outcome,
            verification_criteria=list(self.verification_criteria),
            action_templates=[a.to_dict() for a in self.action_templates],
        )


INITIAL_PLAYBOOKS: List[Playbook] = [
    # 1. Credential Access
    Playbook(
        playbook_id="BGD-PB-001",
        playbook_version="1.0.0",
        title="Compromised Credential Rotation & Session Revocation",
        description="Invalidates exposed credentials, revokes active identity sessions, and forces MFA re-enrollment.",
        category="Credential Access",
        recommendation_type=RecommendationType.CORRECTIVE,
        target_threat_classes=["Credential Access", "credential_theft", "credential_access"],
        mitre_techniques=["T1003", "T1552"],
        default_priority=RecommendationPriority.P0,
        complexity="medium",
        rationale="Extracted or dumped credentials permit immediate unauthorized access across synthetic asset boundaries without triggering initial authentication guards.",
        expected_outcome="All identified compromised credentials rotated, active sessions terminated, and privileged access tokens re-issued with restricted scopes.",
        verification_criteria=[
            "Verify zero active sessions for compromised accounts in identity provider",
            "Confirm password hash update in directory service",
            "Audit authentication logs for failed attempts using stale credentials",
        ],
        action_templates=[
            PlaybookActionTemplate(
                action_code="ACT-PB-001-01",
                title="Revoke Active Identity Sessions & OAuth Tokens",
                description="Terminate all active SSO and OAuth sessions for affected identities across synthetic nodes.",
                action_type="session_revocation",
                sequence_order=1,
                depends_on=[],
                expected_outcome="All existing bearer tokens invalidated immediately.",
                verification_criteria=["Session store returns 401 for previous token signatures"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-001-02",
                title="Force Credential Reset & Enforce MFA",
                description="Trigger mandatory credential reset and verify multi-factor authentication enrollment on affected accounts.",
                action_type="credential_reset",
                sequence_order=2,
                depends_on=["ACT-PB-001-01"],
                expected_outcome="Account password changed and MFA token challenged on subsequent sign-on.",
                verification_criteria=["Password last_modified timestamp updated to current time"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-001-03",
                title="Invalidate & Rotate Service API Keys and Vault Secrets",
                description="Rotate machine-to-machine secrets and API tokens discovered in memory or process dumps.",
                action_type="secret_rotation",
                sequence_order=3,
                depends_on=["ACT-PB-001-02"],
                expected_outcome="Stale API keys rejected by all internal microservices.",
                verification_criteria=["Key management vault marks previous secret versions destroyed"],
            ),
        ],
    ),
    # 2. Initial Access
    Playbook(
        playbook_id="BGD-PB-002",
        playbook_version="1.0.0",
        title="Perimeter Ingress Filtering & Brute-Force Rate Limiting",
        description="Applies perimeter firewall blocks against aggressive external ingress sources and tightens login throttling.",
        category="Initial Access",
        recommendation_type=RecommendationType.PREVENTIVE,
        target_threat_classes=["Initial Access", "brute_force", "ingress_anomaly"],
        mitre_techniques=["T1110", "T1190", "T1566"],
        default_priority=RecommendationPriority.P1,
        complexity="medium",
        rationale="Unmitigated external ingress endpoints and repeated authentication attempts risk full perimeter penetration.",
        expected_outcome="Aggressor source IPs dynamically blocked at firewall/WAF boundaries and progressive rate-limiting enforced on edge ingress services.",
        verification_criteria=[
            "Confirm IP blacklist rules deployed on gateway ACLs",
            "Verify edge rate-limiting drops excessive authentication probes",
            "Ensure synthetic external service remains available to legitimate clients",
        ],
        action_templates=[
            PlaybookActionTemplate(
                action_code="ACT-PB-002-01",
                title="Deploy Dynamic Ingress IP Blocks at Edge Gateway",
                description="Add attacking external IP addresses and subnets to the ingress boundary drop list.",
                action_type="network_filtering",
                sequence_order=1,
                depends_on=[],
                expected_outcome="Inbound traffic from designated source addresses dropped silently at edge firewall.",
                verification_criteria=["WAF/Edge ACL rule count incremented and telemetry shows zero inbound packets accepted"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-002-02",
                title="Configure Exponential Backoff & Account Lockout Policies",
                description="Enable progressive backoff delays after 3 failed login attempts from any single origin.",
                action_type="rate_limiting",
                sequence_order=2,
                depends_on=["ACT-PB-002-01"],
                expected_outcome="Brute force velocity curtailed by >95% on public authentication endpoints.",
                verification_criteria=["Simulated rapid login returns HTTP 429 Too Many Requests"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-002-03",
                title="Restrict Exposed Ingress Endpoints via Zero Trust Access Gateways",
                description="Place administrative interfaces behind authenticated Zero Trust access proxy.",
                action_type="access_gateway_lockdown",
                sequence_order=3,
                depends_on=["ACT-PB-002-02"],
                expected_outcome="Management ports no longer reachable directly from public internet IP space.",
                verification_criteria=["External port scan against management port returns closed/filtered"],
            ),
        ],
    ),
    # 3. Privilege Escalation
    Playbook(
        playbook_id="BGD-PB-003",
        playbook_version="1.0.0",
        title="Privileged Execution Lockdown & Local Token Demotion",
        description="Terminates unauthorized elevated processes, strips exploitable SUID permissions, and audits local sudo rights.",
        category="Privilege Escalation",
        recommendation_type=RecommendationType.CORRECTIVE,
        target_threat_classes=["Privilege Escalation", "privilege_escalation", "sudo_abuse"],
        mitre_techniques=["T1068", "T1548"],
        default_priority=RecommendationPriority.P0,
        complexity="high",
        rationale="Abuse of elevated privileges or local exploits grants adversaries administrative control over the underlying synthetic node.",
        expected_outcome="Elevated processes terminated, vulnerable SUID/sudo permissions removed, and local access rights stripped back to minimum viable privilege.",
        verification_criteria=[
            "Confirm termination of spawned privileged shell processes",
            "Verify sudoers configuration contains no wildcard execution rules",
            "Verify local root/SYSTEM privileges restricted to authorized daemon accounts",
        ],
        action_templates=[
            PlaybookActionTemplate(
                action_code="ACT-PB-003-01",
                title="Terminate Unauthorized Elevated Child Processes",
                description="Identify and terminate all shell or tool processes running with root/SYSTEM privileges spawned from non-system parents.",
                action_type="process_termination",
                sequence_order=1,
                depends_on=[],
                expected_outcome="Adversary interactive elevated shells immediately killed.",
                verification_criteria=["Process table scan confirms absence of target PID"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-003-02",
                title="Demote Compromised Local Service Account Privileges",
                description="Remove administrative or sudo group membership from compromised service accounts.",
                action_type="privilege_revocation",
                sequence_order=2,
                depends_on=["ACT-PB-003-01"],
                expected_outcome="Compromised user account restricted to non-privileged standard shell.",
                verification_criteria=["id command output confirms user not in sudo/wheel/admin groups"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-003-03",
                title="Remediate SUID/SUDO File Misconfigurations and Apply OS Patches",
                description="Clear SUID bit on non-standard binaries and patch local privilege escalation vulnerabilities.",
                action_type="os_hardening",
                sequence_order=3,
                depends_on=["ACT-PB-003-02"],
                expected_outcome="Binaries no longer executable with elevated privileges by unprivileged users.",
                verification_criteria=["Audit scan finds no unexpected SUID binaries in /usr/bin or /opt"],
            ),
        ],
    ),
    # 4. Lateral Movement
    Playbook(
        playbook_id="BGD-PB-004",
        playbook_version="1.0.0",
        title="Internal Network Micro-segmentation & Host Isolation",
        description="Enforces strict East-West network micro-segmentation and isolates compromised workloads from database and identity tiers.",
        category="Lateral Movement",
        recommendation_type=RecommendationType.COMPENSATING,
        target_threat_classes=["Lateral Movement", "lateral_movement", "psexec", "ssh_hijack"],
        mitre_techniques=["T1021", "T1080"],
        default_priority=RecommendationPriority.P0,
        complexity="high",
        rationale="Host-to-host lateral traversal threatens critical synthetic core database and identity assets across adjacent subnets.",
        expected_outcome="Compromised node logically quarantined in an isolated VLAN and internal East-West traffic strictly restricted.",
        verification_criteria=[
            "Verify host firewall drops all East-West connections from affected node",
            "Confirm central monitoring telemetry continues to ingest from management port",
            "Validate database subnets reject connections from unauthorized application tiers",
        ],
        action_templates=[
            PlaybookActionTemplate(
                action_code="ACT-PB-004-01",
                title="Apply Host-Level Firewall Micro-segmentation Rules",
                description="Deploy iptables/host firewall policies restricting outbound connections exclusively to security monitoring endpoints.",
                action_type="host_isolation",
                sequence_order=1,
                depends_on=[],
                expected_outcome="Target node cannot initiate connections to sibling nodes in the synthetic subnet.",
                verification_criteria=["Network probe to neighboring asset IP times out"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-004-02",
                title="Invalidate Active Internal SSH/Kerberos/SMB Sessions",
                description="Sever active SSH connections, clear cached Kerberos tickets, and drop active SMB sessions originating from the compromised node.",
                action_type="session_termination",
                sequence_order=2,
                depends_on=["ACT-PB-004-01"],
                expected_outcome="All existing lateral authenticated sessions closed.",
                verification_criteria=["Active connection table shows zero ESTABLISHED lateral connections"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-004-03",
                title="Tighten Transit ACLs Between Workload and Database Subnets",
                description="Update router ACLs so only verified, healthy application hosts can communicate with database port 5432.",
                action_type="subnet_acl_enforcement",
                sequence_order=3,
                depends_on=["ACT-PB-004-02"],
                expected_outcome="Database tier shielded from general subnet ingress.",
                verification_criteria=["Access logs verify only authorized frontend service VIP reaches DB port"],
            ),
        ],
    ),
    # 5. Persistence
    Playbook(
        playbook_id="BGD-PB-005",
        playbook_version="1.0.0",
        title="Scheduled Job Purge & System Integrity Baseline Restoration",
        description="Eradicates unauthorized scheduled tasks, rogue system services, and restores system files to gold-image integrity.",
        category="Persistence",
        recommendation_type=RecommendationType.CORRECTIVE,
        target_threat_classes=["Persistence", "persistence", "cron_job_added", "scheduled_task"],
        mitre_techniques=["T1053", "T1136"],
        default_priority=RecommendationPriority.P1,
        complexity="medium",
        rationale="Adversaries maintain ongoing access via persistent scheduled tasks, systemd services, or rogue user accounts across node reboots.",
        expected_outcome="All unauthorized cron jobs, scheduled tasks, and persistence hooks eradicated, returning node integrity to verified gold image.",
        verification_criteria=[
            "Confirm rogue cron table entries purged",
            "Verify removal of rogue local user accounts from system registry",
            "Audit file integrity checksums against baseline manifest",
        ],
        action_templates=[
            PlaybookActionTemplate(
                action_code="ACT-PB-005-01",
                title="Remove Rogue Cron Jobs and Systemd Service Units",
                description="Scan /etc/cron.*, user crontabs, and /etc/systemd/system for non-baseline persistence entries and remove them.",
                action_type="persistence_removal",
                sequence_order=1,
                depends_on=[],
                expected_outcome="Malicious scheduled commands eliminated from auto-start queues.",
                verification_criteria=["crontab -l returns standard baseline entries only"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-005-02",
                title="Delete Unauthorized Local User Accounts and SSH Authorized Keys",
                description="Purge backdoor accounts added during the incident and remove rogue public keys from ~/.ssh/authorized_keys.",
                action_type="account_sanitization",
                sequence_order=2,
                depends_on=["ACT-PB-005-01"],
                expected_outcome="Rogue interactive login capabilities revoked.",
                verification_criteria=["/etc/passwd matches baseline asset manifest"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-005-03",
                title="Perform File Integrity Audit and Restore Tampered Binaries",
                description="Run cryptographic hashing across system binaries and re-install any tampered packages from trusted repositories.",
                action_type="integrity_restoration",
                sequence_order=3,
                depends_on=["ACT-PB-005-02"],
                expected_outcome="System binary hashes align 100% with distribution package signatures.",
                verification_criteria=["Package verification command passes with zero discrepancies"],
            ),
        ],
    ),
    # 6. Exfiltration
    Playbook(
        playbook_id="BGD-PB-006",
        playbook_version="1.0.0",
        title="Outbound Data Channel Termination & Egress Firewall Policy",
        description="Terminates active egress channels, blocks unauthorized outbound destinations, and purges staged archive artifacts.",
        category="Exfiltration",
        recommendation_type=RecommendationType.CORRECTIVE,
        target_threat_classes=["Exfiltration", "exfiltration", "data_exfiltration", "covert_channel"],
        mitre_techniques=["T1048", "T1567"],
        default_priority=RecommendationPriority.P0,
        complexity="medium",
        rationale="Active exfiltration channels leak proprietary synthetic telemetry and intellectual property to unauthorized external endpoints.",
        expected_outcome="Outbound egress sockets terminated, external drop rules applied, and staged archive artifacts quarantined.",
        verification_criteria=[
            "Verify outbound connections to destination IP reset and blocked",
            "Confirm staging directory emptied and temporary exfiltration archives deleted",
            "Validate strict outbound proxy whitelisting is active",
        ],
        action_templates=[
            PlaybookActionTemplate(
                action_code="ACT-PB-006-01",
                title="Sever Active Egress Socket Connections and Block Destination IPs",
                description="Kill network sockets transmitting data to external C2 or unauthorized drop sites and blacklist remote IPs.",
                action_type="egress_severance",
                sequence_order=1,
                depends_on=[],
                expected_outcome="Immediate halt of data leakage over external network interfaces.",
                verification_criteria=["tcpdump confirms zero egress packets to suspicious destinations"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-006-02",
                title="Quarantine Staged Exfiltration Archives in Local Temp Folders",
                description="Securely wipe or quarantine compressed zip/tar/encrypted archives prepared for outbound staging.",
                action_type="archive_cleanup",
                sequence_order=2,
                depends_on=["ACT-PB-006-01"],
                expected_outcome="Staged data artifacts inaccessible to adversary processes.",
                verification_criteria=["Disk scan finds no staged archive files in /tmp or /var/tmp"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-006-03",
                title="Enforce Strict Outbound HTTP/DNS Proxy Whitelisting",
                description="Route all egress web and DNS traffic through inspecting proxy with mandatory domain allowlisting.",
                action_type="proxy_enforcement",
                sequence_order=3,
                depends_on=["ACT-PB-006-02"],
                expected_outcome="Arbitrary outbound socket establishment prevented across all internal synthetic nodes.",
                verification_criteria=["Direct outbound curl to unauthorized external IP blocked by proxy"],
            ),
        ],
    ),
    # 7. Reconnaissance
    Playbook(
        playbook_id="BGD-PB-007",
        playbook_version="1.0.0",
        title="Network Discovery Suppression & Synthetic Honeytoken Deployment",
        description="Suppresses internal network sweep responses, deploys deceptive canary honeytokens, and enhances probe telemetry.",
        category="Reconnaissance",
        recommendation_type=RecommendationType.DETECTIVE,
        target_threat_classes=["Reconnaissance", "reconnaissance", "port_scan", "network_discovery"],
        mitre_techniques=["T1595", "T1046"],
        default_priority=RecommendationPriority.P2,
        complexity="low",
        rationale="Port scanning and discovery sweeps identify exploitable services and map network topology prior to penetration.",
        expected_outcome="Internal ICMP and port discovery suppressed, honeypot traps deployed to detect subsequent probe activity.",
        verification_criteria=[
            "Verify host stops answering unsolicited ICMP echo probes",
            "Confirm decoy honeytokens planted in synthetic credentials registry",
            "Verify alerts fire on honeytoken interaction",
        ],
        action_templates=[
            PlaybookActionTemplate(
                action_code="ACT-PB-007-01",
                title="Suppress Internal ICMP and Port Sweep Responses",
                description="Configure kernel network parameters to ignore broadcast ICMP and drop closed-port RST responses.",
                action_type="probe_suppression",
                sequence_order=1,
                depends_on=[],
                expected_outcome="Port scanners observe stealth/filtered results rather than active service discovery.",
                verification_criteria=["sysctl net.ipv4.icmp_echo_ignore_broadcasts equals 1"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-007-02",
                title="Deploy Synthetic Decoy Canary Files and Honeytokens",
                description="Seed decoy configuration files and credential tokens into common discovery paths to trap active scanners.",
                action_type="honeytoken_deployment",
                sequence_order=2,
                depends_on=["ACT-PB-007-01"],
                expected_outcome="Immediate high-fidelity alarm upon any adversary attempt to read canary artifacts.",
                verification_criteria=["SIEM Canary watcher confirms active file tripwires"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-007-03",
                title="Enable High-Fidelity Audit Logging on Sensitive Ports",
                description="Turn on connection attempt logging for database, management, and internal RPC ports.",
                action_type="telemetry_enhancement",
                sequence_order=3,
                depends_on=["ACT-PB-007-02"],
                expected_outcome="Full forensic capture of any subsequent reconnaissance probes.",
                verification_criteria=["Connection audit logs record complete source IP and port tuples"],
            ),
        ],
    ),
    # 8. Weak Configuration
    Playbook(
        playbook_id="BGD-PB-008",
        playbook_version="1.0.0",
        title="Service Configuration Hardening & Cipher Suite Enforcement",
        description="Remediates insecure default credentials, disables legacy protocols, and enforces TLS 1.3 encryption baselines.",
        category="Weak Configuration",
        recommendation_type=RecommendationType.PREVENTIVE,
        target_threat_classes=["Suspicious Configuration", "Weak Configuration", "weak_configuration", "misconfiguration"],
        mitre_techniques=["T1190", "M1026"],
        default_priority=RecommendationPriority.P2,
        complexity="low",
        rationale="Default settings, plaintext protocols, and weak cipher suites expose synthetic services to eavesdropping and opportunistic exploit.",
        expected_outcome="Insecure configuration parameters remediated, modern TLS 1.3 ciphers enforced, and default passwords replaced.",
        verification_criteria=[
            "Verify service rejects SSLv3 and TLS 1.0/1.1 handshakes",
            "Confirm default administrative accounts disabled or renamed",
            "Validate configuration compliance scan reports 100% pass",
        ],
        action_templates=[
            PlaybookActionTemplate(
                action_code="ACT-PB-008-01",
                title="Disable Insecure Protocols and Enforce TLS 1.3 / Strict Ciphers",
                description="Reconfigure web servers, reverse proxies, and database listeners to require TLS 1.3 with forward secrecy.",
                action_type="cipher_hardening",
                sequence_order=1,
                depends_on=[],
                expected_outcome="Plaintext and legacy weak encryption handshakes rejected universally.",
                verification_criteria=["SSL test tool confirms no ciphers below AES-GCM-256 accepted"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-008-02",
                title="Rotate Default Configuration Secrets and Disable Unused Endpoints",
                description="Audit application config files, change default passwords, and disable debugging or Swagger UI in production tiers.",
                action_type="configuration_cleanup",
                sequence_order=2,
                depends_on=["ACT-PB-008-01"],
                expected_outcome="No default credentials or exposed diagnostic endpoints remain active.",
                verification_criteria=["Default credentials rejected on login test"],
            ),
            PlaybookActionTemplate(
                action_code="ACT-PB-008-03",
                title="Enforce Automated Configuration Drift Detection",
                description="Establish recurring configuration audit job comparing live system settings to verified hardening baseline.",
                action_type="compliance_monitoring",
                sequence_order=3,
                depends_on=["ACT-PB-008-02"],
                expected_outcome="Immediate notification upon unauthorized configuration alterations.",
                verification_criteria=["Configuration compliance audit job scheduled in cron"],
            ),
        ],
    ),
]


class PlaybookLibrary:
    """Manages available defensive playbooks and performs deterministic playbook matching."""

    def __init__(self, playbooks: Optional[List[Playbook]] = None):
        self._playbooks: Dict[str, Playbook] = {}
        for pb in (playbooks or INITIAL_PLAYBOOKS):
            self._playbooks[pb.playbook_id] = pb

    def get_all_playbooks(self) -> List[Playbook]:
        """Returns sorted list of registered playbooks."""
        return sorted(list(self._playbooks.values()), key=lambda p: p.playbook_id)

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        """Retrieves a single playbook by its unique identifier."""
        return self._playbooks.get(playbook_id)

    def find_playbooks_for_detection(
        self,
        classification: str,
        mitre_technique_ids: Optional[List[str]] = None,
    ) -> List[Playbook]:
        """Deterministically matches playbooks against a threat detection.
        
        Matches primarily by target threat classification, with fallback or augmentation
        by MITRE ATT&CK technique IDs.
        """
        matched: List[Playbook] = []
        cls_lower = classification.lower().strip()
        techniques = set(t.upper() for t in (mitre_technique_ids or []))

        for pb in self.get_all_playbooks():
            # Check classification match
            class_match = any(
                target.lower() in cls_lower or cls_lower in target.lower()
                for target in pb.target_threat_classes
            )
            # Check MITRE technique match
            mitre_match = bool(techniques.intersection(set(pb.mitre_techniques)))

            if class_match or mitre_match:
                matched.append(pb)

        # If no specific match, default to Weak Configuration (general hardening)
        if not matched and "BGD-PB-008" in self._playbooks:
            matched.append(self._playbooks["BGD-PB-008"])

        return matched

    def to_response_list(self) -> List[PlaybookResponse]:
        """Serializes all playbooks to Pydantic responses."""
        return [pb.to_response() for pb in self.get_all_playbooks()]

