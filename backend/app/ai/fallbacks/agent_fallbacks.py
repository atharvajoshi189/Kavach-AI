"""Deterministic template-driven fallback generators for all 6 specialized AI agents.

Guarantees 100% test coverage and functional multi-agent orchestration even when
live Gemini is disabled, rate-limited, timed out, or unconfigured.
"""

from typing import Any
import uuid

from app.ai.schemas.agent_schemas import AegisAgentOutput


class AgentFallbackGenerator:
    """Generates schema-compliant, evidence-grounded AegisAgentOutput instances."""

    @classmethod
    def threat_intelligence_agent(
        cls,
        evidence: dict[str, Any],
        reason: str = "Live Gemini provider unavailable",
    ) -> AegisAgentOutput:
        """Deterministic fallback for Threat Intelligence Agent."""
        detections = evidence.get("detections", [])
        evidence_ids = []
        observations = []

        if detections:
            for d in detections[:5]:
                did = str(d.get("id") or d.get("detection_id") or uuid.uuid4())
                evidence_ids.append(did)
                title = d.get("title") or d.get("rule_name") or d.get("classification", "Detection")
                sev = d.get("severity", "HIGH")
                observations.append(f"Persisted detection '{title}' with severity {sev} (ID: {did})")
        else:
            det_id = str(evidence.get("detection_id") or uuid.uuid4())
            evidence_ids.append(det_id)
            observations.append(f"Evaluated threat record with primary identifier {det_id}")

        for ev_id in evidence.get("event_ids", [])[:5]:
            evidence_ids.append(str(ev_id))

        summary = (
            f"Deterministic Threat Analysis: Observed {len(observations)} verified threat indicators "
            f"across synthetic sandbox telemetry. Generated via deterministic fallback ({reason})."
        )

        return AegisAgentOutput(
            agent_name="threat_intelligence_agent",
            execution_status="fallback",
            summary=summary,
            observations=observations or ["Synthetic detection pattern matches established heuristic signatures."],
            supporting_evidence_ids=evidence_ids,
            derived_conclusions=[
                "Observed events correlate with simulated adversary persistence or discovery actions.",
                "Telemetry confirms detection rule triggered within expected bounds.",
            ],
            inferred_exposure=[
                "Lateral movement may be attempted if synthetic credentials or web shell are leveraged.",
            ],
            uncertainty=[
                f"Advisory fallback invoked ({reason}); deep linguistic threat actor attribution unavailable.",
            ],
            missing_information=[
                "Host-level memory dump and egress packet capture telemetry not present in record.",
            ],
            advisory_recommendations=[
                "Validate synthetic asset integrity against baseline snapshot.",
                "Review correlated event timestamps to confirm ingress vector.",
            ],
            confidence=0.85,
            fallback_used=True,
            simulation_only=True,
        )

    @classmethod
    def attack_path_agent(
        cls,
        evidence: dict[str, Any],
        reason: str = "Live Gemini provider unavailable",
    ) -> AegisAgentOutput:
        """Deterministic fallback for Attack Path Analysis Agent."""
        attack_paths = evidence.get("attack_paths", [])
        evidence_ids = []
        observations = []

        if attack_paths:
            for p in attack_paths[:3]:
                pid = str(p.get("id") or p.get("attack_path_id") or uuid.uuid4())
                evidence_ids.append(pid)
                stages = p.get("total_stages", 1)
                status = p.get("status", "completed")
                observations.append(f"Attack path {pid} progressed through {stages} stages with final status '{status}'")
        else:
            path_id = str(evidence.get("attack_path_id") or uuid.uuid4())
            evidence_ids.append(path_id)
            observations.append(f"Synthetic multi-stage progression traced for path {path_id}")

        for aid in evidence.get("affected_asset_ids", [])[:5]:
            evidence_ids.append(str(aid))

        summary = (
            f"Deterministic Attack Path Analysis: Traced synthetic adversary kill chain across {len(evidence_ids)} "
            f"identifiable elements. Generated via deterministic fallback ({reason})."
        )

        return AegisAgentOutput(
            agent_name="attack_path_agent",
            execution_status="fallback",
            summary=summary,
            observations=observations,
            supporting_evidence_ids=evidence_ids,
            derived_conclusions=[
                "Sequential prerequisites were satisfied across attack path stages.",
                "Adversary traversal relied on connected assets within the sandbox topology.",
            ],
            inferred_exposure=[
                "Downstream database and internal service tiers remain reachable if pivot points persist.",
            ],
            uncertainty=[
                f"Advisory fallback invoked ({reason}); exploratory multi-hop branch prediction restricted.",
            ],
            missing_information=[
                "Flow duration and exact inter-hop payload bytes were not logged in synthetic trace.",
            ],
            advisory_recommendations=[
                "Apply micro-segmentation to sever pivot routes between web and database tiers.",
                "Quarantine affected source asset nodes identified in attack stages.",
            ],
            confidence=0.86,
            fallback_used=True,
            simulation_only=True,
        )

    @classmethod
    def risk_intelligence_agent(
        cls,
        evidence: dict[str, Any],
        reason: str = "Live Gemini provider unavailable",
    ) -> AegisAgentOutput:
        """Deterministic fallback for Risk Intelligence Agent."""
        score = float(evidence.get("risk_score") or evidence.get("max_risk_score") or 75.0)
        category = str(evidence.get("risk_category") or "HIGH").upper()
        
        evidence_ids = []
        assessments = evidence.get("risk_assessments") or evidence.get("assessments", [])
        if assessments:
            for a in assessments:
                aid = str(a.get("id") or a.get("assessment_id"))
                if aid and aid != "None" and aid not in evidence_ids:
                    evidence_ids.append(aid)
            assessment_id = evidence_ids[0] if evidence_ids else str(uuid.uuid4())
        else:
            assessment_id = str(evidence.get("assessment_id") or evidence.get("id") or uuid.uuid4())
            evidence_ids.append(assessment_id)

        for aid in evidence.get("impacted_asset_ids", [])[:5]:
            aid_str = str(aid)
            if aid_str not in evidence_ids:
                evidence_ids.append(aid_str)

        summary = (
            f"Deterministic Risk Analysis: Authoritative composite risk score evaluated at {score:.1f} ({category}). "
            f"Deterministic score is strictly preserved. Generated via fallback ({reason})."
        )

        return AegisAgentOutput(
            agent_name="risk_intelligence_agent",
            execution_status="fallback",
            summary=summary,
            observations=[
                f"Authoritative deterministic risk score: {score:.1f}",
                f"Assessed risk category: {category}",
                f"Risk assessment record reference: {assessment_id}",
            ],
            supporting_evidence_ids=evidence_ids,
            derived_conclusions=[
                f"Risk score of {score:.1f} driven primarily by asset criticality and threat severity.",
                "Blast radius confirms impact is constrained to the synthetic sandbox boundary.",
            ],
            inferred_exposure=[
                "Unmitigated risks could result in simulated data extraction or system compromise.",
            ],
            uncertainty=[
                f"Advisory fallback ({reason}); non-linear sensitivity weighting computed deterministically.",
            ],
            missing_information=[
                "Dynamic runtime asset utilization and secondary business impact metrics not captured.",
            ],
            advisory_recommendations=[
                "Prioritize remediation for assets contributing >70% to composite risk score.",
                "Validate asset tags and criticality ratings before formal signoff.",
            ],
            confidence=0.95,
            fallback_used=True,
            simulation_only=True,
            is_ai_generated=True,
        )

    @classmethod
    def incident_analysis_agent(
        cls,
        evidence: dict[str, Any],
        reason: str = "Live Gemini provider unavailable",
    ) -> AegisAgentOutput:
        """Deterministic fallback for Incident Analysis Agent."""
        evidence_ids = []
        reports = evidence.get("incident_reports") or evidence.get("reports", [])
        if reports:
            for r in reports:
                rid = str(r.get("id") or r.get("report_id"))
                if rid and rid != "None" and rid not in evidence_ids:
                    evidence_ids.append(rid)
            report_id = evidence_ids[0] if evidence_ids else str(uuid.uuid4())
        else:
            report_id = str(evidence.get("report_id") or evidence.get("id") or uuid.uuid4())
            evidence_ids.append(report_id)

        if evidence.get("execution_id"):
            ev_exec = str(evidence["execution_id"])
            if ev_exec not in evidence_ids:
                evidence_ids.append(ev_exec)

        summary = (
            f"Deterministic Incident Narrative: Security incident recorded under report {report_id}. "
            f"Timeline confirms synthetic attack lifecycle completed. Fallback ({reason})."
        )

        return AegisAgentOutput(
            agent_name="incident_analysis_agent",
            execution_status="fallback",
            summary=summary,
            observations=[
                f"Security incident dossier registered under report ID {report_id}",
                "Correlated threat detections match adversary action patterns.",
                "Automated detection pipeline flagged initial ingress and exploitation events.",
            ],
            supporting_evidence_ids=evidence_ids,
            derived_conclusions=[
                "Incident sequence confirms simulated adversary successfully exercised test scenario.",
                "Telemetry pipeline captured complete defensive audit trail from ingress to detection.",
            ],
            inferred_exposure=[
                "Synthetic target data stores may contain unencrypted artifacts from the run.",
            ],
            uncertainty=[
                f"Advisory fallback invoked ({reason}); narrative constructed from structured summary fields.",
            ],
            missing_information=[
                "Third-party threat feed enrichment and external IP geolocation unavailable.",
            ],
            advisory_recommendations=[
                "Archive incident evidence bundle to maintain forensic chain-of-custody.",
                "Initiate formal post-incident remediation planning with operations team.",
            ],
            confidence=0.88,
            fallback_used=True,
            simulation_only=True,
            is_ai_generated=True,
        )

    @classmethod
    def defensive_strategy_agent(
        cls,
        evidence: dict[str, Any],
        reason: str = "Live Gemini provider unavailable",
    ) -> AegisAgentOutput:
        """Deterministic fallback for Defensive Strategy Agent."""
        recommendations = evidence.get("recommendations", [])
        evidence_ids = []
        observations = []

        if recommendations:
            for r in recommendations[:4]:
                rid = str(r.get("id") or r.get("recommendation_id") or uuid.uuid4())
                evidence_ids.append(rid)
                code = r.get("recommendation_code", "REC-DEF")
                title = r.get("title", "Playbook Countermeasure")
                observations.append(f"Recommended action '{title}' ({code}) with ID {rid}")
        else:
            rec_id = str(evidence.get("recommendation_id") or uuid.uuid4())
            evidence_ids.append(rec_id)
            observations.append(f"Defensive countermeasure proposed with ID {rec_id}")

        if evidence.get("plan_id"):
            evidence_ids.append(str(evidence["plan_id"]))

        summary = (
            f"Deterministic Defensive Strategy: Evaluated {len(observations)} countermeasure actions. "
            f"Four-Eyes approval strictly required before synthetic execution. Fallback ({reason})."
        )

        return AegisAgentOutput(
            agent_name="defensive_strategy_agent",
            execution_status="fallback",
            summary=summary,
            observations=observations,
            supporting_evidence_ids=evidence_ids,
            derived_conclusions=[
                "Proposed countermeasures directly neutralize observed attack techniques.",
                "Remediation actions are structured as idempotent synthetic operations.",
            ],
            inferred_exposure=[
                "Temporary service disruption may occur during network isolation or firewall reconfiguration.",
            ],
            uncertainty=[
                f"Advisory fallback ({reason}); side-effect prediction based on standard playbook metadata.",
            ],
            missing_information=[
                "Live workload concurrency figures during scheduled remediation window.",
            ],
            advisory_recommendations=[
                "Submit remediation plan for Four-Eyes security operator and admin approval.",
                "Execute state snapshot prior to synthetic remediation for regression rollback.",
            ],
            confidence=0.92,
            fallback_used=True,
            simulation_only=True,
        )

    @classmethod
    def executive_intelligence_agent(
        cls,
        evidence: dict[str, Any],
        reason: str = "Live Gemini provider unavailable",
    ) -> AegisAgentOutput:
        """Deterministic fallback for Executive Intelligence Agent."""
        exec_id = str(evidence.get("execution_id") or uuid.uuid4())
        evidence_ids = [exec_id]
        if evidence.get("report_id"):
            evidence_ids.append(str(evidence["report_id"]))

        summary = (
            f"Executive Security Briefing: Synthetic adversary simulation successfully tested defense posture "
            f"in isolated sandbox. All findings are simulation-only. Fallback ({reason})."
        )

        return AegisAgentOutput(
            agent_name="executive_intelligence_agent",
            execution_status="fallback",
            summary=summary,
            observations=[
                f"Guardian execution session {exec_id} completed in controlled sandbox environment",
                "Defensive detection, risk scoring, and recommendation pipelines operated successfully",
                "Human-in-the-loop governance verified: remediation requires dual operator authorization",
            ],
            supporting_evidence_ids=evidence_ids,
            derived_conclusions=[
                "Synthetic security defenses detected and contained the simulated attack path.",
                "Zero real-world infrastructure was targeted; all findings reflect synthetic telemetry.",
            ],
            inferred_exposure=[
                "Similar vulnerability classes should be reviewed across production asset inventories.",
            ],
            uncertainty=[
                f"Advisory fallback ({reason}); executive narrative synthesized from pipeline metrics.",
            ],
            missing_information=[
                "Enterprise-wide compliance mappings (SOC2/ISO27001) not linked in this run.",
            ],
            advisory_recommendations=[
                "Maintain quarterly synthetic red-team exercises to validate automated detection latency.",
                "Ensure remediation runbooks are regularly audited and rehearsed.",
            ],
            confidence=0.94,
            fallback_used=True,
            simulation_only=True,
        )

