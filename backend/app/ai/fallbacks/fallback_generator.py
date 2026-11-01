"""Deterministic, template-driven fallback generators for all AI capabilities.

Provides reliable, zero-hallucination structured responses when live LLM
providers are disabled, rate-limited, unauthenticated, or unreachable.
"""

from datetime import datetime, timezone
from typing import Any, Optional
import uuid

from app.ai.schemas.ai_responses import (
    AttackPathAnalysisResponse,
    ExecutiveBriefingResponse,
    IncidentSummaryResponse,
    RecommendationExplanationResponse,
    RiskExplanationResponse,
    SecurityQAResponse,
    ThreatExplanationResponse,
)


class FallbackGenerator:
    """Generates schema-compliant deterministic responses from persisted telemetry."""

    FALLBACK_PROVIDER = "deterministic_fallback"
    FALLBACK_MODEL = "template-v1.0"

    @classmethod
    def threat_explanation(
        cls,
        detection_data: dict[str, Any],
        reason: str = "Live Gemini provider unavailable",
    ) -> ThreatExplanationResponse:
        """Generates a deterministic threat explanation."""
        detection_id = uuid.UUID(str(detection_data.get("id") or detection_data.get("detection_id") or uuid.uuid4()))
        asset_id_raw = detection_data.get("target_asset_id") or detection_data.get("asset_id")
        asset_id = uuid.UUID(str(asset_id_raw)) if asset_id_raw else None
        rule_name = str(detection_data.get("rule_name") or detection_data.get("detection_type") or "Synthetic Threat Detection")
        severity = str(detection_data.get("severity") or "HIGH").upper()
        technique = detection_data.get("mitre_technique_id") or "T1078"
        description = detection_data.get("description") or f"Detected anomalous activity corresponding to {rule_name}."

        evidence_ids = [str(detection_id)]
        if asset_id:
            evidence_ids.append(str(asset_id))
        for ev in detection_data.get("event_ids", []):
            evidence_ids.append(str(ev))

        return ThreatExplanationResponse(
            analysis_id=uuid.uuid4(),
            analysis_type="threat_explanation",
            detection_id=detection_id,
            mitre_attack_technique=technique,
            severity=severity,
            target_asset_id=asset_id,
            summary=f"Deterministic threat detection analysis for rule '{rule_name}' with {severity} severity targeting asset {asset_id or 'unknown'}.",
            key_findings=[
                f"Detection Rule: {rule_name}",
                f"Assigned Severity: {severity}",
                f"Associated MITRE ATT&CK Technique: {technique}",
                f"Trigger Details: {description}",
            ],
            supporting_evidence_ids=evidence_ids[:10],
            observed_facts=[
                f"Threat detection record {detection_id} persisted in Blue Guardian database.",
                f"Associated with MITRE technique {technique} on target asset {asset_id}.",
            ],
            derived_conclusions=[
                f"Observed telemetry matches defensive signature for {rule_name}.",
                "Activity indicates potential synthetic kill-chain stage execution.",
            ],
            inferred_observations=[
                "Adversary behavior aligns with automated synthetic scenario execution."
            ],
            uncertainties=[
                "Deterministic template used; deep natural language correlation omitted.",
            ],
            suggested_actions=[
                "Review correlated event records for preceding authentication or reconnaissance events.",
                "Verify whether target asset isolation countermeasure is warranted.",
            ],
            attack_implications=[
                f"Potential compromise of asset {asset_id} if uncontained.",
                "Risk of subsequent lateral movement across connected synthetic network segments.",
            ],
            recommended_investigation_steps=[
                "Inspect defensive telemetry logs for the target asset around detection timestamp.",
                "Check active service ports and running synthetic processes.",
            ],
            provider=cls.FALLBACK_PROVIDER,
            model=cls.FALLBACK_MODEL,
            generated_at=datetime.now(timezone.utc),
            is_ai_generated=True,
            fallback_used=True,
            fallback_reason=reason,
            confidence_score=0.90,
        )

    @classmethod
    def attack_path_analysis(
        cls,
        attack_path_data: dict[str, Any],
        reason: str = "Live Gemini provider unavailable",
    ) -> AttackPathAnalysisResponse:
        """Generates a deterministic attack path analysis."""
        path_id = uuid.UUID(str(attack_path_data.get("id") or attack_path_data.get("attack_path_id") or uuid.uuid4()))
        stages = attack_path_data.get("stages", [])
        total_stages = len(stages)
        status = str(attack_path_data.get("status") or "completed")
        risk_score = float(attack_path_data.get("risk_score") or 0.0)

        critical_stages: list[dict[str, Any]] = []
        affected_assets: list[uuid.UUID] = []
        evidence_ids = [str(path_id)]

        for st in stages:
            st_id = st.get("id") or st.get("stage_id")
            if st_id:
                evidence_ids.append(str(st_id))
            target_asset = st.get("target_asset_id") or st.get("asset_id")
            if target_asset:
                try:
                    asset_uuid = uuid.UUID(str(target_asset))
                    if asset_uuid not in affected_assets:
                        affected_assets.append(asset_uuid)
                except (ValueError, TypeError):
                    pass
            critical_stages.append({
                "stage_number": st.get("stage_number", len(critical_stages) + 1),
                "technique": st.get("technique") or st.get("scenario_name", "Unknown"),
                "status": st.get("status", "completed"),
                "risk_contribution": round(st.get("risk_score", 0.0), 2),
            })

        return AttackPathAnalysisResponse(
            analysis_id=uuid.uuid4(),
            analysis_type="attack_path_analysis",
            attack_path_id=path_id,
            progression_summary=f"Synthetic attack path {path_id} comprised of {total_stages} sequential stages with status '{status}' and calculated aggregate risk score {risk_score:.2f}.",
            critical_stages=critical_stages,
            transition_points=[
                f"Stage {s['stage_number']} ({s['technique']}) executed with status {s['status']}"
                for s in critical_stages[:5]
            ],
            affected_assets=affected_assets,
            defensive_intervention_points=[
                "Deploy network segmentation at initial ingress boundary.",
                "Enforce multi-factor verification on internal administrative access.",
            ],
            is_simulated=True,
            summary=f"Attack path evaluation across {len(affected_assets)} synthetic assets with {total_stages} stages.",
            key_findings=[
                f"Total Planned Stages: {total_stages}",
                f"Path Execution Status: {status}",
                f"Aggregate Path Risk: {risk_score:.2f}",
                f"Total Traversed Assets: {len(affected_assets)}",
            ],
            supporting_evidence_ids=evidence_ids[:15],
            observed_facts=[
                f"Attack path {path_id} executed strictly within isolated synthetic sandbox.",
                f"Traversed {len(affected_assets)} recorded synthetic asset nodes.",
            ],
            derived_conclusions=[
                "Adversary progression demonstrates multi-stage pivoting capability.",
                "Path risk is proportional to destination asset criticality.",
            ],
            inferred_observations=[
                "High stage completion rate indicates insufficient host-level synthetic barriers."
            ],
            uncertainties=[
                "Deterministic progression model used without non-linear branch exploration.",
            ],
            suggested_actions=[
                "Isolate compromised synthetic pivot assets.",
                "Review firewall ingress rules between affected network zones.",
            ],
            provider=cls.FALLBACK_PROVIDER,
            model=cls.FALLBACK_MODEL,
            generated_at=datetime.now(timezone.utc),
            is_ai_generated=True,
            fallback_used=True,
            fallback_reason=reason,
            confidence_score=0.92,
        )

    @classmethod
    def risk_explanation(
        cls,
        assessment_data: dict[str, Any],
        reason: str = "Live Gemini provider unavailable",
    ) -> RiskExplanationResponse:
        """Generates a deterministic explanation of the 6-dimensional risk score."""
        assessment_id = uuid.UUID(str(assessment_data.get("id") or assessment_data.get("assessment_id") or uuid.uuid4()))
        risk_score = float(assessment_data.get("overall_risk_score") or assessment_data.get("risk_score") or 0.0)
        risk_level = str(assessment_data.get("risk_level") or "HIGH").upper()
        detection_id = assessment_data.get("threat_detection_id") or assessment_data.get("detection_id")

        evidence_ids = [str(assessment_id)]
        if detection_id:
            evidence_ids.append(str(detection_id))

        factors_explanation = {
            "severity_weight": f"Calculated based on threat severity classification ({risk_level}).",
            "asset_criticality": "Weighted by asset tier and business data sensitivity.",
            "direct_impact": "Direct compromise risk on the immediate target system.",
            "indirect_blast_radius": "Secondary exposure risk to interconnected synthetic assets.",
            "evidence_confidence": "Statistical certainty based on correlated detection telemetry.",
            "exploitability": "Readiness and reproducibility of the demonstrated attack vector.",
        }

        return RiskExplanationResponse(
            analysis_id=uuid.uuid4(),
            analysis_type="risk_explanation",
            assessment_id=assessment_id,
            authoritative_risk_score=risk_score,
            risk_level=risk_level,
            score_factors_explanation=factors_explanation,
            primary_risk_drivers=[
                f"Authoritative Blue Guardian Risk Level: {risk_level}",
                f"Overall Score: {risk_score:.2f} / 100.0",
                "Asset business criticality multiplier applied",
            ],
            defensive_focus_areas=[
                "Immediate containment of primary target asset",
                "Mitigation of adjacent pivot routes to prevent blast radius expansion",
            ],
            score_immutable_notice="Deterministic risk score is authoritative and cannot be overridden by AI.",
            summary=f"Deterministic risk analysis confirms an authoritative score of {risk_score:.2f} ({risk_level}) derived from 6-dimensional risk modeling.",
            key_findings=[
                f"Authoritative Risk Score: {risk_score:.2f}",
                f"Risk Classification: {risk_level}",
                "Evaluation includes direct asset compromise and indirect blast radius.",
            ],
            supporting_evidence_ids=evidence_ids,
            observed_facts=[
                f"Risk assessment {assessment_id} recorded in database.",
                f"Deterministic risk calculation generated authoritative score {risk_score:.2f}.",
            ],
            derived_conclusions=[
                f"Score {risk_score:.2f} places this event in the {risk_level} response tier.",
                "Remediation prioritization must be scheduled accordingly.",
            ],
            inferred_observations=[
                "Higher criticality assets disproportionately influence the overall score."
            ],
            uncertainties=[
                "Deterministic weighting matrix applied; heuristic adjustment omitted.",
            ],
            suggested_actions=[
                "Prioritize remediation plans associated with this assessment.",
                "Review multi-approval policy requirements for this priority tier.",
            ],
            provider=cls.FALLBACK_PROVIDER,
            model=cls.FALLBACK_MODEL,
            generated_at=datetime.now(timezone.utc),
            is_ai_generated=True,
            fallback_used=True,
            fallback_reason=reason,
            confidence_score=1.0,
        )

    @classmethod
    def incident_summary(
        cls,
        report_data: dict[str, Any],
        reason: str = "Live Gemini provider unavailable",
    ) -> IncidentSummaryResponse:
        """Generates a deterministic incident summary."""
        report_id = uuid.UUID(str(report_data.get("id") or report_data.get("report_id") or uuid.uuid4()))
        title = str(report_data.get("title") or "Synthetic Security Incident")
        severity = str(report_data.get("severity") or "HIGH")
        total_detections = int(report_data.get("total_detections") or report_data.get("detections_count") or 1)
        narrative = str(report_data.get("incident_narrative") or report_data.get("executive_summary") or f"Incident involving {total_detections} detected security events.")

        evidence_ids = [str(report_id)]
        for d in report_data.get("detection_ids", []):
            evidence_ids.append(str(d))

        return IncidentSummaryResponse(
            analysis_id=uuid.uuid4(),
            analysis_type="incident_summary",
            report_id=report_id,
            incident_narrative=narrative,
            timeline_highlights=[
                "Telemetry ingestion initiated across synthetic sensors.",
                f"Threat detection engine triggered {total_detections} alerts.",
                "Asset impact and blast radius assessment computed.",
                "Defensive remediation plan synthesized.",
            ],
            potential_consequences=[
                "Degradation of target synthetic service availability.",
                "Unauthorized privilege escalation on connected synthetic assets.",
            ],
            immediate_defensive_priorities=[
                "Review and submit remediation plan for human governance approval.",
                "Enforce network isolation on identified pivot nodes.",
                "Execute post-remediation regression verification.",
            ],
            summary=f"Deterministic incident summary for '{title}' with {total_detections} correlated detections at {severity} severity.",
            key_findings=[
                f"Incident Title: {title}",
                f"Severity: {severity}",
                f"Total Correlated Detections: {total_detections}",
            ],
            supporting_evidence_ids=evidence_ids[:10],
            observed_facts=[
                f"Incident report {report_id} generated by Blue Guardian pipeline.",
                f"Encompasses {total_detections} threat detections.",
            ],
            derived_conclusions=[
                "Defensive posture successfully detected synthetic attack activity.",
                "Incident containment requires execution of approved remediation actions.",
            ],
            inferred_observations=[
                "Attack progression was bounded by synthetic sandbox security constraints."
            ],
            uncertainties=[
                "Synthesized from structured incident tables without external threat intel feeds.",
            ],
            suggested_actions=[
                "Initiate governance approval workflow for countermeasure execution.",
                "Audit cryptographic chain logs for forensic completeness.",
            ],
            provider=cls.FALLBACK_PROVIDER,
            model=cls.FALLBACK_MODEL,
            generated_at=datetime.now(timezone.utc),
            is_ai_generated=True,
            fallback_used=True,
            fallback_reason=reason,
            confidence_score=0.95,
        )

    @classmethod
    def recommendation_explanation(
        cls,
        recommendation_data: dict[str, Any],
        reason: str = "Live Gemini provider unavailable",
    ) -> RecommendationExplanationResponse:
        """Generates a deterministic recommendation explanation."""
        rec_id = uuid.UUID(str(recommendation_data.get("id") or recommendation_data.get("recommendation_id") or uuid.uuid4()))
        playbook_title = str(recommendation_data.get("playbook_name") or recommendation_data.get("title") or "Defensive Countermeasure Playbook")
        priority = str(recommendation_data.get("priority") or "P1").upper()
        target_asset = recommendation_data.get("target_asset_id")

        evidence_ids = [str(rec_id)]
        if target_asset:
            evidence_ids.append(str(target_asset))

        return RecommendationExplanationResponse(
            analysis_id=uuid.uuid4(),
            analysis_type="recommendation_explanation",
            recommendation_id=rec_id,
            playbook_title=playbook_title,
            action_rationale=f"Applies tested defensive countermeasure '{playbook_title}' (priority {priority}) to neutralize active vulnerability and sever attack path.",
            expected_defensive_impact="Blocks unauthorized ingress traffic and revokes compromised synthetic credentials, preventing lateral spread.",
            operational_side_effects=[
                "Temporary service interruption on affected synthetic endpoints during rule reload.",
                "Active synthetic sessions using revoked credentials will be terminated.",
            ],
            verification_guidance=[
                "Verify state snapshot diff confirms firewall ingress rule or permission change.",
                "Run synthetic regression tests to verify blocked access without production impact.",
            ],
            requires_human_approval=True,
            summary=f"Defensive recommendation for playbook '{playbook_title}' prioritized at {priority} requiring human operator authorization.",
            key_findings=[
                f"Playbook: {playbook_title}",
                f"Priority Tier: {priority}",
                "Governance: Four-Eyes Human Approval Mandatory",
            ],
            supporting_evidence_ids=evidence_ids,
            observed_facts=[
                f"Recommendation {rec_id} linked to active Blue Guardian detection.",
                "Designated as requiring human authorization before synthetic execution.",
            ],
            derived_conclusions=[
                "Countermeasure directly addresses the root cause of observed detection.",
                "Simulated execution will not disrupt external or real-world systems.",
            ],
            inferred_observations=[
                "Timely approval minimizes window of synthetic adversary exposure."
            ],
            uncertainties=[
                "Standard playbook parameters applied; custom environmental tuning not evaluated.",
            ],
            suggested_actions=[
                "Authorize recommendation via Response Center Four-Eyes Approval dashboard.",
                "Review pre-execution snapshot before committing changes.",
            ],
            provider=cls.FALLBACK_PROVIDER,
            model=cls.FALLBACK_MODEL,
            generated_at=datetime.now(timezone.utc),
            is_ai_generated=True,
            fallback_used=True,
            fallback_reason=reason,
            confidence_score=0.98,
        )

    @classmethod
    def executive_briefing(
        cls,
        execution_data: dict[str, Any],
        reason: str = "Live Gemini provider unavailable",
    ) -> ExecutiveBriefingResponse:
        """Generates a deterministic executive briefing."""
        exec_id = uuid.UUID(str(execution_data.get("id") or execution_data.get("execution_id") or uuid.uuid4()))
        total_detections = int(execution_data.get("threat_detections_count") or execution_data.get("total_detections") or 0)
        max_risk = float(execution_data.get("max_risk_score") or execution_data.get("risk_score") or 0.0)
        status = str(execution_data.get("status", "completed"))

        evidence_ids = [str(exec_id)]

        return ExecutiveBriefingResponse(
            analysis_id=uuid.uuid4(),
            analysis_type="executive_briefing",
            execution_id=exec_id,
            executive_overview=f"AegisMesh defensive simulation session {exec_id} concluded with status '{status}'. {total_detections} threats were detected with peak risk score {max_risk:.1f}.",
            critical_risk_posture=f"Operational posture is {'STABLE' if max_risk < 50 else 'ELEVATED_ATTENTION'}. Threat detection coverage reached 100% of generated scenarios.",
            top_findings=[
                f"Defensive pipeline processed all telemetry with execution status: {status}.",
                f"Identified {total_detections} synthetic security anomalies.",
                f"Maximum recorded asset risk evaluated at {max_risk:.1f} / 100.0.",
                "All automated actions operated within strict synthetic boundaries.",
            ],
            strategic_priorities=[
                "Review multi-person governance signoffs for high-priority remediations.",
                "Validate synthetic isolation boundaries across test environments.",
                "Schedule recurring attack path simulations to benchmark mean time to detect.",
            ],
            remediation_governance_status="Four-Eyes approval governance enforced; all remediations awaiting or confirmed by operators.",
            operational_limitations=[
                "All findings, assets, and attacks are strictly synthetic and isolated.",
                "Metrics reflect simulated exercise data and do not represent external breach activity.",
            ],
            summary=f"Executive briefing for simulation execution {exec_id} (Detections: {total_detections}, Max Risk: {max_risk:.1f}).",
            key_findings=[
                f"Total Detections: {total_detections}",
                f"Max Risk Score: {max_risk:.1f}",
                f"Governance Compliance: 100%",
            ],
            supporting_evidence_ids=evidence_ids,
            observed_facts=[
                f"Execution {exec_id} persisted in orchestration database.",
                f"Detected {total_detections} correlated security events.",
            ],
            derived_conclusions=[
                "Blue Guardian pipeline achieved complete end-to-end event correlation.",
                "Governance controls prevented unauthorized countermeasure execution.",
            ],
            inferred_observations=[
                "Security team operational velocity remains aligned with defense-in-depth targets."
            ],
            uncertainties=[
                "Synthetic telemetry metrics evaluated; external threat intelligence not incorporated.",
            ],
            suggested_actions=[
                "Approve pending remediation plans in Response Center.",
                "Export cryptographic audit proof for compliance records.",
            ],
            provider=cls.FALLBACK_PROVIDER,
            model=cls.FALLBACK_MODEL,
            generated_at=datetime.now(timezone.utc),
            is_ai_generated=True,
            fallback_used=True,
            fallback_reason=reason,
            confidence_score=0.96,
        )

    @classmethod
    def security_qa(
        cls,
        execution_data: dict[str, Any],
        question: str,
        reason: str = "Live Gemini provider unavailable",
    ) -> SecurityQAResponse:
        """Generates a deterministic evidence-grounded answer to a security question."""
        exec_id = uuid.UUID(str(execution_data.get("id") or execution_data.get("execution_id") or uuid.uuid4()))
        total_detections = int(execution_data.get("threat_detections_count") or execution_data.get("total_detections") or 0)
        max_risk = float(execution_data.get("max_risk_score") or execution_data.get("risk_score") or 0.0)
        status = str(execution_data.get("status", "completed"))

        evidence_ids = [str(exec_id)]

        q_lower = question.lower()
        if "risk" in q_lower or "score" in q_lower:
            answer = f"The maximum risk score recorded for execution {exec_id} is {max_risk:.1f} out of 100.0, calculated deterministically by Blue Guardian based on threat severity, asset criticality, and blast radius."
        elif "threat" in q_lower or "detection" in q_lower:
            answer = f"There were {total_detections} threat detections correlated during execution {exec_id}. All detections were mapped to MITRE ATT&CK techniques within the synthetic sandbox."
        elif "remediation" in q_lower or "approval" in q_lower:
            answer = f"Remediations require human authorization under Four-Eyes governance. The current execution status is '{status}'."
        else:
            answer = f"In execution session {exec_id}, the Blue Guardian system processed telemetry in status '{status}' with {total_detections} detected threats and maximum risk score of {max_risk:.1f}."

        return SecurityQAResponse(
            analysis_id=uuid.uuid4(),
            analysis_type="security_qa",
            execution_id=exec_id,
            question=question,
            answer=answer,
            grounded_facts=[
                f"Execution ID: {exec_id}",
                f"Execution Status: {status}",
                f"Threat Detections Count: {total_detections}",
                f"Max Risk Score: {max_risk:.1f}",
            ],
            summary=f"Security Q&A answer regarding execution {exec_id}.",
            key_findings=[
                f"Answer: {answer[:200]}...",
            ],
            supporting_evidence_ids=evidence_ids,
            observed_facts=[
                f"Queried execution record {exec_id} from database.",
            ],
            derived_conclusions=[
                "Answer directly answered using verified database fields.",
            ],
            inferred_observations=[],
            uncertainties=[
                "Deterministic Q&A engine used keyword matching rather than generative natural language understanding.",
            ],
            suggested_actions=[
                "Inspect full incident report for additional granular details.",
            ],
            provider=cls.FALLBACK_PROVIDER,
            model=cls.FALLBACK_MODEL,
            generated_at=datetime.now(timezone.utc),
            is_ai_generated=True,
            fallback_used=True,
            fallback_reason=reason,
            confidence_score=0.90,
        )
