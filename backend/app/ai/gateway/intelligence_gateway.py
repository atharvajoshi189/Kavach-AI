"""Centralized AI Intelligence Gateway coordinating generative analysis, evidence guarding, and persistence."""

from datetime import datetime, timezone
import logging
from typing import Any, Optional, Set, Type, TypeVar
import uuid

from fastapi import HTTPException
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.ai.fallbacks.fallback_generator import FallbackGenerator
from app.ai.prompts.system_instructions import BASE_CYBERSECURITY_SYSTEM_INSTRUCTION
from app.ai.prompts.templates import (
    build_attack_path_prompt,
    build_executive_briefing_prompt,
    build_incident_summary_prompt,
    build_recommendation_prompt,
    build_risk_explanation_prompt,
    build_security_qa_prompt,
    build_threat_explanation_prompt,
)
from app.ai.providers.base import AIProviderError, BaseAIProvider
from app.ai.providers.gemini_provider import GeminiProvider
from app.ai.safety.evidence_guard import EvidenceGuard
from app.ai.safety.input_validator import sanitize_untrusted_text
from app.ai.safety.output_validator import validate_ai_output
from app.ai.schemas.agent_schemas import AegisAgentOutput
from app.ai.schemas.ai_responses import (
    AttackPathAnalysisResponse,
    BaseAIAnalysisResponse,
    ExecutiveBriefingResponse,
    IncidentSummaryResponse,
    RecommendationExplanationResponse,
    RiskExplanationResponse,
    SecurityQAResponse,
    ThreatExplanationResponse,
)
from app.ai.services.ai_cache_service import ai_cache
from app.ai.services.ai_usage_service import ai_usage
from app.core.config import settings
from app.models.ai import AIAnalysisRecord
from app.models.attack_path import AttackPath
from app.models.attack_path_stage import AttackPathStage
from app.models.guardian import (
    CorrelatedEventGroup,
    DefensiveEventRecord,
    DefensiveRecommendation,
    GuardianExecution,
    IncidentReport,
    ThreatAssetImpact,
    ThreatDetection,
    ThreatRiskAssessment,
)
from app.models.synthetic_asset import SyntheticAsset
from app.models.user import User

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseAIAnalysisResponse)


class IntelligenceGateway:
    """Coordinates generative AI analysis with deterministic evidence grounding and forensic persistence."""

    def __init__(self, provider: Optional[BaseAIProvider] = None):
        self._provider = provider or GeminiProvider()
        self._prompt_version = "v1.0"

    @property
    def provider(self) -> BaseAIProvider:
        return self._provider

    # --------------------------------------------------------------------------
    # Threat Intelligence Explainer
    # --------------------------------------------------------------------------
    async def explain_threat(
        self,
        session: AsyncSession,
        user: User,
        detection_id: uuid.UUID,
        sandbox_id: uuid.UUID,
    ) -> ThreatExplanationResponse:
        """Explains a ThreatDetection record using persisted telemetry."""
        # 1. Fetch detection and related entities
        stmt = (
            select(ThreatDetection)
            .where(
                ThreatDetection.id == detection_id,
                ThreatDetection.sandbox_id == sandbox_id,
            )
            .options(
                selectinload(ThreatDetection.correlated_group),
            )
        )
        res = await session.execute(stmt)
        detection = res.scalar_one_or_none()
        if not detection:
            raise HTTPException(status_code=404, detail="Threat detection not found in sandbox.")

        # 2. Build evidence payload and valid ID set
        valid_ids: Set[str] = {str(detection.id)}
        target_asset_str = None
        if detection.affected_asset_ids:
            for aid in detection.affected_asset_ids:
                valid_ids.add(str(aid))
            target_asset_str = detection.affected_asset_ids[0]
        if detection.correlated_group_id:
            valid_ids.add(str(detection.correlated_group_id))

        event_summaries: list[dict[str, Any]] = []
        if detection.correlated_group and detection.correlated_group.member_event_ids:
            for ev_id in detection.correlated_group.member_event_ids[:10]:
                valid_ids.add(str(ev_id))
                event_summaries.append({
                    "event_id": str(ev_id),
                })

        technique_str = None
        if detection.mitre_techniques:
            first_t = detection.mitre_techniques[0]
            technique_str = first_t.get("technique_id") if isinstance(first_t, dict) else str(first_t)

        evidence = {
            "detection_id": str(detection.id),
            "rule_name": detection.title or detection.rule_code,
            "detection_type": detection.classification,
            "severity": detection.severity,
            "mitre_technique_id": technique_str or "T1078",
            "mitre_tactic": detection.mitre_tactics[0] if detection.mitre_tactics else "General",
            "description": detection.description,
            "target_asset_id": target_asset_str,
            "target_asset_name": "Synthetic Asset",
            "confidence_score": detection.confidence_score,
            "events": event_summaries,
        }

        # 3. Check Cache
        cache_key = ai_cache.build_cache_key(
            analysis_type="threat_explanation",
            source_entity_id=str(detection.id),
            source_version=str(detection.created_at),
            model=self._provider.model_name,
        )
        cached = ai_cache.get(cache_key)
        if cached:
            return ThreatExplanationResponse.model_validate(cached)

        # 4. Generate Analysis via Provider or Fallback
        prompt = build_threat_explanation_prompt(evidence)
        fallback_func = lambda reason: FallbackGenerator.threat_explanation(evidence, reason=reason)

        response = await self._execute_capability(
            capability="threat_explain",
            system_instruction=BASE_CYBERSECURITY_SYSTEM_INSTRUCTION,
            prompt=prompt,
            schema=ThreatExplanationResponse,
            valid_evidence_ids=valid_ids,
            fallback_factory=fallback_func,
        )

        # 5. Persist Analysis Record
        await self._persist_analysis(
            session=session,
            user=user,
            sandbox_id=sandbox_id,
            guardian_execution_id=detection.guardian_execution_id,
            analysis_type="threat_explanation",
            source_entity_type="threat_detection",
            source_entity_id=detection.id,
            response=response,
        )

        # 6. Store in Cache
        ai_cache.set(cache_key, response.model_dump())
        return response

    # --------------------------------------------------------------------------
    # Attack Path Analyst
    # --------------------------------------------------------------------------
    async def analyze_attack_path(
        self,
        session: AsyncSession,
        user: User,
        attack_path_id: uuid.UUID,
        sandbox_id: uuid.UUID,
    ) -> AttackPathAnalysisResponse:
        """Analyzes a multi-stage AttackPath record and its progression."""
        stmt = (
            select(AttackPath)
            .where(
                AttackPath.id == attack_path_id,
                AttackPath.sandbox_id == sandbox_id,
            )
            .options(
                selectinload(AttackPath.stages),
                selectinload(AttackPath.source_asset),
            )
        )
        res = await session.execute(stmt)
        attack_path = res.scalar_one_or_none()
        if not attack_path:
            raise HTTPException(status_code=404, detail="Attack path not found in sandbox.")

        valid_ids: Set[str] = {str(attack_path.id)}
        if attack_path.source_asset_id:
            valid_ids.add(str(attack_path.source_asset_id))

        stages_data: list[dict[str, Any]] = []
        for stage in attack_path.stages:
            valid_ids.add(str(stage.id))
            target_id = getattr(stage, "destination_asset_id", None) or getattr(stage, "target_asset_id", None)
            if target_id:
                valid_ids.add(str(target_id))
            stages_data.append({
                "stage_id": str(stage.id),
                "stage_number": stage.sequence_number if hasattr(stage, "sequence_number") else stage.stage_order,
                "technique": getattr(stage, "scenario_id", getattr(stage, "technique_id", "Unknown")),
                "status": stage.status,
                "target_asset_id": str(target_id) if target_id else None,
                "risk_score": getattr(stage, "risk_score", getattr(stage, "stage_risk_score", 0.0)) or 0.0,
            })

        evidence = {
            "attack_path_id": str(attack_path.id),
            "status": attack_path.status,
            "total_stages": attack_path.total_stages,
            "completed_stages": attack_path.completed_stages,
            "risk_score": attack_path.risk_score or 0.0,
            "execution_mode": attack_path.execution_mode,
            "source_asset_name": attack_path.source_asset.name if attack_path.source_asset else "Unknown",
            "stages": stages_data,
        }

        cache_key = ai_cache.build_cache_key(
            analysis_type="attack_path_analysis",
            source_entity_id=str(attack_path.id),
            source_version=str(attack_path.created_at),
            model=self._provider.model_name,
        )
        cached = ai_cache.get(cache_key)
        if cached:
            return AttackPathAnalysisResponse.model_validate(cached)

        prompt = build_attack_path_prompt(evidence)
        fallback_func = lambda reason: FallbackGenerator.attack_path_analysis(evidence, reason=reason)

        response = await self._execute_capability(
            capability="attack_path_analyze",
            system_instruction=BASE_CYBERSECURITY_SYSTEM_INSTRUCTION,
            prompt=prompt,
            schema=AttackPathAnalysisResponse,
            valid_evidence_ids=valid_ids,
            fallback_factory=fallback_func,
        )

        await self._persist_analysis(
            session=session,
            user=user,
            sandbox_id=sandbox_id,
            guardian_execution_id=None,
            analysis_type="attack_path_analysis",
            source_entity_type="attack_path",
            source_entity_id=attack_path.id,
            response=response,
        )

        ai_cache.set(cache_key, response.model_dump())
        return response

    # --------------------------------------------------------------------------
    # Risk Assessment Explainer
    # --------------------------------------------------------------------------
    async def explain_risk(
        self,
        session: AsyncSession,
        user: User,
        assessment_id: uuid.UUID,
        sandbox_id: uuid.UUID,
    ) -> RiskExplanationResponse:
        """Explains deterministic risk scoring for a ThreatRiskAssessment record."""
        stmt = (
            select(ThreatRiskAssessment)
            .where(
                ThreatRiskAssessment.id == assessment_id,
                ThreatRiskAssessment.sandbox_id == sandbox_id,
            )
            .options(
                selectinload(ThreatRiskAssessment.threat_detection),
                selectinload(ThreatRiskAssessment.asset_impacts),
            )
        )
        res = await session.execute(stmt)
        assessment = res.scalar_one_or_none()
        if not assessment:
            raise HTTPException(status_code=404, detail="Risk assessment not found in sandbox.")

        valid_ids: Set[str] = {str(assessment.id)}
        if assessment.threat_detection_id:
            valid_ids.add(str(assessment.threat_detection_id))
        for impact in assessment.asset_impacts:
            valid_ids.add(str(impact.id))
            valid_ids.add(str(impact.asset_id))

        evidence = {
            "assessment_id": str(assessment.id),
            "threat_detection_id": str(assessment.threat_detection_id) if assessment.threat_detection_id else None,
            "overall_risk_score": assessment.risk_score,
            "risk_score": assessment.risk_score,
            "risk_level": assessment.risk_category,
            "assessment_status": assessment.assessment_status,
            "calculated_at": assessment.assessed_at.isoformat() if assessment.assessed_at else "",
            "threat_rule": assessment.threat_detection.title if assessment.threat_detection else "Unknown",
            "impacts_count": len(assessment.asset_impacts),
        }

        cache_key = ai_cache.build_cache_key(
            analysis_type="risk_explanation",
            source_entity_id=str(assessment.id),
            source_version=str(assessment.assessed_at),
            model=self._provider.model_name,
        )
        cached = ai_cache.get(cache_key)
        if cached:
            return RiskExplanationResponse.model_validate(cached)

        prompt = build_risk_explanation_prompt(evidence)
        fallback_func = lambda reason: FallbackGenerator.risk_explanation(evidence, reason=reason)

        response = await self._execute_capability(
            capability="risk_explain",
            system_instruction=BASE_CYBERSECURITY_SYSTEM_INSTRUCTION,
            prompt=prompt,
            schema=RiskExplanationResponse,
            valid_evidence_ids=valid_ids,
            fallback_factory=fallback_func,
            authoritative_score=assessment.risk_score,
        )

        await self._persist_analysis(
            session=session,
            user=user,
            sandbox_id=sandbox_id,
            guardian_execution_id=assessment.guardian_execution_id,
            analysis_type="risk_explanation",
            source_entity_type="threat_risk_assessment",
            source_entity_id=assessment.id,
            response=response,
        )

        ai_cache.set(cache_key, response.model_dump())
        return response

    # --------------------------------------------------------------------------
    # Incident Intelligence Summarizer
    # --------------------------------------------------------------------------
    async def summarize_incident(
        self,
        session: AsyncSession,
        user: User,
        report_id: uuid.UUID,
        sandbox_id: uuid.UUID,
    ) -> IncidentSummaryResponse:
        """Synthesizes comprehensive incident intelligence for an IncidentReport."""
        stmt = (
            select(IncidentReport)
            .where(
                IncidentReport.id == report_id,
                IncidentReport.sandbox_id == sandbox_id,
            )
        )
        res = await session.execute(stmt)
        report = res.scalar_one_or_none()
        if not report:
            raise HTTPException(status_code=404, detail="Incident report not found in sandbox.")

        valid_ids: Set[str] = {str(report.id)}
        if report.guardian_execution_id:
            valid_ids.add(str(report.guardian_execution_id))

        evidence = {
            "report_id": str(report.id),
            "title": report.title,
            "severity": report.severity,
            "report_status": report.report_status,
            "executive_summary": report.executive_summary,
            "incident_narrative": report.executive_summary,
            "total_detections": len(report.detection_summaries) if report.detection_summaries else 1,
            "total_impacted_assets": len(report.affected_asset_ids) if report.affected_asset_ids else 1,
            "max_risk_score": report.max_risk_score,
        }

        cache_key = ai_cache.build_cache_key(
            analysis_type="incident_summary",
            source_entity_id=str(report.id),
            source_version=str(report.created_at),
            model=self._provider.model_name,
        )
        cached = ai_cache.get(cache_key)
        if cached:
            return IncidentSummaryResponse.model_validate(cached)

        prompt = build_incident_summary_prompt(evidence)
        fallback_func = lambda reason: FallbackGenerator.incident_summary(evidence, reason=reason)

        response = await self._execute_capability(
            capability="incident_summarize",
            system_instruction=BASE_CYBERSECURITY_SYSTEM_INSTRUCTION,
            prompt=prompt,
            schema=IncidentSummaryResponse,
            valid_evidence_ids=valid_ids,
            fallback_factory=fallback_func,
        )

        await self._persist_analysis(
            session=session,
            user=user,
            sandbox_id=sandbox_id,
            guardian_execution_id=report.guardian_execution_id,
            analysis_type="incident_summary",
            source_entity_type="incident_report",
            source_entity_id=report.id,
            response=response,
        )

        ai_cache.set(cache_key, response.model_dump())
        return response

    # --------------------------------------------------------------------------
    # Defensive Recommendation Explainer
    # --------------------------------------------------------------------------
    async def explain_recommendation(
        self,
        session: AsyncSession,
        user: User,
        recommendation_id: uuid.UUID,
        sandbox_id: uuid.UUID,
    ) -> RecommendationExplanationResponse:
        """Explains rationale and operational side-effects of a DefensiveRecommendation."""
        stmt = (
            select(DefensiveRecommendation)
            .where(
                DefensiveRecommendation.id == recommendation_id,
                DefensiveRecommendation.sandbox_id == sandbox_id,
            )
            .options(
                selectinload(DefensiveRecommendation.threat_detection),
                selectinload(DefensiveRecommendation.risk_assessment),
            )
        )
        res = await session.execute(stmt)
        rec = res.scalar_one_or_none()
        if not rec:
            raise HTTPException(status_code=404, detail="Recommendation not found in sandbox.")

        valid_ids: Set[str] = {str(rec.id)}
        if rec.threat_detection_id:
            valid_ids.add(str(rec.threat_detection_id))
        if rec.risk_assessment_id:
            valid_ids.add(str(rec.risk_assessment_id))

        evidence = {
            "recommendation_id": str(rec.id),
            "recommendation_code": rec.recommendation_code,
            "playbook_id": rec.playbook_id,
            "playbook_name": getattr(rec, "playbook_name", rec.playbook_id),
            "title": rec.title,
            "description": rec.description,
            "priority": rec.priority,
            "recommendation_type": rec.recommendation_type,
            "requires_approval": True,
            "target_asset_name": "Synthetic Asset",
        }

        cache_key = ai_cache.build_cache_key(
            analysis_type="recommendation_explanation",
            source_entity_id=str(rec.id),
            source_version=str(rec.created_at),
            model=self._provider.model_name,
        )
        cached = ai_cache.get(cache_key)
        if cached:
            return RecommendationExplanationResponse.model_validate(cached)

        prompt = build_recommendation_prompt(evidence)
        fallback_func = lambda reason: FallbackGenerator.recommendation_explanation(evidence, reason=reason)

        response = await self._execute_capability(
            capability="recommendation_explain",
            system_instruction=BASE_CYBERSECURITY_SYSTEM_INSTRUCTION,
            prompt=prompt,
            schema=RecommendationExplanationResponse,
            valid_evidence_ids=valid_ids,
            fallback_factory=fallback_func,
        )

        await self._persist_analysis(
            session=session,
            user=user,
            sandbox_id=sandbox_id,
            guardian_execution_id=rec.guardian_execution_id,
            analysis_type="recommendation_explanation",
            source_entity_type="defensive_recommendation",
            source_entity_id=rec.id,
            response=response,
        )

        ai_cache.set(cache_key, response.model_dump())
        return response

    # --------------------------------------------------------------------------
    # Executive Security Briefing
    # --------------------------------------------------------------------------
    async def generate_executive_briefing(
        self,
        session: AsyncSession,
        user: User,
        execution_id: uuid.UUID,
        sandbox_id: uuid.UUID,
    ) -> ExecutiveBriefingResponse:
        """Produces a C-level executive posture briefing for a GuardianExecution."""
        stmt = (
            select(GuardianExecution)
            .where(
                GuardianExecution.id == execution_id,
                GuardianExecution.sandbox_id == sandbox_id,
            )
        )
        res = await session.execute(stmt)
        execution = res.scalar_one_or_none()
        if not execution:
            raise HTTPException(status_code=404, detail="Guardian execution not found in sandbox.")

        valid_ids: Set[str] = {str(execution.id)}
        evidence = {
            "execution_id": str(execution.id),
            "status": execution.status,
            "events_ingested": execution.events_ingested,
            "threat_detections_count": execution.threat_detections_count,
            "max_risk_score": execution.max_risk_score,
            "recommendations_count": execution.recommendations_count,
            "remediation_plans_count": execution.remediation_plans_count,
            "started_at": execution.started_at.isoformat() if execution.started_at else "",
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else "",
        }

        cache_key = ai_cache.build_cache_key(
            analysis_type="executive_briefing",
            source_entity_id=str(execution.id),
            source_version=str(execution.completed_at or execution.created_at),
            model=self._provider.model_name,
        )
        cached = ai_cache.get(cache_key)
        if cached:
            return ExecutiveBriefingResponse.model_validate(cached)

        prompt = build_executive_briefing_prompt(evidence)
        fallback_func = lambda reason: FallbackGenerator.executive_briefing(evidence, reason=reason)

        response = await self._execute_capability(
            capability="executive_briefing",
            system_instruction=BASE_CYBERSECURITY_SYSTEM_INSTRUCTION,
            prompt=prompt,
            schema=ExecutiveBriefingResponse,
            valid_evidence_ids=valid_ids,
            fallback_factory=fallback_func,
        )

        await self._persist_analysis(
            session=session,
            user=user,
            sandbox_id=sandbox_id,
            guardian_execution_id=execution.id,
            analysis_type="executive_briefing",
            source_entity_type="guardian_execution",
            source_entity_id=execution.id,
            response=response,
        )

        ai_cache.set(cache_key, response.model_dump())
        return response

    # --------------------------------------------------------------------------
    # Context-Aware Security Q&A
    # --------------------------------------------------------------------------
    async def answer_security_question(
        self,
        session: AsyncSession,
        user: User,
        execution_id: uuid.UUID,
        question: str,
        sandbox_id: uuid.UUID,
    ) -> SecurityQAResponse:
        """Answers an ad-hoc security question using strictly verified execution telemetry."""
        clean_q = sanitize_untrusted_text(question, max_length=1000)
        if not clean_q:
            raise HTTPException(status_code=400, detail="Question cannot be empty.")

        stmt = (
            select(GuardianExecution)
            .where(
                GuardianExecution.id == execution_id,
                GuardianExecution.sandbox_id == sandbox_id,
            )
        )
        res = await session.execute(stmt)
        execution = res.scalar_one_or_none()
        if not execution:
            raise HTTPException(status_code=404, detail="Guardian execution not found in sandbox.")

        valid_ids: Set[str] = {str(execution.id)}
        evidence = {
            "execution_id": str(execution.id),
            "status": execution.status,
            "threat_detections_count": execution.threat_detections_count,
            "max_risk_score": execution.max_risk_score,
            "events_ingested": execution.events_ingested,
        }

        prompt = build_security_qa_prompt(evidence, clean_q)
        fallback_func = lambda reason: FallbackGenerator.security_qa(evidence, clean_q, reason=reason)

        response = await self._execute_capability(
            capability="security_qa",
            system_instruction=BASE_CYBERSECURITY_SYSTEM_INSTRUCTION,
            prompt=prompt,
            schema=SecurityQAResponse,
            valid_evidence_ids=valid_ids,
            fallback_factory=fallback_func,
        )

        await self._persist_analysis(
            session=session,
            user=user,
            sandbox_id=sandbox_id,
            guardian_execution_id=execution.id,
            analysis_type="security_qa",
            source_entity_type="guardian_execution",
            source_entity_id=execution.id,
            response=response,
        )

        return response

    # --------------------------------------------------------------------------
    # Persisted Analysis Listing
    # --------------------------------------------------------------------------
    async def list_execution_analyses(
        self,
        session: AsyncSession,
        execution_id: uuid.UUID,
        sandbox_id: uuid.UUID,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[AIAnalysisRecord], int]:
        """Queries persisted historical AI analysis records for a given execution."""
        base_query = select(AIAnalysisRecord).where(
            AIAnalysisRecord.guardian_execution_id == execution_id,
            AIAnalysisRecord.sandbox_id == sandbox_id,
        )

        count_res = await session.execute(
            select(func.count()).select_from(base_query.subquery())
        )
        total = count_res.scalar_one()

        offset = max(0, (page - 1) * page_size)
        items_res = await session.execute(
            base_query.order_by(desc(AIAnalysisRecord.created_at))
            .offset(offset)
            .limit(page_size)
        )
        items = list(items_res.scalars().all())
        return items, total

    # --------------------------------------------------------------------------
    # Core Pipeline Executor
    # --------------------------------------------------------------------------
    async def _execute_capability(
        self,
        capability: str,
        system_instruction: str,
        prompt: str,
        schema: Type[T],
        valid_evidence_ids: Set[str],
        fallback_factory: Any,
        authoritative_score: Optional[float] = None,
    ) -> T:
        """Executes LLM query with schema validation, evidence verification, and fallback handling."""
        if not self._provider.is_available():
            logger.info("Provider '%s' unavailable. Invoking deterministic fallback for '%s'", self._provider.provider_name, capability)
            ai_usage.record_request(
                capability=capability,
                success=True,
                fallback_used=True,
                latency_ms=1.0,
            )
            return fallback_factory("Provider disabled or unconfigured")

        try:
            raw_dict, p_tok, c_tok, latency = await self._provider.generate_structured_response(
                system_instruction=system_instruction,
                prompt=prompt,
                response_schema=schema,
            )

            # Apply EvidenceGuard grounding checks
            raw_dict = EvidenceGuard.verify_evidence_references(
                raw_dict,
                known_valid_ids=valid_evidence_ids,
                strict=False,
            )
            if authoritative_score is not None:
                raw_dict = EvidenceGuard.verify_risk_score_immutability(
                    raw_dict,
                    expected_score=authoritative_score,
                )
            raw_dict = EvidenceGuard.enforce_synthetic_boundary(raw_dict)

            # Validate against strict schema
            validated_obj = validate_ai_output(raw_dict, schema)

            ai_usage.record_request(
                capability=capability,
                success=True,
                fallback_used=False,
                prompt_tokens=p_tok,
                completion_tokens=c_tok,
                latency_ms=latency,
            )
            return validated_obj

        except Exception as e:
            logger.warning("Generative AI capability '%s' failed (%s: %s). Falling back to deterministic template.", capability, type(e).__name__, str(e))
            ai_usage.record_request(
                capability=capability,
                success=False,
                fallback_used=True,
                latency_ms=5.0,
            )
            return fallback_factory(f"Generative error: {type(e).__name__}")

    async def execute_agent_analysis(
        self,
        agent_name: str,
        system_instruction: str,
        prompt: str,
        valid_evidence_ids: Set[str],
        fallback_factory: Any,
        authoritative_score: Optional[float] = None,
    ) -> AegisAgentOutput:
        """Executes an individual specialized agent through the centralized Gemini provider and EvidenceGuard."""
        return await self._execute_capability(
            capability=f"agent.{agent_name}",
            system_instruction=system_instruction,
            prompt=prompt,
            schema=AegisAgentOutput,
            valid_evidence_ids=valid_evidence_ids,
            fallback_factory=fallback_factory,
            authoritative_score=authoritative_score,
        )

    # --------------------------------------------------------------------------
    # Persistence Helper
    # --------------------------------------------------------------------------
    async def _persist_analysis(
        self,
        session: AsyncSession,
        user: User,
        sandbox_id: uuid.UUID,
        guardian_execution_id: Optional[uuid.UUID],
        analysis_type: str,
        source_entity_type: str,
        source_entity_id: uuid.UUID,
        response: BaseAIAnalysisResponse,
    ) -> AIAnalysisRecord:
        """Persists the AI analysis into PostgreSQL."""
        record = AIAnalysisRecord(
            id=response.analysis_id,
            sandbox_id=sandbox_id,
            guardian_execution_id=guardian_execution_id,
            analysis_type=analysis_type,
            source_entity_type=source_entity_type,
            source_entity_id=source_entity_id,
            source_version="v1.0",
            provider=response.provider,
            model=response.model,
            prompt_version=self._prompt_version,
            response_content=response.model_dump(mode="json"),
            evidence_references=response.supporting_evidence_ids,
            fallback_used=response.fallback_used,
            fallback_reason=response.fallback_reason,
            tokens_used=None,
            latency_ms=None,
            created_at=response.generated_at,
            created_by=user.id if user else None,
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)
        return record


# Global singleton gateway
intelligence_gateway = IntelligenceGateway()
