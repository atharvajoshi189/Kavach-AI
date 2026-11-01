"""
AEGIS Vulnerability & Risk Management Subsystem
Step 09.2.3.4 - Risk Prioritization Engine

Implements deterministic prioritization and ranking of threat risk assessments,
enforcing multi-key sort orders, tie-breakers, and asset risk profile aggregations.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID

from app.models.guardian import ThreatRiskAssessment, ThreatAssetImpact, ThreatDetection
from app.agents.blue_guardian.schemas import AssetImpactType, RiskCategory


SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}


class RiskPrioritizer:
    """
    Deterministic prioritization engine for risk assessments and asset impacts.
    
    Sorting criteria for ThreatRiskAssessment:
      1. risk_score DESC
      2. detection severity DESC (Critical > High > Medium > Low > Informational)
      3. critical_asset_exposed DESC (True > False)
      4. directly_affected_count DESC
      5. detected_at ASC (Deterministic tie-breaker: earlier detection first)
    """

    @classmethod
    def rank_threats(cls, assessments: List[ThreatRiskAssessment]) -> List[ThreatRiskAssessment]:
        """
        Sorts a list of ThreatRiskAssessment instances deterministically.
        """
        def sort_key(assessment: ThreatRiskAssessment):
            risk_score = float(assessment.risk_score or 0.0)
            
            # Severity weight
            sev_str = "informational"
            if hasattr(assessment, "detection") and assessment.detection and hasattr(assessment.detection, "severity"):
                sev_val = assessment.detection.severity
                sev_str = sev_val.value if hasattr(sev_val, "value") else str(sev_val).lower()
            sev_rank = SEVERITY_ORDER.get(sev_str, 0)
            
            # Critical asset exposed flag
            crit_flag = 1 if getattr(assessment, "critical_asset_exposed", False) else 0
            
            # Directly affected count
            direct_count = int(getattr(assessment, "directly_affected_count", 0) or 0)
            
            # Detected timestamp tie breaker (earlier is prioritized, so negative timestamp or direct asc)
            det_time = datetime.min
            if hasattr(assessment, "detection") and assessment.detection and hasattr(assessment.detection, "detected_at"):
                det_time = assessment.detection.detected_at or datetime.min
            elif assessment.created_at:
                det_time = assessment.created_at

            # To sort descending on score, sev, crit, direct, and ascending on time:
            # We can use a tuple where positive/negative values represent direction.
            # ( -risk_score, -sev_rank, -crit_flag, -direct_count, det_time.timestamp(), str(assessment.id) )
            return (
                -risk_score,
                -sev_rank,
                -crit_flag,
                -direct_count,
                det_time.timestamp() if det_time else 0.0,
                str(assessment.id),
            )

        return sorted(assessments, key=sort_key)

    @classmethod
    def get_highest_risk_detection(
        cls, assessments: List[ThreatRiskAssessment]
    ) -> Optional[ThreatRiskAssessment]:
        """Returns the single highest-priority risk assessment, or None if list is empty."""
        if not assessments:
            return None
        ranked = cls.rank_threats(assessments)
        return ranked[0]

    @classmethod
    def build_asset_risk_profiles(
        cls,
        impacts: List[ThreatAssetImpact],
        assessments: Optional[List[ThreatRiskAssessment]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Aggregates risk exposure metrics per unique asset_id across given impacts.
        Returns a sorted list of asset profile dictionaries ranked by:
          1. max_risk_score DESC
          2. is_critical DESC
          3. direct_detection_count DESC
          4. asset_id ASC
        """
        # Map assessment_id to assessment for quick lookup if provided
        assessment_map: Dict[UUID, ThreatRiskAssessment] = {}
        if assessments:
            for ass in assessments:
                assessment_map[ass.id] = ass

        profiles_by_asset: Dict[UUID, Dict[str, Any]] = {}

        for imp in impacts:
            aid = imp.asset_id
            if aid not in profiles_by_asset:
                profiles_by_asset[aid] = {
                    "asset_id": aid,
                    "asset_name": imp.asset_name,
                    "asset_type": imp.asset_type,
                    "is_critical": imp.is_critical,
                    "max_risk_score": 0.0,
                    "associated_detection_ids": set(),
                    "direct_detection_count": 0,
                    "exposed_detection_count": 0,
                    "min_hop_distance": imp.hop_distance if imp.hop_distance is not None else 999,
                    "max_confidence": 0.0,
                }
            
            p = profiles_by_asset[aid]
            
            # Lookup risk score from impact or associated assessment
            score = 0.0
            det_id = None
            conf = 0.0
            
            if hasattr(imp, "risk_assessment") and imp.risk_assessment:
                score = float(imp.risk_assessment.risk_score or 0.0)
                det_id = imp.risk_assessment.threat_detection_id
                if imp.risk_assessment.detection:
                    conf = float(imp.risk_assessment.detection.confidence or 0.0)
            elif imp.risk_assessment_id in assessment_map:
                ass = assessment_map[imp.risk_assessment_id]
                score = float(ass.risk_score or 0.0)
                det_id = ass.threat_detection_id
                if ass.detection:
                    conf = float(ass.detection.confidence or 0.0)
            
            if score > p["max_risk_score"]:
                p["max_risk_score"] = score
            
            if conf > p["max_confidence"]:
                p["max_confidence"] = conf
                
            if det_id:
                p["associated_detection_ids"].add(det_id)

            imp_type_val = imp.impact_type.value if hasattr(imp.impact_type, "value") else str(imp.impact_type)
            if imp_type_val == AssetImpactType.DIRECTLY_AFFECTED.value:
                p["direct_detection_count"] += 1
            else:
                p["exposed_detection_count"] += 1

            if imp.hop_distance is not None and imp.hop_distance < p["min_hop_distance"]:
                p["min_hop_distance"] = imp.hop_distance

        # Format and sort profiles
        result = []
        for aid, data in profiles_by_asset.items():
            if data["min_hop_distance"] == 999:
                data["min_hop_distance"] = 0
            
            # Compute category
            max_score = data["max_risk_score"]
            if max_score >= 8.0:
                cat = RiskCategory.CRITICAL.value
            elif max_score >= 6.0:
                cat = RiskCategory.HIGH.value
            elif max_score >= 4.0:
                cat = RiskCategory.MEDIUM.value
            elif max_score >= 2.0:
                cat = RiskCategory.LOW.value
            else:
                cat = RiskCategory.INFORMATIONAL.value

            profile = {
                "asset_id": aid,
                "asset_name": data["asset_name"],
                "asset_type": data["asset_type"],
                "is_critical": data["is_critical"],
                "max_risk_score": round(max_score, 2),
                "risk_category": cat,
                "associated_detection_ids": sorted([str(did) for did in data["associated_detection_ids"]]),
                "total_threat_count": len(data["associated_detection_ids"]),
                "direct_detection_count": data["direct_detection_count"],
                "exposed_detection_count": data["exposed_detection_count"],
                "min_hop_distance": data["min_hop_distance"],
            }
            result.append(profile)

        def profile_sort_key(p: Dict[str, Any]):
            return (
                -p["max_risk_score"],
                -1 if p["is_critical"] else 0,
                -p["direct_detection_count"],
                str(p["asset_id"]),
            )

        return sorted(result, key=profile_sort_key)
