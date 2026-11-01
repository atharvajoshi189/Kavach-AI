"""Deterministic risk aggregation for attack paths."""
from typing import Optional

RISK_LEVEL_MAP = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}


def risk_level_to_float(risk_level: str) -> float:
    return RISK_LEVEL_MAP.get(risk_level, 0.5)


def calculate_path_risk(
    completed_stage_risk_scores: list[float],
    all_stage_risk_scores: list[float],
    asset_risk_levels: list[str],
    total_stages: int,
    completed_stages: int,
) -> float:
    """
    Calculates deterministic risk score bounded [0.0, 10.0].

    Formula:
      base_score = weighted_avg(completed_stage_risk_scores)  # only completed stages
      path_multiplier = min(1.0 + (path_length * 0.05), 1.5)
      asset_criticality = avg(risk_level_to_float(r) for r in asset_risk_levels)
      evidence_confidence = completed_stages / total_stages
      path_risk = min(base_score * path_multiplier * asset_criticality * evidence_confidence * 10.0, 10.0)
    """
    if not completed_stage_risk_scores or total_stages == 0:
        return 0.0

    base_score = sum(completed_stage_risk_scores) / len(completed_stage_risk_scores)
    path_multiplier = min(1.0 + (total_stages * 0.05), 1.5)
    asset_criticality = (
        sum(risk_level_to_float(r) for r in asset_risk_levels) / len(asset_risk_levels)
        if asset_risk_levels else 0.5
    )
    evidence_confidence = completed_stages / total_stages

    # base_score is already 0-10 range; normalize to 0-1 first
    normalized_base = base_score / 10.0
    path_risk = min(normalized_base * path_multiplier * asset_criticality * evidence_confidence * 10.0, 10.0)

    return round(path_risk, 4)

