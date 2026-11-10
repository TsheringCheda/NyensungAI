
"""Centralized heuristic risk scoring for NyensungAI."""

from typing import Any


def clamp_score(score: int | float) -> int:
    """Keep risk scores within the 0–100 range."""
    return max(0, min(100, round(score)))


def get_risk_severity(score: int | float) -> str:
    """Convert a numerical risk score into a severity."""
    score = clamp_score(score)

    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def calculate_risk_score(
    *,
    failed_logins: int = 0,
    unique_usernames: int = 0,
    unique_ports: int = 0,
    is_brute_force_detected: bool = False,
    is_ml_anomaly: bool = False,
    is_web_attack_indicator: bool = False,
    is_confirmed_malicious: bool = False,
) -> dict[str, Any]:
    """
    Calculate a transparent heuristic risk score.

    These weights are initial project rules, not calibrated probabilities.
    Normal network observations receive no additional risk.
    """

    score = 0
    factors = []

    if is_brute_force_detected:
        points = min(80, 60 + max(0, failed_logins - 5) * 4)
        score += points
        factors.append({
            "indicator": "Brute-force attack pattern detected",
            "points": points,
        })

    elif failed_logins >= 5:
        points = min(30, 10 + (failed_logins - 5) * 4)
        score += points
        factors.append({
            "indicator": "Repeated failed logins",
            "points": points,
        })

    if unique_usernames >= 5:
        score += 20
        factors.append({
            "indicator": "Multiple usernames targeted",
            "points": 20,
        })

    if unique_ports >= 8:
        score += 20
        factors.append({
            "indicator": "Possible port scanning",
            "points": 20,
        })

    if is_ml_anomaly:
        score += 15
        factors.append({
            "indicator": "ML anomaly detected",
            "points": 15,
        })

    if is_web_attack_indicator:
        score += 25
        factors.append({
            "indicator": "Web attack signature detected",
            "points": 25,
        })

    if is_confirmed_malicious:
        score += 40
        factors.append({
            "indicator": "Confirmed malicious indicator",
            "points": 40,
        })

    final_score = clamp_score(score)

    return {
        "risk_score": final_score,
        "severity": get_risk_severity(final_score),
        "risk_factors": factors,
        "scoring_method": "NYENSUNG_HEURISTIC_V1",
    }
