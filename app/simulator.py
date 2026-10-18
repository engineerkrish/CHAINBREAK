
from itertools import combinations


def simulate_remediation(
    severity: str,
    service_criticality: str,
    affected_services: int,
):
    """
    Compare hypothetical remediation strategies.
    Scores are estimates for demo purposes, not measured guarantees.
    """

    severity_scores = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1,
    }

    criticality_scores = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 2,
    }

    severity = severity.upper()
    service_criticality = service_criticality.upper()

    if severity not in severity_scores:
        raise ValueError("Invalid severity")
    if service_criticality not in criticality_scores:
        raise ValueError("Invalid service criticality")
    if affected_services < 0:
        raise ValueError("affected_services cannot be negative")

    base_risk = (
        severity_scores[severity]
        * criticality_scores[service_criticality]
        * max(affected_services, 1)
    )

    strategies = [
        {
            "name": "Upgrade vulnerable package",
            "risk_reduction": 0.90,
            "effort": 4,
            "availability_impact": 2,
            "description": "Upgrade to a verified fixed version and run tests.",
        },
        {
            "name": "Isolate affected service",
            "risk_reduction": 0.75,
            "effort": 3,
            "availability_impact": 8,
            "description": "Restrict exposure while preparing a permanent fix.",
        },
        {
            "name": "Apply temporary mitigation",
            "risk_reduction": 0.50,
            "effort": 2,
            "availability_impact": 1,
            "description": "Apply a temporary control and schedule an upgrade.",
        },
        {
            "name": "Accept risk temporarily",
            "risk_reduction": 0.0,
            "effort": 1,
            "availability_impact": 0,
            "description": "Document the risk, owner, justification, and expiry.",
        },
    ]

    results = []

    for strategy in strategies:
        reduction = strategy["risk_reduction"]
        results.append({
            **strategy,
            "estimated_risk_before": base_risk,
            "estimated_risk_after": round(base_risk * (1 - reduction), 2),
            "estimated_risk_reduction_percent": round(reduction * 100),
            "approval_required": True,
            "execution_status": "NOT_EXECUTED",
            "score": round(
                reduction * 100
                - strategy["effort"] * 5
                - strategy["availability_impact"] * 3,
                2,
            ),
        })

    results.sort(key=lambda item: item["score"], reverse=True)

    return {
        "severity": severity,
        "service_criticality": service_criticality,
        "affected_services": affected_services,
        "estimated_base_risk": base_risk,
        "simulation_only": True,
        "recommendations": results,
        "notice": (
            "Illustrative estimates only. Verify fixed versions and test "
            "compatibility before approval. No remediation was executed."
        ),
    }
