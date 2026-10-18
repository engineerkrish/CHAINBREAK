from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.database import get_graph
from app.simulator import simulate_remediation
from app.approvals import (
    create_approval,
    decide_approval,
    get_approval,
    list_approvals,
)


# --------------------------------------------------
# Application configuration
# --------------------------------------------------

app = FastAPI(
    title="CHAINBREAK API",
    description="Graph-powered software supply-chain vulnerability impact analysis",
    version="0.1.0",
)

# Allow the local React frontend to communicate with FastAPI.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "https://chainbreak-orpin.vercel.app",
],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# Root endpoint
# --------------------------------------------------

@app.get("/")
def root():
    return {
        "project": "CHAINBREAK",
        "status": "running",
        "docs": "/docs",
    }


# --------------------------------------------------
# Database health check
# --------------------------------------------------

@app.get("/health")
def health():
    try:
        graph = get_graph()
        graph.query("RETURN 1 AS ok")

        return {
            "status": "healthy",
            "database": "connected",
        }

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Database connection failed: {type(exc).__name__}",
        )


# --------------------------------------------------
# List vulnerabilities from FalkorDB
# --------------------------------------------------

@app.get("/vulnerabilities")
def list_vulnerabilities():
    try:
        graph = get_graph()

        result = graph.query(
            """
            MATCH (v:Vulnerability)
            RETURN v.id AS id,
                   v.severity AS severity,
                   v.title AS title
            ORDER BY v.id
            """
        )

        vulnerabilities = [
            {
                "id": row[0],
                "severity": row[1] or "UNKNOWN",
                "title": row[2] or "Untitled vulnerability",
            }
            for row in result.result_set
        ]

        return {
            "count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Vulnerability query failed: {type(exc).__name__}",
        )


# --------------------------------------------------
# Vulnerability blast-radius analysis
# --------------------------------------------------

@app.get("/blast-radius/{vulnerability_id}")
def blast_radius(vulnerability_id: str):
    try:
        graph = get_graph()

        result = graph.query(
            """
            MATCH (v:Vulnerability {id: $vulnerability_id})
            OPTIONAL MATCH (v)-[:AFFECTS]->(p:Package)
            OPTIONAL MATCH (p)-[:USED_BY]->(r:Repository)
            OPTIONAL MATCH (r)-[:DEPLOYED_IN]->(s:Service)
            RETURN v.id AS vulnerability,
                   v.severity AS severity,
                   v.title AS title,
                   collect(DISTINCT p.name) AS packages,
                   collect(DISTINCT r.name) AS repositories,
                   collect(DISTINCT s.name) AS services
            """,
            {"vulnerability_id": vulnerability_id},
        )

        if not result.result_set:
            raise HTTPException(
                status_code=404,
                detail="Vulnerability not found",
            )

        row = result.result_set[0]

        return {
            "vulnerability": row[0],
            "severity": row[1],
            "title": row[2],
            "packages": [
                item for item in (row[3] or []) if item
            ],
            "repositories": [
                item for item in (row[4] or []) if item
            ],
            "services": [
                item for item in (row[5] or []) if item
            ],
            "note": (
                "Impact depends on the dependency and deployment "
                "relationships represented in the graph."
            ),
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Blast-radius query failed: {type(exc).__name__}",
        )

# --------------------------------------------------
# Graph-grounded vulnerability investigation
# --------------------------------------------------

@app.get("/investigate/{vulnerability_id}")
def investigate_vulnerability(vulnerability_id: str):
    """
    Trace a vulnerability through the dependency graph and simulate
    remediation using the graph's actual severity and service data.

    This is a deterministic investigation workflow, not an LLM agent.
    No infrastructure changes are executed.
    """
    try:
        graph = get_graph()

        result = graph.query(
            """
            MATCH (v:Vulnerability {id: $vulnerability_id})
            OPTIONAL MATCH (v)-[:AFFECTS]->(p:Package)
            OPTIONAL MATCH (p)-[:USED_BY]->(r:Repository)
            OPTIONAL MATCH (r)-[:DEPLOYED_IN]->(s:Service)
            RETURN v.id AS vulnerability,
                   v.severity AS severity,
                   v.title AS title,
                   collect(DISTINCT p.name) AS packages,
                   collect(DISTINCT r.name) AS repositories,
                   collect(DISTINCT s.name) AS services,
                   collect(DISTINCT s.criticality) AS criticalities
            """,
            {"vulnerability_id": vulnerability_id},
        )

        if not result.result_set:
            raise HTTPException(
                status_code=404,
                detail="Vulnerability not found",
            )

        row = result.result_set[0]

        # Aggregation queries can return a row with a null vulnerability
        # when the requested node does not exist.
        if not row[0]:
            raise HTTPException(
                status_code=404,
                detail="Vulnerability not found",
            )

        packages = [x for x in (row[3] or []) if x]
        repositories = [x for x in (row[4] or []) if x]
        services = [x for x in (row[5] or []) if x]
        criticalities = [
            str(x).upper()
            for x in (row[6] or [])
            if x
        ]

        evidence = {
            "vulnerability": row[0],
            "title": row[2] or "Untitled vulnerability",
            "severity": str(row[1] or "UNKNOWN").upper(),
            "packages": packages,
            "repositories": repositories,
            "services": services,
            "service_criticalities": criticalities,
            "affected_service_count": len(services),
        }

        # Do not invent severity or criticality values if graph data
        # is incomplete or uses unsupported labels.
        supported_severities = {
            "CRITICAL", "HIGH", "MEDIUM", "LOW"
        }
        supported_criticalities = {
            "CRITICAL", "HIGH", "MEDIUM", "LOW"
        }

        if evidence["severity"] not in supported_severities:
            return {
                "status": "investigation_complete",
                "evidence": evidence,
                "simulation": None,
                "simulation_blocked_reason": (
                    "The graph does not contain a supported severity "
                    "value. Add or correct the vulnerability severity "
                    "before simulating remediation."
                ),
                "execution_status": "NOT_EXECUTED",
            }

        if not services:
            return {
                "status": "investigation_complete",
                "evidence": evidence,
                "simulation": None,
                "simulation_blocked_reason": (
                    "No affected services were found through the "
                    "represented dependency relationships."
                ),
                "execution_status": "NOT_EXECUTED",
            }

        unsupported = [
            value for value in criticalities
            if value not in supported_criticalities
        ]

        if unsupported or not criticalities:
            return {
                "status": "investigation_complete",
                "evidence": evidence,
                "simulation": None,
                "simulation_blocked_reason": (
                    "One or more affected services lack a supported "
                    "criticality value."
                ),
                "execution_status": "NOT_EXECUTED",
            }

        # Use the highest criticality among affected services.
        criticality_rank = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        service_criticality = max(
            criticalities,
            key=lambda value: criticality_rank[value],
        )

        simulation = simulate_remediation(
            severity=evidence["severity"],
            service_criticality=service_criticality,
            affected_services=len(services),
        )

        return {
            "status": "investigation_complete",
            "evidence": evidence,
            "simulation_inputs": {
                "severity": evidence["severity"],
                "service_criticality": service_criticality,
                "affected_services": len(services),
            },
            "simulation": simulation,
            "execution_status": "NOT_EXECUTED",
            "notice": (
                "Recommendations are illustrative. Graph evidence "
                "reflects only relationships represented in FalkorDB. "
                "No remediation was executed."
            ),
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Vulnerability investigation failed: "
                f"{type(exc).__name__}"
            ),
        )
# --------------------------------------------------
# Remediation simulation
# --------------------------------------------------

class SimulationRequest(BaseModel):
    severity: str = "CRITICAL"
    service_criticality: str = "HIGH"
    affected_services: int = Field(
        default=1,
        ge=0,
        le=10000,
    )


@app.post("/simulate-remediation")
def remediation_simulation(request: SimulationRequest):
    try:
        return simulate_remediation(
            severity=request.severity,
            service_criticality=request.service_criticality,
            affected_services=request.affected_services,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        )


# --------------------------------------------------
# Approval request models
# --------------------------------------------------

class ApprovalRequest(BaseModel):
    action: str = Field(min_length=1, max_length=200)
    vulnerability_id: str = Field(min_length=1, max_length=100)
    requested_by: str = Field(min_length=1, max_length=100)


class ApprovalDecision(BaseModel):
    decision: str
    decided_by: str = Field(min_length=1, max_length=100)
    reason: str = Field(default="", max_length=500)


# --------------------------------------------------
# Create an approval request
# --------------------------------------------------

@app.get("/approvals")
def approvals_list():
    return {"approvals": list_approvals()}


@app.post("/approvals")
def submit_approval(request: ApprovalRequest):
    try:
        return create_approval(
            action=request.action,
            vulnerability_id=request.vulnerability_id,
            requested_by=request.requested_by,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        )


# --------------------------------------------------
# Approve or reject a request
# --------------------------------------------------

@app.post("/approvals/{approval_id}/decision")
def submit_decision(
    approval_id: str,
    request: ApprovalDecision,
):
    try:
        return decide_approval(
            approval_id=approval_id,
            decision=request.decision,
            decided_by=request.decided_by,
            reason=request.reason,
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        )


# --------------------------------------------------
# Retrieve approval status
# --------------------------------------------------

@app.get("/approvals/{approval_id}")
def approval_status(approval_id: str):
    result = get_approval(approval_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Approval not found",
        )

    return result