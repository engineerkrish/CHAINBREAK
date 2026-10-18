
from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4

_APPROVALS = {}
_LOCK = Lock()

VALID_STATUSES = {
    "PENDING",
    "APPROVED",
    "REJECTED",
}


def create_approval(
    action: str,
    vulnerability_id: str,
    requested_by: str,
):
    if not action.strip():
        raise ValueError("Action cannot be empty")

    if not vulnerability_id.strip():
        raise ValueError("Vulnerability ID cannot be empty")

    if not requested_by.strip():
        raise ValueError("Requester cannot be empty")

    approval_id = str(uuid4())

    record = {
        "approval_id": approval_id,
        "action": action.strip(),
        "vulnerability_id": vulnerability_id.strip(),
        "requested_by": requested_by.strip(),
        "status": "PENDING",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "decided_at": None,
        "decided_by": None,
        "reason": None,
        "execution_status": "NOT_EXECUTED",
    }

    with _LOCK:
        _APPROVALS[approval_id] = record.copy()

    return record


def decide_approval(
    approval_id: str,
    decision: str,
    decided_by: str,
    reason: str = "",
):
    decision = decision.upper().strip()

    if decision not in {"APPROVED", "REJECTED"}:
        raise ValueError("Decision must be APPROVED or REJECTED")

    if not decided_by.strip():
        raise ValueError("Decision maker cannot be empty")

    with _LOCK:
        record = _APPROVALS.get(approval_id)

        if record is None:
            raise KeyError("Approval request not found")

        if record["status"] != "PENDING":
            raise ValueError(
                f"Cannot decide a request with status {record['status']}"
            )

        record["status"] = decision
        record["decided_by"] = decided_by.strip()
        record["reason"] = reason.strip()
        record["decided_at"] = datetime.now(timezone.utc).isoformat()

        # Approval records authorization only.
        # It does not execute a remediation.
        record["execution_status"] = "NOT_EXECUTED"

        return record.copy()


def get_approval(approval_id: str):
    with _LOCK:
        record = _APPROVALS.get(approval_id)
        return record.copy() if record else None


def list_approvals():
    with _LOCK:
        return [record.copy() for record in _APPROVALS.values()]
