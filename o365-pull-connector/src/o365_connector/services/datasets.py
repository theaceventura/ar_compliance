import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from o365_connector.clients.graph_client import GraphClient
from o365_connector.config import AppConfig
from o365_connector.utils.constants import (
    DSET_CONDITIONAL_ACCESS,
    DSET_DEFENDER_ALERTS,
    DSET_MFA_COVERAGE,
    DSET_ROLE_ASSIGNMENTS,
    DSET_SIGNINS,
)
from o365_connector.utils.errors import ConnectorError


def iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def parse_dt(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return datetime.utcnow().replace(tzinfo=timezone.utc)


def hash_payload(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def normalize_signin(item: Dict[str, Any]) -> Dict[str, Any]:
    occurred_at = parse_dt(item.get("createdDateTime"))
    status = item.get("status") or {}
    severity = "medium"
    if status.get("errorCode") not in (None, 0):
        severity = "high"
    if item.get("riskLevelAggregated") == "high":
        severity = "high"
    actor = {
        "userPrincipalName": item.get("userPrincipalName"),
        "userId": item.get("userId"),
    }
    target = {"appDisplayName": item.get("appDisplayName")}
    summary = f"Sign-in by {actor.get('userPrincipalName')} to {target.get('appDisplayName')}"
    return {
        "type": "SignInEvent",
        "occurred_at": occurred_at,
        "actor": actor,
        "target": target,
        "severity": severity,
        "confidence": "medium",
        "summary": summary,
        "details": {
            "ipAddress": item.get("ipAddress"),
            "status": status,
            "clientAppUsed": item.get("clientAppUsed"),
            "conditionalAccessStatus": item.get("conditionalAccessStatus"),
        },
    }


def normalize_role_assignment(item: Dict[str, Any]) -> Dict[str, Any]:
    occurred_at = parse_dt(item.get("createdDateTime") or item.get("modifiedDateTime") or iso(datetime.utcnow()))
    actor = {"userId": item.get("principalId")}
    target = {"roleDefinitionId": item.get("roleDefinitionId")}
    summary = f"Role assignment {item.get('id')} for principal {item.get('principalId')}"
    return {
        "type": "PrivilegeAssignment",
        "occurred_at": occurred_at,
        "actor": actor,
        "target": target,
        "severity": "high",
        "confidence": "high",
        "summary": summary,
        "details": {"directoryScopeId": item.get("directoryScopeId")},
    }


def normalize_conditional_access(item: Dict[str, Any]) -> Dict[str, Any]:
    occurred_at = parse_dt(item.get("modifiedDateTime") or iso(datetime.utcnow()))
    severity = "medium"
    state = item.get("state")
    if state == "disabled":
        severity = "high"
    summary = f"Conditional access policy {item.get('displayName')} is {state}"
    return {
        "type": "ConditionalAccessPolicy",
        "occurred_at": occurred_at,
        "actor": {"policyId": item.get("id")},
        "target": {"displayName": item.get("displayName")},
        "severity": severity,
        "confidence": "high",
        "summary": summary,
        "details": {"state": state},
    }


def normalize_mfa(item: Dict[str, Any]) -> Dict[str, Any]:
    occurred_at = parse_dt(item.get("createdDateTime") or iso(datetime.utcnow()))
    methods = item.get("methodIds") or []
    has_mfa = len(methods) > 0
    severity = "medium" if has_mfa else "high"
    summary = f"MFA registration for {item.get('userPrincipalName')}: {'enabled' if has_mfa else 'missing'}"
    return {
        "type": "MFARegistrationStatus",
        "occurred_at": occurred_at,
        "actor": {"userPrincipalName": item.get("userPrincipalName"), "userId": item.get("id")},
        "target": {},
        "severity": severity,
        "confidence": "high",
        "summary": summary,
        "details": {"methods": methods, "isRegistered": has_mfa},
    }


DatasetResult = Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Optional[Dict[str, Any]]]


class DatasetHandlers:
    def __init__(self, config: AppConfig):
        self.config = config

    def pull(
        self, dataset: str, client: GraphClient, state_cursor: Optional[Dict[str, Any]]
    ) -> DatasetResult:
        if dataset == DSET_SIGNINS:
            return self._pull_signins(client, state_cursor)
        if dataset == DSET_ROLE_ASSIGNMENTS:
            return self._pull_role_assignments(client, state_cursor)
        if dataset == DSET_CONDITIONAL_ACCESS:
            return self._pull_conditional_access(client, state_cursor)
        if dataset == DSET_MFA_COVERAGE:
            return self._pull_mfa(client, state_cursor)
        if dataset == DSET_DEFENDER_ALERTS:
            raise ConnectorError("defender_alerts disabled in this build")
        raise ConnectorError(f"Unsupported dataset {dataset}")

    def _pull_signins(
        self, client: GraphClient, state_cursor: Optional[Dict[str, Any]]
    ) -> DatasetResult:
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        start_time = now - self.config.default_pull_window
        if state_cursor and state_cursor.get("last_seen"):
            start_time = parse_dt(state_cursor["last_seen"])
        params = {"$filter": f"createdDateTime ge {iso(start_time)}", "$orderby": "createdDateTime asc"}
        raw_items: List[Dict[str, Any]] = []
        normalized_items: List[Dict[str, Any]] = []
        latest = start_time
        for item in client.get_paginated("/auditLogs/signIns", params=params):
            raw_items.append(item)
            norm = normalize_signin(item)
            normalized_items.append(norm)
            if norm["occurred_at"] > latest:
                latest = norm["occurred_at"]
        cursor = {"last_seen": iso(latest)} if raw_items else state_cursor
        return raw_items, normalized_items, cursor

    def _pull_role_assignments(
        self, client: GraphClient, state_cursor: Optional[Dict[str, Any]]
    ) -> DatasetResult:
        params = {}
        raw_items: List[Dict[str, Any]] = []
        normalized_items: List[Dict[str, Any]] = []
        latest = parse_dt(state_cursor["last_seen"]) if state_cursor and state_cursor.get("last_seen") else None
        for item in client.get_paginated("/roleManagement/directory/roleAssignments", params=params):
            raw_items.append(item)
            norm = normalize_role_assignment(item)
            normalized_items.append(norm)
            if latest is None or norm["occurred_at"] > latest:
                latest = norm["occurred_at"]
        cursor = {"last_seen": iso(latest)} if latest else state_cursor
        return raw_items, normalized_items, cursor

    def _pull_conditional_access(
        self, client: GraphClient, state_cursor: Optional[Dict[str, Any]]
    ) -> DatasetResult:
        raw_items = list(client.get_paginated("/identity/conditionalAccess/policies"))
        normalized_items = [normalize_conditional_access(item) for item in raw_items]
        latest = None
        for item in normalized_items:
            if latest is None or item["occurred_at"] > latest:
                latest = item["occurred_at"]
        cursor = {"last_seen": iso(latest)} if latest else state_cursor
        return raw_items, normalized_items, cursor

    def _pull_mfa(self, client: GraphClient, state_cursor: Optional[Dict[str, Any]]) -> DatasetResult:
        raw_items = list(client.get_paginated("/reports/authenticationMethods/userRegistrationDetails"))
        normalized_items = [normalize_mfa(item) for item in raw_items]
        latest = None
        for item in normalized_items:
            if latest is None or item["occurred_at"] > latest:
                latest = item["occurred_at"]
        cursor = {"last_seen": iso(latest)} if latest else state_cursor
        return raw_items, normalized_items, cursor


def to_storable_events(
    tenant_id: str, dataset: str, raw_items: List[Dict[str, Any]], normalized_items: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    now = datetime.utcnow()
    stored_raw = []
    stored_norm = []
    for item in raw_items:
        payload_hash = hash_payload(item)
        stored_raw.append(
            {
                "tenant_id": tenant_id,
                "source": "microsoft_graph",
                "dataset": dataset,
                "event_id": item.get("id") or payload_hash,
                "occurred_at": parse_dt(item.get("createdDateTime")) if item.get("createdDateTime") else None,
                "received_at": now,
                "payload_json": json.dumps(item),
                "payload_hash": payload_hash,
            }
        )
    for n in normalized_items:
        stored_norm.append(
            {
                "tenant_id": tenant_id,
                "type": n["type"],
                "occurred_at": n["occurred_at"].replace(tzinfo=None),
                "actor_json": json.dumps(n.get("actor") or {}),
                "target_json": json.dumps(n.get("target") or {}),
                "severity": n["severity"],
                "confidence": n["confidence"],
                "summary": n["summary"],
                "json": json.dumps({k: v for k, v in n.items() if k not in {"occurred_at", "summary"}}),
            }
        )
    return stored_raw, stored_norm
