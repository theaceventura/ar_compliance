import json
from datetime import datetime, timedelta
from typing import Dict, List

import yaml
from sqlalchemy import and_, select

from o365_connector.models import NormalizedEvent
from o365_connector.utils.constants import (
    DSET_CONDITIONAL_ACCESS,
    DSET_MFA_COVERAGE,
    DSET_ROLE_ASSIGNMENTS,
    DSET_SIGNINS,
)


def load_rules(path: str = "config/correlation.yml") -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def correlate_incidents(session, tenant_id: str) -> None:
    rules = load_rules()
    now = datetime.utcnow()
    window_minutes = max(rules.get("IdentityTakeoverCandidate", {}).get("window_minutes", 60), 60)
    window = now - timedelta(minutes=window_minutes)
    stmt = select(NormalizedEvent).where(
        NormalizedEvent.tenant_id == tenant_id,
        NormalizedEvent.occurred_at >= window,
        NormalizedEvent.type != "IncidentCandidate",
    )
    events = session.execute(stmt).scalars().all()
    signins: List[NormalizedEvent] = [e for e in events if e.type == "SignInEvent" and e.severity == "high"]
    role_changes = [e for e in events if e.type == "PrivilegeAssignment"]
    incident_candidates: List[Dict] = []

    for signin in signins:
        actor = json.loads(signin.actor_json or "{}")
        user_id = actor.get("userId") or actor.get("userPrincipalName")
        for role_event in role_changes:
            r_actor = json.loads(role_event.actor_json or "{}")
            if (r_actor.get("userId") or r_actor.get("userPrincipalName")) != user_id:
                continue
            if 0 <= (role_event.occurred_at - signin.occurred_at).total_seconds() <= window_minutes * 60:
                evidence = [signin.id, role_event.id]
                if not _candidate_exists(session, tenant_id, evidence):
                    incident_candidates.append(
                        {
                            "candidate_type": "IdentityTakeoverCandidate",
                            "severity": "high",
                            "confidence": "medium",
                            "start_time": signin.occurred_at,
                            "last_time": role_event.occurred_at,
                            "evidence_event_ids": evidence,
                        }
                    )

    for inc in incident_candidates:
        session.add(
            NormalizedEvent(
                tenant_id=tenant_id,
                type="IncidentCandidate",
                occurred_at=inc["start_time"],
                actor_json=json.dumps({"candidate_type": inc["candidate_type"]}),
                target_json=json.dumps({}),
                severity=inc["severity"],
                confidence=inc["confidence"],
                summary=f"{inc['candidate_type']} detected",
                json=json.dumps(inc),
            )
        )
    session.flush()


def _candidate_exists(session, tenant_id: str, evidence_ids: List[int]) -> bool:
    stmt = select(NormalizedEvent).where(
        NormalizedEvent.tenant_id == tenant_id,
        NormalizedEvent.type == "IncidentCandidate",
    )
    for event in session.execute(stmt).scalars().all():
        data = json.loads(event.json or "{}")
        if data.get("evidence_event_ids") == evidence_ids:
            return True
    return False
