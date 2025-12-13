import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import yaml
from sqlalchemy import select

from o365_connector.config import AppConfig
from o365_connector.models import NormalizedEvent


def load_mapping(path: str = "config/mapping.yml") -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def export_summary(session, tenant_id: str, since: Optional[datetime], config: AppConfig) -> Dict:
    mapping = load_mapping()
    since_time = since or datetime.utcnow() - timedelta(hours=24)
    stmt = select(NormalizedEvent).where(
        NormalizedEvent.tenant_id == tenant_id, NormalizedEvent.occurred_at >= since_time
    )
    events = session.execute(stmt).scalars().all()
    posture_metrics: List[Dict] = []
    findings: List[Dict] = []
    indicators: List[Dict] = []
    mfa_total = 0
    mfa_registered = 0
    risky_signins = 0
    privilege_changes = 0
    disabled_ca = 0

    for event in events:
        data = json.loads(event.json or "{}")
        if event.type == "MFARegistrationStatus":
            mfa_total += 1
            if data.get("details", {}).get("isRegistered"):
                mfa_registered += 1
        if event.type == "SignInEvent" and event.severity == "high":
            risky_signins += 1
        if event.type == "PrivilegeAssignment":
            privilege_changes += 1
        if event.type == "ConditionalAccessPolicy" and data.get("details", {}).get("state") == "disabled":
            disabled_ca += 1
        entry = mapping.get("type_map", {}).get(event.type, {})
        record = {
            "type": event.type,
            "severity": event.severity,
            "confidence": event.confidence,
            "summary": event.summary,
            "domain": entry.get("domain"),
            "control_key": entry.get("control_key"),
            "board_metric": entry.get("board_metric"),
            "evidence_id": event.id,
        }
        if event.type in {"IncidentCandidate", "PrivilegeAssignment", "ConditionalAccessPolicy"}:
            findings.append(record)
        else:
            indicators.append(record)

    coverage = (mfa_registered / mfa_total * 100) if mfa_total else 0
    posture_metrics.append({"metric_name": "mfa_coverage_percent", "value": round(coverage, 2), "trend_hint": "stable"})
    posture_metrics.append({"metric_name": "risky_signins", "value": risky_signins, "trend_hint": "stable"})
    posture_metrics.append({"metric_name": "privilege_changes", "value": privilege_changes, "trend_hint": "stable"})
    posture_metrics.append({"metric_name": "disabled_ca_policies", "value": disabled_ca, "trend_hint": "stable"})

    return {
        "export_version": config.export_version,
        "generated_at": datetime.utcnow().isoformat(),
        "tenant_id": tenant_id,
        "posture_metrics": posture_metrics,
        "findings": findings,
        "indicators": indicators,
    }
