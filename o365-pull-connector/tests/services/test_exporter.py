from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from o365_connector.config import AppConfig
from o365_connector.models import Base, NormalizedEvent
from o365_connector.services.exporter import export_summary


def setup_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_export_summary_structure():
    session = setup_session()
    now = datetime.utcnow()
    session.add(
        NormalizedEvent(
            tenant_id="t1",
            type="SignInEvent",
            occurred_at=now - timedelta(minutes=5),
            actor_json="{}",
            target_json="{}",
            severity="high",
            confidence="medium",
            summary="bad signin",
            json='{"details": {"isRegistered": false}}',
        )
    )
    session.add(
        NormalizedEvent(
            tenant_id="t1",
            type="MFARegistrationStatus",
            occurred_at=now - timedelta(minutes=4),
            actor_json="{}",
            target_json="{}",
            severity="medium",
            confidence="high",
            summary="mfa ok",
            json='{"details": {"isRegistered": true}}',
        )
    )
    session.commit()
    data = export_summary(session, "t1", since=now - timedelta(hours=1), config=AppConfig())
    assert data["export_version"] == 1
    assert any(m["metric_name"] == "mfa_coverage_percent" for m in data["posture_metrics"])
    assert data["tenant_id"] == "t1"
