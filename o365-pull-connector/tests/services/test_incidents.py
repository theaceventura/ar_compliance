from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from o365_connector.models import Base, NormalizedEvent
from o365_connector.services.incidents import correlate_incidents


def test_correlation_creates_incident_candidate(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    now = datetime.utcnow()
    sign_in = NormalizedEvent(
        tenant_id="t1",
        type="SignInEvent",
        occurred_at=now - timedelta(minutes=10),
        actor_json='{"userId": "u1"}',
        target_json="{}",
        severity="high",
        confidence="medium",
        summary="",
        json="{}",
    )
    role = NormalizedEvent(
        tenant_id="t1",
        type="PrivilegeAssignment",
        occurred_at=now - timedelta(minutes=5),
        actor_json='{"userId": "u1"}',
        target_json="{}",
        severity="high",
        confidence="high",
        summary="",
        json="{}",
    )
    session.add(sign_in)
    session.add(role)
    session.commit()
    correlate_incidents(session, "t1")
    incidents = session.query(NormalizedEvent).filter_by(type="IncidentCandidate").all()
    assert len(incidents) == 1
