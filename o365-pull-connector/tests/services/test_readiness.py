from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from o365_connector.config import AppConfig
from o365_connector.models import Base, DatasetState, Tenant
from o365_connector.services.readiness import readiness_for_tenant


class DummySecrets:
    def get_client_secret(self, tenant_id: str):
        return "secret"


def test_readiness(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    tenant = Tenant(
        tenant_id="t1",
        tenant_name="Tenant 1",
        client_id="cid",
        client_secret_ref="ref",
        is_enabled=True,
    )
    session.add(tenant)
    session.add(DatasetState(tenant_id="t1", dataset="signins", last_run_at=datetime.utcnow()))
    session.commit()

    monkeypatch.setattr("o365_connector.clients.graph_client.GraphClient._request", lambda *args, **kwargs: {"value": []})
    checks = readiness_for_tenant(session, tenant, AppConfig(), DummySecrets())
    assert checks
    assert all("required_permissions" in c for c in checks)
