import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select

from o365_connector.clients.graph_client import GraphClient
from o365_connector.config import AppConfig
from o365_connector.models import DatasetState, NormalizedEvent, RawEvent, RunHistory, Tenant
from o365_connector.services.datasets import DatasetHandlers, to_storable_events
from o365_connector.services.incidents import correlate_incidents
from o365_connector.utils.constants import SUPPORTED_DATASETS
from o365_connector.utils.errors import ConnectorError
from o365_connector.utils.secrets import SecretsProvider

logger = logging.getLogger(__name__)


class DatasetRunner:
    def __init__(self, config: AppConfig, secrets_provider: SecretsProvider):
        self.config = config
        self.handlers = DatasetHandlers(config)
        self.secrets_provider = secrets_provider
        self.metrics: Dict[str, int] = {}

    def _inc_metric(self, name: str, amount: int = 1):
        self.metrics[name] = self.metrics.get(name, 0) + amount

    def run_for_tenant(self, session, tenant: Tenant, dataset: Optional[str] = None) -> Dict[str, any]:
        datasets = [dataset] if dataset else SUPPORTED_DATASETS
        results = {}
        for ds in datasets:
            if ds == "defender_alerts" and not self.config.defender_enabled:
                results[ds] = {"status": "skipped", "reason": "defender disabled"}
                continue
            try:
                results[ds] = self._run_dataset(session, tenant, ds)
            except ConnectorError as exc:
                logger.error("Dataset run failed", extra={"dataset": ds, "error": str(exc)})
                results[ds] = {"status": "error", "error": str(exc)}
        return results

    def _get_state(self, session, tenant_id: str, dataset: str) -> DatasetState:
        stmt = select(DatasetState).where(DatasetState.tenant_id == tenant_id, DatasetState.dataset == dataset)
        existing = session.execute(stmt).scalars().first()
        if existing:
            return existing
        state = DatasetState(tenant_id=tenant_id, dataset=dataset)
        session.add(state)
        session.flush()
        return state

    def _run_dataset(self, session, tenant: Tenant, dataset: str) -> Dict[str, any]:
        secret = self.secrets_provider.get_client_secret(tenant.tenant_id)
        if not secret:
            raise ConnectorError(f"Secret not found for tenant {tenant.tenant_id}")
        state = self._get_state(session, tenant.tenant_id, dataset)
        cursor_json = json.loads(state.cursor_json) if state.cursor_json else None
        client = GraphClient(tenant.tenant_id, tenant.client_id, secret, self.config)
        run = RunHistory(
            tenant_id=tenant.tenant_id,
            dataset=dataset,
            started_at=datetime.utcnow(),
            status="running",
            pulled_count=0,
            normalized_count=0,
        )
        session.add(run)
        session.flush()
        try:
            raw_items, normalized_items, new_cursor = self.handlers.pull(dataset, client, cursor_json)
            stored_raw, stored_norm = to_storable_events(tenant.tenant_id, dataset, raw_items, normalized_items)
            for item in stored_raw:
                session.add(RawEvent(**item))
            for item in stored_norm:
                session.add(NormalizedEvent(**item))
            run.pulled_count = len(stored_raw)
            run.normalized_count = len(stored_norm)
            run.status = "success"
            run.finished_at = datetime.utcnow()
            if new_cursor:
                state.cursor_json = json.dumps(new_cursor)
            state.last_run_at = datetime.utcnow()
            session.flush()
            correlate_incidents(session, tenant.tenant_id)
            self._inc_metric(f"runs_{dataset}")
            return {"status": "success", "pulled": len(stored_raw), "normalized": len(stored_norm)}
        except Exception as exc:  # noqa: BLE001
            run.status = "failed"
            run.finished_at = datetime.utcnow()
            run.error_text = str(exc)
            session.flush()
            logger.error("Run failed", extra={"dataset": dataset, "error": str(exc)}, exc_info=True)
            return {"status": "error", "error": str(exc)}
