from typing import Dict, List

from sqlalchemy import select

from o365_connector.clients.graph_client import GraphClient
from o365_connector.config import AppConfig
from o365_connector.models import DatasetState, Tenant
from o365_connector.utils.constants import (
    DSET_CONDITIONAL_ACCESS,
    DSET_MFA_COVERAGE,
    DSET_ROLE_ASSIGNMENTS,
    DSET_SIGNINS,
)
from o365_connector.utils.errors import ConnectorError
from o365_connector.utils.secrets import SecretsProvider


REQUIRED_PERMISSIONS = {
    DSET_SIGNINS: ["AuditLog.Read.All"],
    DSET_ROLE_ASSIGNMENTS: ["Directory.Read.All"],
    DSET_CONDITIONAL_ACCESS: ["Policy.Read.All"],
    DSET_MFA_COVERAGE: ["Reports.Read.All"],
}

TEST_ENDPOINTS = {
    DSET_SIGNINS: "/auditLogs/signIns",
    DSET_ROLE_ASSIGNMENTS: "/roleManagement/directory/roleAssignments",
    DSET_CONDITIONAL_ACCESS: "/identity/conditionalAccess/policies",
    DSET_MFA_COVERAGE: "/reports/authenticationMethods/userRegistrationDetails",
}


def readiness_for_tenant(session, tenant: Tenant, config: AppConfig, secrets: SecretsProvider) -> List[Dict]:
    secret = secrets.get_client_secret(tenant.tenant_id)
    if not secret:
        raise ConnectorError(f"Secret missing for {tenant.tenant_id}")
    client = GraphClient(tenant.tenant_id, tenant.client_id, secret, config)
    results = []
    for dataset, endpoint in TEST_ENDPOINTS.items():
        state = (
            session.execute(
                select(DatasetState).where(DatasetState.tenant_id == tenant.tenant_id, DatasetState.dataset == dataset)
            )
            .scalars()
            .first()
        )
        last_success = state.last_run_at.isoformat() if state and state.last_run_at else None
        try:
            client._request("GET", endpoint, params={"$top": 1})
            results.append(
                {
                    "dataset": dataset,
                    "required_permissions": REQUIRED_PERMISSIONS.get(dataset, []),
                    "can_connect": True,
                    "last_successful_run_at": last_success,
                    "last_error": None,
                }
            )
        except Exception as exc:  # noqa: BLE001
            results.append(
                {
                    "dataset": dataset,
                    "required_permissions": REQUIRED_PERMISSIONS.get(dataset, []),
                    "can_connect": False,
                    "last_successful_run_at": last_success,
                    "last_error": str(exc),
                }
            )
    return results
