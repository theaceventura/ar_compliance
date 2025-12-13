from datetime import datetime, timedelta, timezone

from o365_connector.config import AppConfig
from o365_connector.services.datasets import DatasetHandlers, normalize_conditional_access, normalize_mfa, normalize_role_assignment, normalize_signin


class FakeClient:
    def __init__(self, items):
        self.items = items
        self.calls = []

    def get_paginated(self, path, params=None):
        self.calls.append({"path": path, "params": params})
        for item in self.items:
            yield item


def test_signin_cursor_first_then_next():
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    items = [
        {"id": "1", "createdDateTime": (now - timedelta(hours=1)).isoformat(), "status": {"errorCode": 0}},
        {"id": "2", "createdDateTime": now.isoformat(), "status": {"errorCode": 500}},
    ]
    handlers = DatasetHandlers(AppConfig())
    client = FakeClient(items)
    raw, normalized, cursor = handlers._pull_signins(client, None)
    assert len(raw) == 2
    assert cursor["last_seen"].startswith(str(now.date()))
    # subsequent run should use cursor filter
    client2 = FakeClient(items[:1])
    handlers._pull_signins(client2, cursor)
    assert "createdDateTime ge" in client2.calls[0]["params"]["$filter"]


def test_normalizers():
    signin = normalize_signin({"createdDateTime": datetime.utcnow().isoformat(), "status": {"errorCode": 5}})
    assert signin["severity"] == "high"
    role = normalize_role_assignment({"principalId": "u1", "roleDefinitionId": "r1"})
    assert role["type"] == "PrivilegeAssignment"
    ca = normalize_conditional_access({"displayName": "test", "state": "disabled"})
    assert ca["severity"] == "high"
    mfa = normalize_mfa({"userPrincipalName": "a", "id": "u", "methodIds": []})
    assert mfa["severity"] == "high"
