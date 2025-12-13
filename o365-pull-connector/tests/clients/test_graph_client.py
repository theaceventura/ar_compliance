import types

import pytest

from o365_connector.clients.graph_client import GraphClient
from o365_connector.config import AppConfig


class DummyResponse:
    def __init__(self, status_code, json_data=None, headers=None, text=""):
        self.status_code = status_code
        self._json = json_data or {}
        self.headers = headers or {}
        self.text = text

    def json(self):
        return self._json


def test_pagination(monkeypatch):
    config = AppConfig(max_retry_attempts=1)
    client = GraphClient("t", "c", "s", config)
    client._acquire_token = types.MethodType(lambda self: "tok", client)
    calls = []

    def fake_request(method, url, headers=None, params=None, timeout=None):
        calls.append(url)
        if len(calls) == 1:
            return DummyResponse(
                200,
                {
                    "value": [{"id": "1"}],
                    "@odata.nextLink": "https://graph.microsoft.com/v1.0/test?page=2",
                },
            )
        return DummyResponse(200, {"value": [{"id": "2"}]})

    monkeypatch.setattr("requests.request", fake_request)
    items = list(client.get_paginated("/test"))
    assert [i["id"] for i in items] == ["1", "2"]
    assert len(calls) == 2


def test_retry_on_429(monkeypatch):
    config = AppConfig(max_retry_attempts=2, retry_backoff_seconds=0.01, retry_backoff_jitter=0)
    client = GraphClient("t", "c", "s", config)
    client._acquire_token = types.MethodType(lambda self: "tok", client)
    calls = []

    def fake_request(method, url, headers=None, params=None, timeout=None):
        calls.append(1)
        if len(calls) == 1:
            return DummyResponse(429, {}, headers={"Retry-After": "0"})
        return DummyResponse(200, {"value": []})

    monkeypatch.setattr("requests.request", fake_request)
    list(client.get_paginated("/retry"))
    assert len(calls) == 2
