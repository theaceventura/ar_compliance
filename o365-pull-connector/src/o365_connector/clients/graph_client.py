import time
from typing import Any, Dict, Iterator, List, Optional

import msal
import requests

from o365_connector.config import AppConfig
from o365_connector.utils.errors import ConnectorError


class GraphClient:
    _token_cache: Dict[str, Dict[str, Any]] = {}

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, config: AppConfig):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.config = config
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        self._app = msal.ConfidentialClientApplication(
            client_id=client_id, client_credential=client_secret, authority=authority
        )

    def _get_cached_token(self) -> Optional[str]:
        cached = self._token_cache.get(self.tenant_id)
        if not cached:
            return None
        if cached["expires_at"] <= time.time() + 30:
            return None
        return cached["token"]

    def _store_token(self, token: str, expires_in: int) -> None:
        self._token_cache[self.tenant_id] = {"token": token, "expires_at": time.time() + expires_in}

    def _acquire_token(self) -> str:
        cached = self._get_cached_token()
        if cached:
            return cached
        result = self._app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in result:
            raise ConnectorError(f"Token acquisition failed: {result.get('error_description')}")
        token = result["access_token"]
        self._store_token(token, int(result.get("expires_in", 300)))
        return token

    def _request(
        self, method: str, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        token = self._acquire_token()
        url = f"https://graph.microsoft.com/v1.0{path}"
        headers = {"Authorization": f"Bearer {token}"}
        attempts = 0
        delay = self.config.retry_backoff_seconds
        while True:
            response = requests.request(method, url, headers=headers, params=params, timeout=30)
            if response.status_code in (429, 500, 502, 503, 504):
                attempts += 1
                if attempts > self.config.max_retry_attempts:
                    raise ConnectorError(f"Graph request failed after retries: {response.status_code}")
                retry_after = response.headers.get("Retry-After")
                wait = float(retry_after) if retry_after else delay
                time.sleep(wait)
                delay = delay * 2 + self.config.retry_backoff_jitter
                continue
            if response.status_code >= 400:
                raise ConnectorError(
                    f"Graph error {response.status_code}: {response.text}", status_code=response.status_code
                )
            return response.json()

    def get_paginated(self, path: str, params: Optional[Dict[str, Any]] = None) -> Iterator[Dict[str, Any]]:
        next_url = path
        next_params = params or {}
        while next_url:
            data = self._request("GET", next_url, next_params)
            for item in data.get("value", []):
                yield item
            next_url = None
            next_params = None
            if "@odata.nextLink" in data:
                # nextLink is an absolute URL; Graph accepts absolute path so keep hostless path
                next_url = data["@odata.nextLink"].replace("https://graph.microsoft.com/v1.0", "")
                next_params = None
