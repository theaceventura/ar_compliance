import os
import re
from abc import ABC, abstractmethod
from typing import Optional


class SecretsProvider(ABC):
    @abstractmethod
    def get_client_secret(self, tenant_id: str) -> Optional[str]:
        raise NotImplementedError


def env_var_for_tenant(tenant_id: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9]", "_", tenant_id).upper()
    return f"O365_SECRET_{sanitized}"


class EnvSecretsProvider(SecretsProvider):
    def get_client_secret(self, tenant_id: str) -> Optional[str]:
        return os.getenv(env_var_for_tenant(tenant_id))
