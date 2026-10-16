"""OPA policy client helpers."""
"""Client for evaluating access decisions with Open Policy Agent."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Collection
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OPAClientError(RuntimeError):
    """Base error for OPA request and response failures."""


class OPAUnavailableError(OPAClientError):
    """OPA could not be reached or returned a server error."""


class OPAResponseError(OPAClientError):
    """OPA returned an unsuccessful or invalid response."""


class OPAClient:
    """Evaluate the gateway.authz.allow policy decision."""

    def __init__(self, base_url: str | None = None, timeout: float = 3.0) -> None:
        configured_url = base_url or os.getenv("OPA_URL", "http://opa:8181")
        self.base_url = configured_url.rstrip("/")
        self.decision_url = f"{self.base_url}/v1/data/gateway/authz/allow"
        if timeout <= 0:
            raise ValueError("OPA timeout must be greater than zero")
        self.timeout = timeout

    async def authorize_access(
        self,
        *,
        subject_sub: str,
        roles: Collection[str],
        resource_name: str,
        port: int,
        protocol: str,
    ) -> bool:
        """Return the policy decision for a requested service access."""
        if not isinstance(subject_sub, str) or not subject_sub:
            raise ValueError("subject_sub must be a non-empty string")
        if (
            not isinstance(roles, Collection)
            or isinstance(roles, (str, bytes))
            or not all(isinstance(role, str) for role in roles)
        ):
            raise ValueError("roles must be a collection of strings")
        if not isinstance(resource_name, str) or not resource_name:
            raise ValueError("resource_name must be a non-empty string")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        if not isinstance(protocol, str) or protocol not in {"tcp", "udp"}:
            raise ValueError("protocol must be 'tcp' or 'udp'")

        payload = {
            "input": {
                "action": "connect",
                "subject": {
                    "sub": subject_sub,
                    "roles": list(roles),
                },
                "resource": {
                    "name": resource_name,
                    "port": port,
                    "protocol": protocol,
                },
            }
        }
        return await asyncio.to_thread(self._evaluate, payload)

    def _evaluate(self, payload: dict[str, object]) -> bool:
        request = Request(
            self.decision_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                response_body = response.read()
        except HTTPError as exc:
            if 500 <= exc.code <= 599:
                raise OPAUnavailableError(
                    f"OPA returned HTTP {exc.code}"
                ) from exc
            raise OPAResponseError(f"OPA returned HTTP {exc.code}") from exc
        except (TimeoutError, URLError, OSError) as exc:
            raise OPAUnavailableError("Unable to reach OPA") from exc

        try:
            result = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OPAResponseError("OPA returned invalid JSON") from exc

        if not isinstance(result, dict) or not isinstance(result.get("result"), bool):
            raise OPAResponseError(
                "OPA response must contain a boolean 'result' decision"
            )

        return result["result"]


opa_client = OPAClient()


async def authorize_access(
    *,
    subject_sub: str,
    roles: Collection[str],
    resource_name: str,
    port: int,
    protocol: str,
) -> bool:
    """Convenience function for the configured OPA client."""
    return await opa_client.authorize_access(
        subject_sub=subject_sub,
        roles=roles,
        resource_name=resource_name,
        port=port,
        protocol=protocol,
    )
