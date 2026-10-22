import asyncio
import json
from urllib.error import URLError

import pytest

from app.policy import OPAClient, OPAUnavailableError


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


def test_authorize_access_sends_policy_input(monkeypatch):
    client = OPAClient("http://opa.test:8181")
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured["body"] = json.loads(request.data)
        return FakeResponse(b'{"result": true}')

    monkeypatch.setattr("app.policy.urlopen", fake_urlopen)

    allowed = asyncio.run(
        client.authorize_access(
            subject_sub="subject-1",
            roles={"gateway-user"},
            resource_name="mock-backend",
            port=5678,
            protocol="tcp",
        )
    )

    assert allowed is True
    assert captured["url"] == "http://opa.test:8181/v1/data/gateway/authz/allow"
    assert captured["body"] == {
        "input": {
            "action": "connect",
            "subject": {"sub": "subject-1", "roles": ["gateway-user"]},
            "resource": {
                "name": "mock-backend",
                "port": 5678,
                "protocol": "tcp",
            },
        }
    }


def test_unavailable_opa_fails_explicitly(monkeypatch):
    client = OPAClient("http://opa.test:8181")
    monkeypatch.setattr(
        "app.policy.urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(URLError("offline")),
    )

    with pytest.raises(OPAUnavailableError):
        client._evaluate({"input": {}})
