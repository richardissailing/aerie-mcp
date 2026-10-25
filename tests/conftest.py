from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import replace
from typing import Any

import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa

from falcon_fleet_mcp.app import build_app
from falcon_fleet_mcp.auth import TokenValidator
from falcon_fleet_mcp.config import Settings
from falcon_fleet_mcp.falcon import ClientPool
from falcon_fleet_mcp.registry import Registry

POOL_ID = "us-east-1_TEST"
CLIENT_ID = "public-client"
REDIRECT = "http://localhost:33418/callback"

REGISTRY = {
    "tenants": {
        "corp-us": {"display_name": "Corp US", "base_url": "us1", "credential": "env:CORP", "allow_actions": True},
        "corp-eu": {"display_name": "Corp EU", "base_url": "eu1", "credential": "env:CORP_EU"},
        "sub-child": {
            "display_name": "Subsidiary (Flight Control child)",
            "base_url": "us2",
            "credential": "env:PARENT",
            "member_cid": "abc123",
            "allow_actions": True,
        },
        "broken": {"display_name": "Broken", "base_url": "us1", "credential": "env:BROKEN"},
    },
    "grants": [
        {"group": "soc-analysts", "tenants": ["*"], "role": "reader"},
        {"group": "ir-us", "tenants": ["corp-us"], "role": "responder"},
        {"group": "ir-eu", "tenants": ["corp-eu"], "role": "responder"},
    ],
}

USERS = {
    "analyst@corp.com": {"soc-analysts"},
    "responder@corp.com": {"soc-analysts", "ir-us", "ir-eu"},
    "nobody@corp.com": {"unrelated-group"},
}


class FakeFalcon:
    """Stands in for APIHarnessV2; records every call."""

    calls: list[tuple[str, str, dict[str, Any]]] = []

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def command(self, operation: str, **kwargs: Any) -> dict[str, Any]:
        FakeFalcon.calls.append((self.tenant_id, operation, kwargs))
        if self.tenant_id == "broken":
            return {"status_code": 403, "body": {"errors": [{"code": 403, "message": "access denied"}]}}
        t = self.tenant_id
        if operation == "GetQueriesAlertsV2":
            return {"status_code": 200, "body": {"meta": {"pagination": {"total": 1}}, "resources": [f"{t}:ind:1"]}}
        if operation == "PostEntitiesAlertsV2":
            alerts = [
                {"composite_id": cid, "severity_name": "Critical", "status": "new", "display_name": "Ransomware",
                 "device": {"hostname": f"{t}-ws01", "device_id": "d1"}, "noise": "dropped"}
                for cid in kwargs["body"]["composite_ids"]
            ]  # fmt: skip
            return {"status_code": 200, "body": {"resources": alerts}}
        if operation == "PerformActionV2":
            return {"status_code": 202, "body": {"resources": [{"id": i} for i in kwargs["body"]["ids"]]}}
        if operation == "QueryDevicesByFilter":
            return {"status_code": 200, "body": {"meta": {"pagination": {"total": 3}}, "resources": [f"{t}-d1"]}}
        if operation == "PostDeviceDetailsV2":
            hosts = [{"device_id": i, "hostname": f"{t}-ws01", "platform_name": "Windows"} for i in kwargs["body"]["ids"]]
            return {"status_code": 200, "body": {"resources": hosts}}
        if operation == "indicator_get_devices_ran_on_v1":
            if kwargs["parameters"]["value"] == "unseen.example":
                return {"status_code": 404, "body": {"errors": [{"code": 404, "message": "not found"}]}}
            return {"status_code": 200, "body": {"meta": {"pagination": {"total": 1}}, "resources": [f"{t}-d1"]}}
        return {"status_code": 200, "body": {"resources": []}}


class FakeJwks:
    def __init__(self, public_key: Any):
        self.public_key = public_key

    def get_signing_key_from_jwt(self, _token: str) -> Any:
        return type("Key", (), {"key": self.public_key})()


@pytest.fixture(scope="session")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def make_token(signing_key: rsa.RSAPrivateKey):
    def make(user: str, **overrides: Any) -> str:
        claims = {
            "iss": f"https://cognito-idp.us-east-1.amazonaws.com/{POOL_ID}",
            "sub": f"sub-{user}",
            "username": f"IdentityCenter_{user}",
            "client_id": CLIENT_ID,
            "token_use": "access",
            "scope": "openid email",
            "exp": int(time.time()) + 600,
            **overrides,
        }
        return jwt.encode(claims, signing_key, algorithm="RS256")

    return make


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path, signing_key):
    """Run the real ASGI app under uvicorn; yields (base_url, settings)."""

    def start(**setting_overrides: Any):
        registry_file = tmp_path / "registry.json"
        registry_file.write_text(json.dumps(REGISTRY))
        settings = replace(
            Settings(),
            **{
                "cognito_region": "us-east-1",
                "cognito_user_pool_id": POOL_ID,
                "cognito_domain": "https://auth.example.com",
                "cognito_client_ids": [CLIENT_ID],
                "allowed_redirect_uris": [REDIRECT],
                "registry_file": str(registry_file),
                "actions_enabled": True,
                "max_action_targets": 3,
                **setting_overrides,
            },
        )
        FakeFalcon.calls = []
        app = build_app(
            settings,
            registry=Registry(settings),
            groups_for=lambda user: USERS.get(user, set()),
            pool=ClientPool(settings, factory=lambda tenant: FakeFalcon(tenant.id)),
            validator=TokenValidator(settings, jwks=FakeJwks(signing_key.public_key())),
        )
        port = _free_port()
        srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        thread = threading.Thread(target=srv.run, daemon=True)
        thread.start()
        while not srv.started:
            time.sleep(0.02)
        servers.append((srv, thread))
        return f"http://127.0.0.1:{port}", settings

    servers: list[tuple[uvicorn.Server, threading.Thread]] = []
    yield start
    for srv, thread in servers:
        srv.should_exit = True
        thread.join(timeout=5)
