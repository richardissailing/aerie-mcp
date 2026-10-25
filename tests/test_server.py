from __future__ import annotations

import json
import logging
from urllib.parse import parse_qs, urlparse

import httpx
import httpx2
import pytest
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

from conftest import CLIENT_ID, REDIRECT, FakeFalcon

pytestmark = pytest.mark.asyncio


async def call(base: str, token: str, tool: str, args: dict | None = None, mode: str = "auto") -> tuple[bool, dict]:
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"})
    async with Client(streamable_http_client(f"{base}/mcp", http_client=http), mode=mode) as client:
        result = await client.call_tool(tool, args or {})
    text = result.content[0].text if result.content else "{}"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = {"text": text}
    return bool(result.is_error), payload


# --- OAuth plumbing -----------------------------------------------------------------------


async def test_unauthenticated_request_gets_discovery_challenge(server):
    base, _ = server()
    r = httpx.post(f"{base}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 401
    assert f'resource_metadata="{base}/.well-known/oauth-protected-resource/mcp"' in r.headers["www-authenticate"]


async def test_discovery_documents_point_at_facade(server):
    base, _ = server()
    prm = httpx.get(f"{base}/.well-known/oauth-protected-resource/mcp").json()
    assert prm["resource"] == f"{base}/mcp" and prm["authorization_servers"] == [base]
    asm = httpx.get(f"{base}/.well-known/oauth-authorization-server").json()
    assert asm["issuer"] == base
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["registration_endpoint"] == f"{base}/register"


async def test_dynamic_registration_returns_public_client(server):
    base, _ = server()
    ok = httpx.post(f"{base}/register", json={"redirect_uris": [REDIRECT], "client_name": "Claude Code"})
    assert ok.status_code == 201 and ok.json()["client_id"] == CLIENT_ID
    bad = httpx.post(f"{base}/register", json={"redirect_uris": ["https://evil.example/cb"]})
    assert bad.status_code == 400


async def test_authorize_redirects_straight_to_identity_center(server):
    base, _ = server()
    params = {
        "client_id": CLIENT_ID, "redirect_uri": REDIRECT, "response_type": "code", "state": "s",
        "code_challenge": "abc", "code_challenge_method": "S256", "resource": f"{base}/mcp", "scope": "openid email",
    }  # fmt: skip
    r = httpx.get(f"{base}/authorize", params=params)
    assert r.status_code == 302
    loc = urlparse(r.headers["location"])
    q = parse_qs(loc.query)
    assert loc.netloc == "auth.example.com" and loc.path == "/oauth2/authorize"
    assert q["identity_provider"] == ["IdentityCenter"] and "resource" not in q
    no_pkce = httpx.get(f"{base}/authorize", params={k: v for k, v in params.items() if k != "code_challenge"})
    assert no_pkce.status_code == 400


async def test_rejects_wrong_client_and_id_tokens(server, make_token):
    base, _ = server()
    for token in (make_token("analyst@corp.com", client_id="other"), make_token("analyst@corp.com", token_use="id")):
        r = httpx.post(f"{base}/mcp", json={}, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401 and 'error="invalid_token"' in r.headers["www-authenticate"]


async def test_user_without_grants_is_forbidden(server, make_token):
    base, _ = server()
    r = httpx.post(f"{base}/mcp", json={}, headers={"Authorization": f"Bearer {make_token('nobody@corp.com')}"})
    assert r.status_code == 403


# --- tools ---------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_list_tenants_scoped_to_caller(server, make_token, mode):
    base, _ = server()
    err, out = await call(base, make_token("responder@corp.com"), "list_tenants", mode=mode)
    assert not err
    roles = {t["tenant"]: t["your_role"] for t in out["tenants"]}
    assert roles == {"broken": "reader", "corp-eu": "responder", "corp-us": "responder", "sub-child": "reader"}
    assert out["user"] == "responder@corp.com"


async def test_search_alerts_fans_out_and_isolates_failures(server, make_token):
    base, _ = server()
    err, out = await call(base, make_token("analyst@corp.com"), "search_alerts", {"filter": "status:'new'"})
    assert not err
    assert out["tenants_queried"] == 4 and out["tenants_failed"] == ["broken"]
    us = out["results"]["corp-us"]["data"]["alerts"][0]
    assert us["device"]["hostname"] == "corp-us-ws01" and "noise" not in us
    assert out["results"]["sub-child"]["ok"]  # Flight Control child queried with its own client
    assert out["results"]["broken"]["status"] == 403


async def test_search_restricted_to_requested_tenants(server, make_token):
    base, _ = server()
    err, out = await call(base, make_token("analyst@corp.com"), "fleet_overview", {"tenants": ["corp-eu"]})
    assert not err and list(out["results"]) == ["corp-eu"]
    assert out["results"]["corp-eu"]["data"]["new_alerts"] == 1


async def test_unknown_tenant_is_refused(server, make_token):
    base, _ = server()
    err, out = await call(base, make_token("analyst@corp.com"), "search_hosts", {"tenants": ["secret-tenant"]})
    assert err and "not found or not permitted" in out["text"]


async def test_reader_cannot_contain(server, make_token):
    base, _ = server()
    args = {"tenant": "corp-us", "device_ids": ["d1"], "reason": "test"}
    err, out = await call(base, make_token("analyst@corp.com"), "contain_hosts", args)
    assert err and not any(op == "PerformActionV2" for _, op, _ in FakeFalcon.calls)


async def test_responder_contains_in_granted_tenant_and_is_audited(server, make_token, caplog):
    base, _ = server()
    caplog.set_level(logging.INFO, logger="falcon_fleet_mcp.audit")
    args = {"tenant": "corp-us", "device_ids": ["d1", "d2"], "reason": "INC-42 ransomware"}
    err, out = await call(base, make_token("responder@corp.com"), "contain_hosts", args)
    assert not err and out["tenant"] == "corp-us"
    assert ("corp-us", "PerformActionV2", {"parameters": {"action_name": "contain"}, "body": {"ids": ["d1", "d2"]}}) in FakeFalcon.calls
    records = [json.loads(r.getMessage()) for r in caplog.records if r.name == "falcon_fleet_mcp.audit"]
    assert any(r["tool"] == "contain_hosts" and r["user"] == "responder@corp.com" and r["reason"] == "INC-42 ransomware" for r in records)


async def test_action_refused_when_tenant_disallows_actions(server, make_token):
    base, _ = server()
    args = {"tenant": "corp-eu", "device_ids": ["d1"], "reason": "x"}  # responder there, but allow_actions=false
    err, out = await call(base, make_token("responder@corp.com"), "contain_hosts", args)
    assert err and "not enabled for tenant" in out["text"]


async def test_action_target_cap(server, make_token):
    base, _ = server()
    args = {"tenant": "corp-us", "device_ids": ["a", "b", "c", "d"], "reason": "x"}
    err, out = await call(base, make_token("responder@corp.com"), "contain_hosts", args)
    assert err and "at most 3" in out["text"]


async def test_action_tools_absent_when_disabled(server, make_token):
    base, _ = server(actions_enabled=False)
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {make_token('responder@corp.com')}"})
    async with Client(streamable_http_client(f"{base}/mcp", http_client=http)) as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert "search_alerts" in names and "contain_hosts" not in names
