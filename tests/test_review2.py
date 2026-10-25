from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlparse

import httpx
import jwt

from conftest import CLIENT_ID, REDIRECT, FakeFalcon, FakeJwks
from falcon_fleet_mcp.config import Settings
from falcon_fleet_mcp.identity import IdentityCenterGroups
from test_server import call


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def test_challenge_header_stays_well_formed_for_quoted_jwt_errors(server, make_token):
    base, _ = server()
    token = make_token("analyst@corp.com", exp=None)  # PyJWT: Token is missing the "exp" claim
    r = httpx.post(f"{base}/mcp", json={}, headers=_bearer(token))
    assert r.status_code == 401
    desc = r.headers["www-authenticate"].split('error_description="', 1)[1]
    assert desc.count('"') == 1  # only the closing quote


async def test_jwks_outage_is_503(server, make_token, monkeypatch):
    base, _ = server()

    def down(self, _token):
        raise jwt.PyJWKClientConnectionError("cognito unreachable")

    monkeypatch.setattr(FakeJwks, "get_signing_key_from_jwt", down)
    r = httpx.post(f"{base}/mcp", json={}, headers=_bearer(make_token("analyst@corp.com")))
    assert r.status_code == 503


async def test_authorize_always_requests_openid(server):
    base, _ = server()
    params = {"client_id": CLIENT_ID, "redirect_uri": REDIRECT, "response_type": "code",
              "code_challenge": "abc", "code_challenge_method": "S256", "scope": "email profile"}  # fmt: skip
    r = httpx.get(f"{base}/authorize", params=params)
    assert "openid" in parse_qs(urlparse(r.headers["location"]).query)["scope"][0].split()


async def test_register_rejects_non_list_redirect_uris(server):
    base, _ = server()
    for value in (5, "http://localhost:33418/callback", [5]):
        assert httpx.post(f"{base}/register", json={"redirect_uris": value}).status_code == 400


async def test_get_alerts_rejects_oversized_and_empty_id_lists(server, make_token):
    base, _ = server()
    tok = make_token("analyst@corp.com")
    err, out = await call(base, tok, "get_alerts", {"tenant": "corp-us", "composite_ids": [f"x{i}" for i in range(26)]})
    assert err and "25" in out["text"]
    err, _ = await call(base, tok, "get_alerts", {"tenant": "corp-us", "composite_ids": []})
    assert err and not any(op == "PostEntitiesAlertsV2" for _, op, _ in FakeFalcon.calls)


async def test_unexpected_tenant_errors_are_not_leaked(server, make_token, monkeypatch):
    base, _ = server()
    original = FakeFalcon.command

    def leaky(self, operation, **kwargs):
        if self.tenant_id == "corp-eu":
            raise RuntimeError("AccessDenied: arn:aws:iam::123456789012:role/secret-role")
        return original(self, operation, **kwargs)

    monkeypatch.setattr(FakeFalcon, "command", leaky)
    err, out = await call(base, make_token("analyst@corp.com"), "fleet_overview")
    assert not err
    eu = out["results"]["corp-eu"]
    assert not eu["ok"] and "arn:aws" not in eu["error"] and eu["error"].startswith("internal error (ref ")
    assert out["results"]["corp-us"]["ok"]


class FakeIdentityStore:
    class exceptions:  # noqa: N801 - mirrors boto3's client.exceptions
        class ResourceNotFoundException(Exception):
            pass

    def __init__(self, groups: dict[str, str], delay: float = 0.0):
        self.groups, self.delay = groups, delay
        self.active = self.peak = 0
        self.lock = threading.Lock()

    def get_user_id(self, **_):
        return {"UserId": "u1"}

    def get_paginator(self, _name):
        groups = self.groups
        return type("P", (), {"paginate": lambda self, **_: [{"GroupMemberships": [{"GroupId": g} for g in groups]}]})()

    def describe_group(self, GroupId, **_):  # noqa: N803
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(self.delay)
        with self.lock:
            self.active -= 1
        return {"DisplayName": self.groups[GroupId]}


def test_group_names_fetched_in_parallel_and_renames_expire(monkeypatch):
    store = FakeIdentityStore({f"g{i}": f"Group-{i}" for i in range(6)}, delay=0.1)
    groups = IdentityCenterGroups(replace(Settings(), cache_ttl_seconds=0))
    monkeypatch.setattr(groups, "_identitystore", lambda: store)

    started = time.monotonic()
    assert groups.groups_for("alice@corp.com") == {f"Group-{i}" for i in range(6)}
    assert store.peak > 1 and time.monotonic() - started < 0.5

    store.groups["g0"] = "Renamed"
    assert "Renamed" in groups.groups_for("alice@corp.com")


async def test_empty_tenant_list_is_rejected_not_treated_as_all(server, make_token):
    base, _ = server()
    err, out = await call(base, make_token("analyst@corp.com"), "search_hosts", {"tenants": []})
    assert err and "omit it" in out["text"] and not FakeFalcon.calls


async def test_oversized_result_gets_clear_error(server, make_token, monkeypatch):
    base, _ = server()
    original = FakeFalcon.command

    def huge(self, operation, **kwargs):
        if operation == "PostEntitiesAlertsV2":
            ids = kwargs["body"]["composite_ids"]
            return {"status_code": 200, "body": {"resources": [{"composite_id": i, "blob": "x" * 200_000} for i in ids]}}
        return original(self, operation, **kwargs)

    monkeypatch.setattr(FakeFalcon, "command", huge)
    ids = [f"a{i}" for i in range(20)]  # ~4 MB of raw records
    err, out = await call(base, make_token("analyst@corp.com"), "get_alerts", {"tenant": "corp-us", "composite_ids": ids})
    assert err and "over the" in out["text"]


async def test_read_denials_are_audited(server, make_token, caplog):
    import json as _json
    import logging

    base, _ = server()
    caplog.set_level(logging.INFO, logger="falcon_fleet_mcp.audit")
    await call(base, make_token("analyst@corp.com"), "search_alerts", {"tenants": ["secret-sub"]})
    records = [_json.loads(r.getMessage()) for r in caplog.records if r.name == "falcon_fleet_mcp.audit"]
    assert any(r["tool"] == "search_alerts" and r["outcome"] == "denied" and r["tenants"] == ["secret-sub"] for r in records)


async def test_native_cognito_user_cannot_impersonate_identity_center_user(server, make_token):
    base, _ = server()
    # Same NameID as a real Identity Center user, but no IdentityCenter_ prefix.
    for username in ("responder@corp.com", "IdentityCenter_"):
        token = make_token("responder@corp.com", username=username)
        r = httpx.post(f"{base}/mcp", json={}, headers=_bearer(token))
        assert r.status_code == 401, username


async def test_no_access_403_does_not_trigger_reauthorization(server, make_token):
    base, _ = server()
    r = httpx.post(f"{base}/mcp", json={}, headers=_bearer(make_token("nobody@corp.com")))
    assert r.status_code == 403
    assert "insufficient_scope" not in r.headers.get("www-authenticate", "")


def test_group_deleted_mid_lookup_is_skipped(monkeypatch):
    store = FakeIdentityStore({"g1": "SOC-Analysts", "g2": "Deleted-Group"})
    original = store.describe_group

    def describe(GroupId, **kw):  # noqa: N803
        if GroupId == "g2":
            raise FakeIdentityStore.exceptions.ResourceNotFoundException()
        return original(GroupId=GroupId, **kw)

    store.describe_group = describe
    groups = IdentityCenterGroups(Settings())
    monkeypatch.setattr(groups, "_identitystore", lambda: store)
    assert groups.groups_for("alice@corp.com") == {"SOC-Analysts"}


# --- review 5: features and fixes -----------------------------------------------------------


async def test_fleet_overview_counts_per_tenant(server, make_token):
    base, _ = server()
    err, out = await call(base, make_token("analyst@corp.com"), "fleet_overview", {"hours": 9999})
    assert not err and out["tenants_failed"] == ["broken"]
    us = out["results"]["corp-us"]["data"]
    assert us == {"new_alerts": 1, "new_critical_high_alerts": 1, "hosts": 3, "contained_hosts": 3,
                  "hosts_not_seen_7d": 3}  # fmt: skip
    filters = [kw["parameters"].get("filter") for t, op, kw in FakeFalcon.calls if t == "corp-us"]
    assert "status:'new'+created_timestamp:>'now-720h'+severity_name:['Critical','High']" in filters


async def test_hunt_indicator_finds_hosts_and_treats_404_as_unseen(server, make_token):
    base, _ = server()
    tok = make_token("analyst@corp.com")
    err, out = await call(base, tok, "hunt_indicator", {"type": "domain", "value": "evil.example", "tenants": ["corp-us"]})
    assert not err and out["results"]["corp-us"]["data"]["hosts"][0]["hostname"] == "corp-us-ws01"
    err, out = await call(base, tok, "hunt_indicator", {"type": "domain", "value": "unseen.example"})
    assert not err and out["results"]["corp-eu"]["data"] == {"total": 0, "hosts": []}
    err, out = await call(base, tok, "hunt_indicator", {"type": "sha256", "value": "abc"})
    assert err and "not a valid sha256" in out["text"]


async def test_search_offset_is_passed_and_bounded(server, make_token):
    base, _ = server()
    tok = make_token("analyst@corp.com")
    err, _ = await call(base, tok, "search_hosts", {"tenants": ["corp-us"], "offset": 40})
    assert not err
    assert any(op == "QueryDevicesByFilter" and kw["parameters"]["offset"] == 40 for _, op, kw in FakeFalcon.calls)
    err, out = await call(base, tok, "search_alerts", {"offset": 20000})
    assert err and "offset must be between" in out["text"]


async def test_action_with_per_target_errors_is_audited_as_partial(server, make_token, monkeypatch, caplog):
    base, _ = server()
    original = FakeFalcon.command

    def partly(self, operation, **kwargs):
        if operation == "PerformActionV2":
            return {"status_code": 202, "body": {"resources": [{"id": "h1"}], "errors": [{"id": "h2", "code": 404}]}}
        return original(self, operation, **kwargs)

    monkeypatch.setattr(FakeFalcon, "command", partly)
    caplog.set_level(logging.INFO, logger="falcon_fleet_mcp.audit")
    err, out = await call(base, make_token("responder@corp.com"), "contain_hosts",
                          {"tenant": "corp-us", "device_ids": ["h1", "h2"], "reason": "IR-1"})  # fmt: skip
    assert not err and out["errors"]
    records = [json.loads(r.getMessage()) for r in caplog.records if r.name == "falcon_fleet_mcp.audit"]
    assert records[-1]["outcome"] == "partial"


def test_audit_log_lines_are_bare_json_for_metric_filters():
    from falcon_fleet_mcp.app import _LogFormatter

    fmt = _LogFormatter("%(levelname)s %(name)s %(message)s")
    audit = logging.LogRecord("falcon_fleet_mcp.audit", logging.INFO, "", 0, '{"audit": true}', None, None)
    other = logging.LogRecord("falcon_fleet_mcp.auth", logging.INFO, "", 0, "hello", None, None)
    assert json.loads(fmt.format(audit)) == {"audit": True}
    assert fmt.format(other) == "INFO falcon_fleet_mcp.auth hello"


async def test_hunt_indicator_validates_ips_and_domains(server, make_token):
    base, _ = server()
    tok = make_token("analyst@corp.com")
    for kind, value in [("ipv4", "999.1.1.1"), ("ipv4", "::1"), ("ipv6", "10.0.0.1"), ("domain", "a b.com")]:
        err, out = await call(base, tok, "hunt_indicator", {"type": kind, "value": value})
        assert err and f"not a valid {kind}" in out["text"], (kind, value)
    err, _ = await call(base, tok, "hunt_indicator", {"type": "ipv6", "value": "2001:db8::1", "tenants": ["corp-us"]})
    assert not err


def test_audit_survives_a_quieter_log_level():
    from falcon_fleet_mcp.tools import audit_log

    root = logging.getLogger()
    previous = root.level
    root.setLevel(logging.WARNING)
    try:
        assert audit_log.isEnabledFor(logging.INFO)
    finally:
        root.setLevel(previous)


async def test_fleet_overview_keeps_metrics_when_one_scope_is_missing(server, make_token, monkeypatch):
    base, _ = server()
    original = FakeFalcon.command

    def no_hosts_scope(self, operation, **kwargs):
        if operation == "QueryDevicesByFilter":
            return {"status_code": 403, "body": {"errors": [{"code": 403, "message": "access denied"}]}}
        return original(self, operation, **kwargs)

    monkeypatch.setattr(FakeFalcon, "command", no_hosts_scope)
    err, out = await call(base, make_token("analyst@corp.com"), "fleet_overview", {"tenants": ["corp-us"]})
    us = out["results"]["corp-us"]
    assert not err and us["ok"] and us["data"]["new_alerts"] == 1 and us["data"]["hosts"] is None
    assert set(us["data"]["errors"]) == {"hosts", "contained_hosts", "hosts_not_seen_7d"}


async def test_update_alerts_and_lift_containment_send_the_documented_payloads(server, make_token):
    base, _ = server()
    tok = make_token("responder@corp.com")
    err, _ = await call(base, tok, "update_alerts",
                        {"tenant": "corp-us", "composite_ids": ["a1"], "reason": "IR-7", "status": "closed"})  # fmt: skip
    assert not err
    err, _ = await call(base, tok, "lift_containment", {"tenant": "corp-us", "device_ids": ["d1"], "reason": "IR-7"})
    assert not err
    calls = {op: kw for t, op, kw in FakeFalcon.calls if t == "corp-us"}
    assert calls["PatchEntitiesAlertsV3"]["body"] == {
        "composite_ids": ["a1"],
        "action_parameters": [{"name": "update_status", "value": "closed"},
                              {"name": "append_comment", "value": "[falcon-fleet-mcp] IR-7"}],
    }  # fmt: skip
    assert calls["PerformActionV2"]["parameters"] == {"action_name": "lift_containment"}


async def test_lookup_indicator_quotes_fql(server, make_token):
    base, _ = server()
    err, _ = await call(base, make_token("analyst@corp.com"), "lookup_indicator",
                        {"value": "evil'.com", "tenants": ["corp-us"]})  # fmt: skip
    assert not err
    (kw,) = [kw for _, op, kw in FakeFalcon.calls if op == "QueryIntelIndicatorEntities"]
    assert kw["parameters"]["filter"] == "indicator:'evil\\'.com'"


async def test_token_endpoint_outage_is_a_502_not_a_crash(server):
    base, _ = server(cognito_domain="http://127.0.0.1:1")  # nothing listens on port 1
    r = httpx.post(f"{base}/token", data={"client_id": CLIENT_ID, "grant_type": "refresh_token", "refresh_token": "x"})
    assert r.status_code == 502 and r.json()["error"] == "temporarily_unavailable"
    assert r.headers["cache-control"] == "no-store"
