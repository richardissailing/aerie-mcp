from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import replace

import httpx
import pytest

from conftest import FakeFalcon
from falcon_fleet_mcp.config import Settings
from falcon_fleet_mcp.falcon import ClientPool, FalconError, checked_base_url
from falcon_fleet_mcp.registry import Registry, Tenant
from test_server import call


def _tenants(n: int) -> list[Tenant]:
    return [Tenant(id=f"t{i}", display_name=f"t{i}", base_url="us1", credential="env:X") for i in range(n)]


async def test_fan_out_returns_partial_results_within_deadline():
    settings = replace(Settings(), fanout_concurrency=2, per_tenant_timeout_seconds=5, fanout_deadline_seconds=0.6)
    pool = ClientPool(settings, factory=lambda t: object())

    def work(t: Tenant) -> str:
        time.sleep(0.4)
        return t.id

    started = time.monotonic()
    out = await pool.fan_out(_tenants(6), work)
    assert time.monotonic() - started < 1.2
    ok = [tid for tid, r in out.items() if r["ok"]]
    assert len(ok) == 2  # first wave finished; the rest hit the deadline instead of overrunning it
    assert all("deadline" in r["error"] or "timed out" in r["error"] for r in out.values() if not r["ok"])


def test_clients_for_different_tenants_build_in_parallel():
    gate = threading.Barrier(3, timeout=2)  # deadlocks (BrokenBarrierError) if builds are serialized

    def factory(t: Tenant) -> object:
        gate.wait()
        return object()

    pool = ClientPool(Settings(), factory=factory)
    threads = [threading.Thread(target=pool.client, args=(t,)) for t in _tenants(3)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not gate.broken


async def test_registry_outage_is_503_not_403(server, make_token, monkeypatch):
    base, _ = server()

    def boom(self):
        raise RuntimeError("dynamodb throttled")

    monkeypatch.setattr(Registry, "snapshot", boom)
    r = httpx.post(f"{base}/mcp", json={}, headers={"Authorization": f"Bearer {make_token('analyst@corp.com')}"})
    assert r.status_code == 503 and 'error="temporarily_unavailable"' in r.headers["www-authenticate"]


async def test_denied_action_is_audited(server, make_token, caplog):
    base, _ = server()
    caplog.set_level(logging.INFO, logger="falcon_fleet_mcp.audit")
    err, _ = await call(base, make_token("analyst@corp.com"), "contain_hosts",
                        {"tenant": "corp-us", "device_ids": ["d1"], "reason": "probe"})  # fmt: skip
    assert err and not any(op == "PerformActionV2" for _, op, _ in FakeFalcon.calls)
    records = [json.loads(r.getMessage()) for r in caplog.records if r.name == "falcon_fleet_mcp.audit"]
    assert any(r["tool"] == "contain_hosts" and r["outcome"] == "denied" for r in records)


async def test_register_rejects_non_object_body(server):
    base, _ = server()
    for body in ("[]", '"x"', "not json"):
        assert httpx.post(f"{base}/register", content=body).status_code == 400


@pytest.mark.parametrize("value", ["us1", "US-2", "usgov2", "https://api.eu-1.crowdstrike.com", "https://api.crowdstrike.com/"])
def test_falcon_clouds_are_accepted(value):
    assert checked_base_url(value) == value


@pytest.mark.parametrize("value", ["us-2x", "evil.com", "https://api.crowdstrike.com.evil.com", "http://api.crowdstrike.com"])
def test_non_falcon_base_urls_are_refused_before_reading_the_secret(value, monkeypatch):
    from falcon_fleet_mcp import falcon

    monkeypatch.setattr(falcon, "load_credentials", lambda ref: pytest.fail("secret read for a bad base_url"))
    with pytest.raises(ValueError, match="not a Falcon cloud"):
        falcon.ClientPool._build(Tenant(id="t", display_name="t", base_url=value, credential="env:X"))


class _Seq:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), 0

    def command(self, operation, **kwargs):
        self.calls += 1
        return self.responses.pop(0)


def _pool(client):
    return ClientPool(Settings(), factory=lambda tenant: client)


TENANT = Tenant(id="t", display_name="t", base_url="us1", credential="env:X")


def test_rate_limited_call_is_retried_once_when_reset_is_near():
    soon = {"X-Ratelimit-Retryafter": str(int(time.time()))}
    client = _Seq({"status_code": 429, "headers": soon, "body": {}}, {"status_code": 200, "body": {"resources": [1]}})
    assert _pool(client).command(TENANT, "Op") == {"resources": [1]} and client.calls == 2


def test_rate_limited_call_is_not_slept_through_when_reset_is_far():
    later = {"X-Ratelimit-Retryafter": str(int(time.time()) + 60)}
    client = _Seq({"status_code": 429, "headers": later, "body": {"errors": ["slow down"]}})
    with pytest.raises(FalconError) as exc:
        _pool(client).command(TENANT, "Op")
    assert exc.value.status == 429 and client.calls == 1
