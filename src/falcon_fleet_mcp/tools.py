"""MCP tools. Read tools fan out across tenants; action tools target exactly one tenant."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time
from typing import Any, Literal

import pydantic_core
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .auth import Principal, current_principal, request_started_var
from .config import Settings
from .falcon import ClientPool, FalconError, internal_error
from .registry import Registry, Role, Tenant

audit_log = logging.getLogger("falcon_fleet_mcp.audit")
audit_log.setLevel(logging.INFO)  # LOG_LEVEL=WARNING must not silently turn auditing off

MAX_LIMIT = 100
MAX_OFFSET = 9_900  # Falcon query endpoints reject offset + limit above 10,000
MAX_DETAIL_IDS = 25  # full alert/host records are large; see MAX_RESPONSE_BYTES
# Lambda caps a buffered response at 6 MB, so refuse anything that would not fit rather than
# let the client see an opaque 502. Measured as sent; see _response_bytes.
MAX_RESPONSE_BYTES = 5_500_000
READ = ToolAnnotations(read_only_hint=True, open_world_hint=True)
ACTION = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=True)

TenantsArg = list[str] | None
TENANTS_HELP = "Tenant ids to query (see list_tenants). Omit to query every tenant you can access."


def _clamp(limit: int) -> int:
    return max(1, min(limit, MAX_LIMIT))


def _offset(offset: int) -> int:
    if not 0 <= offset <= MAX_OFFSET:
        raise ToolError(f"offset must be between 0 and {MAX_OFFSET}; narrow the filter to see older results")
    return offset


IndicatorType = Literal["sha256", "md5", "domain", "ipv4", "ipv6"]
_HASH_RE = {"sha256": re.compile(r"^[0-9a-fA-F]{64}$"), "md5": re.compile(r"^[0-9a-fA-F]{32}$")}
_IP_VERSION = {"ipv4": 4, "ipv6": 6}


def _valid_indicator(kind: str, value: str) -> bool:
    if kind in _HASH_RE:
        return bool(_HASH_RE[kind].match(value))
    if kind in _IP_VERSION:
        try:
            return ipaddress.ip_address(value).version == _IP_VERSION[kind]
        except ValueError:
            return False
    return 0 < len(value) <= 200 and not any(c.isspace() or c == "/" for c in value)  # domain


def _capped_ids(ids: list[str]) -> list[str]:
    # Refuse rather than silently drop ids past the cap, which would read as "not found".
    if not ids:
        raise ToolError("no ids given")
    if len(ids) > MAX_DETAIL_IDS:
        raise ToolError(f"at most {MAX_DETAIL_IDS} ids per call; split the request")
    return ids


def _response_bytes(result: dict[str, Any]) -> int:
    """Approximate Lambda response size for a tool result.

    MCP sends the result twice: compact ``structuredContent`` and an indented text copy that is
    JSON-escaped inside the JSON-RPC body; the Web Adapter then escapes that body once more into
    the Lambda response envelope. Together that is roughly 3x the compact JSON.
    """
    text = pydantic_core.to_json(result, fallback=str, indent=2).decode()
    rpc = json.dumps({"content": [{"type": "text", "text": text}], "structuredContent": result},
                     default=str, ensure_ascii=False)  # fmt: skip
    return len(json.dumps(rpc, ensure_ascii=False).encode())


def _total(body: dict[str, Any]) -> Any:
    return ((body.get("meta") or {}).get("pagination") or {}).get("total")


def _fql_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _pick(record: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: record[k] for k in keys if record.get(k) not in (None, "", [])}


def summarize_alert(a: dict[str, Any]) -> dict[str, Any]:
    out = _pick(
        a, "composite_id", "severity_name", "severity", "status", "display_name", "name", "description",
        "created_timestamp", "tactic", "technique", "filename", "cmdline", "product",
    )  # fmt: skip
    device = a.get("device") or {}
    if device:
        out["device"] = _pick(device, "device_id", "hostname", "platform_name")
    return out


def summarize_host(h: dict[str, Any]) -> dict[str, Any]:
    return _pick(
        h, "device_id", "hostname", "platform_name", "os_version", "status", "last_seen", "first_seen",
        "local_ip", "external_ip", "agent_version", "tags", "product_type_desc",
    )  # fmt: skip


def summarize_vuln(v: dict[str, Any]) -> dict[str, Any]:
    cve = v.get("cve") or {}
    host = v.get("host_info") or {}
    apps = v.get("apps") or []
    return {
        "id": v.get("id"),
        "status": v.get("status"),
        "cve": cve.get("id"),
        "severity": cve.get("severity"),
        "base_score": cve.get("base_score"),
        "exprt_rating": cve.get("exprt_rating"),
        "hostname": host.get("hostname"),
        "aid": v.get("aid"),
        "products": sorted({a.get("product_name_version") for a in apps if a.get("product_name_version")}),
    }


class FleetTools:
    def __init__(self, settings: Settings, registry: Registry, pool: ClientPool):
        self.settings = settings
        self.registry = registry
        self.pool = pool

    # --- access control ------------------------------------------------------------------

    def tenants_for(self, principal: Principal, requested: TenantsArg, minimum: Role) -> list[Tenant]:
        snapshot = self.registry.snapshot()
        allowed = {tid: t for tid, t in snapshot.tenants.items() if principal.role_for(tid) >= minimum}
        if requested is not None and not requested:
            raise ToolError("tenants is empty; omit it to query every tenant you can access")
        if requested is None:
            if not allowed:
                raise ToolError("you have no tenants at the required access level")
            return sorted(allowed.values(), key=lambda t: t.id)
        denied = [tid for tid in requested if tid not in allowed]
        if denied:
            raise ToolError(f"tenant(s) not found or not permitted: {', '.join(denied)}")
        return [allowed[tid] for tid in dict.fromkeys(requested)]

    def action_tenant(self, principal: Principal, tenant_id: str, targets: list[str]) -> Tenant:
        if not self.settings.actions_enabled:
            raise ToolError("actions are disabled on this deployment")
        (tenant,) = self.tenants_for(principal, [tenant_id], Role.RESPONDER)
        if not tenant.allow_actions:
            raise ToolError(f"actions are not enabled for tenant {tenant_id}")
        if not targets:
            raise ToolError("no targets given")
        if len(targets) > self.settings.max_action_targets:
            raise ToolError(f"at most {self.settings.max_action_targets} targets per call")
        return tenant

    @staticmethod
    def audit(principal: Principal, tool: str, tenants: list[str], outcome: str, **detail: Any) -> None:
        audit_log.info(
            json.dumps(
                {"audit": True, "ts": time.time(), "user": principal.user, "tool": tool,
                 "tenants": tenants, "outcome": outcome, **detail},
                default=str,
            )  # fmt: skip
        )

    async def run_read(self, tool: str, requested: TenantsArg, fn: Any, **detail: Any) -> dict[str, Any]:
        principal = current_principal()
        try:
            tenants = self.tenants_for(principal, requested, Role.READER)
        except ToolError as exc:  # refused reads are audited too, like refused actions
            self.audit(principal, tool, list(requested or []), "denied", error=str(exc), **detail)
            raise
        started = request_started_var.get()
        # Budget from request arrival, not from here: authentication already used some of the Lambda timeout.
        budget = None if started is None else self.settings.fanout_deadline_seconds - (time.monotonic() - started)
        results = await self.pool.fan_out(tenants, fn, budget)
        failed = [tid for tid, r in results.items() if not r["ok"]]
        out = {"tenants_queried": len(tenants), "tenants_failed": failed, "results": results}
        size = _response_bytes(out)
        if size > MAX_RESPONSE_BYTES:
            self.audit(principal, tool, [t.id for t in tenants], "too_large", bytes=size, **detail)
            raise ToolError(
                f"response would be {size / 1e6:.1f} MB, over the {MAX_RESPONSE_BYTES / 1e6:.1f} MB limit; "
                "lower limit, pass fewer ids or tenants, or narrow the filter"
            )
        self.audit(principal, tool, [t.id for t in tenants], "partial" if failed else "ok", failed=failed, **detail)
        return out

    async def run_action(
        self, tool: str, tenant_id: str, targets: list[str], operation: str, reason: str, **kwargs: Any
    ) -> dict[str, Any]:
        principal = current_principal()
        detail = {"operation": operation, "reason": reason, "request": kwargs}
        try:
            if not reason.strip():
                raise ToolError("a reason is required for actions")
            tenant = self.action_tenant(principal, tenant_id, targets)
        except ToolError as exc:  # refused attempts are audited too
            self.audit(principal, tool, [tenant_id], "denied", error=str(exc), **detail)
            raise
        try:
            body = await asyncio.to_thread(self.pool.command, tenant, operation, **kwargs)
        except FalconError as exc:
            self.audit(principal, tool, [tenant.id], "error", error=str(exc), **detail)
            raise ToolError(str(exc)) from exc
        except Exception as exc:
            self.audit(principal, tool, [tenant.id], "error", error=str(exc), **detail)
            raise ToolError(internal_error("action %s on tenant %s failed", tool, tenant.id)) from exc
        errors = body.get("errors") or []
        # Falcon reports per-target failures alongside a 2xx, so some targets may not have been acted on.
        self.audit(principal, tool, [tenant.id], "partial" if errors else "ok", errors=errors, **detail)
        return {"tenant": tenant.id, "resources": body.get("resources"), "errors": errors}

    # --- Falcon calls (sync, run in worker threads) --------------------------------------

    def _count(self, tenant: Tenant, operation: str, fql: str | None) -> Any:
        params: dict[str, Any] = {"limit": 1}
        if fql:
            params["filter"] = fql
        return _total(self.pool.command(tenant, operation, parameters=params))

    def _alerts(self, tenant: Tenant, fql: str | None, limit: int, offset: int, sort: str) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "offset": offset, "sort": sort}
        if fql:
            params["filter"] = fql
        query = self.pool.command(tenant, "GetQueriesAlertsV2", parameters=params)
        ids = query.get("resources") or []
        total = _total(query)
        if not ids:
            return {"total": total, "alerts": []}
        details = self.pool.command(tenant, "PostEntitiesAlertsV2", body={"composite_ids": ids})
        return {"total": total, "alerts": [summarize_alert(a) for a in details.get("resources") or []]}

    def _hosts(self, tenant: Tenant, fql: str | None, limit: int, offset: int) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "offset": offset, "sort": "last_seen.desc"}
        if fql:
            params["filter"] = fql
        query = self.pool.command(tenant, "QueryDevicesByFilter", parameters=params)
        ids = query.get("resources") or []
        total = _total(query)
        if not ids:
            return {"total": total, "hosts": []}
        details = self.pool.command(tenant, "PostDeviceDetailsV2", body={"ids": ids})
        return {"total": total, "hosts": [summarize_host(h) for h in details.get("resources") or []]}

    def _overview(self, tenant: Tenant, hours: int) -> dict[str, Any]:
        new = f"status:'new'+created_timestamp:>'now-{hours}h'"
        metrics = {
            "new_alerts": ("GetQueriesAlertsV2", new),
            "new_critical_high_alerts": ("GetQueriesAlertsV2", f"{new}+severity_name:['Critical','High']"),
            "hosts": ("QueryDevicesByFilter", None),
            "contained_hosts": ("QueryDevicesByFilter", "status:'contained'"),
            "hosts_not_seen_7d": ("QueryDevicesByFilter", "last_seen:<'now-7d'"),
        }
        out: dict[str, Any] = {}
        errors: dict[str, str] = {}
        first: FalconError | None = None
        for name, (operation, fql) in metrics.items():
            # One missing API scope (say Hosts: Read) should blank its metrics, not the whole tenant.
            try:
                out[name] = self._count(tenant, operation, fql)
            except FalconError as exc:
                out[name], errors[name], first = None, str(exc), first or exc
        if first is not None and len(errors) == len(metrics):
            raise first
        if errors:
            out["errors"] = errors
        return out

    def _hunt(self, tenant: Tenant, kind: str, value: str, limit: int) -> dict[str, Any]:
        try:
            query = self.pool.command(
                tenant, "indicator_get_devices_ran_on_v1", parameters={"type": kind, "value": value, "limit": limit}
            )
        except FalconError as exc:
            if exc.status == 404:  # the IOC API answers "never seen" with a 404
                return {"total": 0, "hosts": []}
            raise
        ids = query.get("resources") or []
        total = _total(query)
        if not ids:
            return {"total": total if total is not None else 0, "hosts": []}
        details = self.pool.command(tenant, "PostDeviceDetailsV2", body={"ids": ids})
        hosts = [_pick(h, "device_id", "hostname", "platform_name", "status", "last_seen", "local_ip")
                 for h in details.get("resources") or []]  # fmt: skip
        return {"total": total, "hosts": hosts}


def register_tools(mcp: MCPServer, fleet: FleetTools) -> None:
    @mcp.tool(annotations=READ)
    async def list_tenants() -> dict[str, Any]:
        """List the CrowdStrike tenants (CIDs) you can access and your role in each."""
        principal = current_principal()
        snapshot = fleet.registry.snapshot()
        tenants = [
            {**t.public_view(), "your_role": principal.role_for(t.id).name.lower()}
            for t in sorted(snapshot.tenants.values(), key=lambda t: t.id)
            if principal.role_for(t.id) >= Role.READER
        ]
        fleet.audit(principal, "list_tenants", [t["tenant"] for t in tenants], "ok")
        return {"user": principal.user, "actions_enabled": fleet.settings.actions_enabled, "tenants": tenants}

    @mcp.tool(annotations=READ)
    async def search_alerts(
        filter: str | None = None,
        tenants: TenantsArg = None,
        limit: int = 20,
        offset: int = 0,
        sort: str = "created_timestamp.desc",
    ) -> dict[str, Any]:
        """Search detections/alerts across tenants using Falcon Query Language.

        filter examples: "status:'new'+severity_name:'Critical'", "created_timestamp:>'now-24h'",
        "device.hostname:'WS-01'". tenants: omit to query every tenant you can access.
        offset pages through results (applied per tenant; compare with each tenant's total).
        Returns summaries; use get_alerts for full records.
        """
        n, skip = _clamp(limit), _offset(offset)
        return await fleet.run_read(
            "search_alerts", tenants, lambda t: fleet._alerts(t, filter, n, skip, sort), filter=filter, offset=skip
        )

    @mcp.tool(annotations=READ)
    async def get_alerts(tenant: str, composite_ids: list[str]) -> dict[str, Any]:
        """Fetch full alert records (process tree, IOCs, MITRE details) from one tenant."""
        ids = _capped_ids(composite_ids)
        return await fleet.run_read(
            "get_alerts", [tenant],
            lambda t: fleet.pool.command(t, "PostEntitiesAlertsV2", body={"composite_ids": ids}).get("resources"),
        )  # fmt: skip

    @mcp.tool(annotations=READ)
    async def search_hosts(
        filter: str | None = None, tenants: TenantsArg = None, limit: int = 20, offset: int = 0
    ) -> dict[str, Any]:
        """Search managed hosts across tenants with FQL.

        filter examples: "hostname:'WS-01'", "platform_name:'Windows'+status:'contained'",
        "last_seen:<'now-7d'". tenants: omit to query every tenant you can access.
        offset pages through results (applied per tenant; compare with each tenant's total).
        """
        n, skip = _clamp(limit), _offset(offset)
        return await fleet.run_read(
            "search_hosts", tenants, lambda t: fleet._hosts(t, filter, n, skip), filter=filter, offset=skip
        )

    @mcp.tool(annotations=READ)
    async def get_host_details(tenant: str, device_ids: list[str]) -> dict[str, Any]:
        """Fetch full host records from one tenant."""
        ids = _capped_ids(device_ids)
        return await fleet.run_read(
            "get_host_details", [tenant],
            lambda t: fleet.pool.command(t, "PostDeviceDetailsV2", body={"ids": ids}).get("resources"),
        )  # fmt: skip

    @mcp.tool(annotations=READ)
    async def search_vulnerabilities(filter: str, tenants: TenantsArg = None, limit: int = 20) -> dict[str, Any]:
        """Search Spotlight vulnerabilities across tenants. filter is required FQL, e.g.
        "status:'open'+cve.severity:'CRITICAL'" or "cve.id:'CVE-2026-1234'"."""
        n = _clamp(limit)

        def run(t: Tenant) -> dict[str, Any]:
            body = fleet.pool.command(
                t, "combinedQueryVulnerabilities",
                parameters={"filter": filter, "limit": n, "facet": ["cve", "host_info"]},
            )  # fmt: skip
            return {"total": _total(body), "vulnerabilities": [summarize_vuln(v) for v in body.get("resources") or []]}

        return await fleet.run_read("search_vulnerabilities", tenants, run, filter=filter)

    @mcp.tool(annotations=READ)
    async def fleet_overview(tenants: TenantsArg = None, hours: int = 24) -> dict[str, Any]:
        """Posture snapshot per tenant: new alerts (all, and Critical/High) created in the last
        `hours`, host count, contained hosts and hosts not seen for 7 days. Start triage here."""
        window = max(1, min(hours, 24 * 30))
        return await fleet.run_read("fleet_overview", tenants, lambda t: fleet._overview(t, window), hours=window)

    @mcp.tool(annotations=READ)
    async def hunt_indicator(
        type: IndicatorType, value: str, tenants: TenantsArg = None, limit: int = 20
    ) -> dict[str, Any]:
        """Find hosts in every tenant that have observed an indicator (sha256, md5, domain, ipv4, ipv6).

        Uses Falcon's IOC "devices ran on" lookup, so it can find hosts that raised no alert.
        Use search_alerts for detections and lookup_indicator for intel context.
        """
        value = value.strip()
        if not _valid_indicator(type, value):
            raise ToolError(f"value is not a valid {type}")
        n = _clamp(limit)
        return await fleet.run_read(
            "hunt_indicator", tenants, lambda t: fleet._hunt(t, type, value, n), indicator_type=type, indicator=value
        )

    @mcp.tool(annotations=READ)
    async def search_intel_actors(query: str, tenants: TenantsArg = None, limit: int = 10) -> dict[str, Any]:
        """Search Falcon Intelligence adversary profiles (requires an Intel subscription)."""
        n = _clamp(limit)

        def run(t: Tenant) -> Any:
            body = fleet.pool.command(t, "QueryIntelActorEntities", parameters={"q": query, "limit": n})
            return [
                _pick(a, "name", "slug", "short_description", "motivations", "target_countries", "target_industries")
                for a in body.get("resources") or []
            ]

        return await fleet.run_read("search_intel_actors", tenants, run, query=query)

    @mcp.tool(annotations=READ)
    async def lookup_indicator(value: str, tenants: TenantsArg = None) -> dict[str, Any]:
        """Look up a hash, domain, IP or URL in Falcon Intelligence."""

        def run(t: Tenant) -> Any:
            body = fleet.pool.command(
                t, "QueryIntelIndicatorEntities", parameters={"filter": f"indicator:{_fql_quote(value)}", "limit": 10}
            )
            return [
                _pick(i, "indicator", "type", "malicious_confidence", "labels", "actors", "malware_families",
                      "last_updated", "kill_chains")  # fmt: skip
                for i in body.get("resources") or []
            ]

        return await fleet.run_read("lookup_indicator", tenants, run, indicator=value)

    if not fleet.settings.actions_enabled:
        return

    @mcp.tool(annotations=ACTION)
    async def contain_hosts(tenant: str, device_ids: list[str], reason: str) -> dict[str, Any]:
        """Network-contain hosts in ONE tenant. Requires the responder role and a reason (audited).
        Confirm the hosts with get_host_details first."""
        return await fleet.run_action(
            "contain_hosts", tenant, device_ids, "PerformActionV2", reason,
            parameters={"action_name": "contain"}, body={"ids": device_ids},
        )  # fmt: skip

    @mcp.tool(annotations=ACTION)
    async def lift_containment(tenant: str, device_ids: list[str], reason: str) -> dict[str, Any]:
        """Lift network containment on hosts in ONE tenant. Requires the responder role and a reason."""
        return await fleet.run_action(
            "lift_containment", tenant, device_ids, "PerformActionV2", reason,
            parameters={"action_name": "lift_containment"}, body={"ids": device_ids},
        )  # fmt: skip

    @mcp.tool(annotations=ACTION)
    async def update_alerts(
        tenant: str,
        composite_ids: list[str],
        reason: str,
        status: Literal["new", "in_progress", "reopened", "closed"] | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """Change status and/or add a comment on alerts in ONE tenant. Requires the responder role."""
        params = []
        if status:
            params.append({"name": "update_status", "value": status})
        params.append({"name": "append_comment", "value": comment or f"[falcon-fleet-mcp] {reason}"})
        return await fleet.run_action(
            "update_alerts", tenant, composite_ids, "PatchEntitiesAlertsV3", reason,
            body={"composite_ids": composite_ids, "action_parameters": params},
        )  # fmt: skip
