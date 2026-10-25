"""ASGI entry point: ``uvicorn falcon_fleet_mcp.app:app`` (the Lambda Web Adapter runs this)."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from .auth import AuthMiddleware, Principal, TokenValidator, oauth_routes
from .config import Settings
from .falcon import ClientPool
from .identity import IdentityCenterGroups
from .registry import Registry
from .tools import FleetTools, register_tools

INSTRUCTIONS = """Query and respond across every CrowdStrike Falcon tenant (CID) the signed-in user may access.
Start with list_tenants, or fleet_overview for a posture snapshot. Search tools accept a `tenants` list; omit it
to fan out to all permitted tenants, and check `tenants_failed` in results. Use hunt_indicator to find hosts that
saw an IOC in any tenant. Action tools act on one tenant at a time and require a reason."""


def build_app(
    settings: Settings,
    registry: Registry | None = None,
    groups_for: Callable[[str], Iterable[str]] | None = None,
    pool: ClientPool | None = None,
    validator: TokenValidator | None = None,
) -> ASGIApp:
    registry = registry or Registry(settings)
    pool = pool or ClientPool(settings)
    if settings.auth_disabled:
        lookup: Callable[[str], Iterable[str]] = lambda _user: frozenset(settings.dev_groups)  # noqa: E731
    else:
        lookup = groups_for or IdentityCenterGroups(settings).groups_for
        validator = validator or TokenValidator(settings)

    def authorize(username: str) -> Principal:
        groups = frozenset(lookup(username))
        return Principal(user=username, groups=groups, roles=registry.snapshot().roles_for_groups(groups))

    mcp = MCPServer(name="falcon-fleet", instructions=INSTRUCTIONS, version="0.1.0")
    register_tools(mcp, FleetTools(settings, registry, pool))

    for path, methods, handler in oauth_routes(settings):
        mcp.custom_route(path, methods=methods)(handler)

    @mcp.custom_route("/health", methods=["GET"])
    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    inner = mcp.streamable_http_app(
        stateless_http=True,  # every Lambda invocation may land on a different container
        json_response=True,  # plain request/response; no long-lived SSE streams
        # Host-header checks guard local servers against DNS rebinding; this endpoint is
        # public and bearer-authenticated, and the Function URL host is not known up front.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    return AuthMiddleware(inner, settings, authorize, validator)


class _LogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # Audit lines stay bare JSON so CloudWatch metric filters can match their fields.
        if record.name == "falcon_fleet_mcp.audit":
            return record.getMessage()
        return super().format(record)


_handler = logging.StreamHandler()
_handler.setFormatter(_LogFormatter("%(levelname)s %(name)s %(message)s"))
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), handlers=[_handler])


def __getattr__(name: str) -> ASGIApp:
    # Built on first access so importing the package (e.g. in tests) needs no AWS config.
    if name == "app":
        globals()["app"] = build_app(Settings.from_env())
        return globals()["app"]
    raise AttributeError(name)
