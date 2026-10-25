"""OAuth for the MCP endpoint.

Amazon Cognito federates to IAM Identity Center (SAML) and issues the access tokens.
This server acts as the OAuth *resource server* and also publishes a thin
authorization-server facade over Cognito, because MCP clients need things Cognito
does not provide directly:

* RFC 8414 metadata advertising PKCE (``code_challenge_methods_supported``)
* dynamic client registration, answered with the pre-registered public client
* tolerance of the RFC 8707 ``resource`` parameter, which is stripped before Cognito
* a straight hop to Identity Center, skipping Cognito's provider picker
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import Settings
from .identity import UnknownUser
from .registry import Role

log = logging.getLogger(__name__)

MCP_PATH = "/mcp"
SCOPES = ["openid", "email", "profile"]


@dataclass(frozen=True)
class Principal:
    user: str
    groups: frozenset[str]
    roles: dict[str, Role] = field(default_factory=dict)

    def role_for(self, tenant_id: str) -> Role:
        return self.roles.get(tenant_id, Role.NONE)


principal_var: contextvars.ContextVar[Principal | None] = contextvars.ContextVar("principal", default=None)
# time.monotonic() when the request arrived, so tools can budget against the Lambda timeout
# including the time authentication already used.
request_started_var: contextvars.ContextVar[float | None] = contextvars.ContextVar("request_started", default=None)


def current_principal() -> Principal:
    principal = principal_var.get()
    if principal is None:
        raise PermissionError("no authenticated principal")
    return principal


def base_url(settings: Settings, request: Request) -> str:
    if settings.public_base_url:
        return settings.public_base_url
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return f"{proto}://{request.headers.get('host', request.url.netloc)}"


class TokenValidator:
    def __init__(self, settings: Settings, jwks: Any = None):
        self._settings = settings
        self._jwks = jwks or jwt.PyJWKClient(f"{settings.cognito_issuer}/.well-known/jwks.json", cache_keys=True)

    def validate(self, token: str) -> dict[str, Any]:
        key = self._jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            key.key,
            algorithms=["RS256"],
            issuer=self._settings.cognito_issuer,
            leeway=30,  # tolerate clock skew: PyJWT rejects a token whose iat is even 1s ahead
            options={"require": ["exp", "iss", "sub"], "verify_aud": False},  # Cognito access tokens carry client_id, not aud
        )
        if claims.get("token_use") != "access":
            raise jwt.InvalidTokenError("not an access token")
        if claims.get("client_id") not in self._settings.cognito_client_ids:
            raise jwt.InvalidTokenError("token issued to an unknown client")
        return claims

    def username(self, claims: dict[str, Any]) -> str:
        """Cognito names federated users ``<provider>_<NameID>``; return the NameID.

        Only federated users are accepted: a native Cognito user could otherwise be created
        with an Identity Center user's name and inherit their groups.
        """
        username = claims.get("username", "")
        prefix = f"{self._settings.cognito_idp_name}_"
        if not username.lower().startswith(prefix.lower()) or len(username) == len(prefix):
            raise jwt.InvalidTokenError("token was not issued for an Identity Center user")
        return username[len(prefix) :]


Authorizer = Callable[[str], Principal]  # username -> Principal


class AuthMiddleware:
    """Guards ``/mcp``: bearer token -> Principal, stored for tools and the SDK."""

    def __init__(self, app: ASGIApp, settings: Settings, authorize: Authorizer, validator: TokenValidator | None):
        self.app = app
        self.settings = settings
        self.authorize = authorize
        self.validator = validator

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith(MCP_PATH):
            await self.app(scope, receive, send)
            return
        started = time.monotonic()
        request = Request(scope)
        try:
            # Token validation and the policy lookup make blocking network calls (JWKS, STS,
            # Identity Store, DynamoDB); keep them off the event loop.
            principal, access = await asyncio.to_thread(self._authenticate, request)
        except _AuthFailure as failure:
            await failure.response(self.settings, request)(scope, receive, send)
            return

        scope["user"] = AuthenticatedUser(access)
        p_token = principal_var.set(principal)
        s_token = request_started_var.set(started)
        a_token = auth_context_var.set(scope["user"])
        try:
            await self.app(scope, receive, send)
        finally:
            auth_context_var.reset(a_token)
            request_started_var.reset(s_token)
            principal_var.reset(p_token)

    def _authenticate(self, request: Request) -> tuple[Principal, AccessToken]:
        if self.settings.auth_disabled:
            principal = self.authorize(self.settings.dev_user)
            return principal, AccessToken(token="dev", client_id="dev", scopes=[], subject=principal.user)

        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise _AuthFailure(401)
        assert self.validator is not None
        try:
            claims = self.validator.validate(token)
            username = self.validator.username(claims)
        except jwt.PyJWKClientConnectionError as exc:
            # JWKS endpoint unreachable: the token may be fine, so ask the client to retry
            # instead of discarding it and re-running the sign-in flow.
            log.warning("JWKS fetch failed: %s", exc)
            raise _AuthFailure(503, "temporarily_unavailable", "token signing keys unavailable; retry shortly") from exc
        except jwt.PyJWTError as exc:
            log.info("rejected token: %s", exc)
            raise _AuthFailure(401, "invalid_token", str(exc)) from exc

        # 403s carry no RFC 6750 error code: MCP clients treat "insufficient_scope" as a request
        # for step-up and re-run the browser sign-in, which cannot help a user with no access.
        try:
            principal = self.authorize(username)
        except UnknownUser as exc:
            raise _AuthFailure(403, None, "user not found in IAM Identity Center") from exc
        except Exception as exc:
            # Registry or Identity Store unavailable. Fail closed rather than serve a stale
            # policy, so revocations stay effective; report it as transient, not a denial.
            log.exception("authorization lookup failed for %s", username)
            raise _AuthFailure(503, "temporarily_unavailable", "access policy lookup failed; retry shortly") from exc
        if not principal.roles:
            raise _AuthFailure(403, None, "no CrowdStrike tenant access granted to your groups")
        access = AccessToken(
            token=token,
            client_id=claims["client_id"],
            scopes=claims.get("scope", "").split(),
            expires_at=claims.get("exp"),
            subject=claims["sub"],
            claims={"iss": claims["iss"]},
        )
        return principal, access


def _header_safe(text: str) -> str:
    """RFC 6750 error_description: printable ASCII without ``"`` or ``\\``."""
    return "".join(c for c in text.replace('"', "'") if " " <= c <= "~" and c != "\\")


class _AuthFailure(Exception):
    def __init__(self, status: int, error: str | None = None, description: str | None = None):
        self.status, self.error, self.description = status, error, description

    def response(self, settings: Settings, request: Request) -> Response:
        challenge = f'Bearer resource_metadata="{base_url(settings, request)}/.well-known/oauth-protected-resource{MCP_PATH}"'
        if self.error:
            challenge += f', error="{self.error}"'
        if self.description:
            challenge += f', error_description="{_header_safe(self.description)}"'
        default_error = "access_denied" if self.status == 403 else "unauthorized"
        body = {"error": self.error or default_error, "error_description": self.description or "authentication required"}
        return JSONResponse(body, status_code=self.status, headers={"WWW-Authenticate": challenge})


# --- OAuth discovery + authorization-server facade -------------------------------------


def oauth_routes(settings: Settings) -> list[tuple[str, list[str], Callable[[Request], Any]]]:
    async def protected_resource(request: Request) -> Response:
        base = base_url(settings, request)
        return JSONResponse(
            {
                "resource": f"{base}{MCP_PATH}",
                "authorization_servers": [base],
                "scopes_supported": SCOPES,
                "bearer_methods_supported": ["header"],
                "resource_name": "CrowdStrike Falcon (multi-tenant)",
            }
        )

    async def as_metadata(request: Request) -> Response:
        base = base_url(settings, request)
        return JSONResponse(
            {
                "issuer": base,
                "authorization_endpoint": f"{base}/authorize",
                "token_endpoint": f"{base}/token",
                "registration_endpoint": f"{base}/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": SCOPES,
            }
        )

    async def authorize(request: Request) -> Response:
        params = dict(request.query_params)
        if params.get("client_id") not in settings.cognito_client_ids:
            return JSONResponse({"error": "invalid_client"}, status_code=400)
        if params.get("redirect_uri") not in settings.allowed_redirect_uris:
            return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri not allowed"}, 400)
        if params.get("code_challenge_method") != "S256" or not params.get("code_challenge"):
            return JSONResponse({"error": "invalid_request", "error_description": "PKCE S256 required"}, 400)
        params.pop("resource", None)
        params["identity_provider"] = settings.cognito_idp_name
        # Cognito rejects email/profile unless openid is also requested.
        scopes = [s for s in params.get("scope", " ".join(SCOPES)).split() if s in SCOPES and s != "openid"]
        params["scope"] = " ".join(["openid", *scopes])
        return RedirectResponse(f"{settings.cognito_domain}/oauth2/authorize?{urlencode(params)}", status_code=302)

    async def token(request: Request) -> Response:
        form = {k: v for k, v in (await request.form()).items() if k != "resource"}
        if form.get("client_id") not in settings.cognito_client_ids:
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                upstream = await client.post(f"{settings.cognito_domain}/oauth2/token", data=form)
        except httpx.HTTPError as exc:
            log.warning("token endpoint unreachable: %s", exc)
            return JSONResponse({"error": "temporarily_unavailable"}, status_code=502, headers={"Cache-Control": "no-store"})
        return Response(
            upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
            headers={"Cache-Control": "no-store"},
        )

    async def register(request: Request) -> Response:
        try:
            meta = json.loads(await request.body() or b"{}")
        except json.JSONDecodeError:
            meta = None
        if not isinstance(meta, dict):
            return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)
        redirect_uris = meta.get("redirect_uris") or []
        if not isinstance(redirect_uris, list):
            redirect_uris = []
        rejected = [u for u in redirect_uris if not isinstance(u, str) or u not in settings.allowed_redirect_uris]
        if not redirect_uris or rejected:
            return JSONResponse(
                {
                    "error": "invalid_redirect_uri",
                    "error_description": f"allowed redirect URIs: {', '.join(settings.allowed_redirect_uris)}",
                },
                status_code=400,
            )
        return JSONResponse(
            {
                "client_id": settings.cognito_client_ids[0],
                "client_name": meta.get("client_name", "mcp-client"),
                "redirect_uris": redirect_uris,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": " ".join(SCOPES),
            },
            status_code=201,
        )

    return [
        ("/.well-known/oauth-protected-resource", ["GET"], protected_resource),
        (f"/.well-known/oauth-protected-resource{MCP_PATH}", ["GET"], protected_resource),
        ("/.well-known/oauth-authorization-server", ["GET"], as_metadata),
        ("/authorize", ["GET"], authorize),
        ("/token", ["POST"], token),
        ("/register", ["POST"], register),
    ]
