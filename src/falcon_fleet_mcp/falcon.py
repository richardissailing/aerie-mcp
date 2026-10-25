"""One FalconPy client per tenant, created lazily and reused while the Lambda is warm.

FalconPy binds a token to a single CID (``member_cid`` is fixed at authentication), so a
Flight Control child gets its own client built from the parent's credentials.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TypeVar

from falconpy import APIHarnessV2

from .config import Settings, aws_client
from .registry import Tenant

T = TypeVar("T")
log = logging.getLogger(__name__)
USER_AGENT = "falcon-fleet-mcp/0.1"
MAX_RETRY_WAIT = 2.0  # seconds; a longer rate-limit wait is reported rather than slept through

FALCON_CLOUDS = {"us1", "us2", "us3", "eu1", "usgov1", "usgov2"}
_FALCON_URL_RE = re.compile(r"^https://api(\.[a-z0-9-]+)*\.crowdstrike\.(com|mil)/?$")


def checked_base_url(value: str) -> str:
    """A Falcon cloud name or Falcon API URL; anything else is refused.

    FalconPy treats an unknown name as a hostname, so a typo would send the API client
    secret to whatever host it spells.
    """
    if value.lower().replace("-", "") in FALCON_CLOUDS or _FALCON_URL_RE.match(value.lower()):
        return value
    raise ValueError(f"{value!r} is not a Falcon cloud ({', '.join(sorted(FALCON_CLOUDS))}) or Falcon API URL")


class FalconError(Exception):
    def __init__(self, status: int, errors: Any):
        super().__init__(f"Falcon API returned {status}: {errors}")
        self.status = status
        self.errors = errors


_secrets_client: Any = None
_secrets_lock = threading.Lock()


def _secretsmanager() -> Any:
    global _secrets_client
    with _secrets_lock:
        if _secrets_client is None:
            _secrets_client = aws_client("secretsmanager")
        return _secrets_client


def load_credentials(ref: str) -> dict[str, str]:
    source, _, target = ref.partition(":")
    if source == "secretsmanager":
        secret = _secretsmanager().get_secret_value(SecretId=target)["SecretString"]
        data = json.loads(secret)
    elif source == "env":
        data = {"client_id": os.environ[f"{target}_CLIENT_ID"], "client_secret": os.environ[f"{target}_CLIENT_SECRET"]}
    else:
        raise ValueError(f"unsupported credential reference {ref!r}")
    return {"client_id": data["client_id"], "client_secret": data["client_secret"]}


def internal_error(message: str, *args: Any) -> str:
    """Log the active exception under a reference and return a caller-safe message.

    AWS/config errors can name roles, secret ARNs or env vars: log them, don't return them.
    """
    ref = uuid.uuid4().hex[:12]
    log.exception(message + " (ref %s)", *args, ref)
    return f"internal error (ref {ref})"


def _retry_wait(response: dict[str, Any]) -> float | None:
    """Seconds until Falcon's rate limit resets (X-Ratelimit-Retryafter, epoch seconds), if short."""
    headers = {k.lower(): v for k, v in (response.get("headers") or {}).items()}
    try:
        wait = float(headers.get("x-ratelimit-retryafter", "")) - time.time()
    except ValueError:
        wait = 1.0  # no usable header: one short pause
    return max(0.0, wait) if wait <= MAX_RETRY_WAIT else None


class ClientPool:
    def __init__(self, settings: Settings, factory: Callable[[Tenant], Any] | None = None):
        self._settings = settings
        self._factory = factory or self._build
        self._clients: dict[str, tuple[Tenant, Any]] = {}
        self._lock = threading.Lock()  # guards the dicts below; never held during I/O
        self._build_locks: dict[str, threading.Lock] = {}
        self._semaphore: asyncio.Semaphore | None = None
        # Own pool: the default executor can be smaller than fanout_concurrency (it is sized
        # from the CPU count), which would queue calls while their timeouts are running.
        self._executor = ThreadPoolExecutor(max_workers=settings.fanout_concurrency, thread_name_prefix="falcon")

    @staticmethod
    def _build(tenant: Tenant) -> APIHarnessV2:
        base_url = checked_base_url(tenant.base_url)  # before the secret is even read
        creds = load_credentials(tenant.credential)
        return APIHarnessV2(
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            base_url=base_url,
            member_cid=tenant.member_cid,
            user_agent=USER_AGENT,
            timeout=20,
        )

    def client(self, tenant: Tenant) -> Any:
        with self._lock:
            cached = self._clients.get(tenant.id)
            if cached is not None and cached[0] == tenant:
                return cached[1]
            build_lock = self._build_locks.setdefault(tenant.id, threading.Lock())
        # Per-tenant lock: tenants build (Secrets Manager fetch) in parallel, one build each.
        with build_lock:
            with self._lock:
                cached = self._clients.get(tenant.id)
            # Rebuild when the registry entry changes (new secret, region or child CID).
            if cached is None or cached[0] != tenant:
                cached = (tenant, self._factory(tenant))
                with self._lock:
                    self._clients[tenant.id] = cached
            return cached[1]

    def command(self, tenant: Tenant, operation: str, **kwargs: Any) -> dict[str, Any]:
        """Run one Falcon operation and return the response body, raising on HTTP errors."""
        client = self.client(tenant)
        response = client.command(operation, **kwargs)
        status = response.get("status_code", 0)
        if status == 429 and (wait := _retry_wait(response)) is not None:
            # Rate-limited requests were not processed, so retrying once is safe even for actions.
            time.sleep(wait)
            response = client.command(operation, **kwargs)
            status = response.get("status_code", 0)
        body = response.get("body") or {}
        if status >= 400:
            if status == 401:  # stale token or rotated secret: rebuild on next call
                with self._lock:
                    # Only evict this client, not one another thread has already rebuilt.
                    cached = self._clients.get(tenant.id)
                    if cached is not None and cached[1] is client:
                        del self._clients[tenant.id]
            raise FalconError(status, body.get("errors") or body)
        return body

    async def fan_out(
        self, tenants: list[Tenant], fn: Callable[[Tenant], T], budget_seconds: float | None = None
    ) -> dict[str, Any]:
        """Run ``fn`` against every tenant concurrently; one tenant failing never fails the rest.

        ``budget_seconds`` is the time left for the whole fan-out (default
        ``fanout_deadline_seconds``); pass the remainder when the request has already spent time.

        A slot is held until the worker thread really finishes (a timed-out thread keeps
        running), so every call that gets a slot starts immediately and its timeout never
        includes time spent queued behind abandoned calls.
        """
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._settings.fanout_concurrency)
        semaphore = self._semaphore
        loop = asyncio.get_running_loop()
        # Finish inside the Lambda timeout so callers get partial results rather than nothing.
        if budget_seconds is None:
            budget_seconds = self._settings.fanout_deadline_seconds
        deadline = loop.time() + budget_seconds

        async def one(tenant: Tenant) -> tuple[str, Any]:
            try:
                await asyncio.wait_for(semaphore.acquire(), timeout=max(0.0, deadline - loop.time()))
            except TimeoutError:
                return tenant.id, {"ok": False, "error": "not attempted: request deadline reached"}
            budget = min(self._settings.per_tenant_timeout_seconds, deadline - loop.time())
            if budget <= 0:
                semaphore.release()
                return tenant.id, {"ok": False, "error": "not attempted: request deadline reached"}
            work = loop.run_in_executor(self._executor, fn, tenant)
            work.add_done_callback(lambda _: semaphore.release())
            try:
                result = await asyncio.wait_for(asyncio.shield(work), timeout=budget)
                return tenant.id, {"ok": True, "data": result}
            except TimeoutError:
                work.add_done_callback(lambda f: f.cancelled() or f.exception())  # retrieve late errors
                return tenant.id, {"ok": False, "error": "timed out"}
            except FalconError as exc:
                return tenant.id, {"ok": False, "error": str(exc), "status": exc.status}
            except Exception:
                return tenant.id, {"ok": False, "error": internal_error("tenant %s failed", tenant.id)}

        return dict(await asyncio.gather(*(one(t) for t in tenants)))
