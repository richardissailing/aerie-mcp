"""Resolve a signed-in user's IAM Identity Center group names.

Groups are looked up server-side through the Identity Store API rather than carried in
the SAML assertion, so access changes in Identity Center apply within one cache TTL.
When Identity Center lives in another account (management or delegated admin), set
IDENTITY_STORE_ROLE_ARN to a read-only role there.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any

from .config import Settings, aws_client


class UnknownUser(Exception):
    pass


class IdentityCenterGroups:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, frozenset[str]]] = {}
        self._group_names: dict[str, tuple[float, str]] = {}  # group id -> (fetched at, display name)
        self._client: Any = None
        self._client_lock = threading.Lock()
        self._client_expires: datetime | None = None
        # Long-lived pool for DisplayName lookups instead of one pool per sign-in.
        self._executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="identitystore")

    def groups_for(self, username: str) -> frozenset[str]:
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(username)
            if hit and now - hit[0] < self._settings.cache_ttl_seconds:
                return hit[1]
        groups = self._lookup(username)
        with self._lock:
            self._cache[username] = (now, groups)
        return groups

    def _identitystore(self) -> Any:
        # Lookups run in worker threads; build/refresh the client once, not per racing request.
        with self._client_lock:
            return self._identitystore_locked()

    def _identitystore_locked(self) -> Any:
        role_arn = self._settings.identity_store_role_arn
        region = self._settings.identity_store_region
        if self._client is not None and (
            self._client_expires is None or datetime.now(UTC) < self._client_expires - timedelta(minutes=5)
        ):
            return self._client
        if not role_arn:
            self._client = aws_client("identitystore", region_name=region)
            self._client_expires = None
        else:
            creds = aws_client("sts").assume_role(RoleArn=role_arn, RoleSessionName="falcon-fleet-mcp")["Credentials"]
            self._client = aws_client(
                "identitystore",
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
            self._client_expires = creds["Expiration"]
        return self._client

    def _lookup(self, username: str) -> frozenset[str]:
        client = self._identitystore()
        store_id = self._settings.identity_store_id
        path = "emails.value" if self._settings.user_lookup_attribute == "email" else "userName"
        try:
            user_id = client.get_user_id(
                IdentityStoreId=store_id,
                AlternateIdentifier={"UniqueAttribute": {"AttributePath": path, "AttributeValue": username}},
            )["UserId"]
        except client.exceptions.ResourceNotFoundException as exc:
            raise UnknownUser(username) from exc

        group_ids: list[str] = []
        paginator = client.get_paginator("list_group_memberships_for_member")
        for page in paginator.paginate(IdentityStoreId=store_id, MemberId={"UserId": user_id}):
            group_ids += [m["GroupId"] for m in page["GroupMemberships"]]

        # Grants match display names, so a renamed group must stop matching within one TTL too.
        now = time.monotonic()
        stale = [
            gid for gid in group_ids
            # .get(): concurrent sign-ins update this dict, so never check-then-index it.
            if now - self._group_names.get(gid, (float("-inf"), ""))[0] >= self._settings.cache_ttl_seconds
        ]  # fmt: skip
        if stale:

            def display_name(gid: str) -> str | None:
                try:
                    return client.describe_group(IdentityStoreId=store_id, GroupId=gid)["DisplayName"]
                except client.exceptions.ResourceNotFoundException:
                    return None  # group deleted since the membership listing: it grants nothing

            for gid, name in zip(stale, self._executor.map(display_name, stale), strict=True):
                if name is None:
                    self._group_names.pop(gid, None)
                else:
                    self._group_names[gid] = (now, name)
        names = [self._group_names.get(gid) for gid in group_ids]
        return frozenset(entry[1] for entry in names if entry is not None)
