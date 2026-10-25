"""Tenant registry and access policy.

Each item in the config table has a ``pk`` of ``tenant#<id>`` or ``grant#<name>`` and a
``doc`` attribute holding JSON. Terraform owns the items; this module only reads them.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

from .config import Settings, aws_resource


class Role(IntEnum):
    NONE = 0
    READER = 1
    RESPONDER = 2

    @classmethod
    def parse(cls, value: str) -> Role:
        try:
            return cls[value.upper()]
        except KeyError as exc:
            raise ValueError(f"unknown role {value!r}") from exc


@dataclass(frozen=True)
class Tenant:
    id: str
    display_name: str
    base_url: str
    credential: str  # "secretsmanager:<arn-or-name>" or "env:<PREFIX>"
    member_cid: str | None = None
    allow_actions: bool = False
    tags: tuple[str, ...] = ()

    @classmethod
    def from_doc(cls, tenant_id: str, doc: dict[str, Any]) -> Tenant:
        return cls(
            id=tenant_id,
            display_name=doc.get("display_name", tenant_id),
            base_url=doc["base_url"],
            credential=doc["credential"],
            member_cid=doc.get("member_cid") or None,
            allow_actions=bool(doc.get("allow_actions", False)),
            tags=tuple(doc.get("tags", ())),
        )

    def public_view(self) -> dict[str, Any]:
        return {
            "tenant": self.id,
            "display_name": self.display_name,
            "flight_control_child": self.member_cid is not None,
            "actions_allowed": self.allow_actions,
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class Grant:
    group: str
    tenants: tuple[str, ...]  # "*" means every tenant
    role: Role

    @classmethod
    def from_doc(cls, doc: dict[str, Any]) -> Grant:
        return cls(group=doc["group"], tenants=tuple(doc["tenants"]), role=Role.parse(doc["role"]))


@dataclass
class RegistrySnapshot:
    tenants: dict[str, Tenant] = field(default_factory=dict)
    grants: list[Grant] = field(default_factory=list)

    def roles_for_groups(self, groups: AbstractSet[str]) -> dict[str, Role]:
        """Highest role per tenant across every grant matching one of ``groups``."""
        roles: dict[str, Role] = {}
        for grant in self.grants:
            if grant.group not in groups:
                continue
            targets = self.tenants.keys() if "*" in grant.tenants else grant.tenants
            for tenant_id in targets:
                if tenant_id in self.tenants and grant.role > roles.get(tenant_id, Role.NONE):
                    roles[tenant_id] = grant.role
        return roles


def parse_documents(items: list[tuple[str, dict[str, Any]]]) -> RegistrySnapshot:
    snap = RegistrySnapshot()
    for pk, doc in items:
        kind, _, key = pk.partition("#")
        if kind == "tenant":
            snap.tenants[key] = Tenant.from_doc(key, doc)
        elif kind == "grant":
            snap.grants.append(Grant.from_doc(doc))
    return snap


class Registry:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._lock = threading.Lock()
        self._snapshot: RegistrySnapshot | None = None
        self._loaded_at = 0.0

    def snapshot(self) -> RegistrySnapshot:
        with self._lock:
            if self._snapshot is None or time.monotonic() - self._loaded_at > self._settings.cache_ttl_seconds:
                self._snapshot = self._load()
                self._loaded_at = time.monotonic()
            return self._snapshot

    def _load(self) -> RegistrySnapshot:
        if self._settings.config_table:
            return parse_documents(self._scan_table(self._settings.config_table))
        if self._settings.registry_file:
            data = json.loads(Path(self._settings.registry_file).read_text())
            items = [(f"tenant#{k}", v) for k, v in data.get("tenants", {}).items()]
            items += [(f"grant#{i}", g) for i, g in enumerate(data.get("grants", []))]
            return parse_documents(items)
        raise RuntimeError("set CONFIG_TABLE or REGISTRY_FILE")

    @staticmethod
    def _scan_table(table_name: str) -> list[tuple[str, dict[str, Any]]]:
        table = aws_resource("dynamodb").Table(table_name)
        items: list[tuple[str, dict[str, Any]]] = []
        kwargs: dict[str, Any] = {}
        while True:
            page = table.scan(**kwargs)
            items += [(it["pk"], json.loads(it["doc"])) for it in page.get("Items", [])]
            if "LastEvaluatedKey" not in page:
                return items
            kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
