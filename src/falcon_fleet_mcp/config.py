"""Runtime settings, read once from the environment."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Any

import boto3

# boto3 clients are thread-safe once built, but building them from the default session is
# not; every module builds its clients through these helpers so builds never race.
_boto3_lock = threading.Lock()


def aws_client(service: str, **kwargs: Any) -> Any:
    with _boto3_lock:
        return boto3.client(service, **kwargs)


def aws_resource(service: str, **kwargs: Any) -> Any:
    with _boto3_lock:
        return boto3.resource(service, **kwargs)


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str) -> list[str]:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


def running_in_lambda() -> bool:
    return "AWS_LAMBDA_FUNCTION_NAME" in os.environ


@dataclass(frozen=True)
class Settings:
    # Public URL of this server (no trailing slash). Derived from the request when unset,
    # which is what a bare Lambda Function URL needs.
    public_base_url: str | None = None

    # Cognito user pool that federates to IAM Identity Center and issues access tokens.
    cognito_region: str = ""
    cognito_user_pool_id: str = ""
    cognito_domain: str = ""  # e.g. https://falcon-mcp.auth.us-east-1.amazoncognito.com
    cognito_client_ids: list[str] = field(default_factory=list)
    cognito_idp_name: str = "IdentityCenter"
    # Redirect URIs the dynamic-registration shim will hand out (must also be on the app client).
    allowed_redirect_uris: list[str] = field(default_factory=list)

    # IAM Identity Center identity store, used to resolve the caller's groups.
    identity_store_id: str = ""
    identity_store_region: str = ""
    identity_store_role_arn: str = ""
    user_lookup_attribute: str = "userName"  # userName | email

    # Tenant registry / access policy: DynamoDB table, or a local JSON file for development.
    config_table: str = ""
    registry_file: str = ""
    cache_ttl_seconds: int = 300

    actions_enabled: bool = False
    max_action_targets: int = 20
    fanout_concurrency: int = 8
    per_tenant_timeout_seconds: float = 25.0
    fanout_deadline_seconds: float = 50.0  # keep below the Lambda timeout

    # Local development only: skip OAuth and act as DEV_USER with DEV_GROUPS.
    auth_disabled: bool = False
    dev_user: str = "dev@example.com"
    dev_groups: list[str] = field(default_factory=list)

    @property
    def cognito_issuer(self) -> str:
        return f"https://cognito-idp.{self.cognito_region}.amazonaws.com/{self.cognito_user_pool_id}"

    @classmethod
    def from_env(cls) -> Settings:
        auth_disabled = _bool("AUTH_DISABLED")
        if auth_disabled and running_in_lambda():
            raise RuntimeError("AUTH_DISABLED is only allowed outside Lambda")
        region = os.environ.get("COGNITO_REGION") or os.environ.get("AWS_REGION", "")
        return cls(
            public_base_url=(os.environ.get("PUBLIC_BASE_URL") or "").rstrip("/") or None,
            cognito_region=region,
            cognito_user_pool_id=os.environ.get("COGNITO_USER_POOL_ID", ""),
            cognito_domain=os.environ.get("COGNITO_DOMAIN", "").rstrip("/"),
            cognito_client_ids=_list("COGNITO_CLIENT_IDS"),
            cognito_idp_name=os.environ.get("COGNITO_IDP_NAME", "IdentityCenter"),
            allowed_redirect_uris=_list("ALLOWED_REDIRECT_URIS"),
            identity_store_id=os.environ.get("IDENTITY_STORE_ID", ""),
            identity_store_region=os.environ.get("IDENTITY_STORE_REGION") or region,
            identity_store_role_arn=os.environ.get("IDENTITY_STORE_ROLE_ARN", ""),
            user_lookup_attribute=os.environ.get("USER_LOOKUP_ATTRIBUTE", "userName"),
            config_table=os.environ.get("CONFIG_TABLE", ""),
            registry_file=os.environ.get("REGISTRY_FILE", ""),
            cache_ttl_seconds=int(os.environ.get("CACHE_TTL_SECONDS", "300")),
            actions_enabled=_bool("ACTIONS_ENABLED"),
            max_action_targets=int(os.environ.get("MAX_ACTION_TARGETS", "20")),
            fanout_concurrency=int(os.environ.get("FANOUT_CONCURRENCY", "8")),
            per_tenant_timeout_seconds=float(os.environ.get("PER_TENANT_TIMEOUT_SECONDS", "25")),
            fanout_deadline_seconds=float(os.environ.get("FANOUT_DEADLINE_SECONDS", "50")),
            auth_disabled=auth_disabled,
            dev_user=os.environ.get("DEV_USER", "dev@example.com"),
            dev_groups=_list("DEV_GROUPS"),
        )
