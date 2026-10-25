"""The AWS-facing code paths (registry scan, secrets, Identity Store) against moto."""

from __future__ import annotations

import json
from dataclasses import replace

import boto3
import pytest
from moto import mock_aws

from falcon_fleet_mcp import falcon
from falcon_fleet_mcp.config import Settings
from falcon_fleet_mcp.identity import IdentityCenterGroups, UnknownUser
from falcon_fleet_mcp.registry import Registry, Role

REGION = "ap-southeast-2"


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setattr(falcon, "_secrets_client", None)
    with mock_aws():
        yield


def test_registry_scans_every_page_of_the_config_table(aws):
    ddb = boto3.client("dynamodb")
    ddb.create_table(
        TableName="cfg", KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST",
    )  # fmt: skip
    padding = "x" * 20_000  # forces several scan pages (1 MB each)
    for i in range(120):
        doc = {"display_name": f"T{i}", "base_url": "us1", "credential": "env:X", "tags": [padding]}
        ddb.put_item(TableName="cfg", Item={"pk": {"S": f"tenant#t{i}"}, "doc": {"S": json.dumps(doc)}})
    grant = {"group": "SOC", "tenants": ["*"], "role": "reader"}
    ddb.put_item(TableName="cfg", Item={"pk": {"S": "grant#SOC#abc"}, "doc": {"S": json.dumps(grant)}})

    snap = Registry(replace(Settings(), config_table="cfg")).snapshot()
    assert len(snap.tenants) == 120
    assert snap.roles_for_groups({"SOC"})["t119"] == Role.READER


def test_credentials_load_from_secrets_manager(aws):
    sm = boto3.client("secretsmanager")
    arn = sm.create_secret(Name="falcon/x", SecretString=json.dumps({"client_id": "i", "client_secret": "s"}))["ARN"]
    assert falcon.load_credentials(f"secretsmanager:{arn}") == {"client_id": "i", "client_secret": "s"}


def _identity_store():
    ids = boto3.client("identitystore", region_name=REGION)
    store = "d-1234567890"
    user = ids.create_user(
        IdentityStoreId=store, UserName="alice", DisplayName="Alice",
        Name={"GivenName": "A", "FamilyName": "L"}, Emails=[{"Value": "alice@corp.com", "Primary": True}],
    )["UserId"]  # fmt: skip
    for name in ("SOC-Analysts", "IR-Global"):
        gid = ids.create_group(IdentityStoreId=store, DisplayName=name)["GroupId"]
        ids.create_group_membership(IdentityStoreId=store, GroupId=gid, MemberId={"UserId": user})
    ids.create_group(IdentityStoreId=store, DisplayName="Unrelated")
    return store


@pytest.mark.parametrize(("attribute", "username"), [("userName", "alice"), ("email", "alice@corp.com")])
def test_identity_store_groups_by_username_or_email(aws, attribute, username):
    store = _identity_store()
    settings = replace(Settings(), identity_store_id=store, identity_store_region=REGION, user_lookup_attribute=attribute)
    assert IdentityCenterGroups(settings).groups_for(username) == {"SOC-Analysts", "IR-Global"}


def test_unknown_identity_center_user(aws):
    store = _identity_store()
    settings = replace(Settings(), identity_store_id=store, identity_store_region=REGION)
    with pytest.raises(UnknownUser):
        IdentityCenterGroups(settings).groups_for("mallory")


def test_identity_store_through_an_assumed_role(aws):
    store = _identity_store()
    role = boto3.client("iam").create_role(RoleName="reader", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
    settings = replace(Settings(), identity_store_id=store, identity_store_region=REGION, identity_store_role_arn=role)
    assert IdentityCenterGroups(settings).groups_for("alice") == {"SOC-Analysts", "IR-Global"}
