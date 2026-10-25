"""List a Flight Control parent's child CIDs and print ``tenants`` entries for terraform.tfvars.

    uv run python -m falcon_fleet_mcp.discover --credential acme-parent --base-url us2 \\
        --secret-id falcon-fleet-mcp/falcon/acme-parent --prefix acme- \\
        --tfvars terraform/terraform.tfvars --grant Acme-SOC:reader

Credentials come from Secrets Manager (--secret-id) or from FALCON_CLIENT_ID /
FALCON_CLIENT_SECRET. The parent API client needs the Flight Control: Read scope.
Output goes to stdout for review; nothing is written. Progress and warnings go to stderr,
including tfvars entries for this parent whose child CID has left the parent.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError
from falconpy import APIHarnessV2

from .config import aws_client
from .falcon import USER_AGENT, checked_base_url

PAGE = 100
CID_RE = re.compile(r"^[0-9a-f]{32}$")
TENANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
# A `key = { ... }` object with no nested braces: tenant entries, falcon_credentials entries, etc.
BLOCK_RE = re.compile(r'^[ \t]*"?([A-Za-z0-9_-]+)"?[ \t]*=[ \t]*\{([^{}]*)\}', re.MULTILINE)
ATTR_RE = r'\b{}\s*=\s*"([^"]*)"'  # also matches single-line `{ a = "x", member_cid = "y" }`
MEMBER_CID_RE = re.compile(ATTR_RE.format("member_cid"))
MAX_PAGES = 1000  # 100k children; stops a loop if the API ignores offset and omits the total


class DiscoveryError(Exception):
    pass


class _StatusError(DiscoveryError):
    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


def _body(response: dict[str, Any], operation: str) -> dict[str, Any]:
    body = response.get("body") or {}
    status = response.get("status_code", 0)
    if status >= 400:
        raise _StatusError(f"{operation} returned {status}: {body.get('errors') or body}", status)
    return body


def list_children(falcon: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """(children with name and status, child CIDs whose details did not come back)."""
    cids: list[str] = []
    for _ in range(MAX_PAGES):
        body = _body(falcon.command("queryChildren", parameters={"limit": PAGE, "offset": len(cids)}), "queryChildren")
        page = body.get("resources") or []
        cids += page
        total = ((body.get("meta") or {}).get("pagination") or {}).get("total")
        # The API may cap pages below PAGE, so a short page only ends the listing when there is no total.
        if not page or (len(cids) >= total if total is not None else len(page) < PAGE):
            break
    else:
        raise DiscoveryError(f"queryChildren still returning results after {MAX_PAGES} pages; giving up")
    cids = list(dict.fromkeys(cids))

    children: list[dict[str, Any]] = []
    for i in range(0, len(cids), PAGE):
        batch = cids[i : i + PAGE]
        body = _body(falcon.command("getChildrenV2", body={"ids": batch}), "getChildrenV2")
        children += body.get("resources") or []
    returned = {(c.get("child_cid") or "").lower() for c in children}
    return children, [c for c in cids if c.lower() not in returned]


def slug(name: str, prefix: str) -> str:
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    base = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-") or "child"
    return (prefix + base)[:63].rstrip("-")


def _printable(value: str) -> str:
    # Control characters have no place in a display name, and \b / \f are JSON escapes HCL lacks.
    return "".join(c for c in value if unicodedata.category(c) != "Cc")


def hcl_string(value: str) -> str:
    # JSON escapes are valid HCL escapes; template sequences must be escaped separately.
    return json.dumps(_printable(value)).replace("${", "$${").replace("%{", "%%{")


def _comment(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9 _.:-]", "", str(value))[:40]


@dataclass
class Existing:
    """What a terraform.tfvars already defines, found with a light scan of the file."""

    keys: set[str] = field(default_factory=set)  # every `key = {` (tenant ids and more)
    children: dict[str, tuple[str, str]] = field(default_factory=dict)  # member_cid -> (tenant id, credential)


def existing_from_tfvars(path: Path | None) -> Existing:
    found = Existing()
    if path is None:
        return found
    text = path.read_text()
    for key, block in BLOCK_RE.findall(text):
        found.keys.add(key)
        cid = MEMBER_CID_RE.search(block)
        if cid:
            cred = re.search(ATTR_RE.format("credential"), block)
            found.children[cid.group(1).lower()] = (key, cred.group(1) if cred else "")
    # A block the light parser can't read (e.g. a brace inside a string) must still never be duplicated.
    for cid in MEMBER_CID_RE.findall(text):
        found.children.setdefault(cid.lower(), ("", ""))
    return found


def stale_entries(existing: Existing, credential: str, children: Iterable[dict[str, Any]]) -> list[tuple[str, str]]:
    """(tenant id, member_cid) entries using this parent's credential whose CID is no longer a child."""
    current = {(c.get("child_cid") or "").lower() for c in children}
    return sorted(
        (tid, cid) for cid, (tid, cred) in existing.children.items() if cred == credential and cid not in current
    )


def plan_entries(
    children: Iterable[dict[str, Any]], prefix: str, taken_cids: set[str], taken_ids: set[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split children into (new tenant entries, skipped) with unique, valid tenant ids."""
    new, skipped = [], []
    used = set(taken_ids)
    for child in sorted(children, key=lambda c: (c.get("name") or "", c.get("child_cid") or "")):
        cid = (child.get("child_cid") or "").lower()
        name = _printable(child.get("name") or "").strip() or cid
        if not CID_RE.match(cid):
            skipped.append({"name": name, "cid": cid, "reason": "unrecognised child CID"})
            continue
        if cid in taken_cids:
            skipped.append({"name": name, "cid": cid, "reason": "already in tfvars"})
            continue
        base = slug(name, prefix)
        tenant_id, width = base, 6
        while tenant_id in used or not TENANT_ID_RE.match(tenant_id):  # disambiguate with more of the CID
            tenant_id = f"{base[: 62 - width].rstrip('-')}-{cid[:width]}"
            width += 2
        used.add(tenant_id)
        new.append({"id": tenant_id, "name": name, "cid": cid, "status": child.get("status")})
    return new, skipped


def render(
    entries: list[dict[str, Any]], credential: str, base_url: str, allow_actions: bool, grants: list[tuple[str, str]]
) -> str:
    lines = ["  # --- add inside `tenants = { ... }` ---"]
    for e in entries:
        status = f"  # status: {_comment(e['status'])}" if e.get("status") else ""
        lines += [
            f"  {e['id']} = {{{status}",
            f"    display_name  = {hcl_string(e['name'])}",
            f"    base_url      = {hcl_string(base_url)}",
            f"    credential    = {hcl_string(credential)}",
            f"    member_cid    = {hcl_string(e['cid'])}",
            f"    allow_actions = {str(allow_actions).lower()}",
            "  }",
        ]
    if grants and entries:
        ids = ", ".join(hcl_string(e["id"]) for e in entries)
        lines += ["", "  # --- add inside `access_grants = [ ... ]` ---"]
        lines += [f"  {{ group = {hcl_string(g)}, tenants = [{ids}], role = {hcl_string(r)} }}," for g, r in grants]
    return "\n".join(lines) + "\n"


def _grant(value: str) -> tuple[str, str]:
    group, _, role = value.rpartition(":")
    if not group or role not in {"reader", "responder"}:
        raise argparse.ArgumentTypeError("use GROUP:reader or GROUP:responder")
    return group, role


def _base_url(value: str) -> str:
    try:
        return checked_base_url(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _existing_file(value: str) -> Path:
    path = Path(value)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"{value} not found")
    return path


def _secret(secret_id: str, region: str) -> dict[str, str]:
    # A secret ARN names its own region; a bare name is looked up in --region.
    if secret_id.startswith("arn:"):
        region = secret_id.split(":")[3]
    try:
        value = aws_client("secretsmanager", region_name=region).get_secret_value(SecretId=secret_id)
        data = json.loads(value["SecretString"])
        return {"client_id": data["client_id"], "client_secret": data["client_secret"]}
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        hint = " (has the secret value been loaded? see `terraform output load_secret_commands`)"
        hint = hint if code == "ResourceNotFoundException" else ""
        raise DiscoveryError(f"reading {secret_id} in {region}: {code}{hint}") from exc
    except BotoCoreError as exc:
        raise DiscoveryError(f"reading {secret_id} in {region}: {exc}") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise DiscoveryError(f'{secret_id} is not {{"client_id": ..., "client_secret": ...}} JSON') from exc


HINTS = {
    401: "check the client id/secret and that --base-url is the parent's Falcon cloud",
    403: "check the parent API client has the Flight Control: Read scope",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--credential", required=True, help="key of the parent in falcon_credentials")
    parser.add_argument(
        "--base-url", required=True, type=_base_url, help="parent's Falcon cloud, e.g. us2"
    )
    parser.add_argument("--secret-id", help="Secrets Manager id/ARN of the parent credential")
    parser.add_argument("--region", default="ap-southeast-2", help="Secrets Manager region (default: Sydney)")
    parser.add_argument("--prefix", default="", help="prefix for generated tenant ids, e.g. acme-")
    parser.add_argument(
        "--tfvars", type=_existing_file, help="existing terraform.tfvars: skip listed children, report stale ones"
    )
    parser.add_argument("--allow-actions", action="store_true", help="set allow_actions = true on new entries")
    parser.add_argument("--grant", type=_grant, action="append", default=[], help="GROUP:role grant for new tenants")
    args = parser.parse_args(argv)

    if args.prefix and not re.fullmatch(r"[a-z0-9][a-z0-9-]*", args.prefix):
        parser.error("--prefix must be lowercase letters, digits and dashes")

    from_env = bool(os.environ.get("FALCON_CLIENT_ID") and os.environ.get("FALCON_CLIENT_SECRET"))
    if not args.secret_id and not from_env:
        parser.error("pass --secret-id or set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET")

    try:
        if args.secret_id:
            creds = _secret(args.secret_id, args.region)
        else:
            creds = {"client_id": os.environ["FALCON_CLIENT_ID"], "client_secret": os.environ["FALCON_CLIENT_SECRET"]}
        falcon = APIHarnessV2(
            client_id=creds["client_id"], client_secret=creds["client_secret"], base_url=args.base_url,
            user_agent=USER_AGENT,
        )  # fmt: skip
        children, missing = list_children(falcon)
    except DiscoveryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if hint := HINTS.get(getattr(exc, "status", 0)):
            print(hint, file=sys.stderr)
        return 1

    existing = existing_from_tfvars(args.tfvars)
    entries, skipped = plan_entries(children, args.prefix, set(existing.children), existing.keys)
    stale = stale_entries(existing, args.credential, children)

    print(f"found {len(children)} children: {len(entries)} new, {len(skipped)} skipped", file=sys.stderr)
    for s in skipped:
        print(f"  skipped {s['name']} ({s['cid'] or 'no cid'}): {s['reason']}", file=sys.stderr)
    for cid in missing:
        print(f"  warning: no details returned for child {cid}; it was left out", file=sys.stderr)
    for tid, cid in stale:
        print(f"  stale: tfvars tenant {tid} ({cid}) is no longer a child of this parent; remove it", file=sys.stderr)
    if entries:
        sys.stdout.write(render(entries, args.credential, args.base_url, args.allow_actions, args.grant))
    return 0


if __name__ == "__main__":
    sys.exit(main())
