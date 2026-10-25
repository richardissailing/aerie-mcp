from __future__ import annotations

from pathlib import Path

import pytest

from falcon_fleet_mcp import discover


class FakeParent:
    def __init__(self, children: list[dict], fail: bool = False):
        self.children, self.fail = children, fail
        self.calls: list[tuple[str, dict]] = []

    def command(self, operation: str, **kw):
        self.calls.append((operation, kw))
        if self.fail:
            return {"status_code": 403, "body": {"errors": [{"message": "access denied"}]}}
        if operation == "queryChildren":
            p = kw["parameters"]
            page = [c["child_cid"] for c in self.children[p["offset"] : p["offset"] + p["limit"]]]
            return {"status_code": 200, "body": {"meta": {"pagination": {"total": len(self.children)}}, "resources": page}}
        if operation == "getChildrenV2":
            ids = set(kw["body"]["ids"])
            return {"status_code": 200, "body": {"resources": [c for c in self.children if c["child_cid"] in ids]}}
        raise AssertionError(operation)


def cid(n: int) -> str:
    return f"{n:032x}"


def test_lists_every_child_across_pages():
    parent = FakeParent([{"child_cid": cid(i), "name": f"Child {i}"} for i in range(150)])
    children, missing = discover.list_children(parent)
    assert len(children) == 150 and missing == []
    ops = [op for op, _ in parent.calls]
    assert ops.count("queryChildren") == 2 and ops.count("getChildrenV2") == 2
    assert all(len(kw["body"]["ids"]) <= 100 for op, kw in parent.calls if op == "getChildrenV2")


def test_api_errors_raise():
    with pytest.raises(discover.DiscoveryError, match="403"):
        discover.list_children(FakeParent([], fail=True))


def test_plan_skips_existing_and_makes_unique_valid_ids():
    children = [
        {"child_cid": cid(1), "name": "Acme Retail"},
        {"child_cid": cid(2), "name": "Acme Retail"},       # duplicate name
        {"child_cid": cid(3), "name": "Already There"},
        {"child_cid": cid(4), "name": "Ünïcødé & Co!!"},
        {"child_cid": cid(5), "name": "Existing Key"},      # id clashes with a tfvars key
        {"child_cid": "not-a-cid", "name": "Broken"},
    ]  # fmt: skip
    new, skipped = discover.plan_entries(children, "acme-", {cid(3)}, {"acme-existing-key"})
    ids = [e["id"] for e in new]
    assert len(ids) == len(set(ids)) == 4
    assert all(discover.TENANT_ID_RE.match(i) for i in ids)
    assert "acme-acme-retail" in ids and f"acme-acme-retail-{cid(2)[:6]}" in ids
    assert f"acme-existing-key-{cid(5)[:6]}" in ids
    assert {s["reason"] for s in skipped} == {"already in tfvars", "unrecognised child CID"}


def test_existing_scan_reads_tfvars(tmp_path: Path):
    tfvars = tmp_path / "terraform.tfvars"
    tfvars.write_text(f'tenants = {{\n  corp = {{\n    member_cid = "{cid(9).upper()}"\n  }}\n}}\n')
    found = discover.existing_from_tfvars(tfvars)
    assert set(found.children) == {cid(9)} and "corp" in found.keys


def test_render_escapes_hcl_templates_and_emits_grants():
    entries = [{"id": "acme-x", "name": 'Evil ${file("/etc/passwd")} "quoted"', "cid": cid(1), "status": "active"}]
    out = discover.render(entries, "acme-parent", "us2", False, [("Acme-SOC", "reader")])
    assert "$${file" in out and '\\"quoted\\"' in out
    assert 'member_cid    = "' + cid(1) + '"' in out
    assert '{ group = "Acme-SOC", tenants = ["acme-x"], role = "reader" },' in out


def test_render_strips_control_characters_and_comment_injection():
    entries = [{"id": "x", "name": "bad\bname\x0c", "cid": cid(1), "status": 'active\n  evil = "1"'}]
    out = discover.render(entries, "p", "us2", False, [])
    assert '"badname"' in out and "\\b" not in out and "evil =" not in out


def test_missing_child_details_are_reported():
    parent = FakeParent([{"child_cid": cid(1), "name": "A"}])
    original = parent.command
    parent.command = lambda op, **kw: (
        {"status_code": 200, "body": {"resources": [cid(1), cid(2)]}} if op == "queryChildren" else original(op, **kw)
    )
    children, missing = discover.list_children(parent)
    assert [c["child_cid"] for c in children] == [cid(1)] and missing == [cid(2)]


def test_pagination_stops_when_api_ignores_offset():
    parent = FakeParent([])
    parent.command = lambda op, **kw: {"status_code": 200, "body": {"resources": [cid(i) for i in range(100)]}}
    with pytest.raises(discover.DiscoveryError, match="giving up"):
        discover.list_children(parent)


def test_tfvars_scan_handles_quoted_keys_and_finds_stale_children(tmp_path: Path):
    tfvars = tmp_path / "terraform.tfvars"
    tfvars.write_text(
        "tenants = {\n"
        f'    "old-child" = {{\n      credential = "acme-parent"\n      member_cid = "{cid(5)}"\n    }}\n'
        f'  other = {{ credential = "other-parent", member_cid = "{cid(6)}" }}\n'
        f'  kept = {{\n    credential = "acme-parent"\n    member_cid = "{cid(1)}"\n  }}\n'
        "}\n"
    )
    found = discover.existing_from_tfvars(tfvars)
    assert {"old-child", "other", "kept"} <= found.keys
    stale = discover.stale_entries(found, "acme-parent", [{"child_cid": cid(1)}])
    assert stale == [("old-child", cid(5))]


def test_cli_hint_depends_on_status(monkeypatch, capsys):
    monkeypatch.setenv("FALCON_CLIENT_ID", "id")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "secret")
    unauthorised = FakeParent([])
    unauthorised.command = lambda op, **kw: {"status_code": 401, "body": {"errors": [{"message": "access denied"}]}}
    monkeypatch.setattr(discover, "APIHarnessV2", lambda **kw: unauthorised)
    assert discover.main(["--credential", "p", "--base-url", "us2"]) == 1
    assert "client id/secret" in capsys.readouterr().err
    monkeypatch.setattr(discover, "APIHarnessV2", lambda **kw: FakeParent([], fail=True))
    assert discover.main(["--credential", "p", "--base-url", "us2"]) == 1
    assert "Flight Control: Read" in capsys.readouterr().err


def test_cli_rejects_missing_tfvars(tmp_path, capsys):
    with pytest.raises(SystemExit):
        discover.main(["--credential", "p", "--base-url", "us2", "--tfvars", str(tmp_path / "nope.tfvars")])
    assert "not found" in capsys.readouterr().err


def test_cli_end_to_end(monkeypatch, capsys):
    parent = FakeParent([{"child_cid": cid(1), "name": "Acme Retail", "status": "active"}])
    monkeypatch.setattr(discover, "APIHarnessV2", lambda **kw: parent)
    monkeypatch.setenv("FALCON_CLIENT_ID", "id")
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "secret")
    rc = discover.main(["--credential", "acme-parent", "--base-url", "us2", "--prefix", "acme-",
                        "--allow-actions", "--grant", "Acme-IR:responder"])  # fmt: skip
    out = capsys.readouterr()
    assert rc == 0 and "  acme-acme-retail = {" in out.out and "allow_actions = true" in out.out
    assert "1 new" in out.err


def test_ids_are_readable_and_unique_even_with_shared_cid_prefixes():
    shared = "abcdef"
    children = [{"child_cid": shared + f"{i:026x}", "name": "Same"} for i in range(3)]
    children.append({"child_cid": cid(7), "name": "Ünïcôdé Co"})
    new, _ = discover.plan_entries(children, "", set(), set())
    ids = [e["id"] for e in new]
    assert len(set(ids)) == 4 and "unicode-co" in ids


def test_single_line_and_unparseable_children_are_not_duplicated(tmp_path: Path):
    tfvars = tmp_path / "terraform.tfvars"
    tfvars.write_text(
        f'tenants = {{\n  one = {{ credential = "acme-parent", member_cid = "{cid(1)}" }}\n'
        f'  odd = {{\n    display_name = "Acme {{EU}}"\n    member_cid = "{cid(2)}"\n  }}\n}}\n'
    )
    found = discover.existing_from_tfvars(tfvars)
    assert found.children[cid(1)] == ("one", "acme-parent") and cid(2) in found.children
    new, _ = discover.plan_entries([{"child_cid": cid(1)}, {"child_cid": cid(2)}], "", set(found.children), found.keys)
    assert new == []


def test_pagination_continues_when_api_caps_page_size():
    parent = FakeParent([{"child_cid": cid(i), "name": f"C{i}"} for i in range(120)])
    original = parent.command

    def capped(op, **kw):
        if op == "queryChildren":
            kw = {"parameters": {**kw["parameters"], "limit": 50}}
        return original(op, **kw)

    parent.command = capped
    children, _ = discover.list_children(parent)
    assert len(children) == 120
