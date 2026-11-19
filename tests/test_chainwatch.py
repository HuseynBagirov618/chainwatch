import json
import subprocess
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from chainwatch.analysis import advisory_points, analyze, lookalike
from chainwatch.changes import compare
from chainwatch.cli import DEMO, main
from chainwatch.git_inputs import git_files
from chainwatch.inputs import local_files, upload_files
from chainwatch.intelligence import Intelligence, github_url, key, osv_ids
from chainwatch.model import Package
from chainwatch.parsers import build_inventory
from chainwatch.server import create_app


def npm_project(manifest, entries, version=3):
    lock = {"lockfileVersion": version, "packages": entries}
    if version == 1:
        lock = {"lockfileVersion": 1, "dependencies": entries}
    return {"package.json": json.dumps(manifest), "package-lock.json": json.dumps(lock)}


def test_requirements_preserve_pins_markers_and_direct_references():
    files = {"requirements.txt": (
        "Requests[security]==2.31.0 ; python_version >= \"3.10\" \\\n"
        " --hash=sha256:123\nFlask>=2.0 # range\n-r constraints.txt\n"
        "typed-lib @ https://user:secret@example.invalid/internal.whl\n"
    )}
    report = analyze(build_inventory("app", files))
    packages = {pkg["name"]: pkg for pkg in report["packages"]}
    assert packages["requests"]["version"] == "2.31.0"
    assert "python_version" in packages["requests"]["spec"]
    assert packages["flask"]["version"] is None
    assert packages["typed-lib"]["registry"] == "example.invalid"
    assert "secret" not in json.dumps(report)
    assert len(report["warnings"]) == 2


@pytest.mark.parametrize("version", [2, 3])
def test_graph_resolves_nested_hoisted_scoped_and_unclassified(version):
    files = npm_project({"dependencies": {"app-lib": "^1", "@org/direct": "1.0.0"}}, {
        "": {"dependencies": {"app-lib": "^1", "@org/direct": "1.0.0"}},
        "node_modules/app-lib": {"version": "1.0.0", "dependencies": {"nested": "^1", "shared": "^1"}},
        "node_modules/app-lib/node_modules/nested": {"version": "1.1.0", "dependencies": {"shared": "^1"}},
        "node_modules/nested": {"version": "2.0.0"},
        "node_modules/shared": {"version": "1.1.0", "dependencies": {"app-lib": "^1"}},
        "node_modules/@org/direct": {"version": "1.0.0"},
    }, version)
    report = analyze(build_inventory("app", files))
    summary = report["summary"]
    assert (summary["direct"], summary["transitive"], summary["unclassified"]) == (2, 2, 1)
    packages = {pkg["location"]: pkg for pkg in report["packages"]}
    assert packages["node_modules/nested"]["depth"] is None
    assert packages["node_modules/app-lib/node_modules/nested"]["depth"] == 2
    assert packages["node_modules/@org/direct"]["depth"] == 1
    assert any(edge["from"].endswith(":nested") and edge["to"].endswith(":shared") for edge in report["edges"])


def test_legacy_lockfile_uses_requires_and_nested_installs():
    inv = build_inventory("legacy", npm_project({"dependencies": {"a": "1.0.0"}}, {
        "a": {"version": "1.0.0", "requires": {"b": "^2"}, "dependencies": {"b": {"version": "2.1.0"}}},
        "b": {"version": "1.0.0"},
    }, version=1))
    assert inv.depths() == {"project": 0, "npm:node_modules/a:a": 1, "npm:node_modules/a/node_modules/b:b": 2}


def test_manifest_only_and_application_lifecycle():
    report = analyze(build_inventory("app", {"package.json": json.dumps({
        "name": "app", "dependencies": {"alias": "npm:actual@2.1.0", "flavor": "^1"},
        "scripts": {"postinstall": "node -e \"console.log('fixture')\""},
    })}))
    assert report["summary"]["dependencies"] == 2
    assert {pkg["name"]: pkg["version"] for pkg in report["packages"]} == {"app": None, "actual": "2.1.0", "flavor": None}
    assert {item["code"] for item in report["findings"]} == {"lifecycle_script", "script_indicators"}
    assert "console.log" not in json.dumps(report)


@pytest.mark.parametrize(("ecosystem", "name", "expected"), [
    ("npm", "lodahs", "lodash"), ("npm", "@team/lodahs", None), ("npm", "react", None),
    ("PyPI", "requsets", "requests"), ("PyPI", "requestz", "requests"), ("PyPI", "random-package", None),
])
def test_lookalikes(ecosystem, name, expected):
    assert lookalike(Package(ecosystem, name, "manifest", "manifest")) == expected


def test_advisory_scores_cvss_vectors():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert advisory_points({"severity": [{"type": "CVSS_V3", "score": vector}]}) == 75
    assert advisory_points({"severity": [{"type": "CVSS_V3", "score": "invalid"}]}) == 35


def test_intelligence_adds_explainable_severity_and_trust():
    inv = build_inventory("app", {"requirements.txt": "requests==2.31.0"})
    pkg = next(iter(inv.packages.values()))
    info = Intelligence(enabled=True, osv_checked=1, registry_checked=1, repositories_checked=1)
    info.advisories[key(pkg)] = [{"id": "TEST-123", "database_specific": {"severity": "HIGH"}}]
    repo = "https://github.com/example/archive"
    info.registry[key(pkg)] = {"last_publish": datetime.now(timezone.utc) - timedelta(days=800), "repository": repo}
    info.repositories[repo] = {"archived": True}
    report = analyze(inv, intelligence=info)
    assert report["summary"]["score"] == 70
    assert {item["code"] for item in report["findings"]} == {"known_vulnerability", "stale_release", "repository_archived"}
    assert report["packages"][0]["osv_checked"]


@pytest.mark.parametrize("candidate", [
    "https://github.com.example.invalid/user/repo", "https://github.com/user/../other",
    "https://github.com/../repos", "https://github.com/user/.git", 12,
])
def test_repo_url_is_restricted(candidate):
    assert github_url(candidate) is None
    assert github_url("git+https://github.com/user/repo.git") == "https://github.com/user/repo"


def test_osv_batch_contract():
    def serve(request):
        assert request.url == "https://api.osv.dev/v1/querybatch"
        assert json.loads(request.content)["queries"][0]["package"] == {"name": "requests", "ecosystem": "PyPI"}
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "OSV-1"}, {"id": "a/b"}]}]})

    with httpx.Client(transport=httpx.MockTransport(serve)) as client:
        pkg = ("PyPI", "requests", "2.31.0")
        assert osv_ids(client, [pkg]) == {pkg: ["OSV-1"]}


def test_compare_reports_blast_radius_and_integrity_removal():
    before, after = [build_inventory(name, *local_files(DEMO / name)) for name in ("before", "after")]
    report = compare(before, after)
    analytics = next(change for change in report["changes"] if change["name"] == "northstar-analytics-demo")
    assert analytics["blast_radius"]["added_packages"] == ["debug", "trace-helper-demo"]
    assert "integrity_removed" in {item["code"] for item in report["findings"]}
    assert report["summary"]["added"] == 4


def test_compare_pin_reorder_does_not_count_as_dependency_changes():
    before = build_inventory("before", {"requirements.txt": "requests==2.31.0\npandas==2.0.0\n"})
    after = build_inventory("after", {"requirements.txt": "# comment\npandas==2.0.0\nrequests==2.31.0\n"})
    assert not compare(before, after)["changes"]


def test_compare_ordinary_version_change_and_lockfile_only_change():
    manifest = {"dependencies": {"a": "^1"}}
    def snapshot(version):
        return build_inventory("app", npm_project(manifest, {
            "node_modules/a": {"version": version, "resolved": f"https://registry.npmjs.org/a/-/a-{version}.tgz"},
        }))
    report = compare(snapshot("1.0.0"), snapshot("1.1.0"))
    assert [item["code"] for item in report["findings"]] == ["lockfile_only_change"]


def test_upload_and_local_scan_reject_unwanted_paths(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx")
    vendor = tmp_path / "node_modules"
    vendor.mkdir()
    (vendor / "package.json").write_text("{}")
    (tmp_path / "requirements-link.txt").symlink_to(tmp_path / "requirements.txt")
    assert list(local_files(tmp_path)[0]) == ["requirements.txt"]
    for unsafe in ("../requirements.txt", "node_modules/package.json", "/package.json", "a\\package.json", "secrets.env"):
        with pytest.raises(ValueError):
            upload_files({unsafe: "x"})


def test_malformed_lockfile_is_reported_without_hiding_other_ecosystem():
    report = analyze(build_inventory("app", {"package-lock.json": "invalid", "requirements.txt": "django"}))
    assert report["summary"]["direct"] == 1
    assert report["warnings"][0].startswith("package-lock.json:")


def test_git_reads_commits_instead_of_worktree(tmp_path):
    def run(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], capture_output=True, check=True)
    run("init")
    run("config", "user.name", "Fixture")
    run("config", "user.email", "fixture@example.invalid")
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("requests==2.31.0")
    run("add", "requirements.txt")
    run("commit", "-m", "Fixture")
    reqs.write_text("requests==2.32.4")
    assert git_files(tmp_path, "HEAD")[0] == {"requirements.txt": "requests==2.31.0"}
    with pytest.raises(ValueError):
        git_files(tmp_path, "--help")


def test_cli_json_demo(capsys):
    assert main(["demo", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["transitive"] == 4


def test_dashboard_routes_history_export_and_upload_guards(tmp_path):
    client = TestClient(create_app(tmp_path / "scan.sqlite3"), base_url="http://localhost")
    assert client.get("/").status_code == 200
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/api/demo").json()["report"]["project"] == "Northstar Store"
    scan = {"name": "Example", "files": {"requirements.txt": "requsets==1.0.0"}}
    assert client.post("/api/scan", content="{}").status_code == 415
    assert client.post("/api/scan", json=scan, headers={"Origin": "http://example.com"}).status_code == 403
    assert client.post("/api/scan", json={"files": {"../requirements.txt": "x"}}).status_code == 400
    response = client.post("/api/scan", json=scan, headers={"Origin": "http://localhost"})
    assert response.status_code == 200
    saved = response.json()
    assert client.get("/api/history").json()[0]["name"] == "Example"
    assert client.get(f"/api/history/{saved['id']}").json() == saved["report"]
    assert "resembles a popular library" in client.post("/api/export/scan", json=saved["report"]).text
    assert client.post("/api/compare", json={"before": scan, "after": scan}).json()["changes"] == []
