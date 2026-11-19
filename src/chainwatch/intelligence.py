import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

import httpx

from .model import Inventory, Package
from .parsers import lifecycle, mapping, npm_name

MAX_LOOKUPS = 80
MAX_ADVISORIES = 40
MAX_RESPONSE = 8 * 1024 * 1024
GH_PATH = re.compile(r"/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/?\Z")
OSV_ID = re.compile(r"[A-Za-z0-9_.-]{1,120}\Z")
PackageKey = tuple[str, str, str | None]


@dataclass
class Intelligence:
    advisories: dict[PackageKey, list[dict]] = field(default_factory=dict)
    registry: dict[PackageKey, dict] = field(default_factory=dict)
    repositories: dict[str, dict] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    osv_checked: int = 0
    registry_checked: int = 0
    repositories_checked: int = 0
    enabled: bool = False


def key(package: Package) -> PackageKey:
    return package.ecosystem, package.name, package.version


def github_url(raw: object) -> str | None:
    if not isinstance(raw, str) or len(raw) > 2048:
        return None
    if raw.startswith("github:"):
        raw = "https://github.com/" + raw.removeprefix("github:")
    if raw.startswith("git@github.com:"):
        raw = "https://github.com/" + raw.removeprefix("git@github.com:")
    try:
        parsed = urlsplit(raw.removeprefix("git+"))
        match = GH_PATH.fullmatch(parsed.path)
        if parsed.hostname != "github.com" or not match:
            return None
        owner, repo = match.groups()
        repo = repo.removesuffix(".git")
        if owner in {".", ".."} or repo in {"", ".", ".."}:
            return None
        return f"https://github.com/{owner}/{repo}"
    except ValueError:
        return None


def date(value: object) -> datetime | None:
    if isinstance(value, str) and len(value) <= 40:
        try:
            parsed = datetime.fromisoformat(value)
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        except ValueError:
            pass
    return None


def get_json(client: httpx.Client, url: str, payload: dict | None = None) -> dict:
    with client.stream("POST" if payload is not None else "GET", url, json=payload) as response:
        response.raise_for_status()
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > MAX_RESPONSE:
                raise ValueError("Metadata response is too large.")
    result = json.loads(body)
    if not isinstance(result, dict):
        raise ValueError("Expected a JSON object.")
    return result


def registry_info(client: httpx.Client, pkg: PackageKey) -> dict:
    ecosystem, name, version = pkg
    encoded = quote(name, safe="")
    if ecosystem == "npm":
        if not npm_name(name):
            return {}
        doc = get_json(client, f"https://registry.npmjs.org/{encoded}")
        times = mapping(doc.get("time"))
        versions = mapping(doc.get("versions"))
        current = mapping(versions.get(version or mapping(doc.get("dist-tags")).get("latest")))
        repository = current.get("repository") or doc.get("repository")
        if isinstance(repository, dict):
            repository = repository.get("url")
        return {
            "first_publish": date(times.get("created")),
            "last_publish": max((value for release, raw in times.items()
                                 if release in versions and (value := date(raw))), default=None),
            "repository": github_url(repository),
            "scripts": lifecycle(current) if version else {},
        }
    doc = get_json(client, f"https://pypi.org/pypi/{encoded}/json")
    info = mapping(doc.get("info"))
    urls = mapping(info.get("project_urls"))
    release_dates = [
        timestamp for upload_list in mapping(doc.get("releases")).values() if isinstance(upload_list, list)
        for upload in upload_list if (timestamp := date(mapping(upload).get("upload_time_iso_8601")))
    ]
    repo = next((url for value in list(urls.values()) + [info.get("home_page")]
                 if (url := github_url(value))), None)
    return {
        "first_publish": min(release_dates, default=None),
        "last_publish": max(release_dates, default=None),
        "repository": repo,
        "scripts": {},
    }


def repo_info(client: httpx.Client, url: str) -> dict:
    endpoint = "https://api.github.com/repos/" + url.removeprefix("https://github.com/")
    try:
        doc = get_json(client, endpoint)
    except httpx.HTTPStatusError as error:
        if error.response.status_code == 404:
            return {"unavailable": True}
        raise
    return {"archived": doc.get("archived") is True, "disabled": doc.get("disabled") is True}


def osv_ids(client: httpx.Client, keys: list[PackageKey]) -> dict[PackageKey, list[str]]:
    if not keys:
        return {}
    doc = get_json(client, "https://api.osv.dev/v1/querybatch", {
        "queries": [{"package": {"ecosystem": ecosystem, "name": name}, "version": version}
                    for ecosystem, name, version in keys],
    })
    results = doc.get("results")
    if not isinstance(results, list) or len(results) != len(keys):
        raise ValueError("OSV returned an invalid result count.")
    found = {}
    for pkg, raw in zip(keys, results, strict=True):
        if not isinstance(raw, dict) or (raw.get("next_page_token") is not None):
            raise ValueError("OSV results were incomplete.")
        vulns = raw.get("vulns") or []
        if not isinstance(vulns, list):
            raise ValueError("OSV returned an invalid vulnerability list.")
        found[pkg] = [i for vuln in vulns if isinstance(i := mapping(vuln).get("id"), str) and OSV_ID.fullmatch(i)]
    return found


def collect(inv: Inventory) -> Intelligence:
    intel = Intelligence(enabled=True)
    unique = list(dict.fromkeys(
        key(package) for package in sorted(inv.packages.values(), key=lambda item: not item.direct)
        if not package.application and package.registry in {None, "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org"}
    ))
    selected = unique[:MAX_LOOKUPS]
    if len(unique) > MAX_LOOKUPS:
        intel.warnings.append(f"Network enrichment is capped at {MAX_LOOKUPS} package identities per scan. Direct dependencies are prioritized.")
    exact = [pkg for pkg in selected if pkg[2]]
    if len(exact) < len(selected):
        intel.warnings.append("OSV coverage applies to exact versions. Unresolved versions received registry metadata only.")
    with httpx.Client(timeout=httpx.Timeout(4), follow_redirects=False) as client:
        def attempt(func, *args):
            try:
                return func(client, *args)
            except (httpx.HTTPError, ValueError, RecursionError):
                return None

        with ThreadPoolExecutor(max_workers=12) as executor:
            osv = executor.submit(attempt, osv_ids, exact)
            lookup = list(executor.map(lambda pkg: attempt(registry_info, pkg), selected))
            intel.registry = {pkg: result for pkg, result in zip(selected, lookup, strict=True) if result is not None}
            intel.registry_checked = len(intel.registry)
            if intel.registry_checked < len(selected):
                intel.warnings.append(f"Public registry metadata was unavailable for {len(selected) - intel.registry_checked} package identities.")
            repo_urls = sorted({meta["repository"] for meta in intel.registry.values() if meta.get("repository")})
            repo_results = executor.map(lambda url: attempt(repo_info, url), repo_urls)
            intel.repositories = {url: result for url, result in zip(repo_urls, repo_results, strict=True) if result is not None}
            intel.repositories_checked = len(intel.repositories)
            if intel.repositories_checked < len(repo_urls):
                intel.warnings.append("Some linked GitHub repositories could not be checked.")
            ids_by_pkg = osv.result()
            if ids_by_pkg is None:
                intel.warnings.append("OSV vulnerability lookup was unavailable. Vulnerability coverage is unknown.")
                return intel
            intel.osv_checked = len(exact)
            ids = list(dict.fromkeys(i for values in ids_by_pkg.values() for i in values))
            detail_ids = ids[:MAX_ADVISORIES]
            results = executor.map(lambda i: attempt(get_json, f"https://api.osv.dev/v1/vulns/{i}"), detail_ids)
            detail = {i: doc for i, doc in zip(detail_ids, results, strict=True) if doc is not None}
            if len(detail) < len(ids):
                intel.warnings.append("Some OSV matches have basic advisory IDs only.")
            for pkg, ids_for_pkg in ids_by_pkg.items():
                intel.advisories[pkg] = [
                    {**detail.get(i, {}), "id": i} for i in ids_for_pkg if not detail.get(i, {}).get("withdrawn")
                ]
    return intel
