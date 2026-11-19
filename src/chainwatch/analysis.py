import re
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from urllib.parse import quote

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

from .intelligence import Intelligence, collect, key
from .model import ROOT, Finding, Inventory, Package, risk_level
from .parsers import mapping

POPULAR = {
    "PyPI": ("requests", "urllib3", "flask", "django", "numpy", "pandas", "pytest", "fastapi",
             "pillow", "beautifulsoup4", "sqlalchemy", "pydantic", "cryptography", "scikit-learn",
             "aiohttp", "setuptools", "packaging", "python-dotenv", "pyyaml", "httpx"),
    "npm": ("react", "react-dom", "express", "lodash", "axios", "typescript", "webpack", "next",
            "vite", "eslint", "prettier", "chalk", "commander", "moment", "debug", "zod",
            "jquery", "vue", "dotenv", "cross-env", "jsonwebtoken", "tslib", "uuid"),
}
REGISTRIES = {
    "npm": {"registry.npmjs.org", "registry.yarnpkg.com"},
    "PyPI": {"pypi.org", "files.pythonhosted.org"},
}
SCRIPT_PATTERNS = {
    "network download": re.compile(r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b", re.I),
    "shell handoff": re.compile(r"\|\s*(?:(?:ba|z|da|k)?sh|powershell|pwsh)\b|\b(?:bash|sh|cmd(?:\.exe)?|powershell|pwsh)\s+(?:-[a-z]+|/c)\b", re.I),
    "inline interpreter": re.compile(r"\b(?:node|python3?|ruby)\s+-(?:e|c)\b", re.I),
}
CAPS = {"vulnerability": 75, "identity": 30, "maintenance": 15,
        "behavior": 40, "provenance": 35, "graph": 10}
SEVERITY_POINTS = {"CRITICAL": 75, "HIGH": 50, "MODERATE": 30, "MEDIUM": 30, "LOW": 15}
MAX_FINDINGS = 6000


def one_edit(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) > len(right):
        left, right = right, left
    if len(left) == len(right):
        mismatches = [i for i, (a, b) in enumerate(zip(left, right, strict=True)) if a != b]
        if len(mismatches) == 1:
            return True
        if len(mismatches) == 2:
            first, second = mismatches
            return second == first + 1 and left[first] == right[second] and left[second] == right[first]
        return False
    i = next((i for i, (a, b) in enumerate(zip(left, right)) if a != b), len(left))
    return left[i:] == right[i + 1:]


def lookalike(package: Package) -> str | None:
    name = package.name.lower()
    popular = POPULAR[package.ecosystem]
    # Scoped npm packages have separate ownership; this rule compares unscoped names only.
    if name in popular or "/" in name or len(name) < 5 or len(name) > 40:
        return None
    compact = name.replace("-", "").replace("_", "").replace(".", "")
    return next((target for target in popular if len(target) >= 5 and
                 (one_edit(name, target) or compact == target.replace("-", ""))), None)


def advisory_points(advisory: dict) -> int:
    values = [mapping(advisory.get("database_specific")).get("severity")]
    affected = advisory.get("affected")
    if isinstance(affected, list):
        values.extend(mapping(mapping(item).get("ecosystem_specific")).get("severity") for item in affected)
    points = [SEVERITY_POINTS.get(val.upper(), 0) for val in values if isinstance(val, str)]
    severity = advisory.get("severity")
    formats = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}
    if isinstance(severity, list):
        for item in severity:
            entry = mapping(item)
            vector = entry.get("score")
            kind = entry.get("type")
            if not isinstance(kind, str) or kind not in formats or not isinstance(vector, str) or len(vector) > 512:
                continue
            try:
                rating = formats[kind](vector).severities()[0]
            except (CVSSError, ValueError):
                continue
            points.append(SEVERITY_POINTS.get(rating.upper(), 0))
    return max(points, default=0) or 35


def package_findings(package: Package, intel: Intelligence, depth: int | None) -> list[Finding]:
    findings = []
    meta = intel.registry.get(key(package), {})
    repo = intel.repositories.get(meta.get("repository"), {})
    now = datetime.now(timezone.utc)

    def add(code, category, title, evidence, recommendation, points, reference=None):
        findings.append(Finding(code, category, title, evidence, recommendation, points, package.id, reference))

    if not package.application:
        for advisory in intel.advisories.get(key(package), ())[:20]:
            add("known_vulnerability", "vulnerability", "Known vulnerability",
                f"OSV matched {advisory['id']} to version {package.version}.",
                "Review the OSV advisory and upgrade to a release it identifies as fixed.", advisory_points(advisory),
                f"https://osv.dev/vulnerability/{quote(advisory['id'], safe='')}")
        if target := lookalike(package):
            add("similar_package_name", "identity", "Package name resembles a popular library",
                f"The name {package.name} is close to {target} in the {package.ecosystem} reference list.",
                "Verify the intended package and its publisher before installation.", 25)
        if (first := meta.get("first_publish")) and 0 <= (now - first).days < 14:
            add("recent_publish", "maintenance", "Recently published package",
                f"The first registry publication was {(now - first).days} days ago.",
                "Review the package history and assess it alongside other findings.", 10)
        if (last := meta.get("last_publish")) and (now - last).days >= 730:
            add("stale_release", "maintenance", "No release in at least two years",
                f"The latest dated registry release is from {last.date()}.",
                "Review maintenance activity and look for a supported release if necessary.", 10)
        if repo.get("unavailable") or repo.get("disabled"):
            add("repository_unavailable", "provenance", "Linked repository unavailable",
                "The public GitHub API could not access the linked repository or reported it disabled.",
                "Verify the upstream source and ownership before relying on this package.", 10)
        if repo.get("archived"):
            add("repository_archived", "provenance", "Linked repository archived",
                "The public GitHub API marks the linked repository as archived.",
                "Check the upstream support status and available alternatives.", 10)
        if package.registry and package.registry not in REGISTRIES[package.ecosystem]:
            add("non_default_source", "provenance", "Non-default dependency source",
                f"The manifest or lockfile points to {package.registry}.",
                "Verify the source against the registries or local references your project expects.", 20)
    scripts = package.scripts or meta.get("scripts", {})
    if package.install or scripts:
        hooks = ", ".join(sorted(scripts))
        add("lifecycle_script", "behavior", "Package declares lifecycle execution",
            f"Lifecycle hooks in metadata: {hooks}." if hooks else "The npm lockfile sets hasInstallScript.",
            "Review the lifecycle hook before installing or building.", 15)
    for hook, script in scripts.items():
        observed = [name for name, pattern in SCRIPT_PATTERNS.items() if pattern.search(script)]
        if observed:
            add("script_indicators", "behavior", "Lifecycle script uses commands that warrant review",
                f"{hook} includes indicators of {', '.join(observed)}.",
                "Inspect the script and verify that its commands and any remote sources are expected.", 25)
    if depth is not None and depth > 1 and any(item.points >= 25 for item in findings):
        add("transitive_exposure", "graph", "Risk enters through another dependency",
            f"The shortest known path from the project is {depth} dependency edges.",
            "Use the graph to identify which top-level package introduces this dependency.", 10)
    return findings


def analyze(inv: Inventory, *, online: bool = False, intelligence: Intelligence | None = None) -> dict:
    intel = intelligence or (collect(inv) if online else Intelligence())
    depths = inv.depths()
    direct = transitive = unresolved = 0
    scores: list[int] = []
    all_findings: list[Finding] = []
    packages = []
    max_categories: dict[str, int] = defaultdict(int)
    for package in inv.packages.values():
        depth = depths.get(package.id)
        findings = package_findings(package, intel, depth)
        all_findings.extend(findings)
        raw_categories = Counter()
        for item in findings:
            raw_categories[item.category] += item.points
        categories = {name: min(points, CAPS[name]) for name, points in raw_categories.items()}
        for name, points in categories.items():
            max_categories[name] = max(max_categories[name], points)
        score = min(100, sum(categories.values()))
        scores.append(score)
        if not package.application:
            direct += int(package.direct)
            transitive += int(not package.direct and depth is not None)
            unresolved += int(not package.direct and depth is None)
        meta = intel.registry.get(key(package), {}) if not package.application else {}
        packages.append({
            "id": package.id, "name": package.name, "ecosystem": package.ecosystem,
            "version": package.version, "spec": package.spec, "source": package.source,
            "location": package.location, "direct": package.direct, "application": package.application,
            "depth": depth, "registry": package.registry, "has_integrity": bool(package.integrity),
            "score": score, "level": risk_level(score), "finding_count": len(findings),
            "repository": meta.get("repository"),
            "first_publish": meta["first_publish"].date().isoformat() if meta.get("first_publish") else None,
            "last_publish": meta["last_publish"].date().isoformat() if meta.get("last_publish") else None,
            "osv_checked": key(package) in intel.advisories and not package.application,
        })
    packages.sort(key=lambda item: (-item["score"], item["ecosystem"], item["name"], item["id"]))
    categorized = Counter(risk_level(item.points) for item in all_findings)
    all_findings.sort(key=lambda item: (-item.points, item.package_id or "", item.code))
    warnings = inv.warnings + intel.warnings
    if len(all_findings) > MAX_FINDINGS:
        warnings.append(f"The exported findings list is limited to {MAX_FINDINGS:,} entries.")
    if not intel.enabled:
        warnings.append("Offline scan. OSV, public registry metadata, and GitHub trust checks were skipped.")
    score = max(scores, default=0)
    return {
        "schema_version": 1, "project": inv.name,
        "summary": {
            "score": score, "level": risk_level(score), "direct": direct, "transitive": transitive,
            "unclassified": unresolved, "dependencies": direct + transitive + unresolved,
            "ecosystems": sorted({pkg.ecosystem for pkg in inv.packages.values()}),
            "finding_count": len(all_findings), "severity_counts": dict(categorized),
            "categories": dict(max_categories),
        },
        "coverage": {
            "online": intel.enabled, "osv_versions": intel.osv_checked, "registry_packages": intel.registry_checked,
            "repositories": intel.repositories_checked, "manifests": sorted(inv.manifests),
        },
        "packages": packages,
        "edges": [{"from": parent, "to": child} for parent, child in sorted(inv.edges)],
        "root": ROOT,
        "findings": [{**asdict(item), "level": risk_level(item.points)} for item in all_findings[:MAX_FINDINGS]],
        "warnings": warnings,
    }
