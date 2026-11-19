from collections import deque
from dataclasses import asdict
from pathlib import PurePosixPath

from .model import Finding, Inventory, Package, risk_level

MAX_BLAST_ROOTS = 80


def reachable(root: str, edges: dict[str, list[str]]) -> set[str]:
    seen = {root}
    pending = deque([root])
    while pending:
        for child in edges.get(pending.popleft(), ()):
            if child not in seen:
                seen.add(child)
                pending.append(child)
    return seen - {root}


def package_state(package: Package | None) -> dict | None:
    if package is None:
        return None
    return {"version": package.version, "spec": package.spec, "registry": package.registry,
            "direct": package.direct, "location": package.location}


def compare(before: Inventory, after: Inventory) -> dict:
    old_edges, new_edges = before.adjacency(), after.adjacency()
    findings = []
    changes = []
    blast_checked = 0
    direct_roots = 0
    all_ids = before.packages.keys() | after.packages.keys()
    changed_files = [
        path for path in sorted(before.manifests.keys() | after.manifests.keys())
        if before.manifests.get(path) != after.manifests.get(path)
    ]

    for package_id in sorted(all_ids):
        old = before.packages.get(package_id)
        new = after.packages.get(package_id)
        pkg = new or old
        if pkg.application:
            continue
        old_state, new_state = package_state(old), package_state(new)
        evidence = []

        def flag(code, title, detail, recommendation, points):
            evidence.append(Finding(code, "changes", title, detail, recommendation, points, package_id))

        if old and new:
            if old.origin and new.origin != old.origin and (
                old.registry != new.registry or old.version == new.version
            ):
                flag("source_changed", "Dependency source changed",
                     f"Resolved source changed from {old.registry or 'unknown'} to {new.registry or 'unspecified'}.",
                     "Confirm the new source and validate the lockfile against a trusted registry.", 25)
            if old.integrity and not new.integrity:
                flag("integrity_removed", "Lockfile integrity removed", "The package no longer has an integrity value.",
                     "Review how the lockfile was generated and recover the expected integrity value.", 25)
            elif old.integrity and new.integrity != old.integrity and old.version and old.version == new.version:
                flag("integrity_changed", "Integrity changed for the same version",
                     f"Integrity changed while version {new.version} stayed the same.",
                     "Validate the package artifact independently before accepting the change.", 35)
        if new and new.install and (old is None or not old.install):
            flag("install_script_added", "New lifecycle execution marker",
                 "The updated lockfile sets hasInstallScript for this dependency.",
                 "Review the package lifecycle hooks and confirm the change is expected.", 15)
        if new and new.source.endswith("package-lock.json") and (not old or old.version != new.version):
            manifest = str(PurePosixPath(new.source).with_name("package.json"))
            old_manifest = before.manifests.get(manifest)
            if old_manifest and old_manifest == after.manifests.get(manifest):
                flag("lockfile_only_change", "Dependency changed with an unchanged manifest",
                     "The resolved package was added or changed while its package.json was unchanged.",
                     "Confirm that a routine lockfile refresh or security update explains the change.", 10)
        direct = (old is not None and old.direct) or (new is not None and new.direct)
        direct_roots += int(direct)
        blast = None
        if direct and blast_checked < MAX_BLAST_ROOTS:
            blast_checked += 1
            previous = reachable(package_id, old_edges) if old else set()
            current = reachable(package_id, new_edges) if new else set()
            introduced = current - previous
            removed = previous - current
            updated = {
                item for item in current & previous
                if package_state(before.packages[item]) != package_state(after.packages[item])
            }
            if introduced or removed or updated:
                blast = {"added": len(introduced), "removed": len(removed), "updated": len(updated),
                         "added_packages": sorted(after.packages[item].name for item in introduced)[:30]}
            if len(introduced) >= 10:
                flag("large_blast_radius", "Change adds many reachable dependencies",
                     f"This direct dependency gained {len(introduced)} reachable packages.",
                     "Review the added transitive packages and overall dependency footprint.", 10)
        if old_state != new_state or evidence or blast:
            score = min(65, sum(item.points for item in evidence))
            changes.append({
                "id": package_id, "name": pkg.name, "ecosystem": pkg.ecosystem,
                "kind": "added" if old is None else "removed" if new is None else "updated",
                "before": old_state, "after": new_state,
                "blast_radius": blast, "score": score, "level": risk_level(score),
            })
            findings.extend({**asdict(item), "level": risk_level(item.points)} for item in evidence)
    changes.sort(key=lambda item: (-item["score"], item["name"], item["id"]))
    findings.sort(key=lambda item: (-item["points"], item["package_id"], item["code"]))
    warnings = before.warnings + after.warnings
    if direct_roots > MAX_BLAST_ROOTS:
        warnings = warnings + [f"Blast-radius analysis is limited to {MAX_BLAST_ROOTS} direct dependency roots."]
    score = max((item["score"] for item in changes), default=0)
    return {
        "schema_version": 1, "before": before.name, "after": after.name,
        "summary": {
            "score": score, "level": risk_level(score),
            **{kind: sum(item["kind"] == kind for item in changes) for kind in ("added", "removed", "updated")},
            "finding_count": len(findings),
        },
        "changed_files": changed_files, "changes": changes, "findings": findings, "warnings": warnings,
    }
