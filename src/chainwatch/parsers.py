import json
import posixpath
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .model import ROOT, Inventory, Package, fingerprint

NPM_NAME = re.compile(r"(?:@[a-zA-Z0-9._~-]+/)?[a-zA-Z0-9._~-]+\Z")
NPM_VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?\Z", re.ASCII)
GROUPS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
LIFECYCLE = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"}
MAX_PACKAGES = 10_000
MAX_EDGES = 100_000


def mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def npm_name(name: object) -> bool:
    return isinstance(name, str) and len(name) <= 214 and NPM_NAME.fullmatch(name) is not None and all(part not in {".", ".."} for part in name.split("/"))


def version_for(value: object) -> str | None:
    if isinstance(value, str) and len(value) <= 128 and NPM_VERSION.fullmatch(value):
        return value
    return None


def origin(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value:
        return None, None
    try:
        parsed = urlsplit(value)
        prefix = parsed.scheme.removeprefix("git+")
        if parsed.hostname and prefix in {"http", "https", "git", "ssh"}:
            label = parsed.hostname.lower()
        else:
            label = prefix if prefix in {"file", "workspace", "link", "github", "gitlab", "bitbucket"} else "other"
    except ValueError:
        label = "other"
    return label, fingerprint(value)


def display_spec(value: str) -> str:
    if re.fullmatch(r"[a-zA-Z0-9^~<>=*+.|, -]{1,128}", value):
        return value
    return f"[source reference {fingerprint(value)[:12]}]"


def requirements(inv: Inventory, path: str, content: str) -> None:
    occurrences: dict[str, int] = {}
    logical = re.sub(r"\\\r?\n", " ", content)
    for line_no, line in enumerate(logical.splitlines(), 1):
        line = re.split(r"\s+#", line.strip(), maxsplit=1)[0]
        line = re.split(r"\s+--hash(?:=|\s)", line, maxsplit=1)[0]
        if not line or line.startswith("#"):
            continue
        try:
            if len(line) > 8192:
                raise InvalidRequirement
            req = Requirement(line)
            if len(req.name) > 214:
                raise InvalidRequirement
        except InvalidRequirement:
            if len(inv.warnings) < 200:
                inv.warnings.append(f"{path}:{line_no}: skipped an unsupported requirements entry.")
            continue
        parts = list(req.specifier)
        version = None
        if len(parts) == 1 and parts[0].operator == "==" and "*" not in parts[0].version and len(parts[0].version) <= 128:
            try:
                version = str(Version(parts[0].version))
            except InvalidVersion:
                pass
        registry, reference = origin(req.url)
        spec = display_spec(req.url) if req.url else str(req.specifier)
        if req.marker:
            spec = f"{spec or '*'}; {req.marker}"
        name = canonicalize_name(req.name)
        selector = fingerprint(str(req.marker or "") + ",".join(sorted(req.extras)))[:12]
        identity = f"{name}:{selector}"
        occurrences[identity] = occurrences.get(identity, 0) + 1
        package = Package("PyPI", name, f"{path}:{selector}:{occurrences[identity]}", path,
                          version, spec or "*", True, registry, reference)
        inv.add(package)
        if len(inv.packages) >= MAX_PACKAGES:
            return


def declarations(obj: dict, groups: tuple[str, ...] = GROUPS) -> dict[str, str]:
    result = {}
    for group in groups:
        result.update({
            name: value for name, value in mapping(obj.get(group)).items()
            if npm_name(name) and isinstance(value, str)
        })
    return result


def lifecycle(obj: dict) -> dict[str, str]:
    return {
        name: value[:8192] for name, value in mapping(obj.get("scripts")).items()
        if name in LIFECYCLE and isinstance(value, str) and value.strip()
    }


def installed_name(location: str) -> str:
    return location.rsplit("node_modules/", 1)[-1]


def legacy_packages(deps: dict) -> dict:
    packages = {}
    queue = [(deps, "")]
    while queue and len(packages) < MAX_PACKAGES:
        entries, parent = queue.pop()
        for name, entry in entries.items():
            if not npm_name(name) or not isinstance(entry, dict):
                continue
            location = posixpath.join(parent, "node_modules", name)
            if len(location) > 2048:
                continue
            packages[location] = {**entry, "dependencies": mapping(entry.get("requires"))}
            children = mapping(entry.get("dependencies"))
            if children:
                queue.append((children, location))
            if len(packages) >= MAX_PACKAGES:
                break
    return packages


def resolve(location: str, target: str, packages: dict[str, Package]) -> Package | None:
    while True:
        candidate = posixpath.join(location, "node_modules", target)
        if candidate in packages:
            return packages[candidate]
        if not location:
            return None
        location = location.rsplit("/node_modules/", 1)[0] if "/node_modules/" in location else ""


def read_json(inv: Inventory, files: dict[str, str], path: str) -> dict:
    if path not in files:
        return {}
    try:
        obj = json.loads(files[path])
        if isinstance(obj, dict):
            return obj
    except (ValueError, RecursionError):
        pass
    inv.warnings.append(f"{path}: expected a valid JSON object.")
    return {}


def npm(inv: Inventory, files: dict[str, str], directory: str) -> None:
    manifest = posixpath.join(directory, "package.json")
    lock_path = posixpath.join(directory, "package-lock.json")
    obj = read_json(inv, files, manifest)
    lock = read_json(inv, files, lock_path)
    entries = mapping(lock.get("packages"))
    if not entries and lock.get("lockfileVersion") == 1:
        entries = legacy_packages(mapping(lock.get("dependencies")))
    elif lock and lock.get("lockfileVersion") not in {1, 2, 3}:
        inv.warnings.append(f"{lock_path}: unrecognized npm lockfile version.")
    declared = declarations(obj if manifest in files and obj else mapping(entries.get("")))
    root_scripts = lifecycle(obj)
    relative: dict[str, Package] = {}
    missed_links = False
    for location, raw in entries.items():
        if len(inv.packages) + len(relative) >= MAX_PACKAGES:
            break
        parts = location.split("/")
        if not location.startswith("node_modules/") or len(location) > 2048 or any(p in {"", ".", ".."} for p in parts):
            continue
        name = installed_name(location)
        entry = mapping(raw)
        if entry.get("link"):
            missed_links = True
            continue
        if not npm_name(name):
            continue
        version = version_for(entry.get("version"))
        registry, reference = origin(entry.get("resolved"))
        integrity = entry.get("integrity")
        actual = entry.get("name")
        package = Package(
            "npm", actual if npm_name(actual) else name, posixpath.join(directory, location),
            lock_path, version, registry=registry, origin=reference,
            integrity=fingerprint(integrity) if isinstance(integrity, str) and integrity else None,
            install=entry.get("hasInstallScript") is True,
        )
        relative[location] = package
    if missed_links:
        inv.warnings.append(f"{lock_path}: workspace links are represented by their declarations where available.")
    if lock.get("lockfileVersion") == 1 and manifest not in files:
        inv.warnings.append(f"{lock_path}: direct dependencies require package.json for a v1 lockfile.")
    for name, spec in declared.items():
        location = f"node_modules/{name}"
        if location in relative:
            package = relative[location]
        elif len(inv.packages) + len(relative) < MAX_PACKAGES:
            registry, reference = origin(spec) if (":" in spec or "/" in spec) and not spec.startswith("npm:") else (None, None)
            alias, _, alias_version = spec.removeprefix("npm:").rpartition("@") if spec.startswith("npm:") else ("", "", "")
            package = Package("npm", alias if npm_name(alias) else name, posixpath.join(directory, location), manifest,
                              version_for(alias_version or spec), registry=registry, origin=reference)
            relative[location] = package
        else:
            break
        package.direct = True
        package.spec = display_spec(spec)
        if package.origin is None and (":" in spec or "/" in spec) and not spec.startswith("npm:"):
            package.registry, package.origin = origin(spec)
    for package in relative.values():
        inv.add(package)
    for location, package in relative.items():
        entry = mapping(entries.get(location))
        for name in declarations(entry, ("dependencies", "optionalDependencies", "peerDependencies")):
            child = resolve(location, name, relative)
            if child and child.id != package.id:
                if len(inv.edges) >= MAX_EDGES:
                    break
                inv.edges.add((package.id, child.id))
    if root_scripts and len(inv.packages) < MAX_PACKAGES:
        name = obj.get("name")
        package = Package("npm", name if npm_name(name) else "project", manifest,
                          manifest, version_for(obj.get("version")), scripts=root_scripts, application=True)
        inv.add(package)
        inv.edges.add((ROOT, package.id))


def build_inventory(name: str, files: dict[str, str], warnings: list[str] | None = None) -> Inventory:
    inv = Inventory(name=name, warnings=list(warnings or []))
    npm_dirs = {
        str(PurePosixPath(path).parent).removeprefix("./") for path in files
        if PurePosixPath(path).name in {"package.json", "package-lock.json"}
    }
    for directory in sorted(npm_dirs):
        if len(inv.packages) >= MAX_PACKAGES:
            break
        npm(inv, files, "" if directory == "." else directory)
    for path, content in sorted(files.items()):
        if path.endswith(".txt") and len(inv.packages) < MAX_PACKAGES:
            requirements(inv, path, content)
    inv.manifests = {path: fingerprint(content) for path, content in files.items()}
    if not files:
        inv.warnings.append("No supported dependency manifests found.")
    if len(inv.packages) >= MAX_PACKAGES or len(inv.edges) >= MAX_EDGES:
        inv.warnings.append("Dependency graph reached its size limit. The inventory may be incomplete.")
    return inv
