from collections import defaultdict, deque
from dataclasses import dataclass, field
from hashlib import sha256

ROOT = "project"


def fingerprint(value: str) -> str:
    return sha256(value.encode("utf-8", errors="replace")).hexdigest()


def risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "moderate"
    return "low"


@dataclass
class Package:
    ecosystem: str
    name: str
    location: str
    source: str
    version: str | None = None
    spec: str | None = None
    direct: bool = False
    registry: str | None = None
    origin: str | None = None
    integrity: str | None = None
    install: bool = False
    scripts: dict[str, str] = field(default_factory=dict)
    application: bool = False

    @property
    def id(self) -> str:
        return f"{self.ecosystem}:{self.location}:{self.name}"


@dataclass
class Inventory:
    name: str
    packages: dict[str, Package] = field(default_factory=dict)
    edges: set[tuple[str, str]] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    manifests: dict[str, str] = field(default_factory=dict)

    def add(self, package: Package) -> None:
        self.packages[package.id] = package
        if package.direct:
            self.edges.add((ROOT, package.id))

    def adjacency(self) -> dict[str, list[str]]:
        result = defaultdict(list)
        for parent, child in sorted(self.edges):
            result[parent].append(child)
        return result

    def depths(self) -> dict[str, int]:
        edges = self.adjacency()
        depths = {ROOT: 0}
        queue = deque([ROOT])
        while queue:
            parent = queue.popleft()
            for child in edges.get(parent, ()):
                if child not in depths:
                    depths[child] = depths[parent] + 1
                    queue.append(child)
        return depths


@dataclass(frozen=True)
class Finding:
    code: str
    category: str
    title: str
    evidence: str
    recommendation: str
    points: int
    package_id: str | None = None
    reference: str | None = None
