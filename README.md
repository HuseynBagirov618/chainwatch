# ChainWatch

ChainWatch maps a project's npm and Python dependencies and explains software supply-chain risks. It combines known vulnerabilities, package identity, publication history, repository trust, install-time behavior, and changes between dependency snapshots.

## Quick start

Requires Python 3.11 or later. Create a virtual environment and install ChainWatch from this repository.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install .
chainwatch demo
chainwatch serve
```

Open <http://127.0.0.1:8421>. The dashboard starts with the offline Northstar Store example. Select **New scan** to scan your own folder. The **Changes** view compares pairs of folders. The dashboard includes a searchable inventory, package details, an interactive graph, findings, TXT and JSON export, and local scan history.

## CLI

```sh
chainwatch scan ./my-project
chainwatch scan ./my-project --offline --format json > scan.json
chainwatch graph ./my-project > graph.json
chainwatch compare ./before ./after
chainwatch compare HEAD~1 HEAD --git ./my-project --format json > changes.json
chainwatch serve --port 8421 --database .chainwatch.sqlite3
```

Scans recurse through local project folders and read `package.json`, `package-lock.json` (v1–v3), `requirements.txt`, and `requirements-*.txt`. The graph distinguishes direct, transitive, and unclassified dependencies. Python requirements describe declarations only. Includes, constraints, and Python transitive resolution are outside the supported format. npm workspace links have partial coverage. For ordinary npm lockfiles the graph resolves nested and hoisted package paths and preserves separate installed instances.

CLI scans query OSV, public npm/PyPI registries, and linked public GitHub repositories by default. Use `--offline` to keep analysis local. Dashboard scans start offline and expose an explicit online option. OSV requires an exact version. Online enrichment prioritizes direct dependencies and applies to up to 80 package identities. Coverage, unsupported entries, and lookup errors appear in each report.

## Findings and scores

- **Vulnerabilities** match exact package versions against OSV records. Advisory IDs appear in findings.
- **Identity** flags close matches against a curated list of popular names, including adjacent-letter swaps.
- **Maintenance and trust** use publication age, dated release history, archived or unavailable upstream repositories, and non-default package sources.
- **Behavior** reads npm lifecycle declarations and lockfile indicators. It checks available script text for download and interpreter indicators.
- **Changes** cover additions, removals, updates, source changes, missing or changed integrity values, lifecycle marker changes, and transitive reachability per direct dependency.

Scores express review priority. Each finding has points and a recommendation. The scanner caps correlated signals per category, sums the capped values for each package, and uses the maximum package score as the project score. The change report calculates a separate review score. Risk levels are low (0–24), moderate (25–49), high (50–74), and critical (75–100). Check scan coverage when interpreting a low score.

ChainWatch reads manifests as data and never runs install commands or lifecycle hooks. The dashboard binds to loopback and stores up to 20 recent scan reports in a local SQLite file. Scan reports include dependency names and repository paths, so review them before sharing. The example manifests under `src/chainwatch/demo` are synthetic fixtures intended for scanning.

## Development

```sh
python -m pip install -e '.[test]'
python -m pytest
```
