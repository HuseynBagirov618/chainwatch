import argparse
import json
import sys
from pathlib import Path

from .analysis import analyze
from .changes import compare
from .git_inputs import git_files
from .inputs import local_files
from .parsers import build_inventory
from .reports import comparison_text, scan_text

DEMO = Path(__file__).with_name("demo")


def inventory(path: Path):
    resolved = path.resolve()
    files, warnings = local_files(resolved)
    return build_inventory(resolved.name, files, warnings)


def result(report, format_name, renderer):
    content = json.dumps(report, indent=2, ensure_ascii=True) + "\n" if format_name == "json" else renderer(report)
    if format_name == "text":
        content = "".join(c if c.isprintable() or c == "\n" else f"\\u{ord(c):04x}" for c in content)
    sys.stdout.write(content)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="chainwatch", description="Analyze software supply-chain dependency risk.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Scan a local project directory")
    scan.add_argument("path", type=Path)
    scan.add_argument("--offline", action="store_true", help="Skip public metadata and OSV lookups")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    graph = commands.add_parser("graph", help="Export the local dependency graph as JSON")
    graph.add_argument("path", type=Path)
    diff = commands.add_parser("compare", help="Compare two local project snapshots")
    diff.add_argument("before", help="Before directory, or base Git ref when --git is used")
    diff.add_argument("after", help="After directory, or head Git ref when --git is used")
    diff.add_argument("--git", type=Path, metavar="REPOSITORY", help="Read snapshots from a local Git repository")
    diff.add_argument("--format", choices=("text", "json"), default="text")
    demo = commands.add_parser("demo", help="Scan the bundled example offline")
    demo.add_argument("--format", choices=("text", "json"), default="text")
    serve = commands.add_parser("serve", help="Start the local dashboard")
    serve.add_argument("--port", type=int, default=8421)
    serve.add_argument("--database", type=Path, default=Path(".chainwatch.sqlite3"))

    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            result(analyze(inventory(args.path), online=not args.offline), args.format, scan_text)
        elif args.command == "graph":
            report = analyze(inventory(args.path))
            result({name: report[name] for name in ("root", "project", "packages", "edges", "warnings")}, "json", scan_text)
        elif args.command == "compare":
            if args.git:
                before = build_inventory(args.before, *git_files(args.git, args.before))
                after = build_inventory(args.after, *git_files(args.git, args.after))
            else:
                before, after = inventory(Path(args.before)), inventory(Path(args.after))
            result(compare(before, after), args.format, comparison_text)
        elif args.command == "demo":
            files, warnings = local_files(DEMO / "after")
            result(analyze(build_inventory("Northstar Store", files, warnings)), args.format, scan_text)
        elif args.command == "serve":
            import uvicorn

            from .server import create_app
            if not 1 <= args.port <= 65535:
                parser.error("--port must be between 1 and 65535")
            uvicorn.run(create_app(args.database), host="127.0.0.1", port=args.port)
    except (OSError, ValueError) as error:
        parser.exit(2, f"chainwatch: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
