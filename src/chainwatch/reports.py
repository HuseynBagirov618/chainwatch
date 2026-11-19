def scan_text(report: dict) -> str:
    summary = report["summary"]
    lines = [
        f"ChainWatch | {report['project']}",
        f"Risk {summary['score']}/100 ({summary['level']})",
        f"Dependencies {summary['dependencies']} | {summary['direct']} direct | "
        f"{summary['transitive']} transitive | {summary['unclassified']} unclassified",
        f"Findings {summary['finding_count']}",
        "",
    ]
    packages = {item["id"]: item for item in report["packages"]}
    for item in report["findings"]:
        name = packages[item["package_id"]]["name"]
        lines.extend((
            f"[{item['level'].upper()}] {name} | {item['title']}",
            f"  {item['evidence']}", f"  {item['recommendation']}",
        ))
        if item.get("reference"):
            lines.append(f"  {item['reference']}")
        lines.append("")
    lines.extend(f"Coverage: {warning}" for warning in report["warnings"])
    return "\n".join(lines) + "\n"


def comparison_text(report: dict) -> str:
    summary = report["summary"]
    lines = [
        f"ChainWatch comparison | {report['before']} → {report['after']}",
        f"{summary['added']} added | {summary['removed']} removed | {summary['updated']} updated",
        f"Change risk {summary['score']}/100 ({summary['level']}) | {summary['finding_count']} findings",
        "",
    ]
    for change in report["changes"]:
        before, after = change["before"] or {}, change["after"] or {}
        version = lambda state: state.get("version") or state.get("spec") or "—"
        lines.append(f"{change['kind']:7} {change['ecosystem']}/{change['name']}: {version(before)} → {version(after)}")
        if blast := change["blast_radius"]:
            lines.append(f"  Reachability: +{blast['added']} / −{blast['removed']} / {blast['updated']} updated")
    for item in report["findings"]:
        lines.extend(("", f"[{item['level'].upper()}] {item['title']}", f"  {item['evidence']}", f"  {item['recommendation']}"))
    lines.extend(f"Coverage: {warning}" for warning in report["warnings"])
    return "\n".join(lines) + "\n"
