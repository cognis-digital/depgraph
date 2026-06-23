"""Command-line interface for DEPGRAPH."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import AuditResult, audit_file, audit_text, list_advisories


def _read_stdin() -> str:
    return sys.stdin.read()


_GRADE_GLYPH = {"A": "A", "B": "B", "C": "C", "D": "D", "F": "F"}


def _render_audit_table(result: AuditResult) -> str:
    lines: list[str] = []
    lines.append(f"DEPGRAPH audit of {result.source}")
    lines.append("=" * 60)
    if not result.dependencies:
        lines.append("No dependencies parsed.")
        return "\n".join(lines)

    name_w = max(4, max(len(d.name) for d in result.dependencies))
    ver_w = max(7, max(len((d.version or "-")) for d in result.dependencies))
    header = (
        f"{'GRADE':5}  {'NAME'.ljust(name_w)}  {'VERSION'.ljust(ver_w)}  "
        f"{'SCORE':5}  {'WORST':8}  FINDINGS"
    )
    lines.append(header)
    lines.append("-" * len(header))
    # worst first
    ordered = sorted(result.dependencies, key=lambda d: d.score)
    for d in ordered:
        lines.append(
            f"{_GRADE_GLYPH[d.grade]:5}  {d.name.ljust(name_w)}  "
            f"{(d.version or '-').ljust(ver_w)}  {d.score:5.1f}  "
            f"{d.max_severity:8}  {len(d.findings)}"
        )

    # detail block for anything with findings
    flagged = [d for d in ordered if d.findings]
    if flagged:
        lines.append("")
        lines.append("FINDINGS")
        lines.append("-" * 60)
        for d in flagged:
            lines.append(f"  {d.name} {d.version or ''} [{d.grade}]")
            for f in d.findings:
                # f.message already names the advisory; don't repeat the id.
                lines.append(f"    - [{f.severity}] {f.message}")

    lines.append("")
    lines.append(
        f"project: {result.project_grade}  score={result.project_score}  "
        f"deps={len(result.dependencies)}  vulns={result.vuln_count}  "
        f"findings={result.finding_count}"
    )
    return "\n".join(lines)


def _render_advisories_table(advs: list[dict]) -> str:
    lines = [f"{len(advs)} bundled advisories", "-" * 60]
    for a in advs:
        rng = ", ".join(
            f"[{r.get('introduced','0')},{r.get('fixed','*')})" for r in a["ranges"]
        )
        lines.append(
            f"{a['id']}  {a['ecosystem']}/{a['package']}  "
            f"{a['severity']}  {rng}"
        )
        lines.append(f"    {a['summary']}")
    return "\n".join(lines)


def _render_enrichment(audit: AuditResult, report: dict) -> str:
    lines: list[str] = []
    lines.append(f"DEPGRAPH OSV enrichment of {report['source']}")
    lines.append("=" * 60)
    lines.append(
        f"bundled OSV records: {report['db_record_count']}  |  "
        f"packages with OSV refs: {report['dependencies_with_osv_refs']}  |  "
        f"total references: {report['total_osv_references']}"
    )
    if not report["packages"]:
        lines.append("")
        lines.append("No bundled-OSV advisories reference any audited package.")
        return "\n".join(lines)
    lines.append("")
    for key, refs in report["packages"].items():
        lines.append(f"  {key}  ({len(refs)} OSV advisor{'y' if len(refs) == 1 else 'ies'})")
        for ref in refs[:10]:
            alias = (ref.get("aliases") or [ref["advisory_id"]])[0]
            sev = ref.get("severity", "UNKNOWN")
            summary = (ref.get("summary", "") or "")[:80]
            lines.append(f"    - [{sev}] {ref['advisory_id']} ({alias}) {summary}")
        if len(refs) > 10:
            lines.append(f"    ... and {len(refs) - 10} more")
    return "\n".join(lines)


def _render_vulndb_records(records: list[dict], limit: int) -> str:
    lines = [f"{len(records)} bundled OSV record(s)", "-" * 60]
    for r in records[:limit]:
        aliases = ", ".join(r.get("aliases") or []) or "-"
        sev = r.get("severity") or "-"
        eco = r.get("ecosystem") or "-"
        pkgs = ", ".join(r.get("packages") or []) or "-"
        lines.append(f"{r.get('id','?')}  [{eco}]  sev={sev}  aliases={aliases}")
        lines.append(f"    packages: {pkgs}")
        if r.get("summary"):
            lines.append(f"    {r['summary'][:100]}")
    if len(records) > limit:
        lines.append(f"... ({len(records) - limit} more not shown; raise --limit)")
    return "\n".join(lines)


def _render_feeds(feeds: list[dict]) -> str:
    lines = [f"{len(feeds)} edge/air-gap feed(s) in the catalog", "-" * 60]
    for f in feeds:
        lines.append(
            f"  {f.get('id',''):28} {f.get('domain',''):14} "
            f"[{f.get('format','raw')}]  {f.get('name','')}"
        )
    lines.append("")
    lines.append("Refresh (online, opt-in):  python -m depgraph.datafeeds update <id>")
    lines.append("Air-gap snapshot:          python -m depgraph.datafeeds snapshot-export feeds.tar.gz")
    return "\n".join(lines)


def _emit_json(payload: dict) -> None:
    payload = dict(payload)
    payload["tool"] = TOOL_NAME
    payload["version"] = TOOL_VERSION
    print(json.dumps(payload, indent=2, sort_keys=False))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Offline dependency-risk scorer + OSV-style vulnerability matcher. "
            "Grades pip/npm/Pipfile manifests A-F. Defensive use only."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser(
        "audit", help="Audit a dependency manifest and grade every package."
    )
    p_audit.add_argument(
        "paths", nargs="*",
        help="Manifest file(s) (requirements.txt / package.json / Pipfile). "
             "If omitted, reads requirements from stdin.",
    )
    p_audit.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="Output format (default: table).",
    )
    p_audit.add_argument(
        "--min-severity", choices=("LOW", "MEDIUM", "HIGH", "CRITICAL"),
        default=None,
        help="Only fail (non-zero exit) when a finding at or above this "
             "severity exists.",
    )
    p_audit.add_argument(
        "--fail-grade", choices=("A", "B", "C", "D", "F"), default=None,
        help="Fail when the project grade is at or below this letter.",
    )

    p_adv = sub.add_parser(
        "advisories", help="List the bundled OSV-style advisory database."
    )
    p_adv.add_argument(
        "--ecosystem", choices=("pypi", "npm"), default=None,
        help="Filter advisories by ecosystem.",
    )
    p_adv.add_argument(
        "--format", choices=("table", "json"), default="table",
    )

    # ---- enrich: layer the full bundled 262k OSV corpus onto an audit -------
    p_enr = sub.add_parser(
        "enrich",
        help="Audit a manifest AND cross-reference every package against the "
             "bundled 262k-record offline OSV database.",
    )
    p_enr.add_argument(
        "paths", nargs="*",
        help="Manifest file(s); if omitted, reads requirements from stdin.",
    )
    p_enr.add_argument(
        "--format", choices=("table", "json"), default="table",
    )
    p_enr.add_argument(
        "--limit", type=int, default=50,
        help="Max OSV references to attach per package (default: 50).",
    )

    # ---- vulndb: direct lookups against the bundled OSV corpus --------------
    p_db = sub.add_parser(
        "vulndb",
        help="Query the bundled offline OSV database directly (no network).",
    )
    p_db.add_argument(
        "--cve", default=None, help="Resolve a CVE/GHSA/OSV id to its records.",
    )
    p_db.add_argument(
        "--package", default=None, help="List advisories naming a package.",
    )
    p_db.add_argument(
        "--ecosystem", default=None,
        help="Constrain --package to an ecosystem (PyPI/npm/Go/...).",
    )
    p_db.add_argument(
        "--search", default=None, help="Substring search over advisory summaries.",
    )
    p_db.add_argument("--limit", type=int, default=25)
    p_db.add_argument("--count", action="store_true",
                      help="Print the total number of bundled records and exit.")
    p_db.add_argument("--format", choices=("table", "json"), default="table")

    # ---- feeds: list/refresh the edge/air-gap data-feed catalog ------------
    p_fd = sub.add_parser(
        "feeds",
        help="List the edge/air-gap intelligence-feed catalog (CISA KEV / EPSS "
             "/ OSV / NVD / GHSA). Refresh is online-opt-in only.",
    )
    p_fd.add_argument(
        "--domain", default=None, help="Filter the catalog by domain.",
    )
    p_fd.add_argument("--format", choices=("table", "json"), default="table")
    return parser


def _merge_results(results: list[AuditResult]) -> AuditResult:
    merged = AuditResult(source="+".join(r.source or "?" for r in results))
    for r in results:
        merged.dependencies.extend(r.dependencies)
    return merged


_SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_GRADE_ORDER = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}


def _should_fail(result: AuditResult, min_sev: str | None, fail_grade: str | None) -> bool:
    if min_sev is None and fail_grade is None:
        # default policy: fail if any finding exists
        return result.finding_count > 0
    fail = False
    if min_sev is not None:
        thr = _SEV_ORDER[min_sev]
        for d in result.dependencies:
            for f in d.findings:
                if _SEV_ORDER.get(f.severity, 0) >= thr:
                    fail = True
    if fail_grade is not None:
        if _GRADE_ORDER[result.project_grade] <= _GRADE_ORDER[fail_grade]:
            fail = True
    return fail


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        try:
            if args.paths:
                results = [audit_file(p) for p in args.paths]
                result = results[0] if len(results) == 1 else _merge_results(results)
            else:
                result = audit_text(_read_stdin(), filename="<stdin>")
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if args.format == "json":
            _emit_json(result.as_dict())
        else:
            print(_render_audit_table(result))

        return 1 if _should_fail(result, args.min_severity, args.fail_grade) else 0

    if args.command == "advisories":
        advs = list_advisories(args.ecosystem)
        if args.format == "json":
            _emit_json({"advisories": advs, "count": len(advs)})
        else:
            print(_render_advisories_table(advs))
        return 0

    if args.command == "enrich":
        from .enrich import enrich_result
        try:
            if args.paths:
                results = [audit_file(p) for p in args.paths]
                result = results[0] if len(results) == 1 else _merge_results(results)
            else:
                result = audit_text(_read_stdin(), filename="<stdin>")
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        report = enrich_result(result, limit_per_dep=args.limit)
        if args.format == "json":
            payload = result.as_dict()
            payload["osv_enrichment"] = report
            _emit_json(payload)
        else:
            print(_render_enrichment(result, report))
        return 0

    if args.command == "vulndb":
        from .enrich import lookup_cve, lookup_package
        from .vulndb_local import VulnDB
        if args.count:
            n = VulnDB().count()
            if args.format == "json":
                _emit_json({"db_record_count": n})
            else:
                print(f"{n} bundled OSV records")
            return 0
        records: list[dict] = []
        if args.cve:
            records = lookup_cve(args.cve)
        elif args.package:
            records = lookup_package(args.package, ecosystem=args.ecosystem)
        elif args.search:
            records = VulnDB().search(args.search, limit=args.limit)
        else:
            print("vulndb: provide --cve, --package, --search, or --count",
                  file=sys.stderr)
            return 2
        if args.format == "json":
            _emit_json({"count": len(records),
                        "records": records[:args.limit]})
        else:
            print(_render_vulndb_records(records, args.limit))
        # exit non-zero when a CVE/package lookup found matches (CI signal)
        return 1 if records and (args.cve or args.package) else 0

    if args.command == "feeds":
        from .datafeeds import list_feeds
        feeds = list_feeds(args.domain)
        if args.format == "json":
            _emit_json({"count": len(feeds), "feeds": feeds})
        else:
            print(_render_feeds(feeds))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
