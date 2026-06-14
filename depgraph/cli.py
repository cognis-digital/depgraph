"""Command-line interface for DEPGRAPH."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import AuditResult, audit_file, audit_text, list_advisories


def _read_stdin() -> str:
    try:
        return sys.stdin.read()
    except UnicodeDecodeError as exc:
        raise ValueError(f"stdin contains non-text data: {exc}") from exc


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
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:  # noqa: BLE001
            print(f"error: unexpected failure — {exc}", file=sys.stderr)
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

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
