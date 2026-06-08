"""DEPGRAPH command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import analyze_manifest


def _render_table(report: dict) -> str:
    s = report["summary"]
    lines: List[str] = []
    lines.append(f"DEPGRAPH report — {report.get('manifest', '')}")
    lines.append(
        f"  deps={s['total_dependencies']}  vulnerable={s['vulnerable']}  "
        f"typosquats={s['typosquats']}  avg_risk={s['average_risk']}"
    )
    lines.append("")
    lines.append(f"  {'GRADE':<6}{'SCORE':<7}{'PACKAGE':<24}{'TOP FINDING'}")
    lines.append("  " + "-" * 70)
    for d in report["dependencies"]:
        top = d["findings"][0]["message"] if d["findings"] else "clean"
        ver = d["version"] or "*"
        pkg = f"{d['name']}@{ver}"
        lines.append(f"  {d['grade']:<6}{d['risk_score']:<7}{pkg:<24}{top}")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Dependency risk visualizer (Scorecard + OSV + typosquat "
                    "+ maintainer signals).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Analyze a dependency manifest file.")
    scan.add_argument("manifest",
                      help="Path to requirements.txt or package.json")
    scan.add_argument("--format", choices=("table", "json"), default="table")
    scan.add_argument("--fail-on", type=int, default=None, metavar="SCORE",
                      help="Exit non-zero if any dependency risk >= SCORE")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 1

    try:
        report = analyze_manifest(args.manifest)
    except FileNotFoundError:
        print(f"error: manifest not found: {args.manifest}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        print(f"error: failed to parse manifest: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(_render_table(report))

    if args.fail_on is not None:
        if report["summary"]["highest_risk"] >= args.fail_on:
            print(
                f"FAIL: highest risk {report['summary']['highest_risk']} "
                f">= threshold {args.fail_on}",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
