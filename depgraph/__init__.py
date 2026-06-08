"""DEPGRAPH — offline dependency-risk scorer + OSV-style vuln matcher.

Audits dependency manifests (pip requirements, package.json, Pipfile) and
assigns each dependency a letter-graded risk score from maintainer/age/
typosquat heuristics (scorecard-style) plus matches against a bundled
OSV-style advisory database (osv.dev-style version-range matching).

Local, deterministic, zero-install, no network.
"""

from __future__ import annotations

from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    AuditResult,
    Dependency,
    Finding,
    audit_dependency,
    audit_file,
    audit_text,
    levenshtein,
    list_advisories,
    match_advisories,
    parse_manifest,
    parse_version,
    score_to_grade,
    typosquat_match,
    version_compare,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "AuditResult",
    "Dependency",
    "Finding",
    "audit_dependency",
    "audit_file",
    "audit_text",
    "levenshtein",
    "list_advisories",
    "match_advisories",
    "parse_manifest",
    "parse_version",
    "score_to_grade",
    "typosquat_match",
    "version_compare",
]
