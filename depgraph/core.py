"""DEPGRAPH core engine — real dependency-risk analysis, stdlib only."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Reference data (curated, offline). Mirrors the spirit of OSV + typosquat
# corpora without any network calls.
# ---------------------------------------------------------------------------

# Popular package names used for typosquat distance checks.
POPULAR_PACKAGES = {
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "boto3",
    "pytest", "setuptools", "pip", "cryptography", "pyyaml", "jinja2",
    "click", "colorama", "certifi", "six", "python-dateutil", "scipy",
    "lodash", "react", "express", "axios", "chalk", "webpack", "left-pad",
}

# Minimal OSV-style advisory database: package -> list of advisories.
# Each advisory matches a set of affected version strings (exact) OR an
# inclusive upper bound via 'fixed' (anything strictly below is vulnerable).
ADVISORY_DB: Dict[str, List[dict]] = {
    "requests": [
        {"id": "GHSA-9hjg-9r4m-mvj7", "summary": "Unintended proxy leak",
         "fixed": "2.31.0", "severity": "MODERATE"},
    ],
    "urllib3": [
        {"id": "GHSA-v845-jxx5-vc9f", "summary": "Cookie request smuggling",
         "fixed": "1.26.18", "severity": "HIGH"},
    ],
    "pyyaml": [
        {"id": "CVE-2020-14343", "summary": "Arbitrary code exec via full_load",
         "fixed": "5.4", "severity": "CRITICAL"},
    ],
    "jinja2": [
        {"id": "GHSA-h5c8-rqwp-cp95", "summary": "XSS via xmlattr filter",
         "fixed": "3.1.3", "severity": "MODERATE"},
    ],
    "flask": [
        {"id": "CVE-2023-30861", "summary": "Cookie disclosure via caching",
         "fixed": "2.3.2", "severity": "HIGH"},
    ],
}

# Maintainer signal hints (curated): packages flagged for single-maintainer
# or low-bus-factor risk. Spirit of Scorecard 'Maintained' / 'Contributors'.
SINGLE_MAINTAINER = {"left-pad", "colorama", "six"}

SEVERITY_WEIGHT = {
    "CRITICAL": 40, "HIGH": 30, "MODERATE": 18, "LOW": 8, "UNKNOWN": 12,
}

VERSION_RE = re.compile(r"^\d+(\.\d+)*")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class RiskFinding:
    category: str          # vuln | typosquat | pinning | maintainer
    severity: str          # CRITICAL/HIGH/MODERATE/LOW/INFO
    points: int
    message: str
    ref: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Dependency:
    name: str
    version: Optional[str]
    constraint: str = ""      # raw constraint text e.g. '>=2.0' or '^1.2'
    ecosystem: str = "pypi"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DependencyReport:
    dependency: Dependency
    risk_score: int
    grade: str
    findings: List[RiskFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.dependency.name,
            "version": self.dependency.version,
            "ecosystem": self.dependency.ecosystem,
            "risk_score": self.risk_score,
            "grade": self.grade,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Version utilities
# ---------------------------------------------------------------------------
def _version_tuple(v: str) -> Tuple[int, ...]:
    m = VERSION_RE.match(v or "")
    if not m:
        return tuple()
    return tuple(int(p) for p in m.group(0).split("."))


def _is_below(version: str, fixed: str) -> bool:
    a, b = _version_tuple(version), _version_tuple(fixed)
    if not a or not b:
        return False
    # pad to equal length
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return a < b


# ---------------------------------------------------------------------------
# Typosquat detection (Levenshtein edit distance)
# ---------------------------------------------------------------------------
def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(
                prev[j] + 1,
                cur[j - 1] + 1,
                prev[j - 1] + (ca != cb),
            ))
        prev = cur
    return prev[-1]


def _typosquat_match(name: str) -> Optional[str]:
    """Return the popular package this name is likely squatting, or None."""
    low = name.lower()
    if low in POPULAR_PACKAGES:
        return None
    best: Optional[str] = None
    for pop in POPULAR_PACKAGES:
        if abs(len(pop) - len(low)) > 2:
            continue
        d = _edit_distance(low, pop)
        # close edit distance on a non-trivial name = suspicious
        if 0 < d <= 1 and len(pop) >= 4:
            return pop
        if d == 2 and len(pop) >= 7:
            best = best or pop
    return best


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------
_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*"
    r"(==|>=|<=|~=|!=|>|<)?\s*([0-9][\w.\-]*)?"
)


def _parse_requirements(text: str) -> List[Dependency]:
    deps: List[Dependency] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name, _extras, op, ver = m.groups()
        if not name:
            continue
        constraint = f"{op or ''}{ver or ''}"
        version = ver if op == "==" else (ver if op is None and ver else None)
        deps.append(Dependency(name=name, version=version,
                               constraint=constraint, ecosystem="pypi"))
    return deps


def _parse_package_json(text: str) -> List[Dependency]:
    data = json.loads(text)
    deps: List[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            cleaned = spec.lstrip("^~>=< ")
            pinned = spec and spec[0] not in "^~><*"
            version = cleaned if pinned and cleaned else None
            deps.append(Dependency(name=name, version=version,
                                   constraint=spec, ecosystem="npm"))
    return deps


def parse_manifest(path: str) -> List[Dependency]:
    """Parse a requirements.txt or package.json file into Dependency objects."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    base = os.path.basename(path).lower()
    if base.endswith(".json"):
        return _parse_package_json(text)
    return _parse_requirements(text)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def _grade(score: int) -> str:
    if score >= 60:
        return "F"
    if score >= 40:
        return "D"
    if score >= 25:
        return "C"
    if score >= 10:
        return "B"
    return "A"


def score_dependency(dep: Dependency) -> DependencyReport:
    """Run all signal checks for one dependency and produce a scored report."""
    findings: List[RiskFinding] = []

    # 1. OSV-style known vulnerabilities
    for adv in ADVISORY_DB.get(dep.name.lower(), []):
        if dep.version and _is_below(dep.version, adv["fixed"]):
            sev = adv.get("severity", "UNKNOWN")
            findings.append(RiskFinding(
                category="vuln", severity=sev,
                points=SEVERITY_WEIGHT.get(sev, 12),
                message=f"{adv['summary']} (fixed in {adv['fixed']})",
                ref=adv["id"],
            ))
        elif not dep.version:
            findings.append(RiskFinding(
                category="vuln", severity="INFO", points=4,
                message=f"Unpinned: cannot confirm safety vs {adv['id']}",
                ref=adv["id"],
            ))

    # 2. Typosquat
    target = _typosquat_match(dep.name)
    if target:
        findings.append(RiskFinding(
            category="typosquat", severity="HIGH", points=35,
            message=f"Name resembles popular package '{target}'",
            ref=target,
        ))

    # 3. Pinning / Scorecard-style hygiene
    if not dep.version:
        findings.append(RiskFinding(
            category="pinning", severity="LOW", points=8,
            message=f"Unpinned dependency (constraint '{dep.constraint or '*'}')",
        ))

    # 4. Maintainer signal
    if dep.name.lower() in SINGLE_MAINTAINER:
        findings.append(RiskFinding(
            category="maintainer", severity="MODERATE", points=15,
            message="Low bus factor: effectively single-maintainer package",
        ))

    score = min(100, sum(f.points for f in findings))
    return DependencyReport(dependency=dep, risk_score=score,
                            grade=_grade(score), findings=findings)


def analyze_dependencies(deps: List[Dependency]) -> dict:
    """Score a list of dependencies and produce an aggregate report dict."""
    reports = [score_dependency(d) for d in deps]
    reports.sort(key=lambda r: r.risk_score, reverse=True)
    total = len(reports)
    vulnerable = sum(
        1 for r in reports if any(f.category == "vuln" and f.severity != "INFO"
                                  for f in r.findings)
    )
    typosquats = sum(
        1 for r in reports if any(f.category == "typosquat" for f in r.findings)
    )
    avg = round(sum(r.risk_score for r in reports) / total, 1) if total else 0.0
    return {
        "summary": {
            "total_dependencies": total,
            "vulnerable": vulnerable,
            "typosquats": typosquats,
            "average_risk": avg,
            "highest_risk": reports[0].risk_score if reports else 0,
        },
        "dependencies": [r.to_dict() for r in reports],
    }


def analyze_manifest(path: str) -> dict:
    """Parse a manifest file and return the full analysis report."""
    deps = parse_manifest(path)
    result = analyze_dependencies(deps)
    result["manifest"] = os.path.abspath(path)
    return result
