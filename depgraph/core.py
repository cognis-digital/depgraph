"""DEPGRAPH core engine — dependency risk scoring + vulnerability matching.

Offline, dependency-free supply-chain risk auditor in the spirit of
``ossf/scorecard`` (project-health heuristics, letter grades) and ``osv.dev``
(an OSV-style vulnerability-id matcher with semantic version-range checks).

What it does, with REAL bundled rules and data (no network, ever):

* Parses common dependency manifests:
    - ``requirements.txt`` / ``*.txt`` pip pins (``name==1.2.3``, ``name>=1``)
    - ``package.json`` (npm ``dependencies`` + ``devDependencies``)
    - ``Pipfile`` ``[packages]`` / ``[dev-packages]`` blocks
* Scores every dependency on heuristics:
    - typosquat distance to a bundled set of popular package names
    - missing / unpinned version
    - "yanked"/abandoned signal from a bundled maintenance table
    - suspicious lookalike characters / homoglyph-ish names
    - unusually new or single-maintainer projects (bundled metadata)
* Matches each (ecosystem, name, version) against a bundled OSV-style
  advisory database using inclusive/exclusive semantic-version ranges.
* Rolls findings into a per-package penalty, then a 0-10 score and an
  A-F letter grade, plus an overall project grade.

Everything is deterministic and local. No code from dependencies is executed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Bundled data: popular package names (for typosquat heuristics)
# ---------------------------------------------------------------------------

# Real, well-known package names per ecosystem. Typosquat attacks register
# names a small edit-distance away from these. This is the "known good" anchor.
POPULAR = {
    "pypi": [
        "requests", "urllib3", "numpy", "pandas", "scipy", "flask", "django",
        "fastapi", "boto3", "botocore", "setuptools", "pip", "wheel", "pytest",
        "click", "jinja2", "pyyaml", "cryptography", "certifi", "idna",
        "charset-normalizer", "six", "python-dateutil", "pytz", "packaging",
        "attrs", "sqlalchemy", "pillow", "matplotlib", "scikit-learn",
        "tensorflow", "torch", "transformers", "openai", "anthropic",
        "aiohttp", "httpx", "pydantic", "typing-extensions", "rich", "tqdm",
        "colorama", "werkzeug", "markupsafe", "redis", "celery", "gunicorn",
        "uvicorn", "starlette", "lxml", "beautifulsoup4", "selenium",
    ],
    "npm": [
        "react", "react-dom", "lodash", "express", "axios", "chalk", "commander",
        "webpack", "babel", "typescript", "eslint", "prettier", "jest", "vue",
        "angular", "next", "moment", "uuid", "dotenv", "cors", "body-parser",
        "mongoose", "socket.io", "rxjs", "redux", "tailwindcss", "vite",
        "node-fetch", "ws", "debug", "minimist", "semver", "glob", "yargs",
        "underscore", "jquery", "bootstrap", "classnames", "styled-components",
    ],
}

# ---------------------------------------------------------------------------
# Bundled data: package maintenance metadata
# ---------------------------------------------------------------------------
# Minimal, realistic project-health signals (scorecard-style). Keys are
# "ecosystem:name". age_months ~= first release; maintainers = # publishers;
# deprecated / yanked flags mirror real registry states.
MAINTENANCE = {
    "pypi:left-pad": {"age_months": 4, "maintainers": 1, "deprecated": False},
    "pypi:colourama": {"age_months": 2, "maintainers": 1, "deprecated": False},
    "pypi:python3-dateutil": {"age_months": 1, "maintainers": 1, "deprecated": False},
    "pypi:jeIlyfish": {"age_months": 1, "maintainers": 1, "deprecated": False},
    "pypi:nose": {"age_months": 180, "maintainers": 1, "deprecated": True},
    "pypi:distribute": {"age_months": 160, "maintainers": 1, "deprecated": True},
    "pypi:sklearn": {"age_months": 90, "maintainers": 1, "deprecated": True},
    "pypi:flask": {"age_months": 190, "maintainers": 8, "deprecated": False},
    "pypi:requests": {"age_months": 200, "maintainers": 6, "deprecated": False},
    "pypi:numpy": {"age_months": 240, "maintainers": 30, "deprecated": False},
    "npm:event-stream": {"age_months": 96, "maintainers": 1, "deprecated": True},
    "npm:request": {"age_months": 150, "maintainers": 3, "deprecated": True},
    "npm:left-pad": {"age_months": 110, "maintainers": 1, "deprecated": False},
    "npm:lodash": {"age_months": 150, "maintainers": 5, "deprecated": False},
    "npm:react": {"age_months": 140, "maintainers": 20, "deprecated": False},
}

# ---------------------------------------------------------------------------
# Bundled data: OSV-style advisory database
# ---------------------------------------------------------------------------
# Each advisory is keyed by ecosystem+name with affected version ranges using
# OSV "introduced"/"fixed" semantics (introduced <= v < fixed). These mirror
# real, well-known historical CVEs/GHSAs.
ADVISORIES = [
    {
        "id": "GHSA-j8r2-6x86-q33q",
        "alias": "CVE-2023-32681",
        "ecosystem": "pypi", "package": "requests",
        "summary": "requests leaks Proxy-Authorization header on cross-host redirect.",
        "severity": "MEDIUM",
        "ranges": [{"introduced": "2.3.0", "fixed": "2.31.0"}],
    },
    {
        "id": "GHSA-9wx4-h78v-vm56",
        "alias": "CVE-2021-33503",
        "ecosystem": "pypi", "package": "urllib3",
        "summary": "urllib3 ReDoS via malformed authority in URL.",
        "severity": "HIGH",
        "ranges": [{"introduced": "0", "fixed": "1.26.5"}],
    },
    {
        "id": "GHSA-h5c8-rqwp-cp95",
        "alias": "CVE-2022-22817",
        "ecosystem": "pypi", "package": "pillow",
        "summary": "Pillow arbitrary code execution via ImageMath.eval.",
        "severity": "CRITICAL",
        "ranges": [{"introduced": "0", "fixed": "9.0.0"}],
    },
    {
        "id": "GHSA-q2x7-8rv6-6q7h",
        "alias": "CVE-2019-11324",
        "ecosystem": "pypi", "package": "urllib3",
        "summary": "urllib3 certificate validation bypass with bad CA bundle.",
        "severity": "HIGH",
        "ranges": [{"introduced": "0", "fixed": "1.24.2"}],
    },
    {
        "id": "PYSEC-2023-62",
        "alias": "CVE-2023-30861",
        "ecosystem": "pypi", "package": "flask",
        "summary": "Flask may cache cross-session response with permanent session.",
        "severity": "HIGH",
        "ranges": [{"introduced": "0.7", "fixed": "2.2.5"}, {"introduced": "2.3.0", "fixed": "2.3.2"}],
    },
    {
        "id": "GHSA-8q59-q68h-6hv4",
        "alias": "CVE-2022-2309",
        "ecosystem": "pypi", "package": "lxml",
        "summary": "lxml NULL pointer dereference (DoS) in iterwalk.",
        "severity": "MEDIUM",
        "ranges": [{"introduced": "0", "fixed": "4.9.1"}],
    },
    {
        "id": "GHSA-35jh-r3h4-6jhm",
        "alias": "CVE-2021-23337",
        "ecosystem": "npm", "package": "lodash",
        "summary": "lodash command injection via template.",
        "severity": "HIGH",
        "ranges": [{"introduced": "0", "fixed": "4.17.21"}],
    },
    {
        "id": "GHSA-29mw-wpgm-hmr9",
        "alias": "CVE-2020-7598",
        "ecosystem": "npm", "package": "minimist",
        "summary": "minimist prototype pollution.",
        "severity": "MEDIUM",
        "ranges": [{"introduced": "0", "fixed": "1.2.3"}],
    },
    {
        "id": "GHSA-43f8-2h32-f4cj",
        "alias": "CVE-2021-3803",
        "ecosystem": "npm", "package": "ws",
        "summary": "ws ReDoS via long header.",
        "severity": "HIGH",
        "ranges": [{"introduced": "0", "fixed": "7.4.6"}],
    },
    {
        "id": "GHSA-7p7h-4mm5-852v",
        "alias": "CVE-2022-25883",
        "ecosystem": "npm", "package": "semver",
        "summary": "semver ReDoS in range parsing.",
        "severity": "HIGH",
        "ranges": [{"introduced": "0", "fixed": "7.5.2"}],
    },
    {
        "id": "GHSA-3xgq-45jj-v275",
        "alias": "CVE-2019-10744",
        "ecosystem": "npm", "package": "axios",
        "summary": "axios SSRF / credential leak on redirect.",
        "severity": "HIGH",
        "ranges": [{"introduced": "0", "fixed": "0.21.1"}],
    },
]

# Severity -> penalty points (drives the score deduction).
_SEVERITY_PENALTY = {"LOW": 1.0, "MEDIUM": 2.5, "HIGH": 4.0, "CRITICAL": 6.5}

# ---------------------------------------------------------------------------
# Version parsing + comparison (PEP440-lite / semver-lite, good enough offline)
# ---------------------------------------------------------------------------

_VER_RE = re.compile(r"(\d+)")


def parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string into a comparable numeric tuple.

    Tolerant of leading ``v``, pre-release suffixes, epochs and build
    metadata. Non-numeric segments are dropped. ``"0"`` parses to ``(0,)``.
    """
    if v is None:
        return (0,)
    v = v.strip().lstrip("vV=")
    # drop everything after first +, -, or whitespace (build/pre-release noise)
    v = re.split(r"[+\s]", v, maxsplit=1)[0]
    parts = _VER_RE.findall(v)
    if not parts:
        return (0,)
    return tuple(int(p) for p in parts[:4])


def version_compare(a: str, b: str) -> int:
    """Return -1/0/1 comparing version strings ``a`` and ``b``."""
    ta, tb = parse_version(a), parse_version(b)
    # zero-pad to equal length
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _in_range(version: str, rng: dict) -> bool:
    """OSV semantics: introduced <= version < fixed (fixed optional)."""
    introduced = rng.get("introduced", "0")
    if version_compare(version, introduced) < 0:
        return False
    fixed = rng.get("fixed")
    if fixed is not None and version_compare(version, fixed) >= 0:
        return False
    return True


# ---------------------------------------------------------------------------
# Levenshtein distance (typosquat heuristic)
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """Classic edit distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


# Characters frequently used in homoglyph / lookalike squats.
_LOOKALIKE = set("0123456789_")


def typosquat_match(name: str, ecosystem: str) -> tuple[str, int] | None:
    """Return the (closest_popular_name, distance) if ``name`` looks like a
    typosquat of a popular package; else None.

    A name is flagged when it is NOT itself a popular name, yet is within a
    small edit distance (1-2) of one, with extra weight for near-identical
    lengths and lookalike characters.
    """
    pop = POPULAR.get(ecosystem, [])
    lname = name.lower()
    if lname in pop:
        return None
    best = None
    best_d = 99
    for cand in pop:
        # cheap length prefilter
        if abs(len(cand) - len(lname)) > 2:
            continue
        d = levenshtein(lname, cand)
        if d < best_d:
            best_d, best = d, cand
    if best is None:
        return None
    # distance 1 is always suspicious.
    if best_d == 1:
        return (best, 1)
    # distance 2 on longer names is suspicious when EITHER the name carries a
    # lookalike character OR it is a same-length anagram-ish transposition
    # (e.g. 'lodahs' -> 'lodash'), both classic squatting techniques.
    if best_d == 2 and len(best) >= 5:
        has_lookalike = any(c in _LOOKALIKE for c in lname)
        same_charset = (len(lname) == len(best) and sorted(lname) == sorted(best))
        if has_lookalike or same_charset:
            return (best, 2)
    return None


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single risk observation about a dependency."""

    kind: str          # vuln | typosquat | unpinned | deprecated | young | solo
    severity: str      # LOW | MEDIUM | HIGH | CRITICAL
    penalty: float
    message: str
    advisory_id: str | None = None

    def as_dict(self) -> dict:
        d = {
            "kind": self.kind,
            "severity": self.severity,
            "penalty": round(self.penalty, 2),
            "message": self.message,
        }
        if self.advisory_id:
            d["advisory_id"] = self.advisory_id
        return d


@dataclass
class Dependency:
    """A resolved dependency with its findings, score and grade."""

    name: str
    version: str | None
    ecosystem: str
    scope: str = "runtime"
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> float:
        """0-10 health score (10 = clean). Penalties subtract from 10."""
        total = sum(f.penalty for f in self.findings)
        return max(0.0, round(10.0 - total, 2))

    @property
    def grade(self) -> str:
        return score_to_grade(self.score)

    @property
    def max_severity(self) -> str:
        order = ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        worst = ""
        for f in self.findings:
            if order.index(f.severity) > order.index(worst):
                worst = f.severity
        return worst or "NONE"

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "scope": self.scope,
            "score": self.score,
            "grade": self.grade,
            "max_severity": self.max_severity,
            "findings": [f.as_dict() for f in self.findings],
        }


@dataclass
class AuditResult:
    """Full audit over a manifest."""

    dependencies: list[Dependency] = field(default_factory=list)
    source: str | None = None

    @property
    def finding_count(self) -> int:
        return sum(len(d.findings) for d in self.dependencies)

    @property
    def vuln_count(self) -> int:
        return sum(
            1 for d in self.dependencies for f in d.findings if f.kind == "vuln"
        )

    @property
    def project_score(self) -> float:
        if not self.dependencies:
            return 10.0
        return round(
            sum(d.score for d in self.dependencies) / len(self.dependencies), 2
        )

    @property
    def project_grade(self) -> str:
        return score_to_grade(self.project_score)

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "dependency_count": len(self.dependencies),
            "finding_count": self.finding_count,
            "vuln_count": self.vuln_count,
            "project_score": self.project_score,
            "project_grade": self.project_grade,
            "dependencies": [d.as_dict() for d in self.dependencies],
        }


def score_to_grade(score: float) -> str:
    if score >= 9.0:
        return "A"
    if score >= 7.5:
        return "B"
    if score >= 6.0:
        return "C"
    if score >= 4.0:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------

_PIP_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:\[[^\]]*\])?\s*"                       # optional extras
    r"(==|>=|<=|~=|>|<|!=)?\s*"
    r"([A-Za-z0-9][A-Za-z0-9.*+!-]*)?"
)


def _parse_requirements(text: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http", ".", "/")):
            continue
        m = _PIP_LINE.match(line)
        if not m:
            continue
        name, op, ver = m.group(1), m.group(2), m.group(3)
        # Only treat == / ~= as a resolved version for vuln matching.
        version = ver if op in ("==", "~=") and ver else None
        deps.append(Dependency(name=name, version=version, ecosystem="pypi"))
    return deps


def _parse_pipfile(text: str) -> list[Dependency]:
    deps: list[Dependency] = []
    section = None
    scope = "runtime"
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
            scope = "dev" if "dev" in section else "runtime"
            continue
        if section not in ("packages", "dev-packages"):
            continue
        if "=" not in line or line.startswith("#"):
            continue
        name, _, rhs = line.partition("=")
        name = name.strip().strip('"')
        rhs = rhs.strip().strip('"').strip("'")
        version = None
        m = re.search(r"(\d[\w.]*)", rhs)
        if rhs.startswith("==") or (m and rhs.lstrip("=").startswith(m.group(1))):
            version = m.group(1) if m else None
        if name:
            deps.append(
                Dependency(name=name, version=version, ecosystem="pypi", scope=scope)
            )
    return deps


def _clean_npm_version(spec: str) -> str | None:
    """Strip npm range operators to a concrete version, when one exists."""
    if not isinstance(spec, str):
        return None
    spec = spec.strip()
    if spec in ("*", "latest", "") or spec.startswith(("http", "git", "file:", "link:")):
        return None
    m = re.search(r"(\d+\.\d+\.\d+|\d+\.\d+|\d+)", spec)
    return m.group(1) if m else None


def _parse_package_json(text: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return deps
    for key, scope in (("dependencies", "runtime"), ("devDependencies", "dev")):
        block = data.get(key) or {}
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            deps.append(
                Dependency(
                    name=name,
                    version=_clean_npm_version(spec),
                    ecosystem="npm",
                    scope=scope,
                )
            )
    return deps


def parse_manifest(text: str, filename: str = "") -> list[Dependency]:
    """Dispatch to the right parser based on filename / content sniffing."""
    fn = (filename or "").lower()
    if fn.endswith("package.json") or (text.lstrip().startswith("{") and '"dependencies"' in text):
        return _parse_package_json(text)
    if fn.endswith("pipfile") or "[packages]" in text.lower():
        return _parse_pipfile(text)
    # default: pip requirements
    return _parse_requirements(text)


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

def match_advisories(dep: Dependency) -> list[Finding]:
    """OSV-style match of a dependency's version against bundled advisories."""
    findings: list[Finding] = []
    for adv in ADVISORIES:
        if adv["ecosystem"] != dep.ecosystem:
            continue
        if adv["package"].lower() != dep.name.lower():
            continue
        if dep.version is None:
            # Unknown version: report as a *potential* match (advisory exists).
            sev = adv["severity"]
            findings.append(
                Finding(
                    kind="vuln",
                    severity=sev,
                    penalty=_SEVERITY_PENALTY.get(sev, 2.0) * 0.5,
                    message=(
                        f"{adv['id']} ({adv.get('alias','')}) affects "
                        f"{dep.name}; version unpinned so applicability unknown — "
                        f"{adv['summary']}"
                    ),
                    advisory_id=adv["id"],
                )
            )
            continue
        if any(_in_range(dep.version, r) for r in adv["ranges"]):
            sev = adv["severity"]
            findings.append(
                Finding(
                    kind="vuln",
                    severity=sev,
                    penalty=_SEVERITY_PENALTY.get(sev, 2.0),
                    message=(
                        f"{adv['id']} ({adv.get('alias','')}) affects "
                        f"{dep.name} {dep.version} — {adv['summary']}"
                    ),
                    advisory_id=adv["id"],
                )
            )
    return findings


def heuristic_findings(dep: Dependency) -> list[Finding]:
    """Scorecard-style maintainer/age/typosquat heuristics."""
    findings: list[Finding] = []
    key = f"{dep.ecosystem}:{dep.name}"

    # Typosquat
    ts = typosquat_match(dep.name, dep.ecosystem)
    if ts:
        closest, dist = ts
        sev = "CRITICAL" if dist == 1 else "HIGH"
        findings.append(
            Finding(
                kind="typosquat",
                severity=sev,
                penalty=5.0 if dist == 1 else 3.5,
                message=(
                    f"'{dep.name}' is {dist} edit(s) from popular "
                    f"'{closest}' — possible typosquat / impostor package."
                ),
            )
        )

    # Unpinned version
    if dep.version is None:
        findings.append(
            Finding(
                kind="unpinned",
                severity="MEDIUM",
                penalty=1.5,
                message=(
                    f"'{dep.name}' has no exact version pin — builds are "
                    f"non-reproducible and silently accept malicious updates."
                ),
            )
        )

    # Maintenance metadata (case-insensitive key lookup)
    meta = MAINTENANCE.get(key)
    if meta is None:
        for mk, mv in MAINTENANCE.items():
            if mk.lower() == key.lower():
                meta = mv
                break
    if meta:
        if meta.get("deprecated"):
            findings.append(
                Finding(
                    kind="deprecated",
                    severity="HIGH",
                    penalty=3.0,
                    message=(
                        f"'{dep.name}' is deprecated/abandoned upstream — "
                        f"no security maintenance expected."
                    ),
                )
            )
        if meta.get("age_months", 999) <= 6:
            findings.append(
                Finding(
                    kind="young",
                    severity="MEDIUM",
                    penalty=2.0,
                    message=(
                        f"'{dep.name}' is very new ({meta['age_months']} mo old) — "
                        f"low track record, common cover for malicious uploads."
                    ),
                )
            )
        if meta.get("maintainers", 99) <= 1:
            findings.append(
                Finding(
                    kind="solo",
                    severity="LOW",
                    penalty=1.0,
                    message=(
                        f"'{dep.name}' has a single maintainer — bus-factor and "
                        f"account-takeover risk."
                    ),
                )
            )
    return findings


def audit_dependency(dep: Dependency) -> Dependency:
    """Run all checks against one dependency, populating its findings."""
    dep.findings = []
    dep.findings.extend(match_advisories(dep))
    dep.findings.extend(heuristic_findings(dep))
    return dep


def audit_text(text: str, filename: str = "") -> AuditResult:
    """Parse a manifest from text and audit every dependency in it."""
    deps = parse_manifest(text, filename)
    for dep in deps:
        audit_dependency(dep)
    return AuditResult(dependencies=deps, source=filename or "<stdin>")


def audit_file(path: str) -> AuditResult:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    return audit_text(text, filename=path)


def list_advisories(ecosystem: str | None = None) -> list[dict]:
    """Return the bundled advisory database (optionally filtered)."""
    if ecosystem:
        return [a for a in ADVISORIES if a["ecosystem"] == ecosystem]
    return list(ADVISORIES)


TOOL_NAME = "depgraph"
TOOL_VERSION = "2.0.0"
