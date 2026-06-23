"""OSV-offline enrichment — wire an audit's dependencies / CVE refs against the
bundled 262k-record OSV vulnerability database (``cognis_vulndb.jsonl.gz``).

The built-in ``ADVISORIES`` table in :mod:`depgraph.core` is a small, hand-curated
set of high-signal advisories with precise OSV version ranges. This module layers
the *full* bundled OSV corpus on top: for every dependency (or an explicit list of
CVE/GHSA ids) it pulls every real advisory that names that package or id, fully
offline. No network, ever — the DB ships inside the package.

Enrichment is intentionally *additive* and conservative:

* It never overrides or mutates the curated :func:`core.match_advisories`
  version-range verdicts.
* DB records in the bundle do not carry machine-comparable version ranges, so an
  enrichment hit is reported as an *advisory reference* ("this package has N known
  advisories in OSV"), not a hard "you are vulnerable" claim. That keeps the
  passive/offline posture honest: no fabricated applicability.

Public surface::

    from depgraph.enrich import enrich_result, enrich_dependency, lookup_cve
    enrich_result(audit_text("requests==2.28.0", "r.txt"))   # -> dict report
    lookup_cve("CVE-2021-44228")                              # -> [records...]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from .core import AuditResult, Dependency, Finding
from .vulndb_local import VulnDB

# Map depgraph ecosystem ids to the OSV ecosystem labels used in the bundle.
# The bundle stores OSV ecosystems verbatim (PyPI, npm, Go, Maven, ...).
_ECOSYSTEM_ALIASES = {
    "pypi": {"pypi"},
    "npm": {"npm"},
    "go": {"go"},
    "maven": {"maven"},
    "rubygems": {"rubygems"},
    "crates.io": {"crates.io", "crates"},
    "nuget": {"nuget"},
}

# One shared DB instance — lazy-loaded + indexed on first lookup, then reused.
_DB: Optional[VulnDB] = None


def _db() -> VulnDB:
    global _DB
    if _DB is None:
        _DB = VulnDB()
    return _DB


def set_db(db: VulnDB) -> None:
    """Override the shared DB (used by tests with a fixture corpus)."""
    global _DB
    _DB = db


def _ecosystem_ok(record_eco: str, dep_eco: str) -> bool:
    if not record_eco:
        return True  # bundle records may omit ecosystem; don't drop the hit
    aliases = _ECOSYSTEM_ALIASES.get(dep_eco.lower(), {dep_eco.lower()})
    return record_eco.lower() in aliases


@dataclass
class EnrichmentHit:
    """A single OSV advisory the bundled DB knows about for a package."""

    advisory_id: str
    aliases: list[str]
    ecosystem: str
    severity: str
    summary: str

    def as_dict(self) -> dict:
        return {
            "advisory_id": self.advisory_id,
            "aliases": self.aliases,
            "ecosystem": self.ecosystem,
            "severity": self.severity,
            "summary": self.summary,
        }

    @classmethod
    def from_record(cls, r: dict) -> "EnrichmentHit":
        return cls(
            advisory_id=r.get("id", ""),
            aliases=list(r.get("aliases") or []),
            ecosystem=r.get("ecosystem", ""),
            severity=(r.get("severity") or "").upper() or "UNKNOWN",
            summary=r.get("summary", "") or "",
        )


def enrich_dependency(dep: Dependency, db: Optional[VulnDB] = None,
                      limit: int = 50) -> list[EnrichmentHit]:
    """Return every bundled-OSV advisory that names this dependency's package,
    filtered to a compatible ecosystem. Fully offline."""
    db = db or _db()
    out: list[EnrichmentHit] = []
    seen: set[str] = set()
    for r in db.by_package(dep.name, ecosystem=None):
        if not _ecosystem_ok(r.get("ecosystem", ""), dep.ecosystem):
            continue
        rid = r.get("id", "")
        if rid in seen:
            continue
        seen.add(rid)
        out.append(EnrichmentHit.from_record(r))
        if len(out) >= limit:
            break
    return out


def lookup_cve(cve: str, db: Optional[VulnDB] = None) -> list[dict]:
    """Resolve a CVE/GHSA/OSV id to its full bundled records (offline)."""
    return (db or _db()).by_cve(cve)


def lookup_package(name: str, ecosystem: Optional[str] = None,
                   db: Optional[VulnDB] = None) -> list[dict]:
    """Return every bundled advisory naming ``name`` (optionally by ecosystem)."""
    return (db or _db()).by_package(name, ecosystem=ecosystem)


def enrich_result(result: AuditResult, db: Optional[VulnDB] = None,
                  limit_per_dep: int = 50) -> dict:
    """Layer bundled-OSV advisory references onto an :class:`AuditResult`.

    Returns a JSON-able dict keyed by package, each mapping to the list of
    OSV advisory references the bundle holds. Counts are real lookups against
    the 262k-record corpus. Does not mutate the input result.
    """
    db = db or _db()
    per_pkg: dict[str, list[dict]] = {}
    total_refs = 0
    enriched_deps = 0
    for dep in result.dependencies:
        hits = enrich_dependency(dep, db=db, limit=limit_per_dep)
        if hits:
            key = f"{dep.ecosystem}:{dep.name}"
            per_pkg[key] = [h.as_dict() for h in hits]
            total_refs += len(hits)
            enriched_deps += 1
    return {
        "source": result.source,
        "db_record_count": db.count(),
        "dependencies_with_osv_refs": enriched_deps,
        "total_osv_references": total_refs,
        "packages": per_pkg,
    }


def enrichment_findings(dep: Dependency, db: Optional[VulnDB] = None,
                        limit: int = 50) -> list[Finding]:
    """Convert OSV-DB references for a dependency into advisory-reference Findings.

    These are LOW-penalty informational references (the bundle has no
    machine-comparable ranges) — they surface *that* real advisories exist for
    the package without fabricating an applicability verdict.
    """
    findings: list[Finding] = []
    for h in enrich_dependency(dep, db=db, limit=limit):
        alias = h.aliases[0] if h.aliases else h.advisory_id
        findings.append(
            Finding(
                kind="osv-ref",
                severity="LOW",
                penalty=0.0,  # informational only; does not change the grade
                message=(
                    f"{h.advisory_id} ({alias}) in OSV references {dep.name}"
                    + (f" — {h.summary}" if h.summary else "")
                ),
                advisory_id=h.advisory_id,
            )
        )
    return findings
