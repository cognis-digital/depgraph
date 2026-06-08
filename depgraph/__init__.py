"""DEPGRAPH — Dependency risk visualizer.

Scorecard-style supply-chain risk analysis for a project's dependency
manifest (requirements.txt / package.json). Combines four real, offline
signals into a per-dependency risk score:

  * Scorecard-style heuristics (pinning, version freshness)
  * OSV-style known-vulnerability matching against a local advisory DB
  * Typosquat detection against a curated set of popular package names
  * Maintainer signals (single-maintainer, recent-publish heuristics)

Standard library only. Zero install. No network.
"""
from .core import (
    Dependency,
    DependencyReport,
    RiskFinding,
    analyze_manifest,
    analyze_dependencies,
    parse_manifest,
    score_dependency,
)

TOOL_NAME = "depgraph"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Dependency",
    "DependencyReport",
    "RiskFinding",
    "analyze_manifest",
    "analyze_dependencies",
    "parse_manifest",
    "score_dependency",
]
