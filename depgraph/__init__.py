"""
DEPGRAPH — Dependency risk visualizer — Scorecard + OSV + typosquat + maintainer signals
Part of the Cognis Neural Suite by Cognis Digital.
https://cognis.digital · MIT License
"""
from depgraph.core import scan, TOOL_NAME, TOOL_VERSION

__version__ = TOOL_VERSION
__author__ = "Cognis Digital"
__license__ = "MIT"
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION", "__version__"]
