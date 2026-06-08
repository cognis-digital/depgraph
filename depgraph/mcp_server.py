"""DEPGRAPH MCP server — exposes scan as an MCP tool for Cognis.Studio."""
from cognis_core.mcp import build_mcp_server
from depgraph.core import scan, TOOL_NAME

run_mcp_server = build_mcp_server(
    tool_name=TOOL_NAME,
    description="Dependency risk visualizer — Scorecard + OSV + typosquat + maintainer signals",
    scan_fn=scan,
)

if __name__ == "__main__":
    run_mcp_server()
