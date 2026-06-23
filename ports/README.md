# Ports of depgraph

The same **dependency-risk core** — pip `requirements.txt` parsing, Levenshtein
typosquat detection, and OSV-style version-range advisory matching — ported across
languages so you can drop `depgraph` into any stack or ship a single static binary.

Every port shares the **same JSON output shape**
(`{tool, version, dependency_count, vuln_count, project_score, project_grade, dependencies[]}`)
and the **same curated advisory set + popular-name list** as the Python reference,
so results agree across languages on the same manifest.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | [`../depgraph/`](../depgraph/) | `depgraph audit requirements.txt` | `python -m pytest` |
| JavaScript / Node | [`javascript/`](javascript/) | `node ports/javascript/index.js requirements.txt` | `node ports/javascript/test.js` |
| Go | [`go/`](go/) | `cd ports/go && go run . ../../requirements.txt` | `cd ports/go && go test ./...` |
| Rust | [`rust/`](rust/) | `cd ports/rust && cargo run -- ../../requirements.txt` | `cd ports/rust && cargo test` |
| POSIX Shell | [`shell/`](shell/) | `sh ports/shell/depgraph.sh requirements.txt` | `sh ports/shell/test.sh` |

All ports are **offline and dependency-free** (the shell port uses only `awk`).
Each is built and tested on every push by the
[`ports.yml`](../.github/workflows/ports.yml) GitHub Actions workflow, so the Go
and Rust binaries are verified even if those toolchains aren't installed locally.

### Example (any port, same shape)

```bash
$ printf 'pillow==8.4.0\nreqests==2.31.0\nnumpy\n' | node ports/javascript/index.js
{
  "tool": "depgraph",
  "version": "2.1.0",
  "vuln_count": 1,
  "project_grade": "F",
  "dependencies": [ ... ]
}
```

> The full 262k-record OSV enrichment, MCP server, and `cognis-connect` emitters
> live in the Python reference only — the ports cover the portable scoring core.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
[../CONTRIBUTING.md](../CONTRIBUTING.md).
