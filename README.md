<a name="top"></a>

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=DEPGRAPH&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="DEPGRAPH"/>

# DEPGRAPH

### Offline dependency-risk auditor — Scorecard heuristics + OSV matching + typosquat detection

[![PyPI](https://img.shields.io/pypi/v/cognis-depgraph.svg?color=6b46c1)](https://pypi.org/project/cognis-depgraph/) [![CI](https://github.com/cognis-digital/depgraph/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/depgraph/actions) [![ports](https://github.com/cognis-digital/depgraph/actions/workflows/ports.yml/badge.svg)](https://github.com/cognis-digital/depgraph/actions/workflows/ports.yml) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Developer / Supply Chain — grade your dependencies, match them against 262k real OSV advisories, catch impostor packages — 100% offline.*

</div>

```bash
pip install "git+https://github.com/cognis-digital/depgraph.git"
depgraph audit requirements.txt          # grade every dependency A–F
depgraph enrich requirements.txt         # + cross-reference 262k real OSV vulns, offline
```

`depgraph` is a **single-purpose, zero-network, dependency-free** supply-chain risk
auditor. Point it at a `requirements.txt`, `package.json`, or `Pipfile` and it grades
every package A–F using maintainer/age/typosquat heuristics (in the spirit of
[`ossf/scorecard`](https://github.com/ossf/scorecard)) and matches pinned versions
against an [OSV](https://osv.dev)-style advisory database with real semantic
version-range checks. It **never sends your manifest anywhere** — the entire
262k-record vulnerability corpus ships inside the package.

## Contents

[Why](#why) · [What it really does](#what) · [Quick start](#quick-start) · [Worked example](#example) · [OSV enrichment](#enrich) · [Querying the DB](#vulndb) · [Edge / air-gap](#edge) · [Output formats](#formats) · [Polyglot ports](#ports) · [Install](#install) · [Scope & safety](#scope) · [AI stack](#ai-stack) · [Related](#related)

<a name="why"></a>
## Why depgraph?

Most dependency scanners phone home: they upload your dependency list to a SaaS API
to look up vulnerabilities. `depgraph` does the opposite — **the database comes to
you**. That makes it usable in CI without secrets, on disconnected/air-gapped/edge
gear, and on code you can't legally exfiltrate.

- **Offline by construction.** No API key, no network, no telemetry. The bundled
  `cognis_vulndb.jsonl.gz` carries ~262,000 real OSV advisories across PyPI, npm,
  Go, Maven, RubyGems, crates.io, and NuGet.
- **Three signals, one grade.** OSV version-range vuln matching + Scorecard-style
  maintainer/age health + Levenshtein typosquat detection, rolled into a 0–10 score
  and an A–F letter per package and per project.
- **CI-native.** Exit codes, `--min-severity`, and `--fail-grade` gates; JSON for any
  pipeline.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="what"></a>
## What it really does

| Capability | Detail |
|---|---|
| **Manifest parsing** | pip `requirements.txt` (`name==`, `~=`, unpinned), `package.json` (`dependencies` + `devDependencies`, range operators stripped to concrete versions), `Pipfile` (`[packages]` / `[dev-packages]`). |
| **OSV-style matching** | Curated high-signal advisories with precise `introduced`/`fixed` ranges (`introduced ≤ v < fixed`, multi-range aware) + PEP440/semver-lite version comparison. |
| **OSV enrichment** | `depgraph enrich` cross-references every package against the **full bundled 262k-record OSV corpus**, attaching every real advisory id/CVE/GHSA that names it. |
| **Typosquat detection** | Levenshtein edit-distance to a curated popular-name list, with homoglyph and same-charset transposition heuristics (`colourama → colorama`, `lodahs → lodash`). |
| **Health heuristics** | Deprecated/abandoned, very-new (<6mo), and single-maintainer signals from a bundled maintenance table. |
| **Edge data feeds** | `depgraph feeds` lists a 35-source keyless intel catalog (CISA KEV, EPSS, OSV, NVD, GHSA, MITRE ATT&CK, …) with disk-cache + air-gap snapshot import/export. |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
# audit a manifest (table by default)
depgraph audit requirements.txt

# read from stdin
cat requirements.txt | depgraph audit

# enrich with the full 262k OSV corpus
depgraph enrich requirements.txt

# look a CVE up directly in the bundled DB (offline)
depgraph vulndb --cve CVE-2021-44228

# CI gate: fail when the project grade drops to C or below
depgraph audit requirements.txt --fail-grade C || exit 1
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Worked example

Given `requirements.txt`:

```text
requests==2.28.0
urllib3==1.25.0
pillow==8.4.0
colourama==0.4.6
numpy
cryptography==42.0.0
```

```text
$ depgraph audit requirements.txt
DEPGRAPH audit of requirements.txt
============================================================
GRADE  NAME          VERSION  SCORE  WORST     FINDINGS
-----------------------------------------------------------
F      colourama     0.4.6      2.0  CRITICAL  3
F      pillow        8.4.0      3.5  CRITICAL  1
C      urllib3       1.25.0     6.0  HIGH      1
B      requests      2.28.0     7.5  MEDIUM    1
B      numpy         -          8.5  MEDIUM    1
A      cryptography  42.0.0    10.0  NONE      0

FINDINGS
------------------------------------------------------------
  colourama 0.4.6 [F]
    - [CRITICAL] 'colourama' is 1 edit(s) from popular 'colorama' — possible typosquat / impostor package.
    - [MEDIUM] 'colourama' is very new (2 mo old) — low track record, common cover for malicious uploads.
    - [LOW] 'colourama' has a single maintainer — bus-factor and account-takeover risk.
  pillow 8.4.0 [F]
    - [CRITICAL] GHSA-h5c8-rqwp-cp95 (CVE-2022-22817) affects pillow 8.4.0 — Pillow arbitrary code execution via ImageMath.eval.
  urllib3 1.25.0 [C]
    - [HIGH] GHSA-9wx4-h78v-vm56 (CVE-2021-33503) affects urllib3 1.25.0 — urllib3 ReDoS via malformed authority in URL.
  requests 2.28.0 [B]
    - [MEDIUM] GHSA-j8r2-6x86-q33q (CVE-2023-32681) affects requests 2.28.0 — requests leaks Proxy-Authorization header on cross-host redirect.

project: C  score=6.25  deps=6  vulns=3  findings=7
```

`--format json` emits the same data as a machine-readable document with per-finding
`kind`/`severity`/`penalty`/`advisory_id` and a project rollup — pipe it into CI,
SARIF tooling, or an agent.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="enrich"></a>
## OSV enrichment — the full 262k corpus, offline

`depgraph audit` uses a small, hand-curated advisory set with exact version ranges.
`depgraph enrich` layers the **entire bundled OSV database** on top, attaching every
real advisory that names each package:

```text
$ depgraph enrich requirements.txt
DEPGRAPH OSV enrichment of requirements.txt
============================================================
bundled OSV records: 262351  |  packages with OSV refs: 4  |  total references: 31

  pypi:requests  (13 OSV advisories)
    - [MEDIUM] GHSA-j8r2-6x86-q33q (CVE-2023-32681) Unintended leak of Proxy-Authorization header in requests
    - [HIGH]   GHSA-9hjg-9r4m-mvj7 (CVE-2024-47081) Requests .netrc credentials leak via malicious URLs
    ...
```

Enrichment is **conservative and additive**: bundle records don't carry
machine-comparable ranges, so a hit is reported as an *advisory reference* ("this
package has N known OSV advisories"), never a fabricated "you are vulnerable"
verdict. It never overrides the curated version-range matches and never changes a
package's grade.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="vulndb"></a>
## Querying the bundled DB directly

```bash
depgraph vulndb --count                         # 262351 bundled OSV records
depgraph vulndb --cve CVE-2021-44228            # resolve Log4Shell (and its GHSA)
depgraph vulndb --package lodash                # every advisory naming lodash
depgraph vulndb --package django --ecosystem PyPI
depgraph vulndb --search "deserialization" --limit 10
```

From Python:

```python
from depgraph import VulnDB, lookup_cve, enrich_result, audit_text

VulnDB().count()                      # 262351
lookup_cve("CVE-2021-44228")          # -> [records...] (Log4Shell, real)
enrich_result(audit_text(open("requirements.txt").read(), "requirements.txt"))
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="edge"></a>
## Edge / air-gap refresh

The bundled DB is the offline baseline. To extend or freshen it on the edge,
`depgraph.datafeeds` fetches a keyless intel catalog over HTTPS, caches it to disk,
and can sneakernet a snapshot into a disconnected enclave:

```bash
depgraph feeds                                          # list the catalog (offline)
python -m depgraph.datafeeds update cisa-kev epss       # fetch + cache (online, opt-in)
python -m depgraph.datafeeds get osv --offline          # serve from cache, never network
python -m depgraph.datafeeds snapshot-export feeds.tar.gz   # for air-gap transfer
python -m depgraph.datafeeds snapshot-import feeds.tar.gz   # on the air-gapped side
```

Sources include **CISA KEV**, **FIRST EPSS**, **OSV.dev**, **NIST NVD CVE 2.0**, and
**GitHub GHSA** for vulnerabilities, plus MITRE ATT&CK and NIST OSCAL 800-53 for
control mapping. Online refresh is strictly opt-in; everything else is offline.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="formats"></a>
## Output formats & CI gates

| Flag | Effect |
|---|---|
| `--format table` | Human-readable graded table + findings detail (default). |
| `--format json` | Machine-readable document (audit + optional `osv_enrichment` block). |
| `--min-severity LOW\|MEDIUM\|HIGH\|CRITICAL` | Non-zero exit only when a finding ≥ this severity exists. |
| `--fail-grade A\|B\|C\|D\|F` | Non-zero exit when the project grade is at/below this letter. |

Forward findings to STIX/MISP/Sigma/Splunk/Elastic/Slack via the optional
`depgraph-emit` bridge (`pip install ".[connect]"`). See [INTEGRATIONS.md](INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ports"></a>
## Polyglot ports

The portable scoring core (pip parsing + typosquat + version-range matching, same
JSON shape) is ported to **JavaScript, Go, Rust, and POSIX Shell** under
[`ports/`](ports/). Each has a smoke test and is built/tested on every push by the
[`ports.yml`](.github/workflows/ports.yml) workflow:

```bash
node ports/javascript/index.js requirements.txt
cd ports/go   && go run . ../../requirements.txt
cd ports/rust && cargo run -- ../../requirements.txt
sh ports/shell/depgraph.sh requirements.txt
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/depgraph.git"     # pip
pipx install "git+https://github.com/cognis-digital/depgraph.git"    # isolated CLI
uv tool install "git+https://github.com/cognis-digital/depgraph.git" # uv
pip install cognis-depgraph                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/depgraph:latest --help        # Docker
git clone https://github.com/cognis-digital/depgraph && cd depgraph && pip install -e .
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/depgraph` | [DEPLOY.md](docs/DEPLOY.md) |

Runs on **Linux / macOS / Windows**, Python 3.10+, **standard library only** — no
runtime dependencies.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="scope"></a>
## Scope, authorization & safety

`depgraph` is a **passive, offline, defensive** tool. It reads dependency manifests
and consults a bundled database — it does **not** execute dependency code, perform any
active network scanning, or contact registries during an audit. Online feed refresh
(`datafeeds update`) is the only network path and is strictly opt-in.

- No fabricated CVEs or advisories — every record is real OSV data.
- No exploit payloads, no remote probing, no telemetry.
- Use it on code and projects you are authorized to assess.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

- **MCP server** — `depgraph mcp` (Claude Desktop, Cursor, Cognis.Studio)
- **JSON** — pipe `depgraph audit . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool
- **CI / scripts** — exit codes for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`secretsweep`](https://github.com/cognis-digital/secretsweep) — repo secret scanner + auto-rotator
- [`pipewatch-pro`](https://github.com/cognis-digital/pipewatch-pro) — CI/CD supply-chain auditor
- [`ossaudit`](https://github.com/cognis-digital/ossaudit) — OSS license compliance auditor

**Explore the suite →** [🗂️ all tools](https://github.com/cognis-digital/cognis-neural-suite) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

## Interoperability

`depgraph` composes with the Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the suite map
and composition patterns.

## Contributing

PRs, new rules, ports, and demo scenarios are welcome under the collaboration-pull
model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `depgraph` saved you time, **star it** — it genuinely helps others find it.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for
personal, internal-evaluation, research, and educational use; **commercial / production
use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · part of the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
