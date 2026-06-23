# Sources

## Bundled vulnerability data (offline)

`depgraph` ships a consolidated, real **OSV** corpus in
`depgraph/cognis_vulndb.jsonl.gz` — ~262,000 advisories across PyPI, npm, Go, Maven,
RubyGems, crates.io, and NuGet, each with id, CVE/GHSA aliases, ecosystem, summary,
severity, and affected packages. Lookups (`depgraph vulndb`, `depgraph enrich`) run
entirely offline against this bundle — no network, no key.

The curated, version-range advisories used by `depgraph audit` mirror real, public
CVEs/GHSAs (e.g. CVE-2023-32681 / requests, CVE-2021-33503 / urllib3,
CVE-2022-22817 / pillow, CVE-2021-23337 / lodash).

## Edge / air-gap refresh feeds (opt-in, keyless)

`depgraph feeds` and `depgraph/datafeeds.py` catalog mostly-keyless intelligence
feeds for refreshing the offline baseline on the edge:

- **CISA KEV** — Known Exploited Vulnerabilities catalog
- **FIRST EPSS** — exploit-probability scores
- **OSV.dev** — open-source vulnerability database
- **NIST NVD CVE 2.0** — full CVE corpus
- **GitHub GHSA** — GitHub Security Advisories
- **MITRE ATT&CK** / **NIST OSCAL 800-53** — control mapping

Online refresh is strictly opt-in; audits never touch the network.

<!-- cognis-2026-live-sources -->

## Live 2026 sources (auto-expanded)

_Always-current feeds, live web-search queries, and keyless APIs for real-time monitoring. Ingest at runtime with `livesearch.py`._

### Ai
- **feed** · https://huggingface.co/blog/feed.xml
- **feed** · https://openai.com/news/rss.xml
- **feed** · https://www.anthropic.com/rss.xml
- **feed** · https://export.arxiv.org/rss/cs.AI
- **feed** · https://export.arxiv.org/rss/cs.LG
- **live search** · `frontier AI model release 2026`
- **live search** · `AI agent benchmark state of the art`
- **live search** · `open-weight LLM release`
- **live search** · `AI policy regulation 2026`
- **api** · http://export.arxiv.org/api/query (arXiv, free)
- **api** · https://api.github.com/search/repositories?q=stars (trending repos, free)
- **api** · https://hn.algolia.com/api (Hacker News, free)

### Maritime
- **feed** · https://gcaptain.com/feed/
- **feed** · https://www.maritime-executive.com/rss
- **feed** · https://splash247.com/feed/
- **feed** · https://www.tradewindsnews.com/rss
- **feed** · https://lloydslist.com/rss
- **live search** · `shadow fleet sanctioned tanker AIS`
- **live search** · `ship-to-ship transfer sanctions evasion`
- **live search** · `dark vessel AIS spoofing`
- **live search** · `OFAC sanctioned vessel designation`
- **live search** · `port disruption maritime security`
- **api** · https://aisstream.io (free real-time AIS websocket, key required)
- **api** · https://globalfishingwatch.org/our-apis/ (IUU / dark activity, free API token)
- **api** · https://www.marinetraffic.com (consumer vessel tracking)
- **api** · https://sanctionssearch.ofac.treas.gov (OFAC SDN, free)

### Space
- **feed** · https://spacenews.com/feed/
- **feed** · https://www.nasaspaceflight.com/feed/
- **live search** · `satellite launch 2026 LEO constellation`
- **live search** · `SAR imagery commercial space`
- **api** · https://www.space-track.org (orbital catalog, free account)
- **api** · https://celestrak.org/NORAD/elements/ (TLE, free)

