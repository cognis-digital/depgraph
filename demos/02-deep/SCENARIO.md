# Demo 02 — deep supply-chain risk audit

This scenario shows DEPGRAPH's full feature set: OSV-style vulnerability
matching with semantic version ranges, scorecard-style maintainer/age
heuristics, typosquat detection, and A-F letter grading — all offline.

## Files

- `requirements.txt` — a pip manifest seeded with known-vulnerable pins,
  unpinned packages, deprecated/abandoned projects, and two real typosquats
  (`colourama` -> `colorama`, `python3-dateutil` -> `python-dateutil`, the
  latter being an actual 2019 PyPI attack).
- `package.json` — an npm manifest with vulnerable `lodash`/`axios`/`ws`/
  `minimist`/`semver` pins plus a `lodahs` typosquat of `lodash`.

## Run it

```sh
# Grade the pip manifest as a table (worst packages first)
python -m depgraph audit demos/02-deep/requirements.txt

# Same, as machine-readable JSON for CI gates
python -m depgraph audit demos/02-deep/requirements.txt --format json

# Audit the npm manifest, only fail the build on HIGH+ findings
python -m depgraph audit demos/02-deep/package.json --min-severity HIGH

# Audit both manifests at once
python -m depgraph audit demos/02-deep/requirements.txt demos/02-deep/package.json

# Inspect the bundled OSV-style advisory database
python -m depgraph advisories --ecosystem pypi
```

## What to expect

- `pillow 8.4.0` flagged CRITICAL (GHSA-h5c8-rqwp-cp95 / CVE-2022-22817).
- `colourama` and `python3-dateutil` flagged as typosquats (CRITICAL/HIGH).
- `nose` flagged deprecated/abandoned.
- `numpy` (unpinned) flagged MEDIUM for non-reproducible builds.
- Each package gets a 0-10 score and an A-F grade; the project rolls up to
  an overall grade. Exit code is non-zero when findings exist (or when the
  `--min-severity` / `--fail-grade` gate trips), so it slots into CI.
