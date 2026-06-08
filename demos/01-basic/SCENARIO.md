# Demo 01 — Basic dependency risk scan

This demo runs DEPGRAPH against a realistic, deliberately-risky
`requirements.txt` that contains a mix of clean and problematic
dependencies.

## Input

`requirements.txt` includes:

- `requests==2.28.0` — below the fix version (2.31.0) for an OSV advisory
  (proxy leak), so it is flagged as a **MODERATE vulnerability**.
- `urllib3==1.26.5` — below 1.26.18, flagged as a **HIGH vulnerability**
  (cookie request smuggling).
- `pyyaml==5.3.1` — below 5.4, flagged as a **CRITICAL vulnerability**
  (arbitrary code execution via `full_load`).
- `reqests==2.31.0` — a **typosquat** of `requests` (edit distance 1).
- `flask>=2.0` — **unpinned**, so it gets a pinning-hygiene finding and
  cannot be confirmed safe against the known Flask advisory.
- `numpy==1.26.4` — clean (grade A).

## Run it

```bash
# Human-readable table
python -m depgraph scan demos/01-basic/requirements.txt

# Machine-readable JSON
python -m depgraph scan demos/01-basic/requirements.txt --format json

# CI gate: fail the build if anything scores >= 30
python -m depgraph scan demos/01-basic/requirements.txt --fail-on 30
```

## Expected

The table sorts the riskiest packages first — the `reqests` typosquat and
the `pyyaml` CRITICAL vuln rank at the top. The summary line reports the
vulnerable count and typosquat count. With `--fail-on 30` the process
exits non-zero, which is how you'd wire it into CI.
