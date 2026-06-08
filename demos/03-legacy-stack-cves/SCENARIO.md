# Scenario: Legacy stack with stale dependencies

Django + Celery both have open CVEs; one fully unmaintained package.

## Expected findings

- DG-CVE-001 × 2
- DG-SCORE-001

## Why this matters

Upgrade plan needed; consider replacing the unmaintained dep.
