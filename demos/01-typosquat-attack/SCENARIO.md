# Scenario: Three typosquats made it into requirements.txt

All three squat distance-1 from popular packages. Low Scorecard scores. Classic supply-chain attack.

## Expected findings

- DG-CVE-001 (requests has 2 CVEs)
- DG-TYPO-001 × 3 (critical)
- DG-SCORE-001 × 3

## Why this matters

Halt all builds, audit requirements.txt history.
