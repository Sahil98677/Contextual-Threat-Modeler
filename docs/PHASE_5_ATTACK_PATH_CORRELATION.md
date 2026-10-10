# Phase 5 — Attack-Path Correlation

## Purpose

Make CTM attack paths useful to analysts by correlating related findings and exposing the resulting candidate path in console, JSON, and HTML reports.

## Scope

Phase 5 starts conservatively. Findings are correlated when they belong to the same asset and at least one finding is internet-facing. CTM labels these as **candidate correlations** rather than claiming a verified exploit chain.

## Example

```text
Internet
   ↓
GET /api/users
   ↓
GET /admin
   ↓
Portal
```

The path carries a path ID, score, finding IDs, nodes, entry point, target, impact, and correlation reason.

## Reporting

- Console: compact `ATTACK PATHS` section
- JSON: full machine-readable `attack_paths` objects
- HTML: visual path-flow cards

## Security boundary

CTM does not claim that one finding can exploit another unless input context supports that conclusion. Phase 5 correlation is prioritization and analysis, not automated exploitation.
