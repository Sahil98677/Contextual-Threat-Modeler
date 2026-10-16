# Phase 5 — Attack-Path Correlation

## Purpose

Make CTM attack paths useful to analysts by correlating related findings and exposing the resulting candidate path in console, JSON, and HTML reports.

## Scope

Phase 5 starts conservatively. Findings are correlated when they belong to the same asset and at least one finding explicitly has `internet_facing=true`. Each result is classified as `inferred_candidate` and `confirmed=false`. Correlated findings are an **unordered set**, not a sequence of exploit steps.

## Example

```text
Exposure: Internet-facing
Entry: GET /api/users
Related findings (unordered): F1, F2
Asset: Portal
```

The path carries a path ID, score, finding IDs, nodes, entry point, target, impact, correlation reason, evidence basis, and explicit limitations. IDs and ordering are deterministic for the same input set. The path-priority score is on a 0–100 scale, calculated as the highest finding score plus 5 points per additional same-asset finding (capped at 15) and 5 points for confidential or restricted data, with the final score capped at 100. It is a prioritization heuristic, not a probability of compromise or successful attack.

## Reporting

- Console: compact `ATTACK PATHS` section
- JSON: full machine-readable `attack_paths` objects
- HTML: candidate cards with classification and limitations

## Security boundary

Same-asset membership and internet exposure do not establish exploitability, reachability between endpoints, successful access, trust-boundary traversal, or control bypass. CTM does not claim that one finding can exploit another unless future input context explicitly supports that relationship. Phase 5 correlation is prioritization and analysis, not automated exploitation.
