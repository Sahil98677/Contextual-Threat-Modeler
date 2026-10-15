# Threat Model

CTM uses two complementary threat-modeling views.

## STRIDE

Endpoint types are mapped to likely:

- Spoofing
- Tampering
- Repudiation
- Information Disclosure
- Denial of Service
- Elevation of Privilege

The mapping represents **potential threats**, not proof of exploitation.

## MITRE ATT&CK

Where the context supports it, CTM maps to ATT&CK techniques such as:

- T1190 — Exploit Public-Facing Application
- T1078 — Valid Accounts

Mappings are evidence-aware and are not intended to claim that an attacker actually performed the technique.

## Attack paths

CTM emits deterministic, inferred candidate correlations only when a finding
explicitly declares `internet_facing=true`. Findings sharing an asset ID are
represented as an unordered set:

```text
Internet-facing exposure
Entry endpoint
Related findings (unordered)
Asset
```

This is not evidence of a sequential exploit chain, network reachability,
successful access, trust-boundary traversal, or control bypass. CTM does not
mark these paths as confirmed. See
[attack-path correlation](PHASE_5_ATTACK_PATH_CORRELATION.md) for the recorded
evidence and limitations.

## Trust boundaries and limitations

- Scanner exports and their fields are untrusted input. Parsing and validation
  do not establish that a scanner assertion is correct.
- Scanner-reported validation states are distinct from controlled, independently
  recorded verification. Reviewer identity and authorization must be provided
  by a trusted deployment integration.
- Risk scores, decisions, remediation priorities, STRIDE/ATT&CK mappings, and
  attack-path correlations are decision support. They do not establish
  exploitability, attacker activity, or absence of risk.
- SQLite audit storage is tamper-evident, not immutable against a privileged
  database owner or file rewrite. Deployments must restrict database access and
  manage backups.
- Synthetic fixtures demonstrate supported parsing paths but do not certify
  compatibility with all scanner versions or exports. Test sanitized exports
  representative of the deployed scanner configuration.
- Reports may contain sensitive asset, endpoint, and scanner details. Handle
  and share them according to the organization's data-handling policy.
