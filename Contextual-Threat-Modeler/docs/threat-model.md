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

A simple path can be represented as:

```text
Internet
   ↓
Public endpoint
   ↓
Vulnerability / weakness
   ↓
Application asset
   ↓
Potential impact
```

Future versions can extend this to multi-hop paths across identities, services, hosts, and trust boundaries.
