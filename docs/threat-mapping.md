# STRIDE and MITRE ATT&CK Mapping

CTM threat mappings are contextual candidates, not claims that a threat or
adversary technique has been observed, is exploitable, or applies to a
particular environment. Reports retain both the mapping labels and the inputs
that activated each mapping rule under `evidence.threat_mapping_evidence`.

## STRIDE

STRIDE labels are generated from recognized endpoint types (`file_upload`,
`search`, `profile`, `admin`, and `api`). Each emitted label is marked
`inferred_candidate`, records its endpoint-type basis, and carries a limitation
stating that the category is not evidence the threat is present. Unknown
endpoint types receive no STRIDE labels rather than a generic fallback.

These endpoint-level associations are broad threat-model prompts. Confirm or
remove them using application architecture, trust boundaries, data flows, and
security-control evidence before treating them as a system threat model.

## MITRE ATT&CK

The current candidate rules are intentionally narrow:

- `T1190 - Exploit Public-Facing Application` is a candidate only for an
  explicitly internet-facing `api` or `file_upload` finding with at least one
  vulnerability identifier, CWE, CVE, QID, plugin ID, or explicit
  `exploit_available: true` evidence.
- `T1078 - Valid Accounts` is a candidate only for explicitly internet-facing
  `admin`, `auth`, `authentication`, or `login` findings with CWE-521 or
  CWE-522 evidence.

Each MITRE mapping records the triggering fields, an official ATT&CK technique
reference, `inferred_candidate` classification, and a limitation that technique
use is not established. Missing or unknown internet exposure does not produce
an ATT&CK candidate. No score or decision is changed by these mappings.

References:

- [T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
