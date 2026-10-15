# Risk Model

CTM currently uses:

```text
base risk = likelihood × impact
risk score = base risk × control modifier
```

Control modifiers are applied only when the finding has a supported relevance
match:

- WAF: supported web endpoint types and a mapped web-attack CWE.
- File validation and antivirus: file-upload endpoint and CWE-434.
- MFA: authentication/admin endpoint and CWE-521 or CWE-522.
- Strong security headers: admin endpoint and CWE-79, CWE-352, or CWE-1021.

Unmatched or unknown vulnerability evidence does not receive a control discount.
These mappings are conservative prioritization rules, not proof that a deployed
control fully mitigates a vulnerability.

Both likelihood and impact are bounded to 0–10.

## Likelihood

Factors include:

- internet exposure
- authentication requirement
- DMZ placement
- exploit availability
- attack complexity
- vulnerability lifecycle status

Missing or unrecognized exposure values are retained as unassessed and scored
using the risk-positive exposure factor. CTM also identifies these values in the
finding rationale; they are not reported as confirmed exposure facts.

## Impact

Factors include:

- asset criticality
- data classification
- stated vulnerability impact
- secret exposure

## Confidence

Confidence is tied to the evidence lifecycle:

```text
discovered  = 35%
suspected   = 60%
validated   = 80%
confirmed   = 95%
```

Confidence does not directly multiply the score. It influences the decision threshold for immediate testing and communicates evidence strength separately.

This is a prioritization model, not a CVSS replacement.
