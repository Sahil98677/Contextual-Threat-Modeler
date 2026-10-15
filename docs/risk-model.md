# Risk Model

CTM calculates likelihood and impact on 0–10 scales. The raw score is their
product, adjusted by relevant control modifiers, rounded to one decimal place,
and capped at 100. Secret exposure applies a minimum score of 85 after the cap.

```text
raw score = likelihood × impact
risk score = min(100, raw score × control modifier)
```

After this calculation, secret-exposure evidence raises any score below 85 to
85. The secret-exposure floor is applied after the cap.

## Likelihood weights

Likelihood starts at **2.0** and is capped to 0–10 after adding:

| Input | Contribution |
|---|---:|
| Internet-facing | +3.0 |
| Authentication not required | +2.0 |
| Trust zone other than `internal` (including unassessed) | +1.0 |
| Exploit reported available | +2.0 |
| Attack complexity is `low` | +1.0 |
| Status `discovered` | +0.0 |
| Status `suspected` | +0.75 |
| Status `validated` | +1.5 |
| Status `confirmed` | +2.0 |

Missing or unrecognized internet-facing values receive the risk-positive +3.0
factor. Missing or unrecognized authentication values are treated as
authentication not required for scoring (+2.0). An unassessed trust zone
receives +1.0, as does any zone other than `internal`. These values remain
unassessed in the finding and are identified as unknown in its rationale; the
scoring assumption is not a claim that exposure has been confirmed.

Missing status defaults to `discovered`. Missing exploit evidence adds no
exploit bonus, and only an explicit `low` attack-complexity value adds its
bonus.

## Impact weights

Impact starts at **2.0** and is capped to 0–10 after adding:

| Input | Contribution |
|---|---:|
| Asset criticality | `clamp(criticality − 1, 0, 4)` |
| Data classification is `confidential` or `restricted` | +2.0 |
| Data classification is unknown or unrecognized | +2.0 |
| Vulnerability impact is `high` or `critical` | +2.0 |
| Secret exposure evidence is present | +2.0 |

Scanner data classifications are normalized to `public`, `internal`,
`confidential`, or `restricted`. Missing classification retains the scanner
pipeline's `internal` default; malformed or unrecognized explicit values become
`unknown`. Unknown classification receives the conservative +2.0 impact
adjustment and is identified as unknown in the rationale. This is a scoring
assumption, not a claim that the data is actually confidential.

## Control modifiers

Matching control modifiers multiply together. A control is applied only when
both its value is present and its endpoint/CWE relevance rule matches:

- WAF reduces the score by 10% (modifier `0.90`) for `admin`, `api`, or
  `file_upload` endpoints with CWE-22, CWE-77, CWE-78, CWE-79, CWE-89, CWE-94,
  CWE-434, or CWE-918.
- File validation reduces the score by 25% (modifier `0.75`) for a
  `file_upload` endpoint with CWE-434.
- Antivirus scanning reduces the score by 15% (modifier `0.85`) for a
  `file_upload` endpoint with CWE-434.
- MFA reduces the score by 5% (modifier `0.95`) for an `admin`, `auth`,
  `authentication`, or `login` endpoint with CWE-521 or CWE-522.
- Strong security headers reduce the score by 10% (modifier `0.90`) for an
  `admin` endpoint with CWE-79, CWE-352, or CWE-1021.

Unmatched or unknown vulnerability evidence receives no control discount.
Multiple matching modifiers are multiplied, not added. These are conservative
relevance rules, not proof that a deployed control fully mitigates a
vulnerability.

## Risk levels and decisions

Risk levels use score alone:

| Score | Risk level |
|---:|---|
| ≥ 85 | `CRITICAL` |
| ≥ 70 and < 85 | `HIGH` |
| ≥ 45 and < 70 | `MEDIUM` |
| < 45 | `LOW` |

Decision rules are evaluated in order:

| Condition | Decision |
|---|---|
| Score ≥ 85 **and** confidence ≥ 0.60 | `TEST_IMMEDIATELY` |
| Otherwise, score ≥ 70 | `PRIORITIZE_VALIDATION` |
| Otherwise, score ≥ 45 | `INVESTIGATE` |
| Otherwise | `MONITOR` |

Thus, a score of 85 or higher with confidence below 0.60 falls through to
`PRIORITIZE_VALIDATION`. The score thresholds are 85, 70, and 45; the minimum
confidence for `TEST_IMMEDIATELY` is 0.60.

## Confidence and limitations

Confidence is tied to the evidence lifecycle:

```text
discovered  = 0.35
suspected   = 0.60
validated   = 0.80
confirmed   = 0.95
```

These values are heuristic evidence-strength scores, **not calibrated
probabilities**. Confidence does not multiply the risk score; it only gates the
`TEST_IMMEDIATELY` decision and communicates evidence strength separately.

Passing unit, regression, and synthetic scenario tests demonstrates that CTM
behaves as encoded for those test cases. It does not establish calibration
against real-world incidents, exploitation likelihood, or security outcomes.
This is a prioritization model, not a CVSS replacement; validate and tune it
with representative organizational evidence before relying on it operationally.
