# Risk Model

CTM currently uses:

```text
base risk = likelihood × impact
risk score = base risk × control modifier
```

Both likelihood and impact are bounded to 0–10.

## Likelihood

Factors include:

- internet exposure
- authentication requirement
- DMZ placement
- exploit availability
- attack complexity
- vulnerability lifecycle status

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
