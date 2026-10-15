# CTM Architecture

## Core pipeline

1. **Ingestion** loads scanner/recon data.
2. **Normalization** converts heterogeneous records into CTM findings.
3. **Context** adds asset, exposure, and control information.
4. **Threat modeling** maps endpoint behavior to STRIDE and ATT&CK.
5. **Attack-path analysis** emits deterministic, evidence-backed candidate correlations. Shared asset identity and explicit internet exposure are not treated as an ordered exploit chain or proof of reachability.
6. **Risk engine** calculates likelihood, impact, confidence, and control-adjusted risk.
7. **Decision engine** turns risk into an action.
8. **Reporting** exposes the result as console, validated JSON, SARIF 2.1.0, or HTML, including shared remediation priorities.

The architecture deliberately keeps discovery separate from decision-making.
