from ..decision.decision_engine import risk_level


def render_console(results) -> str:
    results = list(results)
    lines = [
        "",
        "=" * 78,
        "              CTM SECURITY DECISION ENGINE v1.0",
        "=" * 78,
    ]

    for i, finding in enumerate(results, start=1):
        lines.extend(
            [
                f"\n[{i:02d}] {risk_level(finding.score)} | {finding.score:.1f}/100 | {finding.decision}",
                f"  {finding.method} {finding.path} [{finding.endpoint_type}]",
                f"  Likelihood: {finding.likelihood:.2f}/10 | Impact: {finding.impact:.2f}/10 | Confidence: {finding.confidence:.0%}",
                f"  Threats: {', '.join(finding.threats) or 'None'}",
                f"  ATT&CK: {', '.join(finding.attack_techniques) or 'No direct mapping'}",
                f"  Attack paths: {len(finding.attack_paths)}",
                "  Why: " + (" ".join(finding.rationale[:3]) or "No additional rationale."),
            ]
        )

    lines.extend(["", "=" * 78, f"Findings analyzed: {len(results)}"])
    return "\n".join(lines)
