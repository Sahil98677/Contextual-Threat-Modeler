from ..decision.decision_engine import risk_level


def render_console(results) -> str:
    results = list(results)
    paths = []
    seen = set()
    lines = ["", "=" * 78, "              CTM SECURITY DECISION ENGINE v1.0", "=" * 78]
    for i, finding in enumerate(results, start=1):
        for path in finding.attack_paths:
            if path.get("path_id") not in seen:
                seen.add(path.get("path_id")); paths.append(path)
        lines.extend([
            f"\n[{i:02d}] {risk_level(finding.score)} | {finding.score:.1f}/100 | {finding.decision}",
            f"  {finding.method} {finding.path} [{finding.endpoint_type}]",
            f"  Likelihood: {finding.likelihood:.2f}/10 | Impact: {finding.impact:.2f}/10 | Confidence: {finding.confidence:.0%}",
            f"  Threats: {', '.join(finding.threats) or 'None'}",
            f"  ATT&CK: {', '.join(finding.attack_techniques) or 'No direct mapping'}",
            f"  Attack paths: {len(finding.attack_paths)}",
            "  Why: " + (" ".join(finding.rationale[:3]) or "No additional rationale."),
        ])
    if paths:
        lines.extend(["", "ATTACK PATHS", "-" * 78])
        for path in paths:
            lines.append(f"  {path['path_id']} | {risk_level(path['path_score'])} | {path['path_score']:.1f}/100")
            lines.append("    " + " -> ".join(path["nodes"]))
            lines.append(f"    Correlation: {path['relationship']}")
    lines.extend(["", "=" * 78, f"Findings analyzed: {len(results)}", f"Attack paths correlated: {len(paths)}"])
    return "\n".join(lines)
