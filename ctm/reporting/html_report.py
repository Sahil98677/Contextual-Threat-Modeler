import html
from ..decision.decision_engine import risk_level


def render_html(results) -> str:
    cards = []
    for finding in results:
        cards.append(
            f"""
            <section class="finding">
              <h2>{html.escape(risk_level(finding.score))} — {finding.score:.1f}/100</h2>
              <p><strong>{html.escape(finding.method)} {html.escape(finding.path)}</strong>
              · {html.escape(finding.decision)}</p>
              <p>Likelihood: {finding.likelihood:.2f}/10 · Impact: {finding.impact:.2f}/10 · Confidence: {finding.confidence:.0%}</p>
              <p>Threats: {html.escape(", ".join(finding.threats) or "None")}</p>
              <p>ATT&CK: {html.escape(", ".join(finding.attack_techniques) or "None")}</p>
              <p>{html.escape(" ".join(finding.rationale))}</p>
            </section>
            """
        )

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CTM Security Report</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 1000px; margin: 40px auto; padding: 0 20px; }}
.finding {{ border: 1px solid #ddd; border-radius: 10px; padding: 18px; margin: 16px 0; }}
</style>
</head>
<body>
<h1>Contextual Threat Modeler</h1>
<p>Security decision report</p>
{"".join(cards)}
</body>
</html>"""
