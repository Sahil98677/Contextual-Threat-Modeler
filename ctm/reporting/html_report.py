import html

from ..decision.decision_engine import risk_level
from ..scanner_validation import summarize_findings


def _list(value, empty="None"):
    return html.escape(", ".join(value) or empty)


def _attack_paths(results):
    paths = {}
    for finding in results:
        for path in finding.attack_paths:
            paths.setdefault(path["path_id"], path)

    if not paths:
        return (
            '<section class="panel"><h2>Attack paths</h2>'
            "<p>No correlated attack paths were identified.</p></section>"
        )

    cards = []
    for path in sorted(paths.values(), key=lambda item: item["path_score"], reverse=True):
        nodes = "".join(
            f'<div class="path-node">{html.escape(node)}</div>'
            for node in path["nodes"]
        )
        cards.append(
            f"""
            <section class="path-card">
              <div class="finding-head">
                <strong>{html.escape(path["path_id"])}</strong>
                <span class="score">{html.escape(risk_level(path["path_score"]))} · {path["path_score"]:.1f}/100</span>
              </div>
              <div class="path-flow">{nodes}</div>
              <p><strong>Entry:</strong> {html.escape(path["entry"])}</p>
              <p><strong>Target:</strong> {html.escape(path["target"])}</p>
              <p><strong>Correlation:</strong> {html.escape(path["relationship"])}</p>
            </section>
            """
        )
    return '<section class="panel"><h2>Attack paths</h2>' + "".join(cards) + "</section>"


def render_html(results) -> str:
    results = list(results)
    summary = summarize_findings(results)

    cards = []
    for finding in results:
        cards.append(
            f"""
            <section class="finding">
              <div class="finding-head">
                <span class="risk">{html.escape(risk_level(finding.score))}</span>
                <span class="score">{finding.score:.1f}/100</span>
              </div>
              <h2>{html.escape(finding.method)} {html.escape(finding.path)}</h2>
              <p class="decision">{html.escape(finding.decision)}</p>
              <div class="metrics">
                <span>Likelihood <strong>{finding.likelihood:.2f}/10</strong></span>
                <span>Impact <strong>{finding.impact:.2f}/10</strong></span>
                <span>Confidence <strong>{finding.confidence:.0%}</strong></span>
                <span>Attack paths <strong>{len(finding.attack_paths)}</strong></span>
              </div>
              <p><strong>STRIDE:</strong> {_list(finding.threats)}</p>
              <p><strong>ATT&CK:</strong> {_list(finding.attack_techniques)}</p>
              <p><strong>Why:</strong> {html.escape(" ".join(finding.rationale) or "No additional rationale.")}</p>
            </section>
            """
        )

    risk_items = "".join(
        f"<li><strong>{html.escape(level)}</strong><span>{count}</span></li>"
        for level, count in sorted(summary["risk_levels"].items())
    ) or "<li><strong>None</strong><span>0</span></li>"

    decision_items = "".join(
        f"<li><strong>{html.escape(decision)}</strong><span>{count}</span></li>"
        for decision, count in sorted(summary["decisions"].items())
    ) or "<li><strong>None</strong><span>0</span></li>"

    empty = (
        '<div class="empty"><h2>No findings</h2>'
        '<p>CTM did not receive any findings to analyze.</p></div>'
        if not results
        else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTM Security Report</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 1080px; margin: 0 auto; padding: 32px 20px; background: #f7f7f8; color: #202124; }}
header {{ margin-bottom: 24px; }}
.subtitle {{ color: #666; }}
.summary {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 20px 0; }}
.metric, .panel, .finding {{ background: #fff; border: 1px solid #ddd; border-radius: 10px; padding: 16px; }}
.metric strong {{ display: block; font-size: 1.4rem; margin-top: 4px; }}
.panels {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 20px 0; }}
ul {{ list-style: none; padding: 0; margin: 0; }}
li {{ display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #eee; }}
.finding {{ margin: 16px 0; }}
.finding-head {{ display: flex; justify-content: space-between; align-items: center; }}
.risk {{ font-weight: 700; }}
.score {{ font-size: 1.2rem; font-weight: 700; }}
.finding h2 {{ margin: 8px 0; font-size: 1.05rem; }}
.decision {{ font-weight: 700; }}
.metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 14px 0; }}
.metrics span {{ padding: 8px; background: #f2f2f3; border-radius: 6px; font-size: .9rem; }}
.path-card {{ margin: 12px 0; }}
.path-flow {{ display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 14px 0; }}
.path-node {{ padding: 9px 12px; background: #f2f2f3; border-radius: 7px; }}
.path-node:not(:last-child)::after {{ content: "→"; margin-left: 8px; }}
.empty {{ background: #fff; border: 1px solid #ddd; border-radius: 10px; padding: 32px; text-align: center; }}
@media (max-width: 760px) {{
  .summary, .panels, .metrics {{ grid-template-columns: 1fr 1fr; }}
}}
</style>
</head>
<body>
<header>
  <h1>Contextual Threat Modeler</h1>
  <p class="subtitle">Security decision report</p>
</header>
<section class="summary">
  <div class="metric">Findings<strong>{summary["total_findings"]}</strong></div>
  <div class="metric">Average score<strong>{summary["average_score"]:.1f}</strong></div>
  <div class="metric">Highest score<strong>{summary["highest_score"]:.1f}</strong></div>
  <div class="metric">MITRE techniques<strong>{len(summary["mitre_techniques"])}</strong></div>
</section>
<div class="panels">
  <section class="panel"><h2>Risk distribution</h2><ul>{risk_items}</ul></section>
  <section class="panel"><h2>Decisions</h2><ul>{decision_items}</ul></section>
</div>
{_attack_paths(results)}
{empty}
{"".join(cards)}
</body>
</html>"""
