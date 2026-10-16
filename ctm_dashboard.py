"""Local Streamlit dashboard for Contextual Threat Modeler.

Run from the repository root:
    python -m streamlit run ctm_dashboard.py --server.address 127.0.0.1 --server.port 8501
"""
from __future__ import annotations

import csv
import html
import json
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import ParseError

from ctm.decision.decision_engine import risk_level
from ctm.engine import run
from ctm.reporting.html_report import render_html
from ctm.reporting.json_report import render_json
from ctm.reporting.remediation import build_remediation_plan
from ctm.reporting.sarif_report import render_sarif
from ctm.scanner_engine import run_scanner

SCANNERS = ("generic-json", "nmap", "nuclei", "trivy", "qualys-xml", "qualys-csv", "nessus")


RISK_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
RISK_COLORS = {
    "CRITICAL": "#F87171",
    "HIGH": "#FB923C",
    "MEDIUM": "#FBBF24",
    "LOW": "#60A5FA",
}


def build_dashboard_summary(findings: Iterable[Any]) -> dict[str, Any]:
    """Summarize actual engine findings without recalculating their risk."""
    items = list(findings)
    levels = {level: 0 for level in RISK_ORDER}
    decisions: dict[str, int] = {}
    for finding in items:
        levels[risk_level(float(finding.score))] += 1
        decisions[finding.decision] = decisions.get(finding.decision, 0) + 1
    scores = [float(item.score) for item in items]
    paths = {
        str(path.get("path_id")): path
        for item in items
        for path in (item.attack_paths or [])
        if path.get("path_id")
    }
    return {
        "total": len(items),
        "critical_high": levels["CRITICAL"] + levels["HIGH"],
        "average_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
        "risk_levels": levels,
        "decisions": decisions,
        "attack_paths": sorted(paths.values(), key=lambda p: (-float(p.get("path_score", 0)), str(p.get("path_id", "")))),
    }


def finding_table_rows(findings: Iterable[Any]) -> list[dict[str, Any]]:
    items = list(findings)
    rows = []
    remediation = {item["finding_id"]: item for item in build_remediation_plan(items)}
    for finding in items:
        rows.append({
            "ID": finding.id,
            "Risk": risk_level(float(finding.score)),
            "Score": round(float(finding.score), 1),
            "Confidence": round(float(finding.confidence), 2),
            "Decision": finding.decision,
            "Priority": remediation.get(finding.id, {}).get("priority", ""),
            "Asset": finding.asset_id,
            "Endpoint": f"{finding.method} {finding.path}".strip(),
        })
    return rows


def _path_markup(path: dict[str, Any]) -> str:
    nodes = path.get("nodes") or [path.get("source", "Unknown"), path.get("entry", "Entry"), path.get("target", "Target")]
    node_markup = []
    for index, node in enumerate(nodes):
        node_markup.append(
            '<span class="path-node">' + html.escape(str(node)) + "</span>"
        )
        if index < len(nodes) - 1:
            node_markup.append('<span class="path-arrow" aria-hidden="true">→</span>')
    classification = html.escape(str(path.get("classification", "inferred_candidate")))
    relationship = html.escape(str(path.get("relationship", "candidate")))
    limitations = path.get("limitations") or []
    limits_markup = "".join(f"<li>{html.escape(str(item))}</li>" for item in limitations)
    return (
        '<div class="path-card"><div class="path-top"><strong>'
        + html.escape(str(path.get("path_id", "Candidate path")))
        + '</strong><span class="path-score">Priority score '
        + html.escape(str(path.get("path_score", "n/a")))
        + ' / 100 (heuristic; not a probability)</span><span class="path-classification">'
        + classification.replace("_", " ")
        + '</span></div><div class="path-nodes">'
        + "".join(node_markup)
        + '</div><p class="muted">Relationship: '
        + relationship
        + '</p><details><summary>Evidence and limitations</summary><pre>'
        + html.escape(json.dumps(path.get("evidence", {}), indent=2, sort_keys=True))
        + '</pre><ul>'
        + limits_markup
        + "</ul></details></div>"
    )


def _load_findings(st: Any) -> tuple[list[Any] | None, str]:
    mode = st.sidebar.radio("Data source", ("Sample input directory", "Scanner export"))
    previous_mode = st.session_state.get("ctm_mode")
    if previous_mode != mode:
        st.session_state["ctm_mode"] = mode
        st.session_state.pop("ctm_findings", None)
        st.session_state.pop("ctm_source", None)
        st.session_state.pop("ctm_error", None)
    if mode == "Sample input directory":
        default_dir = str(Path("mock_inputs"))
        input_dir = st.sidebar.text_input("Input directory", value=default_dir)
        if st.sidebar.button("Run CTM analysis", type="primary"):
            st.session_state.pop("ctm_findings", None)
            try:
                st.session_state["ctm_findings"] = run(input_dir)
                st.session_state["ctm_source"] = f"Input directory: {input_dir}"
                st.session_state.pop("ctm_error", None)
            except (OSError, TypeError, ValueError) as exc:
                st.session_state["ctm_error"] = f"{type(exc).__name__}: {exc}"
        if "ctm_findings" not in st.session_state:
            try:
                st.session_state["ctm_findings"] = run(input_dir)
                st.session_state["ctm_source"] = f"Input directory: {input_dir}"
            except (OSError, TypeError, ValueError) as exc:
                st.session_state["ctm_error"] = f"{type(exc).__name__}: {exc}"
    else:
        scanner = st.sidebar.selectbox("Scanner format", SCANNERS)
        uploaded = st.sidebar.file_uploader(
            "Upload an existing scanner export",
            type=["json", "jsonl", "xml", "nessus", "csv", "txt"],
            help="The file is processed locally by CTM; it is not uploaded to a service.",
        )
        if uploaded is not None and st.sidebar.button("Analyze scanner export", type="primary"):
            st.session_state.pop("ctm_findings", None)
            try:
                suffix = Path(uploaded.name).suffix or ".data"
                temporary_path = None
                try:
                    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temporary:
                        temporary.write(uploaded.getvalue())
                        temporary_path = temporary.name
                    findings = run_scanner(scanner, temporary_path)
                finally:
                    if temporary_path:
                        Path(temporary_path).unlink(missing_ok=True)
                st.session_state["ctm_findings"] = findings
                st.session_state["ctm_source"] = f"{scanner}: {uploaded.name}"
                st.session_state.pop("ctm_error", None)
            except (OSError, TypeError, ValueError, csv.Error, ParseError) as exc:
                st.session_state["ctm_error"] = f"{type(exc).__name__}: {exc}"

    if st.session_state.get("ctm_error"):
        st.sidebar.error(st.session_state["ctm_error"])
    return st.session_state.get("ctm_findings"), st.session_state.get("ctm_source", "No analysis loaded")


def main() -> None:
    import pandas as pd
    import streamlit as st

    st.set_page_config(page_title="CTM Security Workbench", page_icon="🛡️", layout="wide")
    st.markdown(
        """
        <style>
        :root { color-scheme: dark; }
        .stApp { background: #0B1220; }
        [data-testid="stSidebar"] { background: #0E1727; border-right: 1px solid #263449; }
        [data-testid="stMetric"] { background: #121D2E; border: 1px solid #263449; padding: 16px; border-radius: 12px; }
        [data-testid="stMetricLabel"] { color: #94A3B8; }
        [data-testid="stMetricValue"] { color: #F8FAFC; }
        .ctm-subtitle, .muted { color: #94A3B8; }
        .path-card { background: #121D2E; border: 1px solid #263449; border-radius: 12px; padding: 16px; margin: 12px 0; }
        .path-top { display:flex; flex-wrap:wrap; align-items:center; gap:10px; margin-bottom:14px; }
        .path-score { color:#45D6C5; font-weight:700; }
        .path-classification { background:#382B1C; color:#FBBF24; border-radius:999px; padding:3px 9px; font-size:12px; }
        .path-nodes { display:flex; flex-wrap:wrap; align-items:center; gap:8px; }
        .path-node { background:#17263A; border:1px solid #35516D; color:#E2E8F0; padding:9px 12px; border-radius:8px; }
        .path-arrow { color:#45D6C5; font-size:20px; font-weight:700; }
        .path-card pre { white-space:pre-wrap; overflow-wrap:anywhere; background:#0B1220; padding:12px; border-radius:8px; }
        div[data-testid="stDataFrame"] { border: 1px solid #263449; border-radius: 10px; overflow:hidden; }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.sidebar.markdown("## 🛡️ CTM")
    st.sidebar.caption("Contextual Threat Modeler · Local workbench")
    findings, source_label = _load_findings(st)

    st.title("Security Workbench")
    st.markdown(
        f'<p class="ctm-subtitle">Local analysis · <code>{html.escape(source_label)}</code></p>',
        unsafe_allow_html=True,
    )
    if findings is None:
        st.info("Choose a local input directory or upload an existing scanner export to begin.")
        return

    findings = list(findings)
    summary = build_dashboard_summary(findings)
    remediation = {item["finding_id"]: item for item in build_remediation_plan(findings)}
    all_rows = finding_table_rows(findings)

    nav = st.sidebar.radio(
        "Workspace",
        ("Overview", "Findings explorer", "Attack paths", "Threat mappings", "Reports"),
    )
    if nav == "Overview":
        a, b, c, d = st.columns(4)
        a.metric("Total findings", summary["total"])
        b.metric("Critical / High", summary["critical_high"])
        c.metric("Average risk score", f'{summary["average_score"]:.1f}/100')
        d.metric("Candidate paths", len(summary["attack_paths"]))

        left, right = st.columns([1, 1])
        with left:
            st.subheader("Risk distribution")
            chart_data = pd.DataFrame(
                {"Findings": [summary["risk_levels"][level] for level in RISK_ORDER]},
                index=RISK_ORDER,
            )
            st.bar_chart(chart_data, color="#45D6C5")
        with right:
            st.subheader("Security decisions")
            decisions = summary["decisions"]
            if decisions:
                st.bar_chart(pd.DataFrame({"Findings": decisions}))
            else:
                st.caption("No decisions to display for the current dataset.")

        st.subheader("Highest-priority findings")
        if all_rows:
            st.dataframe(pd.DataFrame(all_rows).head(8), width="stretch", hide_index=True)
        else:
            st.success("No findings were returned by CTM for this input.")
        st.subheader("Candidate attack paths")
        if summary["attack_paths"]:
            st.caption("Candidate correlations are not proof of exploitability or a confirmed attack chain.")
            for path in summary["attack_paths"][:5]:
                st.markdown(_path_markup(path), unsafe_allow_html=True)
        else:
            st.caption("No candidate attack paths were returned by the engine.")

    elif nav == "Findings explorer":
        st.subheader("Findings explorer")
        c1, c2, c3 = st.columns(3)
        risk_filter = c1.multiselect("Risk level", RISK_ORDER, default=list(RISK_ORDER))
        decision_options = sorted({item.decision for item in findings})
        decision_filter = c2.multiselect("Decision", decision_options, default=decision_options)
        min_confidence = c3.slider("Minimum confidence", 0.0, 1.0, 0.0, 0.05)
        search = st.text_input("Search ID, asset, endpoint, or vulnerability")
        filtered = [
            item for item in findings
            if risk_level(float(item.score)) in risk_filter
            and item.decision in decision_filter
            and float(item.confidence) >= min_confidence
            and search.casefold() in " ".join([
                item.id, item.asset_id, item.method, item.path,
                str(item.vulnerability.get("name", "")),
                str(item.vulnerability.get("title", "")),
            ]).casefold()
        ]
        filtered_rows = finding_table_rows(filtered)
        st.caption(f"{len(filtered)} of {len(findings)} findings")
        st.dataframe(pd.DataFrame(filtered_rows), width="stretch", hide_index=True)
        if filtered:
            selected_id = st.selectbox("Inspect finding", [item.id for item in filtered])
            finding = next(item for item in filtered if item.id == selected_id)
            score_cols = st.columns(4)
            score_cols[0].metric("Risk score", f"{finding.score:.1f}/100")
            score_cols[1].metric("Likelihood", f"{finding.likelihood:.1f}/10")
            score_cols[2].metric("Impact", f"{finding.impact:.1f}/10")
            score_cols[3].metric("Confidence", f"{finding.confidence:.0%}")
            st.markdown(f"**Decision:** `{finding.decision}` · **Asset:** `{finding.asset_id}`")
            st.markdown("#### Rationale")
            for reason in finding.rationale or ["No additional rationale recorded."]:
                st.write(f"• {reason}")
            st.markdown("#### Remediation guidance")
            recommendation = remediation.get(finding.id, {})
            st.write(f"**{recommendation.get('priority', '—')}** — {recommendation.get('action', 'No recommendation available.')}")
            with st.expander("Evidence and context"):
                st.json({
                    "evidence": finding.evidence,
                    "exposure": finding.exposure,
                    "controls": finding.controls,
                    "vulnerability": finding.vulnerability,
                })
            with st.expander("Threat mappings"):
                st.write("**STRIDE:** " + (", ".join(finding.threats) or "None mapped"))
                st.write("**MITRE ATT&CK:** " + (", ".join(finding.attack_techniques) or "None mapped"))
            with st.expander("Associated candidate paths"):
                if finding.attack_paths:
                    for path in finding.attack_paths:
                        st.markdown(_path_markup(path), unsafe_allow_html=True)
                else:
                    st.caption("No candidate path associated with this finding.")
        else:
            st.info("No findings match the selected filters.")

    elif nav == "Attack paths":
        st.subheader("Attack-path visualization")
        paths = summary["attack_paths"]
        st.caption(
            "Path-priority score uses a 0–100 heuristic, not a probability of a "
            "successful attack. It combines the highest finding score, +5 per "
            "additional same-asset finding (capped at +15), and +5 for "
            "confidential or restricted data, then caps the total at 100."
        )
        st.warning("These are CTM candidate correlations. They do not establish exploitability, successful access, or a confirmed multi-step attack chain.")
        if not paths:
            st.info("No candidate paths were returned by the CTM engine.")
        for path in paths:
            st.markdown(_path_markup(path), unsafe_allow_html=True)
            st.caption("Finding IDs: " + (", ".join(path.get("finding_ids", [])) or "Not specified"))

    elif nav == "Threat mappings":
        st.subheader("Threat mappings")
        mapping_rows = [
            {
                "ID": item.id,
                "Asset": item.asset_id,
                "Risk": risk_level(float(item.score)),
                "STRIDE": ", ".join(item.threats),
                "MITRE ATT&CK": ", ".join(item.attack_techniques),
                "Evidence references": len(item.evidence),
            }
            for item in findings
        ]
        st.dataframe(pd.DataFrame(mapping_rows), width="stretch", hide_index=True)
        st.caption("Mappings are those produced by CTM. Review source evidence and limitations before treating them as confirmed.")

    else:
        st.subheader("Reports")
        st.write("Download reports rendered by CTM's existing reporting modules.")
        formats = (
            ("JSON report", "application/json", render_json(findings), "ctm-report.json"),
            ("HTML report", "text/html", render_html(findings), "ctm-report.html"),
            ("SARIF 2.1.0", "application/sarif+json", render_sarif(findings), "ctm-report.sarif"),
        )
        for label, mime, content, filename in formats:
            st.download_button(
                f"Download {label}",
                data=content,
                file_name=filename,
                mime=mime,
                key=f"download-{filename}",
            )
        st.caption("The dashboard does not replace or alter CTM's CLI reporting behavior.")


if __name__ == "__main__":
    main()
