import argparse
from pathlib import Path

from ctm.engine import run
from ctm.reporting.console import render_console
from ctm.reporting.html_report import render_html
from ctm.reporting.json_report import render_json
from ctm.scanner_engine import run_scanner
from ctm.trends import build_trend

SCANNERS = (
    "generic-json",
    "nmap",
    "nuclei",
    "trivy",
    "qualys-xml",
    "qualys-csv",
    "nessus",
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Contextual Threat Modeler security decision engine"
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--input-dir", default="mock_inputs", help="Directory containing CTM JSON input files (default: mock_inputs)")
    source.add_argument("--export", help="Existing scanner export to analyze")
    parser.add_argument("--scanner", choices=SCANNERS, help="Scanner format used by --export")
    parser.add_argument("--format", choices=("console", "json", "html"), default="console", help="Report format (default: console)")
    parser.add_argument("--output", help="Write JSON/HTML report to a file instead of stdout")
    parser.add_argument("--history-dir", help="Persist a risk snapshot and compare it with the previous run")
    args = parser.parse_args()

    if args.export and not args.scanner:
        parser.error("--export requires --scanner")
    if args.scanner and not args.export:
        parser.error("--scanner requires --export")
    if args.output and args.format == "console":
        parser.error("--output is only valid with --format json or --format html")

    results = run_scanner(args.scanner, args.export) if args.export else run(args.input_dir)

    trend = None
    if args.history_dir:
        _, trend, _ = build_trend(results, args.history_dir)

    if args.format == "console":
        print(render_console(results, trend=trend))
        return 0

    content = render_json(results, trend=trend) if args.format == "json" else render_html(results)
    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
    else:
        print(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
