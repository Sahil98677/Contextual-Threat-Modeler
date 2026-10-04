import argparse
from pathlib import Path

from ctm.engine import run
from ctm.reporting.console import render_console
from ctm.reporting.html_report import render_html
from ctm.reporting.json_report import render_json


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Contextual Threat Modeler security decision engine"
    )
    parser.add_argument(
        "--input-dir",
        default="mock_inputs",
        help="Directory containing CTM JSON input files",
    )
    parser.add_argument(
        "--format",
        choices=("console", "json", "html"),
        default="console",
    )
    parser.add_argument("--output", help="Output file for JSON or HTML reports")
    args = parser.parse_args()

    results = run(args.input_dir)

    if args.format == "console":
        print(render_console(results))
        return 0

    content = render_json(results) if args.format == "json" else render_html(results)

    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
    else:
        print(content)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
