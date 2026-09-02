from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .reporters import html_report, json_report, sarif_report, terminal_report
from .scanner import scan_repository


SEVERITY_ORDER = {"none": 99, "info": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repotruth", description="Verify repository claims against evidence in the codebase.")
    parser.add_argument("path", nargs="?", default=".", help="repository directory (default: current directory)")
    parser.add_argument("--format", choices=("terminal", "json", "sarif", "html"), default="terminal")
    parser.add_argument("--output", "-o", help="write the report to a file")
    parser.add_argument("--fail-on", choices=("none", "info", "low", "medium", "high"), default="high", help="minimum severity that produces exit code 1")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version="RepoTruth 0.1.0")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = scan_repository(args.path)
    except ValueError as exc:
        print(f"repotruth: {exc}", file=sys.stderr)
        return 2

    renderers = {"terminal": lambda: terminal_report(result, color=not args.no_color and sys.stdout.isatty()), "json": lambda: json_report(result), "sarif": lambda: sarif_report(result), "html": lambda: html_report(result)}
    output = renderers[args.format]()
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(output, encoding="utf-8")
        print(f"RepoTruth wrote {args.format} report to {destination}")
    else:
        print(output)

    threshold = SEVERITY_ORDER[args.fail_on]
    return int(any(SEVERITY_ORDER.get(item.severity, 0) >= threshold for item in result.findings)) if args.fail_on != "none" else 0


if __name__ == "__main__":
    raise SystemExit(main())

