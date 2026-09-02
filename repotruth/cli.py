from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .reporters import github_report, html_report, json_report, sarif_report, terminal_report
from .scanner import scan_repository


SEVERITY_ORDER = {"none": 99, "info": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repotruth", description="Verify repository claims against evidence in the codebase.")
    parser.add_argument("path", nargs="?", default=".", help="repository directory (default: current directory)")
    parser.add_argument("--format", choices=("terminal", "json", "sarif", "html", "github"), default="terminal")
    parser.add_argument("--output", "-o", help="write the report to a file")
    parser.add_argument("--config", help="configuration file (default: .repotruth.json)")
    parser.add_argument("--fail-on", choices=("none", "info", "low", "medium", "high"), default="high", help="minimum severity that produces exit code 1")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--verify-runtime", action="store_true", help="run a detected check in a locked-down, offline Docker container")
    parser.add_argument("--online", action="store_true", help="query OSV.dev for known vulnerabilities in pinned dependencies")
    parser.add_argument("--version", action="version", version="RepoTruth 0.5.1")
    return parser


def serve_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repotruth serve", description="Start the local RepoTruth web interface.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open", action="store_true", dest="open_browser")
    return parser


def fix_parser(command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"repotruth {command}", description="Preview/apply safe repository hardening files.")
    parser.add_argument("path", nargs="?", default=".")
    if command == "fix":
        parser.add_argument("--apply", action="store_true", help="create the proposed files; preview is the default")
    return parser


def main(argv: list[str] | None = None) -> int:
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    if actual_argv and actual_argv[0] == "serve":
        from .server import serve

        serve_args = serve_parser().parse_args(actual_argv[1:])
        return serve(serve_args.host, serve_args.port, serve_args.open_browser)
    if actual_argv and actual_argv[0] in {"fix", "pr"}:
        from .fixes import apply_fixes, create_pull_request, propose_fixes, render_fix_plan

        command = actual_argv[0]
        fix_args = fix_parser(command).parse_args(actual_argv[1:])
        root = Path(fix_args.path).resolve()
        if not root.is_dir():
            print(f"repotruth: not a directory: {root}", file=sys.stderr)
            return 2
        try:
            if command == "pr":
                print(create_pull_request(root))
                return 0
            proposals = propose_fixes(root)
            print(render_fix_plan(root, proposals))
            if fix_args.apply:
                created = apply_fixes(root, proposals)
                print(f"\nCreated {len(created)} file(s). Review them before committing.")
            return 0
        except (OSError, RuntimeError) as exc:
            print(f"repotruth: {exc}", file=sys.stderr)
            return 2
    args = build_parser().parse_args(actual_argv)
    try:
        result = scan_repository(args.path, args.config, verify=args.verify_runtime, online=args.online)
    except ValueError as exc:
        print(f"repotruth: {exc}", file=sys.stderr)
        return 2

    renderers = {"terminal": lambda: terminal_report(result, color=not args.no_color and sys.stdout.isatty()), "json": lambda: json_report(result), "sarif": lambda: sarif_report(result), "html": lambda: html_report(result), "github": lambda: github_report(result)}
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
