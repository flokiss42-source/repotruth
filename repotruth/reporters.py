from __future__ import annotations

import html
import json
from .models import ScanResult


COLORS = {"high": "31", "medium": "33", "low": "36", "info": "37"}


def terminal_report(result: ScanResult, color: bool = True) -> str:
    lines = [f"RepoTruth {result.grade}  score={result.score}/100  findings={len(result.findings)}", f"Scanned: {result.root}"]
    for item in result.findings:
        label = item.severity.upper()
        if color:
            label = f"\033[{COLORS.get(item.severity, '37')}m{label}\033[0m"
        lines.append(f"\n{label} {item.rule_id} {item.path}:{item.line}  {item.title}")
        lines.append(f"  {item.message}")
        if item.remediation:
            lines.append(f"  Fix: {item.remediation}")
    if not result.findings:
        lines.append("\nNo unsupported claims or repository/documentation mismatches found.")
    return "\n".join(lines)


def json_report(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def sarif_report(result: ScanResult) -> str:
    rules = {}
    for finding in result.findings:
        rules.setdefault(finding.rule_id, {"id": finding.rule_id, "name": finding.title, "shortDescription": {"text": finding.title}, "help": {"text": finding.remediation}})
    levels = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "RepoTruth", "version": "0.3.0", "informationUri": "https://github.com/flokiss42-source/repotruth", "rules": list(rules.values())}},
            "results": [{
                "ruleId": item.rule_id,
                "level": levels.get(item.severity, "warning"),
                "message": {"text": item.message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.path}, "region": {"startLine": item.line}}}],
            } for item in result.findings],
        }],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def github_report(result: ScanResult) -> str:
    """Render workflow commands that become inline GitHub annotations."""
    levels = {"high": "error", "medium": "warning", "low": "notice", "info": "notice"}

    def escape(value: str) -> str:
        return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")

    lines = []
    for item in result.findings:
        message = escape(f"{item.rule_id}: {item.message} Fix: {item.remediation}")
        lines.append(f"::{levels.get(item.severity, 'warning')} file={escape(item.path)},line={item.line},title={escape(item.title)}::{message}")
    lines.append(f"::notice title=RepoTruth score::Grade {result.grade}, score {result.score}/100, {len(result.findings)} finding(s)")
    return "\n".join(lines)


def html_report(result: ScanResult) -> str:
    cards = []
    for item in result.findings:
        cards.append(f'''<article class="finding {html.escape(item.severity)}"><div class="meta"><b>{html.escape(item.severity.upper())}</b> · {html.escape(item.rule_id)} · {html.escape(item.path)}:{item.line}</div><h3>{html.escape(item.title)}</h3><p>{html.escape(item.message)}</p><p class="fix"><b>Fix:</b> {html.escape(item.remediation)}</p></article>''')
    content = "".join(cards) or '<article class="clean">No unsupported claims found.</article>'
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>RepoTruth report</title><style>
:root{{--bg:#071018;--panel:#101c27;--text:#e8f0f6;--muted:#91a4b5;--accent:#62f5bd}}*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 15% 0,#123047 0,var(--bg) 45%);color:var(--text);font:16px system-ui,sans-serif}}main{{max-width:920px;margin:auto;padding:64px 24px}}header{{display:flex;justify-content:space-between;gap:24px;align-items:end;margin-bottom:36px}}h1{{font-size:48px;margin:0;letter-spacing:-2px}}.score{{font-size:64px;font-weight:800;color:var(--accent)}}.sub,.meta{{color:var(--muted)}}.finding,.clean{{background:rgba(16,28,39,.92);border:1px solid #263746;border-left:5px solid #91a4b5;border-radius:14px;padding:20px;margin:14px 0;box-shadow:0 14px 40px #0004}}.finding.high{{border-left-color:#ff5f68}}.finding.medium{{border-left-color:#ffc857}}.finding.low{{border-left-color:#50c8ff}}h3{{margin:8px 0}}p{{line-height:1.55}}.fix{{color:#c8d7e3}}code{{color:var(--accent)}}@media(max-width:600px){{header{{display:block}}h1{{font-size:36px}}}}
</style></head><body><main><header><div><h1>RepoTruth</h1><div class="sub">Evidence report for <code>{html.escape(result.root.name)}</code> · grade {result.grade}</div></div><div class="score">{result.score}</div></header>{content}</main></body></html>'''
