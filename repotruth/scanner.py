from __future__ import annotations

import json
import io
import re
import tokenize
from pathlib import Path
from urllib.parse import unquote, urlparse

from .models import Finding, ScanResult


IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "coverage", ".next"}
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".rb"}
TEST_MARKERS = ("test_", "_test.", ".test.", ".spec.")


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _files(root: Path) -> list[Path]:
    return [
        path
        for path in root.rglob("*")
        if path.is_file() and not any(part in IGNORED_DIRS for part in path.relative_to(root).parts)
    ]


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ""


def _readme(root: Path) -> tuple[Path | None, str]:
    for name in ("README.md", "README.rst", "README.txt", "readme.md"):
        path = root / name
        if path.is_file():
            return path, _read(path)
    return None, ""


def _broken_local_links(root: Path, readme: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
    for match in pattern.finditer(text):
        raw = match.group(1).strip().split(maxsplit=1)[0].strip("<>\"'")
        parsed = urlparse(raw)
        if parsed.scheme or raw.startswith(("#", "mailto:")):
            continue
        target_text = unquote(parsed.path).replace("/", str(Path("/")).replace("\\", "/"))
        target = (readme.parent / target_text).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError:
            findings.append(Finding("RT001", "high", "Documentation link escapes repository", f"Local link points outside the repository: {raw}", readme.name, _line_number(text, match.start()), raw, "Use a repository-relative path."))
            continue
        if not target.exists():
            findings.append(Finding("RT001", "medium", "Broken local documentation link", f"README links to a file that does not exist: {raw}", readme.name, _line_number(text, match.start()), raw, "Create the target or correct the link."))
    return findings


def _package_scripts(root: Path) -> dict[str, str]:
    package = root / "package.json"
    if not package.is_file():
        return {}
    try:
        data = json.loads(_read(package))
        scripts = data.get("scripts", {})
        return scripts if isinstance(scripts, dict) else {}
    except json.JSONDecodeError:
        return {}


def _documented_commands(root: Path, readme: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    scripts = _package_scripts(root)
    fenced = re.compile(r"```(?:bash|sh|shell|powershell|console)?\s*\n(.*?)```", re.I | re.S)
    npm_pattern = re.compile(r"(?:npm\s+run|pnpm\s+run|yarn)\s+([\w:-]+)")
    python_pattern = re.compile(r"python(?:3)?\s+([^\s]+\.py)")
    for block in fenced.finditer(text):
        body = block.group(1)
        base_line = _line_number(text, block.start(1))
        for match in npm_pattern.finditer(body):
            script = match.group(1)
            if scripts and script not in scripts:
                findings.append(Finding("RT002", "high", "Documented package command is missing", f"README tells users to run '{script}', but package.json has no such script.", readme.name, base_line + body.count("\n", 0, match.start()), match.group(0), f"Add scripts.{script} or update the README."))
        for match in python_pattern.finditer(body):
            raw = match.group(1).strip("'\"")
            if not (root / raw).is_file():
                findings.append(Finding("RT003", "high", "Documented Python entry file is missing", f"README invokes a Python file that does not exist: {raw}", readme.name, base_line + body.count("\n", 0, match.start()), match.group(0), "Add the file or correct the command."))
    return findings


def _claim_findings(root: Path, readme: Path, text: str, files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    lower = text.lower()
    relative_names = {path.relative_to(root).as_posix().lower() for path in files}
    test_files = [name for name in relative_names if any(marker in Path(name).name for marker in TEST_MARKERS) or name.startswith("tests/")]
    security_evidence = any(name in relative_names for name in ("security.md", ".github/security.md")) or any("security" in name and "test" in name for name in relative_names)
    license_files = [name for name in relative_names if Path(name).name.startswith(("license", "licence", "copying"))]

    claim_rules = [
        ("RT004", r"\b(?:production[- ]ready|готов(?:о|ый) к продакшену|боев(?:ой|ая) готовност)\b", "high", "Production-ready claim lacks release evidence", lambda: bool(test_files) and any(name.startswith(".github/workflows/") for name in relative_names), "Add automated tests and CI evidence, or narrow the claim."),
        ("RT005", r"\b(?:secure|security[- ]first|безопасн(?:ый|ость)|защищ[её]н)\b", "medium", "Security claim lacks a security artifact", lambda: security_evidence, "Add SECURITY.md, a threat model, or security tests."),
        ("RT006", r"\b(?:fully tested|comprehensive tests|полностью протестирован|100%\s+(?:test|coverage|покрыт))\b", "high", "Testing claim has no visible tests", lambda: bool(test_files), "Commit the tests that support this claim."),
        ("RT007", r"\b(?:MIT licensed|MIT license|лицензия MIT)\b", "medium", "License claim has no license file", lambda: bool(license_files), "Add a LICENSE file containing the stated license."),
    ]
    for rule_id, pattern, severity, title, has_evidence, remediation in claim_rules:
        for match in re.finditer(pattern, text, re.I):
            if not has_evidence():
                findings.append(Finding(rule_id, severity, title, f"Claim found without the minimum repository evidence: '{match.group(0)}'.", readme.name, _line_number(text, match.start()), match.group(0), remediation))
                break
    return findings


def _placeholder_findings(root: Path, files: list[Path], production_claimed: bool) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        (re.compile(r"\braise\s+NotImplementedError\b"), "NotImplementedError"),
        (re.compile(r"\bTODO\b|\bFIXME\b", re.I), "TODO/FIXME"),
        (re.compile(r"console\.log\([^\n]*(?:debug|todo|placeholder)", re.I), "debug placeholder"),
    ]
    limit = 12
    for path in files:
        if path.suffix.lower() not in SOURCE_SUFFIXES or any(part in {"tests", "test", "examples"} for part in path.relative_to(root).parts):
            continue
        body = _read(path)
        if path.suffix.lower() == ".py":
            try:
                tokens = tokenize.generate_tokens(io.StringIO(body).readline)
                python_hits = []
                for token in tokens:
                    if token.type == tokenize.NAME and token.string == "NotImplementedError":
                        python_hits.append((token.start[0], "NotImplementedError", token.string))
                    elif token.type == tokenize.COMMENT and re.search(r"\b(?:TODO|FIXME)\b", token.string, re.I):
                        python_hits.append((token.start[0], "TODO/FIXME", token.string.strip()))
                for line, label, evidence in python_hits:
                    severity = "medium" if production_claimed else "low"
                    findings.append(Finding("RT008", severity, "Implementation placeholder found", f"Source contains {label}; this may contradict completeness claims.", path.relative_to(root).as_posix(), line, evidence[:120], "Implement it, move it to an issue, or document the limitation."))
                    if len(findings) >= limit:
                        return findings
            except (tokenize.TokenError, IndentationError):
                pass
            continue
        for pattern, label in patterns:
            for match in pattern.finditer(body):
                severity = "medium" if production_claimed else "low"
                findings.append(Finding("RT008", severity, "Implementation placeholder found", f"Source contains {label}; this may contradict completeness claims.", path.relative_to(root).as_posix(), _line_number(body, match.start()), match.group(0)[:120], "Implement it, move it to an issue, or document the limitation."))
                if len(findings) >= limit:
                    return findings
    return findings


def scan_repository(path: str | Path) -> ScanResult:
    root = Path(path).resolve()
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")
    result = ScanResult(root)
    files = _files(root)
    readme, text = _readme(root)
    if readme is None:
        result.findings.append(Finding("RT000", "high", "README is missing", "No README file was found.", ".", 1, "", "Add a README that documents the project honestly."))
    else:
        result.findings.extend(_broken_local_links(root, readme, text))
        result.findings.extend(_documented_commands(root, readme, text))
        result.findings.extend(_claim_findings(root, readme, text, files))
        production_claimed = bool(re.search(r"production[- ]ready|готов(?:о|ый) к продакшену", text, re.I))
        result.findings.extend(_placeholder_findings(root, files, production_claimed))

    result.findings.sort(key=lambda item: ({"high": 0, "medium": 1, "low": 2, "info": 3}.get(item.severity, 4), item.path, item.line, item.rule_id))
    result.facts = {
        "files_scanned": len(files),
        "readme": readme.name if readme else None,
        "test_files": sum(1 for path in files if any(marker in path.name.lower() for marker in TEST_MARKERS) or "tests" in path.parts),
        "ci_workflows": sum(1 for path in files if path.relative_to(root).as_posix().startswith(".github/workflows/")),
    }
    return result
