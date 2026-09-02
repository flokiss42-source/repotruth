from __future__ import annotations

import json
import io
import fnmatch
import re
import tokenize
from pathlib import Path
from urllib.parse import unquote, urlparse

from .models import Finding, ScanResult
from .security import security_findings


IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "coverage", ".next"}
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".rb", ".php"}
TEST_MARKERS = ("test_", "_test.", ".test.", ".spec.")
VENDOR_DIRS = {"vendor", "vendors", "third_party", "third-party", "bower_components", "libs", "plugins"}


def _load_config(root: Path, config_path: str | Path | None) -> tuple[dict, list[Finding]]:
    path = Path(config_path) if config_path else root / ".repotruth.json"
    if not path.is_absolute():
        path = root / path
    if not path.exists():
        return {}, []
    try:
        data = json.loads(_read(path))
        if not isinstance(data, dict):
            raise ValueError("configuration root must be a JSON object")
        return data, []
    except (json.JSONDecodeError, ValueError) as exc:
        try:
            display = path.relative_to(root).as_posix()
        except ValueError:
            display = str(path)
        return {}, [Finding("RT010", "high", "Invalid RepoTruth configuration", f"Could not parse configuration: {exc}", display, 1, "", "Fix the JSON syntax and configuration shape.")]


def _contract_findings(root: Path, config: dict) -> list[Finding]:
    findings: list[Finding] = []
    contracts = config.get("contracts", [])
    if not isinstance(contracts, list):
        return [Finding("RT010", "high", "Invalid contracts configuration", "'contracts' must be a JSON array.", ".repotruth.json", 1, "", "Use an array of evidence contract objects.")]
    for index, contract in enumerate(contracts):
        if not isinstance(contract, dict):
            findings.append(Finding("RT010", "high", "Invalid evidence contract", f"Contract #{index + 1} must be an object.", ".repotruth.json", 1))
            continue
        contract_id = str(contract.get("id", f"contract-{index + 1}"))
        claim = str(contract.get("claim", contract_id))
        evidence = contract.get("evidence", [])
        mode = contract.get("require", "all")
        severity = contract.get("severity", "high")
        if not isinstance(evidence, list) or not evidence or mode not in {"all", "any"} or severity not in {"info", "low", "medium", "high"}:
            findings.append(Finding("RT010", "high", "Invalid evidence contract", f"Contract '{contract_id}' needs a non-empty evidence array and require='all' or 'any'.", ".repotruth.json", 1, contract_id, "Correct the contract fields."))
            continue
        unsafe = [str(pattern) for pattern in evidence if Path(str(pattern)).is_absolute() or ".." in Path(str(pattern)).parts]
        if unsafe:
            findings.append(Finding("RT010", "high", "Unsafe evidence path", f"Contract '{contract_id}' references evidence outside the repository: {', '.join(unsafe)}", ".repotruth.json", 1, contract_id, "Use repository-relative glob patterns without '..'."))
            continue
        matches = {pattern: [path for path in root.glob(str(pattern)) if path.is_file()] for pattern in evidence}
        satisfied = all(matches.values()) if mode == "all" else any(matches.values())
        if not satisfied:
            missing = [pattern for pattern, found in matches.items() if not found]
            findings.append(Finding("RT009", str(severity), "Evidence contract is broken", f"Claim '{claim}' lost required evidence ({mode}): {', '.join(map(str, missing))}", ".repotruth.json", 1, contract_id, "Restore the evidence or update the claim and contract."))
    return findings


def _ignored(finding: Finding, config: dict) -> bool:
    ignores = config.get("ignore", [])
    if not isinstance(ignores, list):
        return False
    for item in ignores:
        if not isinstance(item, dict):
            continue
        rule_matches = item.get("rule", "*") in {"*", finding.rule_id}
        path_matches = fnmatch.fnmatch(finding.path, str(item.get("path", "*")))
        if rule_matches and path_matches:
            return True
    return False


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


def _is_vendored(root: Path, path: Path) -> bool:
    relative = path.relative_to(root)
    return bool({part.lower() for part in relative.parts} & VENDOR_DIRS) or path.name.lower().endswith((".min.js", ".bundle.js"))


def _readme(root: Path) -> tuple[Path | None, str]:
    preferred = {"readme.md": 0, "readme.rst": 1, "readme.txt": 2, "readme": 3}
    candidates = [path for path in root.iterdir() if path.is_file() and path.name.lower() in preferred]
    for path in sorted(candidates, key=lambda item: preferred[item.name.lower()]):
        return path, _read(path)
    return None, ""


def _broken_local_links(root: Path, readme: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
    for match in pattern.finditer(text):
        raw = match.group(1).strip().split(maxsplit=1)[0].strip("<>\"'")
        if "{" in raw or "}" in raw:
            continue
        parsed = urlparse(raw)
        if parsed.scheme or raw.startswith(("#", "mailto:")):
            continue
        target_text = unquote(parsed.path)
        # GitHub treats /path links as repository-root relative links.
        target = ((root if target_text.startswith("/") else readme.parent) / target_text.lstrip("/")).resolve()
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
        relative = path.relative_to(root)
        if path.suffix.lower() not in SOURCE_SUFFIXES or _is_vendored(root, path) or any(part in {"tests", "test", "examples", "_examples"} for part in relative.parts) or any(marker in path.name.lower() for marker in TEST_MARKERS):
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


def scan_repository(path: str | Path, config_path: str | Path | None = None, verify: bool = False, online: bool = False) -> ScanResult:
    root = Path(path).resolve()
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")
    result = ScanResult(root)
    config, config_findings = _load_config(root, config_path)
    result.findings.extend(config_findings)
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

    result.findings.extend(_contract_findings(root, config))
    result.findings.extend(security_findings(root, files))
    osv_status = {"status": "disabled", "packages_checked": 0}
    if online:
        from .vulnerabilities import osv_findings

        osv_results, osv_status = osv_findings(root)
        result.findings.extend(osv_results)
    result.findings = [finding for finding in result.findings if not _ignored(finding, config)]

    result.findings.sort(key=lambda item: ({"high": 0, "medium": 1, "low": 2, "info": 3}.get(item.severity, 4), item.path, item.line, item.rule_id))
    result.facts = {
        "files_scanned": len(files),
        "readme": readme.name if readme else None,
        "test_files": sum(1 for path in files if any(marker in path.name.lower() for marker in TEST_MARKERS) or "tests" in path.parts),
        "ci_workflows": sum(1 for path in files if path.relative_to(root).as_posix().startswith(".github/workflows/")),
        "evidence_contracts": len(config.get("contracts", [])) if isinstance(config.get("contracts", []), list) else 0,
        "security_findings": sum(1 for finding in result.findings if finding.rule_id.startswith("RT1")),
        "vulnerability_database": osv_status,
    }
    if verify:
        from .runtime import verify_runtime

        runtime = verify_runtime(root)
        result.facts["runtime"] = runtime.to_dict()
        if runtime.status == "failed":
            result.findings.append(Finding("RT200", "high", "Sandbox runtime check failed", f"The detected verification command exited with code {runtime.exit_code}.", ".", 1, " ".join(runtime.command or []), "Reproduce the command in a development environment and fix the failing build or tests."))
        elif runtime.status == "timeout":
            result.findings.append(Finding("RT201", "medium", "Sandbox runtime check timed out", runtime.reason, ".", 1, " ".join(runtime.command or []), "Make the verification command deterministic and faster."))
        result.findings.sort(key=lambda item: ({"high": 0, "medium": 1, "low": 2, "info": 3}.get(item.severity, 4), item.path, item.line, item.rule_id))
    from .benchmark import local_benchmark

    result.facts["benchmark"] = local_benchmark(root, result.score).to_dict()
    return result
