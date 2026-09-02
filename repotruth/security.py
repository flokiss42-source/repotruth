from __future__ import annotations

import ast
import json
import math
import re
from pathlib import Path

from .models import Finding


TEXT_LIMIT = 2 * 1024 * 1024
SECRET_PATTERNS = (
    ("RT100", "high", "GitHub token exposed", re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("RT100", "high", "AWS access key exposed", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("RT100", "high", "Private key committed", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("RT100", "high", "Generic API secret exposed", re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"]([A-Za-z0-9_./+\-=]{16,})['\"]")),
)
SAFE_EXAMPLE_MARKERS = ("example", "sample", "placeholder", "your_", "changeme", "dummy", "test")
SCAN_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".toml", ".env", ".ini", ".cfg", ".sh", ".ps1"}


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > TEXT_LIMIT:
            return ""
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _redact(value: str) -> str:
    clean = value.replace("\n", " ")
    if len(clean) < 10:
        return "[redacted]"
    return f"{clean[:4]}…{clean[-4:]}"


def _secret_findings(root: Path, files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        relative = _relative(root, path)
        if path.suffix.lower() not in SCAN_SUFFIXES and path.name not in {".env", ".npmrc", ".pypirc"}:
            continue
        text = _read(path)
        for rule, severity, title, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                raw = match.group(1) if match.lastindex else match.group(0)
                context = text[max(0, match.start() - 40):match.end() + 20].lower()
                if any(marker in raw.lower() or marker in context for marker in SAFE_EXAMPLE_MARKERS):
                    continue
                findings.append(Finding(rule, severity, title, "A credential-shaped value is committed to the repository.", relative, _line(text, match.start()), _redact(raw), "Revoke the credential, remove it from Git history, and load it from a secret store."))
                if len(findings) >= 20:
                    return findings
    return findings


def _python_findings(root: Path, files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    dangerous = {
        ("eval",): ("RT110", "high", "Dynamic code execution", "Avoid eval; parse an explicit data format."),
        ("exec",): ("RT110", "high", "Dynamic code execution", "Avoid exec; call explicit functions."),
        ("pickle", "loads"): ("RT111", "high", "Unsafe deserialization", "Do not unpickle untrusted data; use JSON or a schema-based format."),
        ("yaml", "load"): ("RT111", "medium", "Potentially unsafe YAML loading", "Use yaml.safe_load for untrusted YAML."),
        ("os", "system"): ("RT112", "medium", "Shell command execution", "Use subprocess with an argument list and validate all input."),
    }
    for path in files:
        if path.suffix.lower() != ".py":
            continue
        text = _read(path)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name: tuple[str, ...] = ()
            if isinstance(node.func, ast.Name):
                name = (node.func.id,)
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                name = (node.func.value.id, node.func.attr)
            if name in dangerous:
                rule, severity, title, fix = dangerous[name]
                findings.append(Finding(rule, severity, title, f"Call to {'.'.join(name)} requires a trust-boundary review.", _relative(root, path), node.lineno, ".".join(name), fix))
            if name in {("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call")}:
                shell_true = any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)
                if shell_true:
                    findings.append(Finding("RT112", "high", "Subprocess uses shell=True", "Shell parsing can turn untrusted text into command execution.", _relative(root, path), node.lineno, "shell=True", "Pass an argument list with shell=False and validate external input."))
    return findings[:30]


def _javascript_findings(root: Path, files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    patterns = (
        ("RT110", "high", "Dynamic code execution", re.compile(r"\b(?:eval|Function)\s*\("), "Avoid runtime evaluation of strings."),
        ("RT112", "high", "Shell command execution", re.compile(r"\b(?:exec|execSync)\s*\("), "Use spawn/execFile with an argument list and validate input."),
        ("RT113", "medium", "TLS verification disabled", re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"), "Restore certificate verification."),
    )
    for path in files:
        if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx"}:
            continue
        text = _read(path)
        for rule, severity, title, pattern, fix in patterns:
            for match in pattern.finditer(text):
                findings.append(Finding(rule, severity, title, "Security-sensitive JavaScript construct requires review.", _relative(root, path), _line(text, match.start()), match.group(0), fix))
    return findings[:30]


def _dependency_findings(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    package = root / "package.json"
    if package.is_file():
        try:
            data = json.loads(_read(package))
        except json.JSONDecodeError:
            data = {}
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        for name in ("preinstall", "install", "postinstall", "prepare"):
            if isinstance(scripts, dict) and name in scripts:
                findings.append(Finding("RT120", "medium", "Package lifecycle script executes on install", f"npm script '{name}' runs automatically during installation.", "package.json", 1, str(scripts[name])[:160], "Review the command; remove it if installation does not require code execution."))
        for group in ("dependencies", "devDependencies", "optionalDependencies"):
            dependencies = data.get(group, {}) if isinstance(data, dict) else {}
            if not isinstance(dependencies, dict):
                continue
            for name, version in dependencies.items():
                value = str(version)
                if value in {"*", "latest", "next"} or value.startswith(("git+", "http:", "https:", "github:")):
                    findings.append(Finding("RT121", "medium", "Unverifiable dependency source", f"{name} uses a floating or non-registry source: {value}", "package.json", 1, f"{name}: {value}", "Pin an audited registry version and commit the lockfile."))
        if data.get("dependencies") and not any((root / name).is_file() for name in ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock")):
            findings.append(Finding("RT122", "medium", "JavaScript lockfile is missing", "Dependency resolution is not reproducible.", "package.json", 1, "", "Generate and commit the lockfile used by your package manager."))
    requirements = root / "requirements.txt"
    if requirements.is_file():
        for number, raw in enumerate(_read(requirements).splitlines(), 1):
            value = raw.strip()
            if not value or value.startswith(("#", "-r", "--")):
                continue
            if "==" not in value or value.startswith(("git+", "http:", "https:")):
                findings.append(Finding("RT123", "low", "Python dependency is not exactly pinned", f"Requirement may resolve differently over time: {value}", "requirements.txt", number, value[:160], "Pin an audited version with == and use hashes for high-assurance builds."))
    return findings[:30]


def _obfuscation_findings(root: Path, files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    blob = re.compile(r"['\"]([A-Za-z0-9+/]{500,}={0,2})['\"]")
    for path in files:
        if path.suffix.lower() not in {".py", ".js", ".ts", ".ps1"}:
            continue
        text = _read(path)
        match = blob.search(text)
        if match:
            sample = match.group(1)
            counts = {char: sample.count(char) for char in set(sample)}
            entropy = -sum((count / len(sample)) * math.log2(count / len(sample)) for count in counts.values())
            if entropy > 4.5:
                findings.append(Finding("RT130", "medium", "Large encoded payload in source", "A high-entropy encoded blob can conceal executable behavior.", _relative(root, path), _line(text, match.start()), f"encoded blob ({len(sample)} chars)", "Decode and review it; store legitimate binary assets as files with provenance."))
    return findings


def security_findings(root: Path, files: list[Path]) -> list[Finding]:
    return _secret_findings(root, files) + _python_findings(root, files) + _javascript_findings(root, files) + _dependency_findings(root) + _obfuscation_findings(root, files)

