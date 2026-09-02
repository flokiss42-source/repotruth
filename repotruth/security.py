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
SCAN_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".php", ".json", ".yml", ".yaml", ".toml", ".env", ".ini", ".cfg", ".sh", ".ps1"}
TEST_MARKERS = ("test_", "_test.", ".test.", ".spec.")
VENDOR_DIRS = {"vendor", "vendors", "third_party", "third-party", "bower_components"}


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


def _is_test(root: Path, path: Path) -> bool:
    relative = path.relative_to(root)
    return any(part.lower() in {"test", "tests", "spec", "specs", "fixtures"} for part in relative.parts) or any(marker in path.name.lower() for marker in TEST_MARKERS)


def _is_vendored(root: Path, path: Path) -> bool:
    relative = path.relative_to(root)
    parts = {part.lower() for part in relative.parts}
    return bool(parts & VENDOR_DIRS) or path.name.lower().endswith((".min.js", ".bundle.js")) or "/static/js/libs/" in f"/{relative.as_posix().lower()}/"


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
                if name in {("eval",), ("exec",)} and node.args and isinstance(node.args[0], ast.Constant):
                    continue
                rule, severity, title, fix = dangerous[name]
                effective_severity = "info" if _is_test(root, path) else severity
                findings.append(Finding(rule, effective_severity, title, f"Call to {'.'.join(name)} requires a trust-boundary review.", _relative(root, path), node.lineno, ".".join(name), fix))
            if name in {("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call")}:
                shell_true = any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)
                if shell_true:
                    findings.append(Finding("RT112", "info" if _is_test(root, path) else "high", "Subprocess uses shell=True", "Shell parsing can turn untrusted text into command execution.", _relative(root, path), node.lineno, "shell=True", "Pass an argument list with shell=False and validate external input."))
    return findings[:30]


def _attribute_name(node: ast.AST) -> tuple[str, ...]:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return tuple(reversed(parts))


def _expression_origins(node: ast.AST, origins: dict[str, set[str]]) -> set[str]:
    if isinstance(node, ast.Name):
        return set(origins.get(node.id, set()))
    if isinstance(node, ast.Subscript):
        chain = _attribute_name(node.value)
        if chain in {("os", "environ"), ("environ",)}:
            return {"secret"}
        if chain[:2] in {("request", "args"), ("request", "form"), ("request", "values"), ("request", "json")} or chain == ("sys", "argv"):
            return {"untrusted"}
        return _expression_origins(node.value, origins) | _expression_origins(node.slice, origins)
    if isinstance(node, ast.Call):
        name = _attribute_name(node.func)
        if name in {("input",), ("request", "get_json")} or name[-2:] in {("args", "get"), ("form", "get"), ("values", "get")}:
            return {"untrusted"}
        if name in {("os", "getenv"), ("getenv",)}:
            return {"secret"}
        found: set[str] = _expression_origins(node.func.value, origins) if isinstance(node.func, ast.Attribute) else set()
        for item in [*node.args, *(keyword.value for keyword in node.keywords)]:
            found |= _expression_origins(item, origins)
        return found
    if isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare, ast.JoinedStr, ast.FormattedValue, ast.List, ast.Tuple, ast.Dict, ast.Set)):
        found: set[str] = set()
        for child in ast.iter_child_nodes(node):
            found |= _expression_origins(child, origins)
        return found
    if isinstance(node, ast.UnaryOp):
        return _expression_origins(node.operand, origins)
    return set()


def _contextual_python_findings(root: Path, files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        if path.suffix.lower() != ".py":
            continue
        text = _read(path)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        origins: dict[str, set[str]] = {}
        assignments = [node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))]
        for _ in range(4):
            changed = False
            for node in assignments:
                value = getattr(node, "value", None)
                if value is None:
                    continue
                value_origins = _expression_origins(value, origins)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and value_origins - origins.get(target.id, set()):
                        origins.setdefault(target.id, set()).update(value_origins)
                        changed = True
            if not changed:
                break
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _attribute_name(node.func)
            arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
            argument_origins: set[str] = set()
            for argument in arguments:
                argument_origins |= _expression_origins(argument, origins)
            sink = None
            if name in {("eval",), ("exec",), ("os", "system"), ("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call")}:
                sink = "code or command execution"
            elif name and name[-1] in {"execute", "executemany"}:
                sink = "SQL execution"
            if sink and "untrusted" in argument_origins:
                findings.append(Finding("RT150", "high", "Untrusted data reaches a dangerous sink", f"User-controlled data flows into {sink} without a visible validation boundary.", _relative(root, path), node.lineno, ".".join(name), "Validate against an allowlist and pass structured values instead of executable text."))
            network_sink = name in {("requests", "get"), ("requests", "post"), ("requests", "put"), ("urllib", "request", "urlopen"), ("urlopen",)}
            if network_sink and "secret" in argument_origins:
                findings.append(Finding("RT151", "high", "Sensitive environment data reaches the network", "A value originating from the process environment flows into an outbound network request.", _relative(root, path), node.lineno, ".".join(name), "Send only the minimum required credential in an explicit authentication field and verify the destination."))
    return findings[:30]


def _javascript_findings(root: Path, files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx"} or _is_vendored(root, path):
            continue
        text = _read(path)
        imports_shell = bool(re.search(r"(?:from\s+['\"](?:node:)?child_process['\"]|require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\))", text))
        patterns = [
            ("RT110", "high", "Dynamic code execution", re.compile(r"\b(?:eval|Function)\s*\("), "Avoid runtime evaluation of strings."),
            ("RT113", "medium", "TLS verification disabled", re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"), "Restore certificate verification."),
        ]
        if imports_shell:
            patterns.append(("RT112", "high", "Shell command execution", re.compile(r"(?<![.\w])(?:exec|execSync)\s*\(|(?:child_process|childProcess)\s*\.\s*(?:exec|execSync)\s*\(|require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)\s*\.\s*(?:exec|execSync)\s*\("), "Use spawn/execFile with an argument list and validate input."))
        for rule, severity, title, pattern, fix in patterns:
            for match in pattern.finditer(text):
                findings.append(Finding(rule, "info" if _is_test(root, path) else severity, title, "Security-sensitive JavaScript construct requires review.", _relative(root, path), _line(text, match.start()), match.group(0), fix))
    return findings[:30]


def _java_findings(root: Path, files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    patterns = (
        ("RT112", "high", "Shell command execution", re.compile(r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|new\s+ProcessBuilder\s*\("), "Use a fixed executable and validated argument list; never pass request data to a shell."),
        ("RT111", "high", "Unsafe Java deserialization", re.compile(r"\bObjectInputStream\b|\.\s*readObject\s*\("), "Avoid native deserialization of untrusted objects; use a constrained data format."),
        ("RT114", "medium", "Dynamic script evaluation", re.compile(r"\bScriptEngineManager\b|\.\s*eval\s*\("), "Do not evaluate user-controlled expressions or scripts."),
    )
    for path in files:
        if path.suffix.lower() not in {".java", ".kt"} or _is_vendored(root, path):
            continue
        text = _read(path)
        for rule, severity, title, pattern, fix in patterns:
            for match in pattern.finditer(text):
                findings.append(Finding(rule, "info" if _is_test(root, path) else severity, title, "Security-sensitive Java construct requires review.", _relative(root, path), _line(text, match.start()), match.group(0)[:120], fix))
    return findings[:30]


def _php_findings(root: Path, files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    patterns = (
        ("RT110", "high", "Dynamic code execution", re.compile(r"(?i)(?<![\w>])eval\s*\("), "Remove eval and dispatch only explicitly supported operations."),
        ("RT112", "high", "Shell command execution", re.compile(r"(?i)(?<![\w>])(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\("), "Use a fixed executable and validated arguments; do not pass request data to a shell."),
        ("RT111", "high", "Unsafe PHP deserialization", re.compile(r"(?i)(?<![\w>])unserialize\s*\("), "Do not deserialize untrusted PHP objects; use JSON and an explicit schema."),
        ("RT115", "high", "Request-controlled file inclusion", re.compile(r"(?is)\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)"), "Map user input to an allowlist of local templates instead of including a request value."),
        ("RT116", "high", "Request data reaches SQL query", re.compile(r"(?is)(?:mysqli_query|->\s*query)\s*\([^;\n]{0,300}\$_(?:GET|POST|REQUEST|COOKIE)"), "Use prepared statements with bound parameters."),
    )
    for path in files:
        if path.suffix.lower() != ".php" or _is_vendored(root, path):
            continue
        text = _read(path)
        for rule, severity, title, pattern, fix in patterns:
            for match in pattern.finditer(text):
                findings.append(Finding(rule, "info" if _is_test(root, path) else severity, title, "Security-sensitive PHP construct requires review.", _relative(root, path), _line(text, match.start()), match.group(0)[:120], fix))
    return findings[:40]


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
    return _secret_findings(root, files) + _python_findings(root, files) + _contextual_python_findings(root, files) + _javascript_findings(root, files) + _java_findings(root, files) + _php_findings(root, files) + _dependency_findings(root) + _obfuscation_findings(root, files)
