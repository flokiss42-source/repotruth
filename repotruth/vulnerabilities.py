from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.request import Request, urlopen

from .models import Finding


OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch"
EXACT = re.compile(r"^[v=]?([0-9][0-9A-Za-z.+-]*)$")


def _packages(root: Path) -> list[tuple[str, str, str, str, int]]:
    packages: list[tuple[str, str, str, str, int]] = []
    package_lock = root / "package-lock.json"
    if package_lock.is_file():
        try:
            data = json.loads(package_lock.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        for key, value in data.get("packages", {}).items() if isinstance(data, dict) else ():
            if key.startswith("node_modules/") and isinstance(value, dict) and value.get("version"):
                packages.append(("npm", key.removeprefix("node_modules/"), str(value["version"]), "package-lock.json", 1))
    requirements = root / "requirements.txt"
    if requirements.is_file():
        for line, raw in enumerate(requirements.read_text(encoding="utf-8").splitlines(), 1):
            match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;]+)", raw.strip())
            if match:
                packages.append(("PyPI", match.group(1), match.group(2), "requirements.txt", line))
    return packages[:500]


def osv_findings(root: Path) -> tuple[list[Finding], dict]:
    packages = _packages(root)
    if not packages:
        return [], {"status": "not_applicable", "packages_checked": 0}
    queries = [{"package": {"ecosystem": ecosystem, "name": name}, "version": version} for ecosystem, name, version, _, _ in packages]
    request = Request(OSV_ENDPOINT, data=json.dumps({"queries": queries}).encode(), headers={"Content-Type": "application/json", "User-Agent": "RepoTruth/0.4"}, method="POST")
    try:
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read(8 * 1024 * 1024))
    except Exception as exc:
        return [], {"status": "unavailable", "packages_checked": 0, "reason": type(exc).__name__}
    findings: list[Finding] = []
    vulnerable = 0
    for package, result in zip(packages, payload.get("results", [])):
        ecosystem, name, version, path, line = package
        vulns = result.get("vulns", []) if isinstance(result, dict) else []
        if not vulns:
            continue
        vulnerable += 1
        ids = [str(item.get("id", "unknown")) for item in vulns[:8] if isinstance(item, dict)]
        findings.append(Finding("RT140", "high", "Known vulnerable dependency", f"{name} {version} is matched by {len(vulns)} OSV advisory record(s): {', '.join(ids)}", path, line, f"{ecosystem}:{name}@{version}", "Upgrade to a non-affected version and verify the change with tests."))
    return findings, {"status": "complete", "packages_checked": len(packages), "vulnerable_packages": vulnerable, "source": "OSV.dev"}

