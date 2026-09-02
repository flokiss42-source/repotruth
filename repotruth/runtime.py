from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class RuntimeCheck:
    status: str
    ecosystem: str | None = None
    command: list[str] | None = None
    image: str | None = None
    exit_code: int | None = None
    output: str = ""
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _candidate(root: Path) -> tuple[str, str, list[str]] | None:
    package = root / "package.json"
    if package.is_file():
        try:
            scripts = json.loads(package.read_text(encoding="utf-8")).get("scripts", {})
        except (OSError, json.JSONDecodeError):
            scripts = {}
        if isinstance(scripts, dict) and "test" in scripts and "no test specified" not in str(scripts["test"]).lower():
            return "node", "node:22-alpine", ["npm", "test"]
    if any((root / name).is_dir() for name in ("tests", "test")) and any(root.rglob("test_*.py")):
        return "python", "python:3.13-alpine", ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
    if any(root.glob("*.py")):
        return "python", "python:3.13-alpine", ["python", "-m", "compileall", "-q", "."]
    return None


def verify_runtime(root: Path, timeout: int = 60) -> RuntimeCheck:
    candidate = _candidate(root)
    if candidate is None:
        return RuntimeCheck("not_available", reason="No safe built-in runtime check was detected.")
    ecosystem, image, command = candidate
    docker = shutil.which("docker")
    if not docker:
        return RuntimeCheck("not_available", ecosystem, command, image, reason="Docker is not installed or not available in PATH.")
    image_check = subprocess.run([docker, "image", "inspect", image], capture_output=True, text=True, timeout=10, check=False)
    if image_check.returncode != 0:
        return RuntimeCheck("not_available", ecosystem, command, image, reason=f"Sandbox image {image} is not downloaded. Run: docker pull {image}")
    docker_command = [
        docker, "run", "--rm", "--network", "none", "--read-only", "--pids-limit", "128",
        "--memory", "512m", "--cpus", "1", "--user", "65534:65534", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--mount", f"type=bind,src={root},dst=/repo,readonly", "--workdir", "/repo", image, *command,
    ]
    try:
        completed = subprocess.run(docker_command, capture_output=True, text=True, timeout=max(5, min(timeout, 300)), check=False)
    except subprocess.TimeoutExpired as exc:
        output = ((exc.stdout or "") + "\n" + (exc.stderr or ""))[-4000:]
        return RuntimeCheck("timeout", ecosystem, command, image, output=output, reason=f"Sandbox exceeded {timeout} seconds.")
    output = (completed.stdout + "\n" + completed.stderr).strip()[-4000:]
    return RuntimeCheck("passed" if completed.returncode == 0 else "failed", ecosystem, command, image, completed.returncode, output)
