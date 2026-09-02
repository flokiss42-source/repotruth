from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class ProposedFile:
    path: str
    reason: str
    content: str


def propose_fixes(root: Path) -> list[ProposedFile]:
    proposals: list[ProposedFile] = []
    name = root.name
    if not any((root / item).is_file() for item in ("README.md", "README.rst", "README.txt", "readme.md")):
        proposals.append(ProposedFile("README.md", "Document the project and its trust boundary", f"# {name}\n\nDescribe what this project does, who it is for, and its current maturity.\n\n## Run\n\nAdd reproducible installation and run commands here.\n\n## Security\n\nDo not commit credentials. Report vulnerabilities according to `SECURITY.md`.\n"))
    if not (root / "SECURITY.md").is_file():
        proposals.append(ProposedFile("SECURITY.md", "Provide a vulnerability reporting policy", "# Security policy\n\nPlease do not disclose vulnerabilities publicly before a fix is available.\n\nOpen a private security advisory in this repository and include reproduction steps, affected versions, and impact.\n"))
    github = root / ".github"
    if not (github / "dependabot.yml").is_file():
        ecosystems = []
        if (root / "package.json").is_file():
            ecosystems.append("npm")
        if any((root / item).is_file() for item in ("requirements.txt", "pyproject.toml", "setup.py")):
            ecosystems.append("pip")
        if ecosystems:
            entries = "".join(f'  - package-ecosystem: "{ecosystem}"\n    directory: "/"\n    schedule:\n      interval: "weekly"\n' for ecosystem in ecosystems)
            proposals.append(ProposedFile(".github/dependabot.yml", "Track vulnerable and outdated dependencies", f"version: 2\nupdates:\n{entries}"))
    return proposals


def render_fix_plan(root: Path, proposals: list[ProposedFile]) -> str:
    if not proposals:
        return "No safe repository scaffolding fixes are available."
    lines = [f"RepoTruth proposes {len(proposals)} new file(s) for {root}:"]
    for item in proposals:
        lines.extend((f"\n+++ {item.path}", f"Reason: {item.reason}", item.content.rstrip()))
    return "\n".join(lines)


def apply_fixes(root: Path, proposals: list[ProposedFile]) -> list[Path]:
    created: list[Path] = []
    for item in proposals:
        destination = (root / item.path).resolve()
        destination.relative_to(root.resolve())
        if destination.exists():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(item.content, encoding="utf-8", newline="\n")
        created.append(destination)
    return created


def create_pull_request(root: Path) -> str:
    git = shutil.which("git")
    gh = shutil.which("gh")
    if not git:
        raise RuntimeError("Git is not installed or not available in PATH.")
    if not gh:
        windows_gh = Path("C:/Program Files/GitHub CLI/gh.exe")
        gh = str(windows_gh) if windows_gh.is_file() else None
    if not gh:
        raise RuntimeError("GitHub CLI is not installed or not available in PATH.")
    status = subprocess.run([git, "status", "--porcelain"], cwd=root, capture_output=True, text=True, check=True)
    if status.stdout.strip():
        raise RuntimeError("Refusing to create a PR from a dirty worktree. Commit or stash existing changes first.")
    proposals = propose_fixes(root)
    if not proposals:
        raise RuntimeError("No safe fixes are available for this repository.")
    branch = "repotruth/hardening-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    subprocess.run([git, "switch", "-c", branch], cwd=root, check=True)
    created = apply_fixes(root, proposals)
    try:
        subprocess.run([git, "add", "--", *[str(path.relative_to(root)) for path in created]], cwd=root, check=True)
        subprocess.run([git, "commit", "-m", "chore: add RepoTruth security scaffolding"], cwd=root, check=True)
        subprocess.run([git, "push", "-u", "origin", branch], cwd=root, check=True)
        completed = subprocess.run([gh, "pr", "create", "--fill", "--title", "chore: RepoTruth security hardening"], cwd=root, capture_output=True, text=True, check=True)
        return completed.stdout.strip()
    except Exception:
        raise RuntimeError(f"PR creation stopped on branch {branch}; generated work was preserved for inspection.")
