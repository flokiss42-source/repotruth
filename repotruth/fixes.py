from __future__ import annotations

import shutil
import subprocess
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class ProposedFile:
    path: str
    reason: str
    content: str


@dataclass(frozen=True)
class FixChoice:
    title: str
    change_risk: str
    effort: str
    guidance: str


@dataclass(frozen=True)
class ExplainedFix:
    rule_id: str
    path: str
    line: int
    finding: str
    why: str
    confidence: str
    choices: tuple[FixChoice, ...]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "path": self.path,
            "line": self.line,
            "finding": self.finding,
            "why": self.why,
            "confidence": self.confidence,
            "choices": [item.__dict__ for item in self.choices],
        }


def explain_fixes(root: Path) -> list[ExplainedFix]:
    from .scanner import scan_repository

    result = scan_repository(root)
    explanations: list[ExplainedFix] = []
    for finding in result.findings:
        if finding.rule_id in {"RT150", "RT151"}:
            why = "RepoTruth traced a value from a trust-boundary source to a security-sensitive sink."
            confidence = "high"
            choices = (
                FixChoice("Validate at the boundary", "low", "small", "Constrain the input with an explicit allowlist before it enters application logic."),
                FixChoice("Replace executable text with structured data", "medium", "medium", "Change the sink API to accept typed values or an argument list rather than code, SQL, or a shell string."),
                FixChoice("Remove the dynamic feature", "medium", "large", "Delete the dynamic execution path when it is not essential; this gives the smallest remaining attack surface."),
            )
        elif finding.rule_id in {"RT110", "RT111", "RT112", "RT114", "RT115", "RT116"}:
            why = "The construct is security-sensitive even when its current caller appears controlled; future data-flow changes can make it exploitable."
            confidence = "medium"
            choices = (
                FixChoice("Use the safe API", "low", "small", finding.remediation),
                FixChoice("Add a narrow adapter", "medium", "medium", "Wrap the operation in one reviewed function that validates types, destinations, and allowed values."),
                FixChoice("Document and suppress intentionally", "low", "small", f"If the risk is accepted, add a path-specific {finding.rule_id} ignore with a review note and expiry date."),
            )
        elif finding.rule_id in {"RT120", "RT121", "RT122", "RT123", "RT140"}:
            why = "Dependency installation or resolution can change the code that runs without a corresponding source change."
            confidence = "high" if finding.rule_id == "RT140" else "medium"
            choices = (
                FixChoice("Pin or upgrade", "medium", "small", finding.remediation),
                FixChoice("Isolate the dependency", "low", "medium", "Move it behind a minimal adapter and test the security-relevant behavior before upgrading."),
                FixChoice("Replace the dependency", "high", "large", "Choose a maintained alternative when a safe compatible version is unavailable."),
            )
        else:
            why = "Repository evidence does not currently support the documented claim or expected trust control."
            confidence = "high" if finding.severity == "high" else "medium"
            choices = (
                FixChoice("Restore the evidence", "low", "small", finding.remediation),
                FixChoice("Narrow the claim", "low", "small", "Update documentation so it states only behavior that the committed repository can demonstrate."),
            )
        explanations.append(ExplainedFix(finding.rule_id, finding.path, finding.line, finding.title, why, confidence, choices))
    return explanations


def render_explanations(explanations: list[ExplainedFix], output_format: str = "terminal") -> str:
    if output_format == "json":
        return json.dumps([item.to_dict() for item in explanations], ensure_ascii=False, indent=2)
    if not explanations:
        return "No findings require an explained fix."
    lines: list[str] = []
    for item in explanations:
        lines.extend((f"{item.rule_id} {item.path}:{item.line} - {item.finding}", f"Why: {item.why}", f"Confidence: {item.confidence}"))
        for index, choice in enumerate(item.choices, 1):
            lines.append(f"  {index}. {choice.title} [change-risk={choice.change_risk}, effort={choice.effort}] {choice.guidance}")
        lines.append("")
    return "\n".join(lines).rstrip()


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
