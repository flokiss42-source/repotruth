from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SEVERITY_WEIGHT = {"info": 1, "low": 3, "medium": 8, "high": 18}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    path: str = "README.md"
    line: int = 1
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def score(self) -> int:
        # Repeated instances of one rule are useful evidence, but should not let
        # a single noisy pattern dominate the repository's entire score.
        by_rule: dict[str, list[int]] = {}
        for item in self.findings:
            by_rule.setdefault(item.rule_id, []).append(SEVERITY_WEIGHT.get(item.severity, 3))
        penalty = sum(min(sum(weights), max(weights) * 2) for weights in by_rule.values())
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        score = self.score
        return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "score": self.score,
            "grade": self.grade,
            "facts": self.facts,
            "findings": [item.to_dict() for item in self.findings],
        }
