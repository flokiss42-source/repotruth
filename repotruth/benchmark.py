from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.request import Request, urlopen

from .models import ScanResult


CALIBRATION_SCORES = {
    "python": [58, 71, 79, 86, 92, 96],
    "javascript": [18, 24, 41, 67, 82, 90],
    "go": [72, 82, 88, 94, 98],
    "rust": [78, 88, 95, 100],
    "java": [12, 30, 52, 71, 87],
    "php": [10, 22, 39, 61, 80],
    "unknown": [35, 50, 65, 75, 85],
}


@dataclass(frozen=True)
class BenchmarkResult:
    ecosystem: str
    percentile: int
    cohort_median: int
    delta: int
    verdict: str
    source: str = "bundled-calibration-v1"
    sample_size: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def detect_ecosystem(root: Path) -> str:
    markers = (
        ("javascript", ("package.json",)),
        ("python", ("pyproject.toml", "requirements.txt", "setup.py")),
        ("go", ("go.mod",)),
        ("rust", ("Cargo.toml",)),
        ("java", ("pom.xml", "build.gradle", "build.gradle.kts")),
        ("php", ("composer.json",)),
    )
    for ecosystem, names in markers:
        if any((root / name).is_file() for name in names):
            return ecosystem
    return "unknown"


def local_benchmark(root: Path, score: int) -> BenchmarkResult:
    ecosystem = detect_ecosystem(root)
    cohort = sorted(CALIBRATION_SCORES[ecosystem])
    middle = len(cohort) // 2
    median = cohort[middle] if len(cohort) % 2 else round((cohort[middle - 1] + cohort[middle]) / 2)
    percentile = round(100 * sum(value <= score for value in cohort) / len(cohort))
    delta = score - median
    if score >= 75 and delta >= 0:
        verdict = "trusted-relative"
    elif score >= 75:
        verdict = "caution-below-peers"
    elif delta >= 0:
        verdict = "caution-leading-weak-cohort"
    else:
        verdict = "untrusted-relative"
    return BenchmarkResult(ecosystem, percentile, median, delta, verdict, sample_size=len(cohort))


def submit_benchmark(url: str, result: ScanResult, timeout: int = 10) -> dict:
    local = local_benchmark(result.root, result.score)
    payload = {
        "schema": 1,
        "ecosystem": local.ecosystem,
        "score": result.score,
        "grade": result.grade,
        "finding_counts": {
            severity: sum(item.severity == severity for item in result.findings)
            for severity in ("high", "medium", "low", "info")
        },
    }
    request = Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "User-Agent": "RepoTruth/0.6"}, method="POST")
    with urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read(1024 * 1024))
    if not isinstance(body, dict):
        raise ValueError("Benchmark service returned a non-object response.")
    return body
