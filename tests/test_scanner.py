import json
import tempfile
import unittest
from pathlib import Path

from repotruth.reporters import github_report, html_report, sarif_report
from repotruth.scanner import scan_repository


class RepoTruthTests(unittest.TestCase):
    def make_repo(self, files: dict[str, str]) -> Path:
        root = Path(tempfile.mkdtemp())
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        return root

    def test_missing_readme(self):
        result = scan_repository(self.make_repo({"app.py": "print('ok')"}))
        self.assertEqual([item.rule_id for item in result.findings], ["RT000"])

    def test_broken_link_and_python_command(self):
        root = self.make_repo({"README.md": "[Guide](docs/missing.md)\n```bash\npython missing.py\n```"})
        result = scan_repository(root)
        self.assertEqual({item.rule_id for item in result.findings}, {"RT001", "RT003"})

    def test_missing_npm_script(self):
        root = self.make_repo({"README.md": "```bash\nnpm run deploy\n```", "package.json": '{"scripts":{"test":"node test.js"}}'})
        result = scan_repository(root)
        self.assertIn("RT002", [item.rule_id for item in result.findings])

    def test_supported_claims_stay_clean(self):
        root = self.make_repo({
            "README.md": "Production-ready, secure and fully tested. MIT licensed. [Security](SECURITY.md)",
            "SECURITY.md": "# Security",
            "LICENSE": "MIT",
            "tests/test_app.py": "def test_ok(): assert True",
            ".github/workflows/test.yml": "name: test",
            "app.py": "print('ok')",
        })
        result = scan_repository(root)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.score, 100)

    def test_production_placeholder_is_medium(self):
        root = self.make_repo({"README.md": "Production-ready", "src/app.py": "raise NotImplementedError"})
        result = scan_repository(root)
        placeholder = next(item for item in result.findings if item.rule_id == "RT008")
        self.assertEqual(placeholder.severity, "medium")

    def test_report_formats(self):
        result = scan_repository(self.make_repo({"README.md": "[Missing](nope.md)"}))
        sarif = json.loads(sarif_report(result))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("RepoTruth", html_report(result))
        self.assertIn("::warning file=README.md", github_report(result))

    def test_broken_evidence_contract(self):
        root = self.make_repo({
            "README.md": "# Project",
            ".repotruth.json": json.dumps({"contracts": [{"id": "release", "claim": "Releases are tested", "evidence": ["tests/test_release.py", ".github/workflows/release.yml"], "require": "all"}]}),
            "tests/test_release.py": "def test_release(): assert True",
        })
        result = scan_repository(root)
        finding = next(item for item in result.findings if item.rule_id == "RT009")
        self.assertIn(".github/workflows/release.yml", finding.message)

    def test_evidence_contract_any_mode(self):
        root = self.make_repo({
            "README.md": "# Project",
            ".repotruth.json": json.dumps({"contracts": [{"id": "policy", "evidence": ["SECURITY.md", "THREAT_MODEL.md"], "require": "any"}]}),
            "SECURITY.md": "# Security",
        })
        self.assertNotIn("RT009", [item.rule_id for item in scan_repository(root).findings])

    def test_ignore_rule_and_path(self):
        root = self.make_repo({
            "README.md": "[Generated](generated/missing.md)",
            ".repotruth.json": json.dumps({"ignore": [{"rule": "RT001", "path": "README.md"}]}),
        })
        self.assertEqual(scan_repository(root).findings, [])

    def test_invalid_configuration(self):
        root = self.make_repo({"README.md": "# Project", ".repotruth.json": "{"})
        result = scan_repository(root)
        self.assertIn("RT010", [item.rule_id for item in result.findings])

    def test_contract_cannot_use_parent_evidence(self):
        root = self.make_repo({
            "README.md": "# Project",
            ".repotruth.json": json.dumps({"contracts": [{"id": "escape", "evidence": ["../secret.txt"]}]}),
        })
        finding = next(item for item in scan_repository(root).findings if item.rule_id == "RT010")
        self.assertEqual(finding.title, "Unsafe evidence path")


if __name__ == "__main__":
    unittest.main()
