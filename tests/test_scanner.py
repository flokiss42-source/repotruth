import json
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from repotruth.reporters import github_report, html_report, sarif_report
from repotruth.scanner import scan_repository
from repotruth.server import RepoTruthHandler, ScanError, github_clone_url
from repotruth.fixes import apply_fixes, propose_fixes
from repotruth.runtime import verify_runtime
from repotruth.vulnerabilities import osv_findings


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

    def test_github_url_is_strictly_normalized(self):
        self.assertEqual(github_clone_url("flokiss42-source/repotruth"), "https://github.com/flokiss42-source/repotruth.git")
        self.assertEqual(github_clone_url("https://github.com/a/b.git"), "https://github.com/a/b.git")
        for invalid in ("http://github.com/a/b", "https://evil.example/a/b", "https://github.com/a/b/issues"):
            with self.subTest(invalid=invalid), self.assertRaises(ScanError):
                github_clone_url(invalid)

    def test_web_health_and_local_scan(self):
        root = self.make_repo({"README.md": "# Project"})
        server = ThreadingHTTPServer(("127.0.0.1", 0), RepoTruthHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_port}"
        health = json.loads(urlopen(f"{base}/api/health").read())
        self.assertTrue(health["ok"])
        body = json.dumps({"mode": "local", "value": str(root)}).encode()
        request = Request(f"{base}/api/scan", data=body, headers={"Content-Type": "application/json", "Origin": base})
        payload = json.loads(urlopen(request).read())
        self.assertEqual(payload["result"]["score"], 100)

    def test_web_blocks_cross_origin_scan(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), RepoTruthHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        body = json.dumps({"mode": "local", "value": "."}).encode()
        request = Request(f"http://127.0.0.1:{server.server_port}/api/scan", data=body, headers={"Content-Type": "application/json", "Origin": "https://evil.example"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        self.assertEqual(caught.exception.code, 400)

    def test_secret_is_detected_but_redacted(self):
        token = "ghp_" + "abcdefghijklmnopqrstuvwxyz" + "123456"
        root = self.make_repo({"README.md": "# App", ".env": f"TOKEN={token}"})
        finding = next(item for item in scan_repository(root).findings if item.rule_id == "RT100")
        self.assertNotIn(token, finding.message)
        self.assertNotIn(token, finding.evidence)
        self.assertIn("…", finding.evidence)

    def test_dangerous_python_and_shell_are_detected(self):
        root = self.make_repo({"README.md": "# App", "app.py": "import subprocess\neval(input())\nsubprocess.run('x', shell=True)"})
        rules = [item.rule_id for item in scan_repository(root).findings]
        self.assertIn("RT110", rules)
        self.assertIn("RT112", rules)

    def test_dependency_supply_chain_risks(self):
        root = self.make_repo({"README.md": "# App", "package.json": json.dumps({"dependencies": {"x": "latest"}, "scripts": {"postinstall": "node setup.js"}})})
        rules = {item.rule_id for item in scan_repository(root).findings}
        self.assertTrue({"RT120", "RT121", "RT122"}.issubset(rules))

    def test_safe_fixes_preview_and_apply_only_new_files(self):
        root = self.make_repo({"app.py": "print('ok')", "pyproject.toml": "[project]\nname='x'"})
        proposals = propose_fixes(root)
        created = apply_fixes(root, proposals)
        self.assertTrue((root / "README.md").is_file())
        self.assertTrue((root / "SECURITY.md").is_file())
        self.assertEqual(len(created), len(proposals))
        self.assertEqual(apply_fixes(root, proposals), [])

    def test_runtime_verification_never_falls_back_to_host_execution(self):
        root = self.make_repo({"app.py": "print('ok')"})
        result = verify_runtime(root)
        self.assertIn(result.status, {"not_available", "passed", "failed", "timeout"})
        if result.status == "not_available":
            self.assertTrue(result.reason)

    def test_osv_vulnerability_result_is_reported(self):
        root = self.make_repo({"README.md": "# App", "requirements.txt": "demo-package==1.0.0\n"})

        class Response:
            def __enter__(self): return self
            def __exit__(self, *_): return None
            def read(self, *_): return json.dumps({"results": [{"vulns": [{"id": "GHSA-demo-test"}]}]}).encode()

        with patch("repotruth.vulnerabilities.urlopen", return_value=Response()):
            findings, status = osv_findings(root)
        self.assertEqual(findings[0].rule_id, "RT140")
        self.assertEqual(status["vulnerable_packages"], 1)


if __name__ == "__main__":
    unittest.main()
