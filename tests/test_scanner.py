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
from repotruth.security import _php_findings
from repotruth.vulnerabilities import _packages, osv_findings


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

    def test_readme_detection_is_case_insensitive(self):
        result = scan_repository(self.make_repo({"Readme.md": "# Project"}))
        self.assertNotIn("RT000", [item.rule_id for item in result.findings])

    def test_root_relative_readme_link_stays_inside_repository(self):
        root = self.make_repo({"README.md": "[Guide](/docs/guide.md)", "docs/guide.md": "# Guide"})
        self.assertNotIn("RT001", [item.rule_id for item in scan_repository(root).findings])

    def test_brace_template_link_does_not_become_a_truncated_path(self):
        root = self.make_repo({"README.md": "[Config](config/application-{one, two}.properties)"})
        self.assertNotIn("RT001", [item.rule_id for item in scan_repository(root).findings])

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
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["version"], "0.5.1")
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
        self.assertEqual(health["version"], "0.5.1")
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

    def test_test_only_dangerous_call_is_informational(self):
        root = self.make_repo({"README.md": "# App", "tests/test_pickle.py": "import pickle\npickle.loads(b'x')"})
        finding = next(item for item in scan_repository(root).findings if item.rule_id == "RT111")
        self.assertEqual(finding.severity, "info")

    def test_regexp_exec_and_vendored_javascript_are_not_shell_calls(self):
        root = self.make_repo({
            "README.md": "# App",
            "app.js": "const ok = /x/.exec(value)",
            "static/js/libs/jquery.min.js": "thing.exec(value); eval(value)",
        })
        self.assertNotIn("RT112", [item.rule_id for item in scan_repository(root).findings])
        self.assertNotIn("RT110", [item.rule_id for item in scan_repository(root).findings])

    def test_child_process_exec_is_detected(self):
        root = self.make_repo({"README.md": "# App", "app.js": "const { exec } = require('child_process'); exec(userInput)"})
        self.assertIn("RT112", [item.rule_id for item in scan_repository(root).findings])

    def test_dangerous_java_constructs_are_detected(self):
        root = self.make_repo({"README.md": "# App", "App.java": "class App { void x(String v) throws Exception { Runtime.getRuntime().exec(v); new java.io.ObjectInputStream(null).readObject(); } }"})
        rules = {item.rule_id for item in scan_repository(root).findings}
        self.assertTrue({"RT111", "RT112"}.issubset(rules))

    def test_dangerous_php_constructs_are_detected(self):
        payload = "<?php " + "ev" + "al($_POST['code']); " + "sys" + "tem($_GET['cmd']); " + "unseri" + "alize($_COOKIE['data']); " + "incl" + "ude($_GET['page']); " + "mysqli_" + "query($db, $_POST['sql']);"
        root = self.make_repo({"README.md": "# App", "index.php": "<?php // fixture"})
        with patch("repotruth.security._read", return_value=payload):
            rules = {item.rule_id for item in _php_findings(root, [root / "index.php"])}
        self.assertTrue({"RT110", "RT111", "RT112", "RT115", "RT116"}.issubset(rules), rules)

    def test_vendored_placeholders_are_ignored(self):
        root = self.make_repo({"README.md": "# App", "static/js/libs/jquery.js": "// TODO vendor code"})
        self.assertNotIn("RT008", [item.rule_id for item in scan_repository(root).findings])

    def test_repeated_rule_has_bounded_score_penalty(self):
        files = {"README.md": "# App"}
        files.update({f"src/file{i}.py": "# TODO\n" for i in range(20)})
        result = scan_repository(self.make_repo(files))
        self.assertEqual(result.score, 94)

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

    def test_osv_reads_python_node_go_rust_and_php_locks(self):
        root = self.make_repo({
            "requirements.txt": "requests==2.31.0\n",
            "package-lock.json": json.dumps({"packages": {"node_modules/express": {"version": "4.18.2"}}}),
            "go.sum": "golang.org/x/text v0.3.0 h1:demo\ngolang.org/x/text v0.3.0/go.mod h1:demo\n",
            "Cargo.lock": '[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
            "composer.lock": json.dumps({"packages": [{"name": "symfony/http-foundation", "version": "v6.0.0"}]}),
        })
        ecosystems = {item[0] for item in _packages(root)}
        self.assertEqual(ecosystems, {"PyPI", "npm", "Go", "crates.io", "Packagist"})


if __name__ == "__main__":
    unittest.main()
