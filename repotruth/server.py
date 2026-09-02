from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .scanner import scan_repository


MAX_REQUEST_BYTES = 32_768
MAX_REPOSITORY_FILES = 20_000
MAX_REPOSITORY_BYTES = 150 * 1024 * 1024
GITHUB_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class ScanError(Exception):
    pass


def github_clone_url(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value if "://" in value else f"https://github.com/{value}")
    if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
        raise ScanError("Only public https://github.com repositories are accepted.")
    slug = parsed.path.strip("/")
    if slug.endswith(".git"):
        slug = slug[:-4]
    if not GITHUB_REPOSITORY.fullmatch(slug):
        raise ScanError("Use a repository URL like https://github.com/owner/project.")
    return f"https://github.com/{slug}.git"


def github_repository_size(clone_url: str) -> int | None:
    slug = urlparse(clone_url).path.strip("/").removesuffix(".git")
    request = Request(f"https://api.github.com/repos/{slug}", headers={"Accept": "application/vnd.github+json", "User-Agent": "RepoTruth/0.5"})
    try:
        with urlopen(request, timeout=10) as response:
            payload = json.loads(response.read(MAX_REQUEST_BYTES))
            return int(payload["size"]) * 1024
    except Exception:
        return None


def validate_repository_size(root: Path) -> None:
    count = 0
    size = 0
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        count += 1
        try:
            size += path.stat().st_size
        except OSError:
            continue
        if count > MAX_REPOSITORY_FILES or size > MAX_REPOSITORY_BYTES:
            raise ScanError("Repository is too large for the local quick scan.")


def scan_github(value: str, verify: bool = False, online: bool = False) -> dict:
    clone_url = github_clone_url(value)
    advertised_size = github_repository_size(clone_url)
    if advertised_size is not None and advertised_size > MAX_REPOSITORY_BYTES:
        raise ScanError("Repository exceeds the 150 MB local quick-scan limit.")
    if shutil.which("git") is None:
        raise ScanError("Git is not installed or is not available in PATH.")
    with tempfile.TemporaryDirectory(prefix="repotruth-") as temporary:
        destination = Path(temporary) / "repository"
        try:
            completed = subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", "--filter=blob:limit=2m", "--quiet", clone_url, str(destination)],
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError("GitHub download exceeded the 90 second limit.") from exc
        if completed.returncode != 0:
            message = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else "clone failed"
            raise ScanError(f"Could not download the public repository: {message}")
        validate_repository_size(destination)
        result = scan_repository(destination, verify=verify, online=online).to_dict()
        result["root"] = clone_url.removesuffix(".git")
        return result


def scan_local(value: str, verify: bool = False, online: bool = False) -> dict:
    root = Path(value).expanduser().resolve()
    if not root.is_dir():
        raise ScanError("The local folder does not exist or is not a directory.")
    validate_repository_size(root)
    return scan_repository(root, verify=verify, online=online).to_dict()


class RepoTruthHandler(BaseHTTPRequestHandler):
    server_version = "RepoTruth/0.5"

    def log_message(self, format: str, *args) -> None:
        return

    def _json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _asset(self, name: str, content_type: str) -> None:
        asset = files("repotruth").joinpath("web", name)
        body = asset.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        routes = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        }
        if self.path == "/api/health":
            self._json({"ok": True, "version": "0.5.1"})
        elif self.path in routes:
            self._asset(*routes[self.path])
        else:
            self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path != "/api/scan":
            self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        try:
            host_header = self.headers.get("Host", "")
            host_name = host_header.rsplit(":", 1)[0]
            if host_name not in {"127.0.0.1", "localhost"}:
                raise ScanError("Invalid local server host.")
            origin = self.headers.get("Origin")
            allowed_origins = {f"http://{host_header}"}
            if origin and origin not in allowed_origins:
                raise ScanError("Cross-origin scan requests are blocked.")
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_REQUEST_BYTES:
                raise ScanError("Invalid request size.")
            payload = json.loads(self.rfile.read(length))
            mode = payload.get("mode")
            value = str(payload.get("value", "")).strip()
            verify = payload.get("verify") is True
            online = payload.get("online") is True
            if not value:
                raise ScanError("Enter a GitHub URL or local folder.")
            result = scan_github(value, verify, online) if mode == "github" else scan_local(value, verify, online) if mode == "local" else None
            if result is None:
                raise ScanError("Unknown scan mode.")
            self._json({"result": result})
        except (ScanError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception:
            self._json({"error": "Unexpected scan failure. Check the server console."}, HTTPStatus.INTERNAL_SERVER_ERROR)


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = False) -> int:
    if host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("RepoTruth UI binds to localhost only to protect local-path scanning.")
    server = ThreadingHTTPServer((host, port), RepoTruthHandler)
    url = f"http://{host}:{server.server_port}"
    print(f"RepoTruth UI: {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
