"""Loopback-only HTTP origin for a TLS reverse proxy; never log request URLs."""

from __future__ import annotations

import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import sys

from .renderer import validate_token


CONTENT_TYPES = {"index.html": "text/html; charset=utf-8",
                 "clash.yaml": "application/yaml; charset=utf-8",
                 "shadowrocket.conf": "text/plain; charset=utf-8"}
MAX_ARTIFACT_BYTES = 32_000_000
_PATH = re.compile(r"/s/([A-Za-z0-9_-]{24,256})(?:/(index\.html|clash\.yaml|shadowrocket\.conf)?)?\Z")


def choose_artifact(path: str, user_agent: str, token: str) -> str | None:
    """Match the original request target, without decoding or normalization."""
    match = _PATH.fullmatch(path)
    candidate = match.group(1) if match else ""
    authentic = hmac.compare_digest(candidate.encode("ascii"), token.encode("ascii"))
    if not match or not authentic:
        return None
    if match.group(2):
        return match.group(2)
    agent = user_agent.lower()
    if "shadowrocket" in agent:
        return "shadowrocket.conf"
    if "clash" in agent or "mihomo" in agent:
        return "clash.yaml"
    return "index.html"


class SubscriptionServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, data_dir: str | Path, token: str, port: int = 18081):
        self.token = validate_token(token)
        self.data_dir = Path(data_dir).resolve()
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("Invalid HTTP port")
        super().__init__(("127.0.0.1", port), SubscriptionHandler)

    def handle_error(self, request, client_address):
        # Base server tracebacks may contain application state. Deliberately quiet.
        pass


class SubscriptionHandler(BaseHTTPRequestHandler):
    server: SubscriptionServer
    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass

    def version_string(self):
        return "Subscription"

    def _headers(self, status: int, size: int = 0, name: str | None = None):
        self.send_response(status)
        self.send_header("Content-Length", str(size))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        if name:
            self.send_header("Content-Type", CONTENT_TYPES[name])
            if name != "index.html":
                self.send_header("profile-update-interval", "24")
                extension = "yaml" if name == "clash.yaml" else "conf"
                self.send_header("Content-Disposition", f'attachment; filename="proxy-profile.{extension}"')
        self.end_headers()
        self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        # Never echo a malformed request target, token, method, or parser message.
        self._headers(code)

    def do_HEAD(self):
        self._serve(body=False)

    def do_GET(self):
        self._serve(body=True)

    def do_POST(self):
        self._headers(404)

    do_PUT = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_POST
    do_PATCH = do_POST
    do_TRACE = do_POST
    do_CONNECT = do_POST

    def _serve(self, *, body: bool):
        # BaseHTTPRequestHandler normalizes a leading //; inspect the raw target
        # so unusual encodings and duplicate separators are still rejected.
        raw_target = self.raw_requestline.split()[1].decode("iso-8859-1")
        name = choose_artifact(raw_target, self.headers.get("User-Agent", ""), self.server.token)
        if name is None:
            self._headers(404)
            return
        # GET/HEAD require no body. Reject rather than read attacker-controlled size.
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or (lengths and lengths != ["0"]):
            self._headers(413)
            return
        try:
            releases = (self.server.data_dir / "releases").resolve(strict=True)
            release = (self.server.data_dir / "current").resolve(strict=True)
            if release.parent != releases or not release.is_dir():
                raise OSError("Invalid published release")
            artifact = release / name
            if artifact.is_symlink() or not artifact.is_file() or artifact.stat().st_size > MAX_ARTIFACT_BYTES:
                raise OSError("Invalid published artifact")
            with artifact.open("rb") as stream:
                data = stream.read(MAX_ARTIFACT_BYTES + 1)
            if len(data) > MAX_ARTIFACT_BYTES:
                raise OSError("Published artifact is too large")
        except OSError:
            self._headers(503)
            return
        self._headers(200, len(data), name)
        if body:
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve private subscriptions on loopback")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--port", default=18081, type=int)
    args = parser.parse_args(argv)
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        if not isinstance(config, dict) or set(config) != {"token"}:
            raise ValueError("HTTP service configuration must contain only a token")
        with SubscriptionServer(args.data_dir, config["token"], args.port) as server:
            server.serve_forever()
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, KeyError):
        print("Subscription HTTP service could not start.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
