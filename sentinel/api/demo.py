"""Vercel adapter for Sentinel's existing read-only demo payload."""

from http.server import BaseHTTPRequestHandler
import json

from sentinel.demo_server import build_demo_payload


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        try:
            body = json.dumps(build_demo_payload(), default=str).encode()
            self.send_response(200)
        except Exception as exc:
            body = json.dumps({"error": str(exc)}).encode()
            self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return
