"""
REST Server and Static File Server for AST Code Inspector.
Pure standard-library implementation with zero external dependencies.
"""

from __future__ import annotations

import json
import mimetypes
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

from backend.api.controllers.inspect_controller import InspectController
from backend.api.services.inspect_service import InspectService
from backend.api.repositories.snippet_repository import SnippetRepository


class ASTRequestHandler(BaseHTTPRequestHandler):
    """Handles REST API and static UI requests."""

    controller = InspectController(InspectService(SnippetRepository()))
    frontend_dir: Path = Path(__file__).parent.parent.parent / "frontend"

    def _set_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._set_cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._set_cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/rules":
            self._send_json(200, self.controller.handle_get_rules())
            return
        elif path == "/api/snippets":
            self._send_json(200, self.controller.handle_get_snippets())
            return
        elif path == "/api/health":
            self._send_json(200, {"status": "healthy", "service": "leke-ast-code-inspector"})
            return

        # Serve static frontend files
        rel_path = path.lstrip("/")
        if not rel_path or rel_path == "index.html":
            target = self.frontend_dir / "index.html"
        else:
            target = self.frontend_dir / rel_path

        if target.is_file():
            mime_type, _ = mimetypes.guess_type(str(target))
            mime_type = mime_type or "application/octet-stream"
            content = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self._set_cors()
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b"{}"

        try:
            payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception as e:
            self._send_json(400, {"status": "error", "message": f"Malformed JSON: {e}"})
            return

        try:
            if path == "/api/analyze":
                result = self.controller.handle_analyze(payload)
                self._send_json(200, result)
            elif path == "/api/sarif":
                result = self.controller.handle_sarif(payload)
                self._send_json(200, result)
            else:
                self._send_json(404, {"status": "error", "message": "Unknown endpoint"})
        except Exception as e:
            self._send_json(500, {"status": "error", "message": f"Server processing error: {e}"})


def start_server(port: int = 8097):
    """Starts the HTTP server on the given port."""
    server = HTTPServer(("0.0.0.0", port), ASTRequestHandler)
    print(f"\n🚀 Leke AST Code Inspector Console running at http://localhost:{port}")
    print(f"   Frontend assets served from: {ASTRequestHandler.frontend_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.server_close()
