"""
Leke AST Code Inspector - Lightweight Embedded Demo Server
Serves the interactive web UI and provides REST API endpoints for AST analysis.
Standard library only (http.server) - zero external dependencies required.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

# Ensure safe UTF-8 terminal encoding on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from inspector import ASTCodeInspector, RULES_REGISTRY, Severity

HERE = Path(__file__).parent.resolve()

SAMPLE_SNIPPETS = {
    "vulnerable_agent": {
        "title": "Vulnerable AI Tool Dispatcher",
        "category": "High Risk / Multiple Injections",
        "code": '''import os
import sqlite3
import hashlib
import pickle
import requests
import subprocess

API_SECRET_KEY = "sk-live-992384729184719238129384"

def dispatch_tool(tool_name: str, user_payload: str, account_id: str):
    # Rule 1 Violation: Dynamic code execution
    result = eval(user_payload)

    # Rule 2 Violation: Shell command injection
    os.system("echo Dispatching " + tool_name)
    subprocess.run(f"curl -X POST https://internal/{user_payload}", shell=True)

    # Rule 3 Violation: Raw SQL string formatting
    conn = sqlite3.connect("app.db")
    conn.execute(f"SELECT * FROM telemetry WHERE account = '{account_id}'")

    # Rule 4 Violation: Insecure pickle deserialization
    cached_obj = pickle.loads(user_payload.encode())

    # Rule 5 Violation: Collision-prone hash
    sig = hashlib.md5(user_payload.encode()).hexdigest()

    # Rule 6 Violation: Disabled TLS verification
    requests.post("https://agents.internal/log", json={"sig": sig}, verify=False)

    # Rule 7 Violation: Blind exception swallowing
    try:
        conn.commit()
    except:
        pass

    return result
''',
    },
    "insecure_crypto_pickle": {
        "title": "Pickle Deserialization & Broken Crypto",
        "category": "Integrity & Cryptographic Weakness",
        "code": '''import pickle
import yaml
import hashlib
import tempfile

JWT_SECRET_TOKEN = "super_duper_secret_key_jwt_9988"

def restore_session(blob, yaml_text):
    # Insecure deserialization via pickle
    session = pickle.loads(blob)

    # Insecure yaml load without SafeLoader
    config = yaml.load(yaml_text)

    # Weak hash for sensitive data
    user_hash = hashlib.sha1(blob).hexdigest()

    # Unsafe temp file creation
    tmp_path = tempfile.mktemp()

    return session, config, user_hash, tmp_path
''',
    },
    "hardened_clean": {
        "title": "Hardened Production Guardrail (Clean)",
        "category": "Secure & Hardened Reference",
        "code": '''import os
import ast
import json
import hashlib
import subprocess
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Credentials securely loaded from environment variables
API_KEY = os.environ.get("AGENT_API_KEY", "")

def safe_compute_expression(expression_str: str) -> Any:
    """Safely parse literal structures without executing arbitrary code."""
    try:
        return ast.literal_eval(expression_str)
    except (ValueError, SyntaxError) as e:
        logger.warning("Invalid literal expression: %s", e)
        return None

def query_telemetry(cursor, account_id: str) -> list:
    """Uses parameterized queries with bind placeholders to prevent SQLi."""
    cursor.execute("SELECT * FROM telemetry WHERE account = ?", (account_id,))
    return cursor.fetchall()

def safe_run_command(binary: str, argument: str) -> subprocess.CompletedProcess:
    """Executes external commands with explicit argument vectors and shell=False."""
    safe_args = [binary, argument]
    return subprocess.run(safe_args, shell=False, check=True, capture_output=True)

def hash_payload(data: bytes) -> str:
    """Uses SHA-256 for cryptographic integrity."""
    return hashlib.sha256(data).hexdigest()
''',
    },
    "complex_branching": {
        "title": "High Cyclomatic Complexity Workflow",
        "category": "Code Quality & Complexity Inspection",
        "code": '''def evaluate_approval_matrix(tier, score, flag_a, flag_b, flag_c, retry_count):
    if tier == "PLATINUM":
        if score > 850:
            if not flag_a and (flag_b or flag_c):
                return "AUTO_APPROVE"
            elif flag_a:
                return "MANUAL_REVIEW_TIER1"
        elif score > 700:
            for attempt in range(retry_count):
                if attempt % 2 == 0:
                    if flag_b and not flag_c:
                        return "CONDITIONAL_ACCEPT"
    elif tier == "GOLD":
        while retry_count > 0:
            if score > 650:
                return "TIER2_APPROVE"
            retry_count -= 1
    return "REJECT"
''',
    },
}


class ASTInspectorHTTPHandler(BaseHTTPRequestHandler):

    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 1. API: Rules catalog
        if path == "/api/rules":
            rules_list = [
                {
                    "rule_id": r.rule_id,
                    "name": r.name,
                    "category": r.category.value,
                    "severity": r.severity.value,
                    "cwe": r.cwe,
                    "owasp": r.owasp,
                    "title": r.title,
                    "description": r.description,
                    "remediation": r.remediation,
                }
                for r in RULES_REGISTRY.values()
            ]
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(rules_list).encode("utf-8"))
            return

        # 2. API: Sample snippets
        if path == "/api/samples":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(SAMPLE_SNIPPETS).encode("utf-8"))
            return

        # 3. Serve static files (/static/...)
        if path.startswith("/static/"):
            rel_path = path.lstrip("/")
            file_path = HERE / rel_path
            if file_path.exists() and file_path.is_file():
                content = file_path.read_bytes()
                mime = "text/plain"
                if path.endswith(".css"):
                    mime = "text/css; charset=utf-8"
                elif path.endswith(".js"):
                    mime = "application/javascript; charset=utf-8"
                elif path.endswith(".json"):
                    mime = "application/json; charset=utf-8"
                elif path.endswith(".html"):
                    mime = "text/html; charset=utf-8"

                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return

        # 4. Serve index.html
        if path in ("/", "/index.html"):
            index_path = HERE / "index.html"
            if index_path.exists():
                content = index_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return

        # 4. 404 Not Found
        self.send_response(404)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps({"error": "Resource not found"}).encode("utf-8"))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/inspect":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                payload = json.loads(body)
                code = payload.get("code", "")
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Invalid JSON payload: {e}"}).encode("utf-8"))
                return

            analysis = ASTCodeInspector.analyze_full(code)

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(analysis).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        # Clean terminal logging
        sys.stderr.write(f"[{self.log_date_time_string()}] {args[0]} {args[1]} -> {args[2]}\n")


def run_server(port: int = 8000, host: str = "127.0.0.1"):
    server_address = (host, port)
    httpd = HTTPServer(server_address, ASTInspectorHTTPHandler)
    url = f"http://localhost:{port}"

    print("=" * 72)
    print("  \U0001f6e1\ufe0f  LEKE AST CODE INSPECTOR — Interactive Web Demo Server")
    print("=" * 72)
    print(f"\n  \U0001f310 Server running at:     {url}")
    print(f"  \U0001f4dc REST API endpoint:     {url}/api/inspect")
    print(f"  \U0001f9e9 Preloaded Samples:     {url}/api/samples")
    print(f"  \U0001f4da Rule Definitions:     {url}/api/rules")
    print("\n  Press Ctrl+C to terminate the server.\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\U0001f6d1 Shutting down server gracefully...")
        httpd.server_close()


if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port=port)
