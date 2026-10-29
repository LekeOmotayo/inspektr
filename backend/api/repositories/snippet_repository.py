"""
Snippet and Rule Definition Repository for AST Code Inspector.
"""

from typing import Dict, Any
from backend.core.inspector import RULES_REGISTRY, RuleDefinition

SAMPLE_SNIPPETS: Dict[str, Dict[str, Any]] = {
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
    return result
'''
    },
    "safe_service": {
        "title": "Hardened Microservice",
        "category": "Zero Violations",
        "code": '''import hmac
import hashlib
import sqlite3
import subprocess
from typing import Optional

def get_record(conn: sqlite3.Connection, record_id: str) -> Optional[tuple]:
    # Parameterized query - Safe from SQLi
    cursor = conn.cursor()
    cursor.execute("SELECT id, payload FROM events WHERE id = ?", (record_id,))
    return cursor.fetchone()

def run_isolated_command(binary_path: str, arg: str) -> int:
    # Parameterized exec list with shell=False
    result = subprocess.run([binary_path, arg], shell=False, check=True)
    return result.returncode

def secure_token_compare(val_a: bytes, val_b: bytes) -> bool:
    # Constant-time comparison
    return hmac.compare_digest(val_a, val_b)
'''
    },
    "sql_injection_web": {
        "title": "SQL Injection & Assert Flaw",
        "category": "Data Access Risk",
        "code": '''import sqlite3

def query_user(username: str, role: str):
    # Assert in production code
    assert username is not None, "Username must be provided"
    
    conn = sqlite3.connect("users.db")
    # Format-string injection
    query = "SELECT * FROM users WHERE username = '%s' AND role = '%s'" % (username, role)
    return conn.execute(query).fetchall()
'''
    }
}


class SnippetRepository:
    """Provides access to curated code snippets and static security rules."""

    @staticmethod
    def get_all_snippets() -> Dict[str, Dict[str, Any]]:
        return SAMPLE_SNIPPETS

    @staticmethod
    def get_snippet_by_id(snippet_id: str) -> Dict[str, Any]:
        return SAMPLE_SNIPPETS.get(snippet_id, {})

    @staticmethod
    def get_rules_registry() -> Dict[str, RuleDefinition]:
        return RULES_REGISTRY
