"""
Leke AST Code Inspector - Enterprise CLI & Guardrail Runner
Provides CLI scanning, SARIF/JSON generation, CI/CD exit-code enforcement,
and one-command local server hosting for the interactive web demo.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List

# Ensure safe UTF-8 terminal encoding on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from inspector import ASTCodeInspector, RULES_REGISTRY, Severity, SecurityViolation


SAMPLE_VULNERABLE_AGENT_CODE = '''import os
import sqlite3
import hashlib
import pickle
import requests
import subprocess

# Vulnerability 1: Hardcoded API Secret
OPENAI_API_KEY = "sk-live-948102948192384910283491"

def agent_tool_dispatcher(user_query: str, target_id: str, payload: bytes):
    # Vulnerability 2: Dangerous Dynamic eval
    calculated_val = eval(user_query)

    # Vulnerability 3: Shell Command Injection
    os.system(f"echo Query received: {user_query}")
    subprocess.run("ping " + user_query, shell=True)

    # Vulnerability 4: Raw SQL Injection in execute()
    db = sqlite3.connect("production.db")
    db.execute(f"SELECT * FROM users WHERE account_id = '{target_id}'")

    # Vulnerability 5: Insecure Deserialization
    untrusted_obj = pickle.loads(payload)

    # Vulnerability 6: Weak Cryptographic Primitives
    legacy_hash = hashlib.md5(user_query.encode()).hexdigest()

    # Vulnerability 7: Disabled TLS Verification
    resp = requests.post("https://internal.vault/tokens", json={"h": legacy_hash}, verify=False)

    # Vulnerability 8: Blind Exception Swallowing
    try:
        db.commit()
    except:
        pass

    return calculated_val
'''

COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_DIM = "\033[2m"


def print_banner():
    print(f"{COLOR_CYAN}{COLOR_BOLD}=" * 72)
    print("  \U0001f6e1\ufe0f  LEKE AST CODE INSPECTOR - Static Python Guardrail Analyzer")
    print("     Enterprise AST NodeVisitor & Security CI/CD Gate")
    print(f"{COLOR_CYAN}=" * 72 + f"{COLOR_RESET}\n")


def print_rules_catalog():
    print_banner()
    print(f"{COLOR_BOLD}REGISTERED SECURITY GUARDRAILS (CWE & OWASP MAPPED):{COLOR_RESET}\n")
    for r_id, r in RULES_REGISTRY.items():
        sev_color = COLOR_RED if r.severity == Severity.CRITICAL else (COLOR_YELLOW if r.severity == Severity.HIGH else COLOR_BLUE)
        print(f"  {COLOR_BOLD}[{r.rule_id}]{COLOR_RESET} {r.name}")
        print(f"     Severity:    {sev_color}{r.severity.value}{COLOR_RESET} | Category: {r.category.value}")
        print(f"     Standard:    {COLOR_DIM}{r.cwe}{COLOR_RESET}")
        print(f"     OWASP:       {COLOR_DIM}{r.owasp}{COLOR_RESET}")
        print(f"     Description: {r.description}")
        print(f"     Remedy:      {COLOR_GREEN}{r.remediation}{COLOR_RESET}\n")


def print_terminal_report(analysis: dict, filepath: str = "InMemorySnippet"):
    violations: List[dict] = analysis.get("violations", [])
    metrics = analysis.get("metrics", {})
    score = analysis.get("score", 0)
    rating = analysis.get("rating", "F")

    # Score color
    score_color = COLOR_GREEN if score >= 80 else (COLOR_YELLOW if score >= 60 else COLOR_RED)

    print(f"{COLOR_BOLD}Analysis Target:{COLOR_RESET} {filepath}")
    print(f"{COLOR_BOLD}Security Score:{COLOR_RESET}  {score_color}{score}/100 [Rating: {rating}]{COLOR_RESET}")
    print(
        f"{COLOR_BOLD}Code Metrics:{COLOR_RESET}    LOC: {metrics.get('total_loc')} | "
        f"AST Nodes: {metrics.get('ast_nodes')} | "
        f"Cyclomatic Complexity: {metrics.get('cyclomatic_complexity')} | "
        f"Maintainability: {metrics.get('maintainability_index')}/100"
    )
    print("-" * 72)

    if not violations:
        print(f"\n{COLOR_GREEN}{COLOR_BOLD}✔ PASSED:{COLOR_RESET} Zero AST security violations detected. Code is guardrail-compliant.\n")
        return

    print(f"\n{COLOR_RED}{COLOR_BOLD}✖ FAILED:{COLOR_RESET} Found {len(violations)} security violation(s) in parsed AST:\n")

    for i, v in enumerate(violations, 1):
        sev = v["severity"]
        sev_color = COLOR_RED if sev == "CRITICAL" else (COLOR_YELLOW if sev == "HIGH" else COLOR_BLUE)

        print(f"{COLOR_BOLD}[{i}] Line {v['line_no']}:{v.get('col_offset', 0)} | {sev_color}{sev}{COLOR_RESET} | {COLOR_CYAN}{v['rule_id']} - {v['rule']}{COLOR_RESET}")
        print(f"    {COLOR_DIM}Standard: {v['cwe']}{COLOR_RESET}")
        print(f"    {COLOR_DIM}OWASP:    {v['owasp']}{COLOR_RESET}")
        print(f"    Details:  {v['message']}")
        if v.get("code_snippet"):
            print(f"    Code:     {COLOR_RED}> {v['code_snippet']}{COLOR_RESET}")
        print(f"    Fix:      {COLOR_GREEN}{v['remediation']}{COLOR_RESET}\n")


def scan_directory(dir_path: Path) -> List[tuple[Path, dict]]:
    results = []
    py_files = list(dir_path.rglob("*.py"))
    # Exclude virtual environments and caches
    filtered = [
        p for p in py_files
        if not any(part.startswith(".") or part in ("venv", ".venv", "__pycache__", "build", "dist") for part in p.parts)
    ]
    for p in filtered:
        try:
            content = p.read_text(encoding="utf-8")
            analysis = ASTCodeInspector.analyze_full(content)
            results.append((p, analysis))
        except Exception as e:
            print(f"Error scanning {p}: {e}", file=sys.stderr)
    return results


def start_server(port: int = 8000):
    from server import run_server
    run_server(port=port)


def main():
    parser = argparse.ArgumentParser(
        description="Leke AST Code Inspector — Static Security Guardrail & Complexity Analyzer"
    )
    parser.add_argument(
        "--file", "-f", type=str, help="Path to a specific Python file to inspect"
    )
    parser.add_argument(
        "--dir", "-d", type=str, help="Path to a directory of Python files to scan recursively"
    )
    parser.add_argument(
        "--format", choices=["table", "json", "sarif"], default="table",
        help="Output format (table, json, or standard SARIF v2.1.0 for GitHub Code Scanning)"
    )
    parser.add_argument(
        "--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None,
        help="Exit with non-zero status code if violations at or above this severity are found"
    )
    parser.add_argument(
        "--rules", action="store_true", help="Display full catalog of registered security rules and CWE mappings"
    )
    parser.add_argument(
        "--serve", action="store_true", help="Launch interactive web dashboard demo on http://localhost:8000"
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Port for the web server demo (default: 8000)"
    )

    args = parser.parse_args()

    if args.rules:
        print_rules_catalog()
        sys.exit(0)

    if args.serve:
        start_server(port=args.port)
        sys.exit(0)

    # 1. Single file analysis
    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"Error: File '{args.file}' does not exist.", file=sys.stderr)
            sys.exit(2)
        code = file_path.read_text(encoding="utf-8")
        analysis = ASTCodeInspector.analyze_full(code)

        if args.format == "json":
            print(json.dumps(analysis, indent=2))
        elif args.format == "sarif":
            violations = ASTCodeInspector.inspect_source(code)
            sarif = ASTCodeInspector.to_sarif(violations, filepath=str(file_path))
            print(json.dumps(sarif, indent=2))
        else:
            print_banner()
            print_terminal_report(analysis, filepath=str(file_path))

        # Check exit condition
        if args.fail_on:
            severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            threshold_idx = severity_order.index(args.fail_on)
            has_failure = any(
                severity_order.index(v["severity"]) >= threshold_idx
                for v in analysis.get("violations", [])
            )
            if has_failure:
                sys.exit(1)
        sys.exit(0)

    # 2. Directory scan
    if args.dir:
        dir_path = Path(args.dir)
        if not dir_path.exists() or not dir_path.is_dir():
            print(f"Error: Directory '{args.dir}' does not exist.", file=sys.stderr)
            sys.exit(2)

        results = scan_directory(dir_path)
        all_violations = []
        for p, a in results:
            for v in a.get("violations", []):
                v_copy = dict(v)
                v_copy["file"] = str(p)
                all_violations.append(v_copy)

        if args.format == "json":
            summary = {
                "scanned_files": len(results),
                "total_violations": len(all_violations),
                "files": {str(p): a for p, a in results},
            }
            print(json.dumps(summary, indent=2))
        else:
            print_banner()
            print(f"Scanned {len(results)} Python files in {dir_path.resolve()}\n")
            for p, a in results:
                if a.get("violations"):
                    print_terminal_report(a, filepath=str(p))
            if not all_violations:
                print(f"{COLOR_GREEN}{COLOR_BOLD}✔ Clean codebase:{COLOR_RESET} No security violations found in any file.")

        if args.fail_on and all_violations:
            sys.exit(1)
        sys.exit(0)

    # 3. Default Demo: Run on sample vulnerable agent code
    print_banner()
    print("Running demonstration scan on sample AI Agent Tool Handler...\n")
    analysis = ASTCodeInspector.analyze_full(SAMPLE_VULNERABLE_AGENT_CODE)

    if args.format == "json":
        print(json.dumps(analysis, indent=2))
    elif args.format == "sarif":
        violations = ASTCodeInspector.inspect_source(SAMPLE_VULNERABLE_AGENT_CODE)
        sarif = ASTCodeInspector.to_sarif(violations, filepath="sample_vulnerable_agent.py")
        print(json.dumps(sarif, indent=2))
    else:
        print_terminal_report(analysis, filepath="sample_vulnerable_agent.py")
        print(f"\n{COLOR_CYAN}{COLOR_BOLD}Demo Tips:{COLOR_RESET}")
        print("  • To launch the visual interactive browser demo:  python main.py --serve")
        print("  • To scan a custom file:                          python main.py --file path/to/script.py")
        print("  • To generate GitHub Actions SARIF:               python main.py --format sarif")
        print("  • To view the full rulebook:                      python main.py --rules\n")


if __name__ == "__main__":
    main()
