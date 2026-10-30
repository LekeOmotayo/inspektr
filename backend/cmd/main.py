"""
Entry point for Leke AST Code Inspector.
Usage:
  python -m backend.cmd.main --serve           # Start web console on port 8097
  python -m backend.cmd.main --file path.py    # Analyze a local file in CLI mode
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Safe encoding for Windows console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.inspector import ASTCodeInspector
from backend.api.server import start_server


def main():
    parser = argparse.ArgumentParser(description="Leke AST Code Inspector & Security Guardrail Analyzer")
    parser.add_argument("--serve", "-s", action="store_true", help="Launch interactive web console on port 8097")
    parser.add_argument("--port", "-p", type=int, default=8097, help="Port for web server (default: 8097)")
    parser.add_argument("--file", "-f", type=str, help="Path to Python file to inspect in CLI mode")
    parser.add_argument("--sarif", action="store_true", help="Output results in OASIS SARIF v2.1.0 format")

    args = parser.parse_args()

    if args.serve or not args.file:
        start_server(args.port)
        return

    # CLI Mode
    filepath = Path(args.file)
    if not filepath.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    code = filepath.read_text(encoding="utf-8")

    if args.sarif:
        sarif = ASTCodeInspector.to_sarif(code, filename=filepath.name)
        print(json.dumps(sarif, indent=2))
        return

    result = ASTCodeInspector.inspect_source_full(code, filename=filepath.name)
    print(f"\n🔍 Inspection Results for: {filepath.name}")
    print(f"   Security Status: {result.metrics.security_status}")
    print(f"   Risk Score:      {result.metrics.risk_score}/100")
    print(f"   Violations:      {len(result.violations)}")
    print(f"   Cyclomatic Comp: {result.metrics.cyclomatic_complexity}")

    if result.violations:
        print("\nViolations:")
        for v in result.violations:
            print(f"  [{v.severity}] Line {v.line}: {v.message} ({v.rule})")


if __name__ == "__main__":
    main()
