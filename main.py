from inspector import ASTCodeInspector

sample_vulnerable_code = """
import os
import sqlite3

API_SECRET = "sk-live-supersecretpassword1234"

def dangerous_handler(user_input, user_id):
    # Violation 1: eval
    result = eval(user_input)

    # Violation 2: os.system
    os.system("ping " + user_input)

    # Violation 3: SQL Injection
    conn = sqlite3.connect("app.db")
    conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    
    return result
"""

def main():
    print("=" * 60)
    print("🔍 Leke AST Code Inspector — Python Static Guardrail Analyzer")
    print("=" * 60)

    print("\nAnalyzing Python source code snippet...\n")
    violations = ASTCodeInspector.inspect_source(sample_vulnerable_code)

    if not violations:
        print("✅ No security violations found! Code passes guardrail.")
        return

    print(f"❌ Found {len(violations)} security violations in code AST:\n")
    for i, v in enumerate(violations, 1):
        print(f"[{i}] Line {v.line_no} | Severity: {v.severity}")
        print(f"    Rule:    {v.rule}")
        print(f"    Details: {v.message}\n")

if __name__ == "__main__":
    main()
