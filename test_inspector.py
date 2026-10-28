"""
Comprehensive Unit Tests for Leke AST Code Inspector
Tests all AST security rules, metrics, complexity calculation, and SARIF output.
"""

import sys
import unittest
from inspector import ASTCodeInspector, RULES_REGISTRY, Severity


class TestASTCodeInspector(unittest.TestCase):

    def test_clean_code(self):
        code = """
def add(a, b):
    return a + b
"""
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 0)

    def test_detect_eval_exec(self):
        code = "eval('2 + 2')"
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].rule, "DANGEROUS_EVAL_EXEC")
        self.assertEqual(violations[0].severity, "CRITICAL")
        self.assertTrue("CWE-95" in violations[0].cwe)

    def test_detect_exec_and_compile(self):
        code = """
exec("import os")
compile("print('hello')", "<string>", "exec")
__import__("subprocess")
"""
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 3)
        for v in violations:
            self.assertEqual(v.rule, "DANGEROUS_EVAL_EXEC")

    def test_detect_raw_sql_formatting(self):
        code = """
def query_user(cursor, uid):
    cursor.execute(f"SELECT * FROM accounts WHERE id = {uid}")
"""
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].rule, "RAW_SQL_STRING_CONCATENATION")
        self.assertEqual(violations[0].severity, "CRITICAL")
        self.assertTrue("CWE-89" in violations[0].cwe)

    def test_detect_sql_percent_and_format(self):
        code = """
cursor.execute("SELECT * FROM items WHERE name = '%s'" % item_name)
cursor.execute("SELECT * FROM items WHERE name = '{}'".format(item_name))
"""
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 2)
        for v in violations:
            self.assertEqual(v.rule, "RAW_SQL_STRING_CONCATENATION")

    def test_detect_hardcoded_secret(self):
        code = 'jwt_secret = "my_ultra_secret_key_12345"'
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].rule, "HARDCODED_CREDENTIAL")
        self.assertEqual(violations[0].severity, "HIGH")
        self.assertTrue("CWE-798" in violations[0].cwe)

    def test_detect_os_system(self):
        code = """
import os
os.system("ls -la")
"""
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].rule, "INSECURE_OS_COMMAND")
        self.assertEqual(violations[0].severity, "HIGH")

    def test_detect_subprocess_shell_true(self):
        code = """
import subprocess
subprocess.run("rm -rf " + target, shell=True)
"""
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].rule, "INSECURE_OS_COMMAND")
        self.assertEqual(violations[0].severity, "HIGH")

    def test_detect_insecure_deserialization(self):
        code = """
import pickle
import yaml

data = pickle.loads(untrusted_payload)
config = yaml.load(user_stream)
"""
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 2)
        for v in violations:
            self.assertEqual(v.rule, "INSECURE_DESERIALIZATION")
            self.assertEqual(v.severity, "CRITICAL")

    def test_detect_weak_crypto(self):
        code = """
import hashlib
digest = hashlib.md5(b"password").hexdigest()
sha = hashlib.sha1(b"data").hexdigest()
"""
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 2)
        for v in violations:
            self.assertEqual(v.rule, "WEAK_CRYPTOGRAPHIC_HASH")

    def test_detect_disabled_tls(self):
        code = """
import requests
resp = requests.get("https://api.internal/data", verify=False)
"""
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].rule, "DISABLED_TLS_VERIFICATION")
        self.assertEqual(violations[0].severity, "HIGH")

    def test_detect_insecure_temp_file(self):
        code = """
import tempfile
path = tempfile.mktemp()
"""
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].rule, "INSECURE_TEMP_FILE")

    def test_detect_blind_exception_swallowing(self):
        code = """
try:
    risky_operation()
except:
    pass
"""
        violations = ASTCodeInspector.inspect_source(code)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].rule, "BLIND_EXCEPTION_SWALLOWING")

    def test_full_analysis_scoring_and_metrics(self):
        code = """
def complex_calc(x, y):
    if x > 0:
        for i in range(x):
            if i % 2 == 0 and y > 0:
                pass
    return x + y
"""
        res = ASTCodeInspector.analyze_full(code)
        self.assertTrue(res["success"])
        self.assertEqual(res["score"], 100)
        self.assertEqual(res["rating"], "A+")
        metrics = res["metrics"]
        self.assertGreater(metrics["cyclomatic_complexity"], 1)
        self.assertEqual(metrics["function_count"], 1)
        self.assertIsNotNone(res["ast_tree"])

    def test_sarif_export(self):
        code = "eval('malicious()')"
        violations = ASTCodeInspector.inspect_source(code)
        sarif = ASTCodeInspector.to_sarif(violations, "agent.py")
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "SEC-001")


if __name__ == "__main__":
    unittest.main()
