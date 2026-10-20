import pytest
from inspector import ASTCodeInspector

def test_clean_code():
    code = """
def add(a, b):
    return a + b
"""
    violations = ASTCodeInspector.inspect_source(code)
    assert len(violations) == 0

def test_detect_eval_exec():
    code = "eval('2 + 2')"
    violations = ASTCodeInspector.inspect_source(code)
    assert len(violations) == 1
    assert violations[0].rule == "DANGEROUS_EVAL_EXEC"
    assert violations[0].severity == "CRITICAL"

def test_detect_raw_sql_formatting():
    code = """
def query_user(cursor, uid):
    cursor.execute(f"SELECT * FROM accounts WHERE id = {uid}")
"""
    violations = ASTCodeInspector.inspect_source(code)
    assert len(violations) == 1
    assert violations[0].rule == "RAW_SQL_STRING_CONCATENATION"

def test_detect_hardcoded_secret():
    code = 'jwt_secret = "my_ultra_secret_key_12345"'
    violations = ASTCodeInspector.inspect_source(code)
    assert len(violations) == 1
    assert violations[0].rule == "HARDCODED_CREDENTIAL"

def test_detect_os_system():
    code = """
import os
os.system("ls -la")
"""
    violations = ASTCodeInspector.inspect_source(code)
    assert len(violations) == 1
    assert violations[0].rule == "INSECURE_OS_SYSTEM"
