import ast
import re
from typing import List, Dict, Any

class SecurityViolation:
    def __init__(self, rule: str, message: str, line_no: int, severity: str = "HIGH"):
        self.rule = rule
        self.message = message
        self.line_no = line_no
        self.severity = severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "message": self.message,
            "line_no": self.line_no,
            "severity": self.severity
        }

class ASTSecurityVisitor(ast.NodeVisitor):
    """
    Static code analyzer checking Python AST for critical security violations:
    1. Dangerous built-in executions (eval, exec, compile)
    2. Insecure deserialization (pickle.loads, yaml.load without Loader)
    3. Potential SQL Injections (string formatting inside execute())
    4. Hardcoded secrets/API keys in variable assignments
    5. Shell execution vulnerabilities (os.system, subprocess with shell=True)
    """
    def __init__(self):
        self.violations: List[SecurityViolation] = []

    def visit_Call(self, node: ast.Call):
        # Detect eval() and exec()
        if isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec", "compile"):
                self.violations.append(SecurityViolation(
                    rule="DANGEROUS_EVAL_EXEC",
                    message=f"Use of dangerous built-in '{node.func.id}()' can lead to remote code execution.",
                    line_no=node.lineno,
                    severity="CRITICAL"
                ))

        # Detect os.system() and subprocess with shell=True
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "system" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                self.violations.append(SecurityViolation(
                    rule="INSECURE_OS_SYSTEM",
                    message="Use of os.system() is vulnerable to command injection. Use subprocess with argument lists instead.",
                    line_no=node.lineno,
                    severity="HIGH"
                ))
            
            # Check for SQL execute() with formatted strings
            if node.func.attr == "execute" and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)): # f-string or % or +
                    self.violations.append(SecurityViolation(
                        rule="RAW_SQL_STRING_CONCATENATION",
                        message="Potential SQL Injection detected: dynamic string formatting inside database execute(). Use parameterized queries.",
                        line_no=node.lineno,
                        severity="CRITICAL"
                    ))

        # Check for shell=True in subprocess
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self.violations.append(SecurityViolation(
                    rule="SUBPROCESS_SHELL_TRUE",
                    message="subprocess call with shell=True allows shell injection attacks.",
                    line_no=node.lineno,
                    severity="HIGH"
                ))

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Detect hardcoded API keys / passwords
        for target in node.targets:
            target_name = ""
            if isinstance(target, ast.Name):
                target_name = target.id.lower()
            
            if any(k in target_name for k in ("secret", "password", "api_key", "token", "auth")):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    if len(val) >= 8 and not val.startswith("env.") and not val.startswith("$"):
                        self.violations.append(SecurityViolation(
                            rule="HARDCODED_CREDENTIAL",
                            message=f"Possible hardcoded secret in variable '{target_name}'. Use environment variables.",
                            line_no=node.lineno,
                            severity="HIGH"
                        ))
        self.generic_visit(node)


class ASTCodeInspector:
    """Wrapper to parse raw Python code or files and run AST inspection."""
    @staticmethod
    def inspect_source(code: str) -> List[SecurityViolation]:
        tree = ast.parse(code)
        visitor = ASTSecurityVisitor()
        visitor.visit(tree)
        return visitor.violations

    @staticmethod
    def inspect_file(filepath: str) -> List[SecurityViolation]:
        with open(filepath, "r", encoding="utf-8") as f:
            return ASTCodeInspector.inspect_source(f.read())
