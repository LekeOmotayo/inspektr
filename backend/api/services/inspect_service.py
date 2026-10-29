"""
Core Inspection Service for AST Code Analysis.
"""

from typing import Dict, Any, List
from backend.core.inspector import ASTCodeInspector, RULES_REGISTRY
from backend.api.repositories.snippet_repository import SnippetRepository


class InspectService:
    """Service orchestrating static AST security inspection and metrics calculation."""

    def __init__(self, repository: SnippetRepository = None):
        self.repo = repository or SnippetRepository()

    def analyze(self, source_code: str, filename: str = "snippet.py") -> Dict[str, Any]:
        """Performs comprehensive AST inspection and returns structured telemetry."""
        result = ASTCodeInspector.inspect_source_full(source_code, filename=filename)
        return {
            "status": "success",
            "filename": filename,
            "metrics": {
                "loc": result.metrics.loc,
                "sloc": result.metrics.sloc,
                "cyclomatic_complexity": result.metrics.cyclomatic_complexity,
                "functions_count": result.metrics.functions_count,
                "classes_count": result.metrics.classes_count,
                "imports_count": result.metrics.imports_count,
                "risk_score": result.metrics.risk_score,
                "security_status": result.metrics.security_status,
            },
            "violations_count": len(result.violations),
            "violations": [
                {
                    "rule": v.rule,
                    "severity": v.severity,
                    "category": v.category,
                    "line": v.line,
                    "col": v.col,
                    "message": v.message,
                    "snippet": v.snippet,
                    "remediation": v.remediation,
                    "cwe": v.cwe,
                    "owasp": v.owasp,
                }
                for v in result.violations
            ],
            "ast_tree": result.ast_summary,
        }

    def export_sarif(self, source_code: str, filename: str = "snippet.py") -> Dict[str, Any]:
        """Generates standard OASIS SARIF v2.1.0 output."""
        return ASTCodeInspector.to_sarif(source_code, filename=filename)

    def get_registered_rules(self) -> List[Dict[str, Any]]:
        """Returns all registered AST security rules."""
        rules = []
        for r in self.repo.get_rules_registry().values():
            rules.append({
                "rule_id": r.rule_id,
                "name": r.name,
                "category": r.category.value,
                "severity": r.severity.value,
                "title": r.title,
                "cwe": r.cwe,
                "owasp": r.owasp,
                "description": r.description,
                "remediation": r.remediation,
            })
        return rules

    def get_snippets(self) -> Dict[str, Any]:
        """Returns pre-loaded code snippets for demonstration."""
        return self.repo.get_all_snippets()
