"""
HTTP Controller for AST Code Inspection endpoints.
"""

from typing import Dict, Any
from backend.api.services.inspect_service import InspectService


class InspectController:
    """Controller handling HTTP requests for code analysis, SARIF export, and rules."""

    def __init__(self, service: InspectService = None):
        self.service = service or InspectService()

    def handle_analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        source = payload.get("source", "")
        filename = payload.get("filename", "snippet.py")
        if not source.strip():
            return {"status": "error", "message": "Source code cannot be empty"}
        return self.service.analyze(source, filename)

    def handle_sarif(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        source = payload.get("source", "")
        filename = payload.get("filename", "snippet.py")
        return self.service.export_sarif(source, filename)

    def handle_get_rules(self) -> Dict[str, Any]:
        return {
            "status": "success",
            "count": len(self.service.get_registered_rules()),
            "rules": self.service.get_registered_rules()
        }

    def handle_get_snippets(self) -> Dict[str, Any]:
        return {
            "status": "success",
            "snippets": self.service.get_snippets()
        }
