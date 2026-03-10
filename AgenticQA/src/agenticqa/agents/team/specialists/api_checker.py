"""API Checker Agent — Validates API endpoints, contracts, versioning, and error handling."""

from __future__ import annotations

import os
import re
from typing import Dict, List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class APICheckerAgent(BaseAgent):
    name = "api_checker"
    description = "Validates API endpoints, REST conventions, error responses, rate limiting, and versioning"
    category = "infrastructure"
    priority = 20
    is_gate = True

    # REST convention checks
    HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        endpoints: List[Dict] = []

        for fpath in context.source_files:
            detected = self._extract_endpoints(fpath)
            endpoints.extend(detected)
            findings.extend(self._check_api_quality(fpath))

        # Validate endpoint patterns
        findings.extend(self._validate_endpoints(endpoints))

        # Check for API security patterns
        findings.extend(self._check_api_security(context.source_files))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={
                "endpoints_found": len(endpoints),
                "files_checked": len(context.source_files),
            },
        )

    def _extract_endpoints(self, fpath: str) -> List[Dict]:
        endpoints = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, IOError):
            return endpoints

        # FastAPI / Flask / Express patterns
        patterns = [
            # FastAPI: @app.get("/path")
            (r"@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)", "fastapi"),
            # Express: app.get("/path", ...)
            (r"(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)", "express"),
            # Flask: @app.route("/path", methods=["GET"])
            (r"@(?:app|bp)\.route\s*\(\s*['\"]([^'\"]+)['\"].*methods=\[([^\]]+)", "flask"),
        ]

        for pattern, framework in patterns:
            for match in re.finditer(pattern, content):
                if framework == "flask":
                    path, methods = match.group(1), match.group(2)
                    endpoints.append({"path": path, "methods": methods, "file": fpath, "framework": framework})
                else:
                    method, path = match.group(1), match.group(2)
                    endpoints.append({"path": path, "method": method, "file": fpath, "framework": framework})

        return endpoints

    def _validate_endpoints(self, endpoints: List[Dict]) -> List[Finding]:
        findings = []
        seen_paths = {}

        for ep in endpoints:
            path = ep["path"]
            method = ep.get("method", "unknown")

            # Check REST naming conventions
            if re.search(r"[A-Z]", path):
                findings.append(Finding(
                    message=f"API path has uppercase letters: {method.upper()} {path}",
                    severity=AgentSeverity.LOW,
                    file_path=ep["file"],
                    suggestion="Use lowercase with hyphens for URL paths",
                ))

            if re.search(r"_", path) and "/api/" in path:
                findings.append(Finding(
                    message=f"API path uses underscores: {path} — prefer hyphens",
                    severity=AgentSeverity.LOW,
                    file_path=ep["file"],
                ))

            # Check for versioning
            if "/api/" in path and not re.search(r"/v\d+/", path):
                findings.append(Finding(
                    message=f"API endpoint missing version prefix: {path}",
                    severity=AgentSeverity.MEDIUM,
                    file_path=ep["file"],
                    suggestion="Add version prefix like /api/v1/...",
                ))

            # Check for duplicate endpoints
            key = f"{method}:{path}"
            if key in seen_paths:
                findings.append(Finding(
                    message=f"Duplicate endpoint: {method.upper()} {path}",
                    severity=AgentSeverity.HIGH,
                    file_path=ep["file"],
                ))
            seen_paths[key] = ep

        return findings

    def _check_api_quality(self, fpath: str) -> List[Finding]:
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, IOError):
            return findings

        # Check for error response patterns
        if re.search(r"@(?:app|router)\.", content):
            if not re.search(r"HTTPException|abort\(|status_code|res\.status", content):
                findings.append(Finding(
                    message="API file has endpoints but no explicit error status codes",
                    severity=AgentSeverity.MEDIUM,
                    file_path=fpath,
                    suggestion="Add proper HTTP error responses (4xx, 5xx)",
                ))

            if not re.search(r"rate.?limit|throttle|RateLimit", content, re.IGNORECASE):
                findings.append(Finding(
                    message="No rate limiting detected in API file",
                    severity=AgentSeverity.MEDIUM,
                    file_path=fpath,
                ))

        return findings

    def _check_api_security(self, source_files: List[str]) -> List[Finding]:
        findings = []
        has_auth = False
        has_cors = False
        has_input_validation = False

        for fpath in source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            if re.search(r"auth|bearer|jwt|oauth|api.?key.*header", content, re.IGNORECASE):
                has_auth = True
            if re.search(r"cors|access.?control.?allow", content, re.IGNORECASE):
                has_cors = True
            if re.search(r"validate|sanitize|escape|pydantic|joi|zod|yup", content, re.IGNORECASE):
                has_input_validation = True

        if not has_auth:
            findings.append(Finding(
                message="No authentication mechanism detected in API layer",
                severity=AgentSeverity.HIGH,
                suggestion="Implement authentication (JWT, API keys, OAuth)",
            ))
        if not has_cors:
            findings.append(Finding(
                message="No CORS configuration detected",
                severity=AgentSeverity.MEDIUM,
            ))
        if not has_input_validation:
            findings.append(Finding(
                message="No input validation library detected",
                severity=AgentSeverity.HIGH,
                suggestion="Add input validation (Pydantic, Joi, Zod)",
            ))

        return findings
