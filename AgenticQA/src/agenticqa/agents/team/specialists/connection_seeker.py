"""Connection Seeking Agent — Finds integration points and tool connections."""

from __future__ import annotations

import os
import re
from typing import Dict, List, Set

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class ConnectionSeekingAgent(BaseAgent):
    name = "connection_seeker"
    description = (
        "Maps integration points, discovers tool connections, validates "
        "API contracts, and ensures systems are properly linked"
    )
    category = "connectivity"
    priority = 70
    is_gate = False

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        # Map all integration points
        integrations = self._map_integrations(context.source_files)
        findings.extend(integrations["findings"])

        # Check for broken/incomplete connections
        findings.extend(self._check_connections(context))

        # Identify orphaned endpoints
        findings.extend(self._find_orphaned_endpoints(context.source_files))

        # Check env var dependencies
        findings.extend(self._check_env_dependencies(context))

        return AgentResult(
            agent_name=self.name,
            passed=True,
            findings=findings,
            metrics={
                "integrations_found": len(integrations["map"]),
                "connection_issues": len(findings),
            },
            learnings=[f"Integration map: {list(integrations['map'].keys())}"],
        )

    def _map_integrations(self, source_files: List[str]) -> Dict:
        integration_map: Dict[str, Set[str]] = {}
        findings = []

        patterns = {
            "http_client": r"fetch\(|axios|requests\.(?:get|post)|http\.request|urllib",
            "database": r"connect\(|createPool|create_engine|mongoose\.connect|prisma",
            "cache": r"redis|memcache|ioredis|node-cache",
            "queue": r"rabbitmq|celery|bull|kafka|sqs",
            "storage": r"s3|gcs|azure.*blob|cloudinary|uploadthing",
            "email": r"smtp|sendgrid|mailgun|ses.*send|nodemailer",
            "auth_provider": r"auth0|firebase.*auth|cognito|clerk|supabase.*auth",
            "ai_provider": r"anthropic|openai|cohere|replicate|hugging.?face",
            "monitoring": r"sentry|datadog|newrelic|prometheus|grafana",
            "search": r"elasticsearch|algolia|meilisearch|typesense",
        }

        for fpath in source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            for name, pattern in patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    if name not in integration_map:
                        integration_map[name] = set()
                    integration_map[name].add(fpath)

        # Report integrations without proper error handling
        for name, files in integration_map.items():
            for fpath in files:
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except (OSError, IOError):
                    continue

                if not re.search(r"try|catch|except|\.catch\(|on\(['\"]error", content):
                    findings.append(Finding(
                        message=f"{name} integration in {os.path.basename(fpath)} lacks error handling",
                        severity=AgentSeverity.MEDIUM,
                        file_path=fpath,
                        suggestion=f"Add error handling for {name} connection failures",
                    ))

        return {"map": integration_map, "findings": findings}

    def _check_connections(self, context: ProjectContext) -> List[Finding]:
        findings = []

        # Check for connection strings without env vars
        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (OSError, IOError):
                continue

            for i, line in enumerate(lines, 1):
                if re.search(r"(?:mongodb|postgres|mysql|redis)://\w+:\w+@", line):
                    findings.append(Finding(
                        message="Hardcoded connection string with credentials",
                        severity=AgentSeverity.CRITICAL,
                        file_path=fpath, line_number=i,
                        suggestion="Use environment variables for connection strings",
                    ))

        return findings

    def _find_orphaned_endpoints(self, source_files: List[str]) -> List[Finding]:
        findings = []
        defined_endpoints = set()
        called_endpoints = set()

        for fpath in source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            # Find defined API routes
            for match in re.finditer(r"(?:@\w+\.(?:get|post|put|delete)|app\.(?:get|post|put|delete))\s*\(\s*['\"]([^'\"]+)", content):
                defined_endpoints.add(match.group(1))

            # Find API calls
            for match in re.finditer(r"(?:fetch|axios|requests)\s*[.(]\s*['\"]([^'\"]+)", content):
                url = match.group(1)
                if url.startswith("/"):
                    called_endpoints.add(url)

        # Endpoints defined but never called internally (could be external-facing)
        unused = defined_endpoints - called_endpoints
        if len(unused) > len(defined_endpoints) * 0.5 and len(defined_endpoints) > 5:
            findings.append(Finding(
                message=f"{len(unused)}/{len(defined_endpoints)} endpoints have no internal callers",
                severity=AgentSeverity.INFO,
                suggestion="Verify these endpoints are used by external clients or remove",
            ))

        return findings

    def _check_env_dependencies(self, context: ProjectContext) -> List[Finding]:
        findings = []
        required_env_vars: Set[str] = set()

        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            # Find env var usage without defaults
            for match in re.finditer(r"(?:os\.environ\[|process\.env\.)([A-Z_]+)", content):
                required_env_vars.add(match.group(1))

        # Check if env vars are documented
        env_example = os.path.join(context.project_root, ".env.example")
        documented_vars: Set[str] = set()
        if os.path.exists(env_example):
            try:
                with open(env_example, "r") as f:
                    for line in f:
                        if "=" in line and not line.startswith("#"):
                            documented_vars.add(line.split("=")[0].strip())
            except OSError:
                pass

        undocumented = required_env_vars - documented_vars
        for var in sorted(undocumented)[:10]:
            findings.append(Finding(
                message=f"Env var {var} used in code but not documented in .env.example",
                severity=AgentSeverity.LOW,
                suggestion="Add to .env.example for developer onboarding",
            ))

        return findings
