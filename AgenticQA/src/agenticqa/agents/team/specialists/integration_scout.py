"""Integration Scout Agent (#14) — Squad 4, Position 2.

Consolidated from: api_mcp_finder + plugin_utilizer + connection_seeker.
Discovers APIs, MCP servers, plugins, and maps integration points.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Set

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class IntegrationScoutAgent(BaseAgent):
    """
    Unified agent for API discovery, plugin validation, and connection mapping.

    Covers:
    - API/MCP server recommendations by detected category
    - Plugin/extension validation and deprecated package detection
    - Integration point mapping, orphaned endpoints, env var documentation
    """

    name = "integration_scout"
    description = (
        "Discovers APIs, MCP servers, plugins, and integration points. "
        "Maps connections, validates contracts, and recommends tooling."
    )
    category = "connectivity"
    priority = 65
    is_gate = False
    squad = Squad.AI_INTEGRATION
    pipeline_position = 2

    # --- API/MCP recommendations ---
    API_RECOMMENDATIONS = {
        "email": {
            "detect": r"email|smtp|sendmail|nodemailer|mailgun",
            "apis": ["SendGrid", "Mailgun", "Resend", "Amazon SES"],
            "mcp": "email-mcp-server",
        },
        "payment": {
            "detect": r"payment|stripe|paypal|checkout|billing",
            "apis": ["Stripe", "PayPal", "Square"],
            "mcp": "stripe-mcp-server",
        },
        "storage": {
            "detect": r"upload|storage|s3|blob|file.*store",
            "apis": ["AWS S3", "Cloudflare R2", "Supabase Storage"],
            "mcp": "s3-mcp-server",
        },
        "database": {
            "detect": r"database|sql|mongo|postgres|mysql|redis",
            "apis": ["Supabase", "PlanetScale", "Neon", "Upstash"],
            "mcp": "postgres-mcp-server",
        },
        "auth": {
            "detect": r"auth|login|signup|jwt|oauth|session",
            "apis": ["Auth0", "Clerk", "Supabase Auth", "Firebase Auth"],
            "mcp": "auth0-mcp-server",
        },
        "ai_ml": {
            "detect": r"ai|ml|model|llm|embedding|vector",
            "apis": ["Anthropic Claude", "OpenAI", "Cohere", "Replicate"],
            "mcp": "anthropic-mcp-server",
        },
        "monitoring": {
            "detect": r"monitor|metric|trace|alert|observ",
            "apis": ["Datadog", "Sentry", "Grafana", "New Relic"],
            "mcp": "sentry-mcp-server",
        },
        "search": {
            "detect": r"search|index|elastic|algolia",
            "apis": ["Algolia", "Meilisearch", "Typesense", "Elasticsearch"],
            "mcp": "search-mcp-server",
        },
        "queue": {
            "detect": r"queue|worker|job|celery|bull|rabbitmq",
            "apis": ["AWS SQS", "RabbitMQ", "Redis Queue", "Inngest"],
            "mcp": "queue-mcp-server",
        },
        "cdn": {
            "detect": r"cdn|cloudfront|fastly|edge|cache.*static",
            "apis": ["Cloudflare", "Fastly", "AWS CloudFront"],
            "mcp": "cloudflare-mcp-server",
        },
    }

    # --- Plugin recommendations ---
    RECOMMENDED_PLUGINS = {
        "python": {
            "pytest-cov": {"detect": r"pytest.*cov|coverage", "purpose": "Test coverage"},
            "pytest-xdist": {"detect": r"xdist|parallel.*test|-n auto", "purpose": "Parallel testing"},
            "mypy": {"detect": r"mypy|type.*check", "purpose": "Static type checking"},
            "black": {"detect": r"black|format.*black", "purpose": "Code formatting"},
            "ruff": {"detect": r"ruff", "purpose": "Fast Python linting"},
            "bandit": {"detect": r"bandit|security.*scan", "purpose": "Security scanning"},
            "pre-commit": {"detect": r"pre.?commit", "purpose": "Git hooks"},
        },
        "javascript": {
            "eslint-security": {"detect": r"eslint.*security|no-eval", "purpose": "Security linting"},
            "prettier": {"detect": r"prettier", "purpose": "Code formatting"},
            "husky": {"detect": r"husky|pre.?commit", "purpose": "Git hooks"},
            "lint-staged": {"detect": r"lint.?staged", "purpose": "Staged file linting"},
            "typescript-eslint": {"detect": r"@typescript.?eslint", "purpose": "TypeScript linting"},
            "jest-coverage": {"detect": r"coverage.*threshold|collectCoverage", "purpose": "Test coverage"},
        },
    }

    # --- Integration mapping patterns ---
    INTEGRATION_PATTERNS = {
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

    DEPRECATED_JS_PACKAGES = {
        "request": "Use 'node-fetch' or 'axios' instead",
        "moment": "Use 'date-fns' or 'dayjs' instead (moment is in maintenance mode)",
        "tslint": "Use '@typescript-eslint/eslint-plugin' instead",
    }

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        has_python = any(f.endswith(".py") for f in context.source_files)
        has_js = any(f.endswith((".js", ".ts", ".jsx", ".tsx")) for f in context.source_files)

        all_content = ""
        for fpath in context.source_files + context.config_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read() + "\n"
            except (OSError, IOError):
                continue

        # --- 1. API/MCP recommendations ---
        categories_detected = 0
        recommendations_count = 0
        for category, info in self.API_RECOMMENDATIONS.items():
            is_detected = bool(re.search(info["detect"], all_content, re.IGNORECASE))
            if is_detected:
                categories_detected += 1
                using_service = any(
                    re.search(api.lower().replace(" ", ".?"), all_content, re.IGNORECASE)
                    for api in info["apis"]
                )
                if not using_service:
                    recommendations_count += 1
                    findings.append(Finding(
                        message=f"[{category}] Consider: {', '.join(info['apis'][:3])}",
                        severity=AgentSeverity.INFO,
                        suggestion=f"MCP server available: {info['mcp']}",
                    ))

        # --- 2. Plugin recommendations ---
        plugins_installed = 0
        plugins_recommended = 0

        if has_python:
            for plugin, info in self.RECOMMENDED_PLUGINS["python"].items():
                if re.search(info["detect"], all_content, re.IGNORECASE):
                    plugins_installed += 1
                else:
                    plugins_recommended += 1
                    findings.append(Finding(
                        message=f"Recommended Python plugin: {plugin} ({info['purpose']})",
                        severity=AgentSeverity.LOW,
                        suggestion=f"pip install {plugin}",
                    ))

        if has_js:
            for plugin, info in self.RECOMMENDED_PLUGINS["javascript"].items():
                if re.search(info["detect"], all_content, re.IGNORECASE):
                    plugins_installed += 1
                else:
                    plugins_recommended += 1
                    findings.append(Finding(
                        message=f"Recommended JS plugin: {plugin} ({info['purpose']})",
                        severity=AgentSeverity.LOW,
                        suggestion=f"npm install -D {plugin}",
                    ))

        # Deprecated packages
        if has_js:
            findings.extend(self._check_deprecated_js(context.project_root))

        # --- 3. Integration mapping ---
        integration_map: Dict[str, Set[str]] = {}
        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            for name, pattern in self.INTEGRATION_PATTERNS.items():
                if re.search(pattern, content, re.IGNORECASE):
                    if name not in integration_map:
                        integration_map[name] = set()
                    integration_map[name].add(fpath)

        # Check integrations without error handling
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

        # Hardcoded credentials
        findings.extend(self._check_hardcoded_creds(context.source_files))

        # Orphaned endpoints
        findings.extend(self._find_orphaned_endpoints(context.source_files))

        # Env var documentation
        findings.extend(self._check_env_dependencies(context))

        return AgentResult(
            agent_name=self.name,
            passed=True,  # Advisory agent
            findings=findings,
            metrics={
                "categories_detected": categories_detected,
                "api_recommendations": recommendations_count,
                "plugins_installed": plugins_installed,
                "plugins_recommended": plugins_recommended,
                "integrations_found": len(integration_map),
            },
            learnings=[
                f"Integrations: {list(integration_map.keys())}",
                f"Plugins: {plugins_installed} installed, {plugins_recommended} recommended",
            ],
        )

    def _check_deprecated_js(self, project_root: str) -> List[Finding]:
        findings = []
        pkg_path = os.path.join(project_root, "package.json")
        if not os.path.exists(pkg_path):
            return findings
        try:
            with open(pkg_path, "r") as f:
                pkg = json.load(f)
        except (json.JSONDecodeError, OSError):
            return findings

        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        for pkg_name, suggestion in self.DEPRECATED_JS_PACKAGES.items():
            if pkg_name in deps:
                findings.append(Finding(
                    message=f"Deprecated package: {pkg_name}",
                    severity=AgentSeverity.MEDIUM,
                    file_path=pkg_path,
                    suggestion=suggestion,
                ))
        return findings

    def _check_hardcoded_creds(self, source_files: List[str]) -> List[Finding]:
        findings = []
        for fpath in source_files:
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
        defined_endpoints: Set[str] = set()
        called_endpoints: Set[str] = set()

        for fpath in source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            for match in re.finditer(
                r"(?:@\w+\.(?:get|post|put|delete)|app\.(?:get|post|put|delete))\s*\(\s*['\"]([^'\"]+)",
                content,
            ):
                defined_endpoints.add(match.group(1))

            for match in re.finditer(r"(?:fetch|axios|requests)\s*[.(]\s*['\"]([^'\"]+)", content):
                url = match.group(1)
                if url.startswith("/"):
                    called_endpoints.add(url)

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
            for match in re.finditer(r"(?:os\.environ\[|process\.env\.)([A-Z_]+)", content):
                required_env_vars.add(match.group(1))

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
