"""Complementary API & MCP Finder Agent — Discovers useful APIs and MCP servers."""

from __future__ import annotations

import re
from typing import Dict, List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class ComplementaryAPIMCPFinderAgent(BaseAgent):
    name = "api_mcp_finder"
    description = (
        "Discovers complementary APIs, MCP servers, and external services "
        "that could enhance the project's capabilities"
    )
    category = "connectivity"
    priority = 75
    is_gate = False
    squad = Squad.AI_INTEGRATION
    pipeline_position = 2

    # Known useful API categories based on detected patterns
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

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        detected_categories: Dict[str, bool] = {}
        recommendations: List[Dict] = []

        all_content = ""
        for fpath in context.source_files + context.config_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read() + "\n"
            except (OSError, IOError):
                continue

        for category, info in self.API_RECOMMENDATIONS.items():
            is_detected = bool(re.search(info["detect"], all_content, re.IGNORECASE))
            detected_categories[category] = is_detected

            if is_detected:
                # Check if they're already using a specific service
                using_service = any(
                    re.search(api.lower().replace(" ", ".?"), all_content, re.IGNORECASE)
                    for api in info["apis"]
                )
                if not using_service:
                    recommendations.append({
                        "category": category,
                        "apis": info["apis"],
                        "mcp": info["mcp"],
                    })
                    findings.append(Finding(
                        message=f"[{category}] Consider: {', '.join(info['apis'][:3])}",
                        severity=AgentSeverity.INFO,
                        suggestion=f"MCP server available: {info['mcp']}",
                    ))
            else:
                # Suggest the category entirely
                findings.append(Finding(
                    message=f"Feature gap: No {category} integration detected",
                    severity=AgentSeverity.LOW,
                    suggestion=f"Consider adding {category}: {', '.join(info['apis'][:2])}",
                ))

        # Check for MCP configuration
        has_mcp = re.search(r"mcp|model.?context.?protocol|\.mcp\.", all_content, re.IGNORECASE)
        if not has_mcp:
            findings.append(Finding(
                message="No MCP (Model Context Protocol) integration detected",
                severity=AgentSeverity.LOW,
                suggestion="MCP servers can enhance AI agent capabilities with tool access",
            ))

        return AgentResult(
            agent_name=self.name,
            passed=True,  # Advisory agent
            findings=findings,
            metrics={
                "categories_detected": sum(detected_categories.values()),
                "recommendations": len(recommendations),
            },
            learnings=[f"Detected integrations: {[k for k, v in detected_categories.items() if v]}"],
        )
