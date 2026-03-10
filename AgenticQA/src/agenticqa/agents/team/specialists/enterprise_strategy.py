"""Enterprise Strategy Agent (#20) — Squad 6, Position 2.

Consolidated from: enterprise_value + enterprise_direction.
Evaluates enterprise readiness, strategic alignment, and AI-first direction.
"""

from __future__ import annotations

import os
import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class EnterpriseStrategyAgent(BaseAgent):
    """
    Unified agent for enterprise value assessment and strategic direction.

    Covers:
    - Enterprise readiness: multi-tenancy, RBAC, audit, SSO, webhooks, SLAs
    - Architecture patterns: separation of concerns, DI, event-driven
    - Tech debt assessment: TODOs, deprecated code, large files
    - AI-first direction: LLM integration, vector stores, agent frameworks
    """

    name = "enterprise_strategy"
    description = (
        "Enterprise readiness and strategic direction: multi-tenancy, RBAC, "
        "audit trails, architecture patterns, tech debt, AI-first assessment"
    )
    category = "enterprise"
    priority = 60
    is_gate = False
    squad = Squad.STRATEGY_VISION
    pipeline_position = 2

    # --- Enterprise readiness patterns ---
    ENTERPRISE_PATTERNS = {
        "multi_tenancy": (r"tenant|multi.?tenant|org_id|organization_id|workspace_id", "Multi-tenancy support"),
        "audit_trail": (r"audit|audit.?log|audit.?trail|action.?log", "Audit trail/logging"),
        "rbac": (r"role|permission|rbac|access.?control|authorize|can_access", "Role-based access control"),
        "sso": (r"saml|sso|single.?sign.?on|oauth2|oidc", "Single sign-on"),
        "rate_limiting": (r"rate.?limit|throttle|quota", "Rate limiting"),
        "data_export": (r"export|csv|xlsx|bulk.?download|data.?portability", "Data export/portability"),
        "webhook": (r"webhook|callback.?url|event.?notification", "Webhook/event notifications"),
        "analytics": (r"analytics|metrics|telemetry|usage.?tracking", "Analytics/metrics"),
        "backup": (r"backup|snapshot|disaster.?recovery|point.?in.?time", "Backup/DR"),
        "sla": (r"sla|uptime|availability|nine.?9|99\.9", "SLA/uptime guarantees"),
        "compliance": (r"gdpr|ccpa|hipaa|soc2|iso.?27001|fedramp", "Compliance certifications"),
        "api_versioning": (r"/v\d+/|api.?version|version.?header", "API versioning"),
    }

    # --- Architecture patterns ---
    ARCHITECTURE_PATTERNS = {
        "separation_of_concerns": r"controller|service|repository|model|view|handler|usecase",
        "dependency_injection": r"inject|@Inject|provide|Container|IoC|dependency.*inject",
        "event_driven": r"event.?bus|EventEmitter|publish|subscribe|on\(['\"]",
        "microservices": r"microservice|service.?mesh|grpc|protobuf|api.?gateway",
        "clean_architecture": r"domain|entity|use.?case|repository|interface|port.*adapter",
    }

    # --- AI-first patterns ---
    AI_PATTERNS = {
        "llm_integration": r"anthropic|openai|llm|claude|gpt|langchain",
        "agent_framework": r"agent|tool_use|function_call|langgraph|crew",
        "vector_store": r"vector|embedding|weaviate|pinecone|qdrant|chroma",
        "ml_pipeline": r"pipeline|model.*train|inference|predict|transform",
        "ai_observability": r"trace|span|langsmith|wandb|mlflow|experiment",
        "prompt_management": r"prompt.*template|system.*prompt|few.?shot|chain.?of.?thought",
    }

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        all_content = ""
        for fpath in context.source_files + context.config_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read() + "\n"
            except (OSError, IOError):
                continue

        # --- 1. Enterprise readiness ---
        enterprise_present = set()
        for pattern_name, (regex, desc) in self.ENTERPRISE_PATTERNS.items():
            if re.search(regex, all_content, re.IGNORECASE):
                enterprise_present.add(pattern_name)
            else:
                severity = (
                    AgentSeverity.HIGH
                    if pattern_name in ("audit_trail", "rbac", "rate_limiting")
                    else AgentSeverity.MEDIUM
                )
                findings.append(Finding(
                    message=f"Missing enterprise feature: {desc}",
                    severity=severity,
                    suggestion=f"Implement {pattern_name.replace('_', ' ')} for enterprise readiness",
                ))

        enterprise_total = len(self.ENTERPRISE_PATTERNS)
        enterprise_score = round(len(enterprise_present) / enterprise_total * 100, 1)

        if enterprise_score < 50:
            findings.append(Finding(
                message=f"Enterprise readiness score: {enterprise_score}% — below threshold",
                severity=AgentSeverity.HIGH,
                suggestion="Prioritize enterprise features for production deployment",
            ))

        # --- 2. Architecture assessment ---
        arch_found = set()
        for name, regex in self.ARCHITECTURE_PATTERNS.items():
            if re.search(regex, all_content, re.IGNORECASE):
                arch_found.add(name)

        if "separation_of_concerns" not in arch_found:
            findings.append(Finding(
                message="No clear separation of concerns detected (MVC, Clean Architecture, etc.)",
                severity=AgentSeverity.HIGH,
                suggestion="Organize code into layers: handlers, services, repositories",
            ))

        arch_score = round(len(arch_found) / max(len(self.ARCHITECTURE_PATTERNS), 1) * 100, 1)

        # --- 3. Tech debt ---
        debt_indicators = 0
        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            todos = len(re.findall(r"#\s*TODO|//\s*TODO|#\s*HACK|#\s*FIXME", content))
            debt_indicators += todos

            if re.search(r"@deprecated|DEPRECATED|deprecated", content):
                debt_indicators += 1

            line_count = content.count("\n")
            if line_count > 500:
                findings.append(Finding(
                    message=f"Large file ({line_count} lines): {os.path.basename(fpath)}",
                    severity=AgentSeverity.LOW,
                    file_path=fpath,
                    suggestion="Consider splitting into smaller, focused modules",
                ))
                debt_indicators += 1

        if debt_indicators > 20:
            findings.append(Finding(
                message=f"High tech debt indicators: {debt_indicators} markers found",
                severity=AgentSeverity.MEDIUM,
                suggestion="Schedule tech debt reduction sprint",
            ))

        tech_debt_score = max(0, 100 - debt_indicators * 3)

        # --- 4. AI-first assessment ---
        ai_found = set()
        for name, regex in self.AI_PATTERNS.items():
            if re.search(regex, all_content, re.IGNORECASE):
                ai_found.add(name)
            else:
                findings.append(Finding(
                    message=f"AI-first opportunity: {name.replace('_', ' ')} not detected",
                    severity=AgentSeverity.LOW,
                    suggestion=f"Consider adding {name.replace('_', ' ')} for AI-first architecture",
                ))

        ai_score = round(len(ai_found) / max(len(self.AI_PATTERNS), 1) * 100, 1)

        passed = enterprise_score >= 50
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={
                "enterprise_score_pct": enterprise_score,
                "enterprise_features_present": len(enterprise_present),
                "enterprise_features_total": enterprise_total,
                "architecture_score": arch_score,
                "tech_debt_score": tech_debt_score,
                "ai_first_score": ai_score,
            },
            learnings=[
                f"Enterprise readiness: {enterprise_score}%",
                f"Architecture patterns: {sorted(arch_found)}",
                f"AI-first score: {ai_score}%",
                f"Tech debt score: {tech_debt_score}/100",
            ],
        )
