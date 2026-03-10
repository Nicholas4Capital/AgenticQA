"""Enterprise Value Creation Agent — Evaluates business value, ROI, and enterprise readiness."""

from __future__ import annotations

import os
import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class EnterpriseValueCreationAgent(BaseAgent):
    name = "enterprise_value"
    description = "Evaluates enterprise readiness: multi-tenancy, SLAs, audit trails, licensing, scalability"
    category = "enterprise"
    priority = 60
    is_gate = False

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

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        present = set()
        enterprise_score = 0

        all_content = ""
        for fpath in context.source_files + context.config_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read() + "\n"
            except (OSError, IOError):
                continue

        for pattern_name, (regex, desc) in self.ENTERPRISE_PATTERNS.items():
            if re.search(regex, all_content, re.IGNORECASE):
                present.add(pattern_name)
                enterprise_score += 1
            else:
                severity = AgentSeverity.HIGH if pattern_name in ("audit_trail", "rbac", "rate_limiting") else AgentSeverity.MEDIUM
                findings.append(Finding(
                    message=f"Missing enterprise feature: {desc}",
                    severity=severity,
                    suggestion=f"Implement {pattern_name.replace('_', ' ')} for enterprise readiness",
                ))

        total = len(self.ENTERPRISE_PATTERNS)
        score_pct = round(enterprise_score / total * 100, 1)

        if score_pct < 50:
            findings.append(Finding(
                message=f"Enterprise readiness score: {score_pct}% — below threshold",
                severity=AgentSeverity.HIGH,
                suggestion="Prioritize enterprise features for production deployment",
            ))

        passed = score_pct >= 50
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={
                "enterprise_score_pct": score_pct,
                "features_present": len(present),
                "features_total": total,
                "features_list": sorted(present),
            },
            learnings=[f"Enterprise readiness: {score_pct}% ({len(present)}/{total} features)"],
        )
