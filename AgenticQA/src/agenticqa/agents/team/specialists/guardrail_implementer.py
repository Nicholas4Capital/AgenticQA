"""Guardrail Implementer Agent — Ensures safety guardrails are in place across the system."""

from __future__ import annotations

import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class GuardrailImplementerAgent(BaseAgent):
    name = "guardrail_implementer"
    description = (
        "Validates safety guardrails: input validation, output sanitization, "
        "rate limiting, circuit breakers, timeouts, and kill switches"
    )
    category = "compliance"
    priority = 12
    is_gate = True
    can_auto_fix = False

    GUARDRAIL_CHECKS = {
        "input_validation": (
            r"validate|sanitize|escape|zod|joi|pydantic|marshmallow|cerberus",
            "Input validation framework",
        ),
        "output_encoding": (
            r"escape.?html|sanitize.?html|DOMPurify|bleach|markupsafe",
            "Output encoding/XSS prevention",
        ),
        "rate_limiting": (
            r"rate.?limit|throttle|express.?rate|slowapi|flask.?limiter",
            "Rate limiting",
        ),
        "circuit_breaker": (
            r"circuit.?breaker|pybreaker|opossum|resilience|hystrix",
            "Circuit breaker pattern",
        ),
        "timeout": (
            r"timeout|deadline|cancel.*after|signal\.alarm|AbortController",
            "Request/operation timeouts",
        ),
        "size_limits": (
            r"max.?size|content.?length|payload.*limit|multer.*limit|body.?parser.*limit",
            "Payload size limits",
        ),
        "auth_guard": (
            r"@auth|@login_required|authenticate|isAuthenticated|requireAuth|protect.*route",
            "Authentication guards",
        ),
        "csrf_protection": (
            r"csrf|csrftoken|xsrf|csurf|CSRFProtect",
            "CSRF protection",
        ),
        "content_security": (
            r"content.?security.?policy|csp|helmet|security.*header",
            "Content Security Policy",
        ),
        "kill_switch": (
            r"kill.?switch|feature.?flag|toggle|circuit.*open|disable.*feature|maintenance.?mode",
            "Kill switch / feature flags",
        ),
    }

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        present = set()

        all_content = ""
        for fpath in context.source_files + context.config_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read() + "\n"
            except (OSError, IOError):
                continue

        for name, (regex, desc) in self.GUARDRAIL_CHECKS.items():
            if re.search(regex, all_content, re.IGNORECASE):
                present.add(name)
            else:
                severity = (
                    AgentSeverity.CRITICAL if name in ("input_validation", "auth_guard")
                    else AgentSeverity.HIGH if name in ("rate_limiting", "timeout", "output_encoding")
                    else AgentSeverity.MEDIUM
                )
                findings.append(Finding(
                    message=f"Missing guardrail: {desc}",
                    severity=severity,
                    suggestion=f"Implement {name.replace('_', ' ')} guardrail",
                ))

        # Check for dangerous operations without guardrails
        findings.extend(self._check_dangerous_ops(context.source_files))

        score = round(len(present) / max(len(self.GUARDRAIL_CHECKS), 1) * 100, 1)
        passed = score >= 60  # Must have at least 60% of guardrails
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={
                "guardrail_score_pct": score,
                "guardrails_present": sorted(present),
                "guardrails_missing": sorted(set(self.GUARDRAIL_CHECKS.keys()) - present),
            },
            learnings=[f"Guardrail coverage: {score}% ({len(present)}/{len(self.GUARDRAIL_CHECKS)})"],
        )

    def _check_dangerous_ops(self, source_files: List[str]) -> List[Finding]:
        findings = []
        dangerous = [
            (r"subprocess\.call|os\.system|child_process\.exec\(",
             "Shell command execution — validate/sanitize input", AgentSeverity.CRITICAL),
            (r"eval\(|exec\(|Function\(",
             "Dynamic code execution — major security risk", AgentSeverity.CRITICAL),
            (r"pickle\.loads|yaml\.load\((?!.*Loader)",
             "Unsafe deserialization — use safe loaders", AgentSeverity.CRITICAL),
            (r"__import__\(|importlib\.import_module\(\s*(?![\'\"])",
             "Dynamic import from user input — injection risk", AgentSeverity.HIGH),
        ]

        for fpath in source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (OSError, IOError):
                continue

            for i, line in enumerate(lines, 1):
                for pattern, msg, severity in dangerous:
                    if re.search(pattern, line):
                        findings.append(Finding(
                            message=msg,
                            severity=severity,
                            file_path=fpath, line_number=i,
                        ))

        return findings
