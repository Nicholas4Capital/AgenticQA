"""Error Logger Agent — Validates logging, error tracking, and observability."""

from __future__ import annotations

import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class ErrorLoggerAgent(BaseAgent):
    name = "error_logger"
    description = "Validates logging practices, error tracking, structured logging, and observability"
    category = "observability"
    priority = 35
    can_auto_fix = False
    is_gate = False
    squad = Squad.CODE_QUALITY
    pipeline_position = 5

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        has_structured_logging = False
        has_error_tracking = False
        has_health_check = False

        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.splitlines()
            except (OSError, IOError):
                continue

            # Check logging practices
            findings.extend(self._check_logging(fpath, lines))

            # Detect structured logging
            if re.search(r"structlog|json_formatter|JsonFormatter|logging\.config", content):
                has_structured_logging = True

            # Detect error tracking services
            if re.search(r"sentry|datadog|newrelic|rollbar|bugsnag|airbrake", content, re.IGNORECASE):
                has_error_tracking = True

            # Detect health checks
            if re.search(r"health|readiness|liveness|/healthz|/ready", content, re.IGNORECASE):
                has_health_check = True

        if not has_structured_logging:
            findings.append(Finding(
                message="No structured logging detected — logs may be hard to parse in production",
                severity=AgentSeverity.MEDIUM,
                suggestion="Use structlog or JSON formatters for structured logging",
            ))

        if not has_error_tracking:
            findings.append(Finding(
                message="No error tracking service detected (Sentry, Datadog, etc.)",
                severity=AgentSeverity.MEDIUM,
                suggestion="Integrate an error tracking service for production monitoring",
            ))

        if not has_health_check:
            findings.append(Finding(
                message="No health check endpoint detected",
                severity=AgentSeverity.MEDIUM,
                suggestion="Add /health or /healthz endpoint for infrastructure monitoring",
            ))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name, passed=passed, findings=findings,
            metrics={
                "structured_logging": has_structured_logging,
                "error_tracking": has_error_tracking,
                "health_check": has_health_check,
            },
        )

    def _check_logging(self, fpath: str, lines: List[str]) -> List[Finding]:
        findings = []
        in_except = False
        except_line = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            if stripped.startswith("except"):
                in_except = True
                except_line = i

            if in_except and stripped and not stripped.startswith("#"):
                if re.search(r"pass$|continue$|\.\.\.$", stripped):
                    findings.append(Finding(
                        message="Exception silently swallowed — add logging",
                        severity=AgentSeverity.HIGH,
                        file_path=fpath, line_number=except_line,
                        suggestion="Log the exception before continuing",
                    ))
                    in_except = False
                elif re.search(r"log|print|raise|return", stripped):
                    in_except = False

            # Check for print-based logging in Python
            if re.search(r"print\(.*(?:error|exception|traceback|fail)", stripped, re.IGNORECASE):
                findings.append(Finding(
                    message="Using print() for error logging — use proper logger",
                    severity=AgentSeverity.LOW,
                    file_path=fpath, line_number=i,
                ))

            # Check for sensitive data in logs
            if re.search(r"log.*(?:password|secret|token|api_key|credit.?card)", stripped, re.IGNORECASE):
                findings.append(Finding(
                    message="Potentially logging sensitive data",
                    severity=AgentSeverity.CRITICAL,
                    file_path=fpath, line_number=i,
                    suggestion="Redact sensitive data before logging",
                ))

        return findings
