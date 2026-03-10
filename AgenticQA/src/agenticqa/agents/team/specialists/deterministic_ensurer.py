"""Deterministic Ensurer Agent — Validates determinism, reproducibility, and predictable behavior."""

from __future__ import annotations

import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class DeterministicEnsurerAgent(BaseAgent):
    name = "deterministic_ensurer"
    description = (
        "Ensures deterministic behavior: seed management, reproducible outputs, "
        "idempotent operations, and predictable AI responses"
    )
    category = "quality"
    priority = 40
    is_gate = True
    squad = Squad.ARCHITECTURE
    pipeline_position = 2

    NON_DETERMINISTIC_PATTERNS = [
        (r"random\(\)|Math\.random\(\)|randint|randrange|choice\(|shuffle\(|sample\(",
         "Random without seed — non-deterministic behavior", AgentSeverity.HIGH),
        (r"uuid[.\w]*\(\)|uuid4\(\)|nanoid|cuid",
         "UUID/random ID generation — ensure this is intentional", AgentSeverity.LOW),
        (r"datetime\.now\(\)|Date\.now\(\)|time\.time\(\)|new Date\(\)",
         "Time-dependent code — mock in tests for determinism", AgentSeverity.LOW),
        (r"os\.environ|process\.env(?!\.[A-Z_]+\s*\|\|)",
         "Environment-dependent behavior — ensure defaults exist", AgentSeverity.MEDIUM),
    ]

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.splitlines()
            except (OSError, IOError):
                continue

            # Check for non-deterministic patterns
            for i, line in enumerate(lines, 1):
                for pattern, msg, severity in self.NON_DETERMINISTIC_PATTERNS:
                    if re.search(pattern, line):
                        findings.append(Finding(
                            message=msg,
                            severity=severity,
                            file_path=fpath, line_number=i,
                        ))

            # Check AI-specific determinism
            findings.extend(self._check_ai_determinism(fpath, lines, content))

            # Check for idempotency
            findings.extend(self._check_idempotency(fpath, content))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name, passed=passed, findings=findings,
            metrics={"files_checked": len(context.source_files)},
            learnings=self._summarize(findings),
        )

    def _check_ai_determinism(self, fpath: str, lines: List[str], content: str) -> List[Finding]:
        findings = []

        if not re.search(r"anthropic|openai|llm|model.*invoke|completion", content, re.IGNORECASE):
            return findings

        # Check for temperature=0 for deterministic AI
        has_temp = re.search(r"temperature\s*[:=]\s*(\d+\.?\d*)", content)
        if has_temp:
            temp = float(has_temp.group(1))
            if temp > 0:
                findings.append(Finding(
                    message=f"AI temperature={temp} — set to 0 for deterministic outputs",
                    severity=AgentSeverity.MEDIUM,
                    file_path=fpath,
                    suggestion="Use temperature=0 for reproducible AI outputs, or make configurable",
                ))
        else:
            findings.append(Finding(
                message="AI call without explicit temperature setting",
                severity=AgentSeverity.MEDIUM,
                file_path=fpath,
                suggestion="Set temperature=0 for deterministic behavior",
            ))

        # Check for seed parameter
        if "seed" not in content.lower() and re.search(r"\.create\(|\.invoke\(", content):
            findings.append(Finding(
                message="AI API call without seed parameter — responses may vary",
                severity=AgentSeverity.LOW,
                file_path=fpath,
                suggestion="Add seed parameter if API supports it for reproducibility",
            ))

        return findings

    def _check_idempotency(self, fpath: str, content: str) -> List[Finding]:
        findings = []

        # Check for non-idempotent operations in retry/loop contexts
        if re.search(r"retry|while.*True|for.*range.*retry", content, re.IGNORECASE):
            if re.search(r"INSERT|create\(|\.add\(|\.append\(.*db|\.save\(", content, re.IGNORECASE):
                if not re.search(r"upsert|on_conflict|IF NOT EXISTS|get_or_create|findOrCreate", content, re.IGNORECASE):
                    findings.append(Finding(
                        message="Non-idempotent write in retry context — may create duplicates",
                        severity=AgentSeverity.HIGH,
                        file_path=fpath,
                        suggestion="Use upsert/get_or_create for idempotent operations",
                    ))

        return findings

    def _summarize(self, findings: List[Finding]) -> List[str]:
        non_det = sum(1 for f in findings if f.severity in (AgentSeverity.HIGH, AgentSeverity.MEDIUM))
        if non_det == 0:
            return ["Code appears deterministic"]
        return [f"Found {non_det} non-deterministic patterns requiring attention"]
