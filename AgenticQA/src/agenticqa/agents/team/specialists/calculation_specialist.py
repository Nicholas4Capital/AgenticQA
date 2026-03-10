"""Calculation Specialist Agent — Validates numerical operations, precision, and financial calculations."""

from __future__ import annotations

import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class CalculationSpecialistAgent(BaseAgent):
    name = "calculation_specialist"
    description = "Validates numerical precision, financial calculations, rounding, currency handling, and math operations"
    category = "quality"
    priority = 35
    is_gate = True
    squad = Squad.TESTING_RESILIENCE
    pipeline_position = 3

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.splitlines()
            except (OSError, IOError):
                continue

            findings.extend(self._check_numeric_precision(fpath, lines, content))
            findings.extend(self._check_financial_patterns(fpath, lines))
            findings.extend(self._check_math_operations(fpath, lines))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name, passed=passed, findings=findings,
            metrics={"files_checked": len(context.source_files)},
        )

    def _check_numeric_precision(self, fpath: str, lines: List[str], content: str) -> List[Finding]:
        findings = []

        # Check for floating point comparison
        for i, line in enumerate(lines, 1):
            if re.search(r"==\s*\d+\.\d+|!=\s*\d+\.\d+", line):
                findings.append(Finding(
                    message="Direct float comparison — use tolerance-based comparison",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath, line_number=i,
                    suggestion="Use abs(a - b) < epsilon or math.isclose()",
                ))

        # Check for float-based currency/money
        if re.search(r"price|amount|total|cost|fee|balance|payment|salary|rate", content, re.IGNORECASE):
            if fpath.endswith(".py") and "Decimal" not in content and "decimal" not in content:
                if re.search(r"float\(|:\s*float", content):
                    findings.append(Finding(
                        message="Using float for monetary values — use Decimal for precision",
                        severity=AgentSeverity.CRITICAL,
                        file_path=fpath,
                        suggestion="from decimal import Decimal; use Decimal for all money",
                    ))
            if fpath.endswith((".js", ".ts")):
                if not re.search(r"BigInt|bignumber|dinero|currency\.js|Decimal", content):
                    if re.search(r"parseFloat|Number\(.*price", content):
                        findings.append(Finding(
                            message="Using float for monetary values in JS — use a decimal library",
                            severity=AgentSeverity.HIGH,
                            file_path=fpath,
                            suggestion="Use dinero.js, bignumber.js, or currency.js",
                        ))

        return findings

    def _check_financial_patterns(self, fpath: str, lines: List[str]) -> List[Finding]:
        findings = []
        for i, line in enumerate(lines, 1):
            # Division without zero check
            if re.search(r"/\s*(?!0\b)\w+(?:\.\w+)?(?:\s*[;,)\]]|\s*$)", line):
                if "/ 0" not in line and re.search(r"(?:rate|ratio|percent|average|mean)", line, re.IGNORECASE):
                    context_lines = lines[max(0, i - 3):i]
                    has_zero_check = any(
                        re.search(r"if.*(?:!=|>)\s*0|if.*(?:not|!).*zero", l, re.IGNORECASE)
                        for l in context_lines
                    )
                    if not has_zero_check:
                        findings.append(Finding(
                            message="Division in financial calculation without zero-check",
                            severity=AgentSeverity.HIGH,
                            file_path=fpath, line_number=i,
                            suggestion="Add explicit zero-division guard",
                        ))

            # Rounding without specifying precision
            if re.search(r"round\(\s*\w+\s*\)", line):
                findings.append(Finding(
                    message="round() without explicit precision — specify decimal places",
                    severity=AgentSeverity.MEDIUM,
                    file_path=fpath, line_number=i,
                    suggestion="Use round(value, 2) for currency or specify precision",
                ))

        return findings

    def _check_math_operations(self, fpath: str, lines: List[str]) -> List[Finding]:
        findings = []
        for i, line in enumerate(lines, 1):
            # Integer overflow potential (in languages without arbitrary precision)
            if fpath.endswith((".js", ".ts")) and re.search(r"\*\s*\d{10,}", line):
                findings.append(Finding(
                    message="Large number multiplication — potential precision loss",
                    severity=AgentSeverity.MEDIUM,
                    file_path=fpath, line_number=i,
                    suggestion="Use BigInt for large integer arithmetic",
                ))

        return findings
