"""Implementation Confirmer Agent — Verifies that implementations match specifications."""

from __future__ import annotations

import os
import re
from typing import Dict, List, Set

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class ImplementationConfirmerAgent(BaseAgent):
    name = "implementation_confirmer"
    description = "Verifies implementations match specs, checks for incomplete features, dead code, and TODO items"
    category = "quality"
    priority = 30
    is_gate = True
    squad = Squad.TESTING_RESILIENCE
    pipeline_position = 2

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        # Check for incomplete implementations
        for fpath in context.source_files:
            findings.extend(self._check_completeness(fpath))

        # Check for dead/unreachable code
        if any(f.endswith(".py") for f in context.source_files):
            findings.extend(self._check_dead_code_python(context.source_files))

        # Verify exports and public API consistency
        findings.extend(self._check_exports(context.source_files))

        # Cross-check: if prior agents found issues that should be resolved
        for prior in context.prior_results:
            for suggestion in prior.suggestions_for_next_run:
                if "implement" in suggestion.lower():
                    findings.append(Finding(
                        message=f"Prior agent suggested: {suggestion}",
                        severity=AgentSeverity.MEDIUM,
                        metadata={"from_agent": prior.agent_name},
                    ))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={"files_checked": len(context.source_files)},
        )

    def _check_completeness(self, fpath: str) -> List[Finding]:
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, IOError):
            return findings

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped in ("pass", "...") and i > 1:
                # Check if this is in a function/class body
                prev = lines[i - 2].strip() if i >= 2 else ""
                if re.match(r"def |class |async def ", prev):
                    findings.append(Finding(
                        message=f"Stub implementation (pass/...) in {os.path.basename(fpath)}",
                        severity=AgentSeverity.HIGH,
                        file_path=fpath, line_number=i,
                        suggestion="Implement the function body",
                    ))

            if re.search(r"raise\s+NotImplementedError", stripped):
                findings.append(Finding(
                    message="NotImplementedError — incomplete implementation",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath, line_number=i,
                ))

            if re.search(r"#\s*TODO.*implement|#\s*FIXME.*implement", stripped, re.IGNORECASE):
                findings.append(Finding(
                    message=f"TODO: implementation needed: {stripped[:80]}",
                    severity=AgentSeverity.MEDIUM,
                    file_path=fpath, line_number=i,
                ))

        return findings

    def _check_dead_code_python(self, source_files: List[str]) -> List[Finding]:
        findings = []
        defined_functions: Dict[str, str] = {}  # name -> file
        called_functions: Set[str] = set()

        for fpath in source_files:
            if not fpath.endswith(".py"):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            for match in re.finditer(r"def\s+(\w+)\s*\(", content):
                name = match.group(1)
                if not name.startswith("_") and name != "__init__":
                    defined_functions[name] = fpath

            for match in re.finditer(r"(\w+)\s*\(", content):
                called_functions.add(match.group(1))

        # Functions defined but never called (heuristic — may have false positives)
        unused = set(defined_functions.keys()) - called_functions
        for name in list(unused)[:10]:  # Limit
            findings.append(Finding(
                message=f"Potentially unused function: {name}",
                severity=AgentSeverity.LOW,
                file_path=defined_functions[name],
                suggestion="Verify if this function is needed or remove it",
            ))

        return findings

    def _check_exports(self, source_files: List[str]) -> List[Finding]:
        findings = []
        for fpath in source_files:
            if not fpath.endswith("__init__.py"):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            all_match = re.search(r"__all__\s*=\s*\[([^\]]+)\]", content, re.DOTALL)
            if all_match:
                exports = re.findall(r"['\"](\w+)['\"]", all_match.group(1))
                for export in exports:
                    if export not in content.replace(all_match.group(0), ""):
                        if f"import {export}" not in content and f"from" not in content:
                            findings.append(Finding(
                                message=f"__all__ exports '{export}' but it's not defined/imported",
                                severity=AgentSeverity.MEDIUM,
                                file_path=fpath,
                            ))

        return findings
