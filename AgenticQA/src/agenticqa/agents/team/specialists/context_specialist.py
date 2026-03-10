"""Context Specialist Agent — Manages and validates context flow across the system."""

from __future__ import annotations

import os
import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class ContextSpecialistAgent(BaseAgent):
    name = "context_specialist"
    description = (
        "Validates context management: state propagation, context window usage, "
        "memory management, session handling, and data flow integrity"
    )
    category = "intelligence"
    priority = 55
    is_gate = False
    squad = Squad.AI_INTEGRATION
    pipeline_position = 5

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.splitlines()
            except (OSError, IOError):
                continue

            findings.extend(self._check_state_management(fpath, lines, content))
            findings.extend(self._check_memory_patterns(fpath, lines, content))
            findings.extend(self._check_context_propagation(fpath, content))

        # Check for global context patterns
        findings.extend(self._check_global_patterns(context))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name, passed=passed, findings=findings,
            metrics={"files_checked": len(context.source_files)},
        )

    def _check_state_management(self, fpath: str, lines: List[str], content: str) -> List[Finding]:
        findings = []

        # Check for global mutable state
        for i, line in enumerate(lines, 1):
            if re.match(r"^[A-Z_]+\s*=\s*(?:\[|\{|set\()", line):
                findings.append(Finding(
                    message=f"Global mutable state — may cause cross-request contamination",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath, line_number=i,
                    suggestion="Use request-scoped or thread-local state",
                ))

        # Check for session management
        if re.search(r"session|cookie|jwt|token", content, re.IGNORECASE):
            if not re.search(r"expire|ttl|max.?age|timeout|invalidat", content, re.IGNORECASE):
                findings.append(Finding(
                    message="Session/token without expiration — security and memory risk",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath,
                    suggestion="Set TTL/expiration on all sessions and tokens",
                ))

        return findings

    def _check_memory_patterns(self, fpath: str, lines: List[str], content: str) -> List[Finding]:
        findings = []

        # Growing collections without bounds
        for i, line in enumerate(lines, 1):
            if re.search(r"\.append\(|\.add\(|\.push\(|\.extend\(", line):
                # Check if there's a size limit nearby
                context_lines = lines[max(0, i - 10):min(len(lines), i + 10)]
                has_limit = any(
                    re.search(r"max.?size|limit|if.*len.*>|\.pop\(|\.remove|truncat|slice", l, re.IGNORECASE)
                    for l in context_lines
                )
                if not has_limit:
                    if re.search(r"history|cache|buffer|queue|log|events|messages", line, re.IGNORECASE):
                        findings.append(Finding(
                            message="Unbounded collection growth — potential memory leak",
                            severity=AgentSeverity.MEDIUM,
                            file_path=fpath, line_number=i,
                            suggestion="Add max size limit or eviction policy",
                        ))

        # Large string concatenation in loops
        for i, line in enumerate(lines, 1):
            if re.search(r"for\s+.*\sin\s+", line):
                next_lines = lines[i:min(len(lines), i + 5)]
                if any("+=" in l and ("str" in l.lower() or '"' in l or "'" in l) for l in next_lines):
                    findings.append(Finding(
                        message="String concatenation in loop — use list + join instead",
                        severity=AgentSeverity.LOW,
                        file_path=fpath, line_number=i,
                    ))

        return findings

    def _check_context_propagation(self, fpath: str, content: str) -> List[Finding]:
        findings = []

        # Check for proper context passing in async code
        if re.search(r"async|await|Promise|asyncio", content):
            if re.search(r"ThreadLocal|thread.?local|contextvars", content):
                pass  # Good — using proper context propagation
            elif re.search(r"global\s+\w+|globals\(\)", content):
                findings.append(Finding(
                    message="Using globals in async code — use contextvars instead",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath,
                    suggestion="Use contextvars.ContextVar for async-safe state",
                ))

        return findings

    def _check_global_patterns(self, context: ProjectContext) -> List[Finding]:
        findings = []

        # Check for configuration consistency across the project
        config_values = {}
        for fpath in context.config_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                for match in re.finditer(r"(\w+)\s*[:=]\s*['\"]?(\d+)['\"]?", content):
                    key, val = match.group(1).lower(), match.group(2)
                    if key in config_values and config_values[key] != val:
                        findings.append(Finding(
                            message=f"Config inconsistency: '{key}' = {config_values[key]} vs {val}",
                            severity=AgentSeverity.MEDIUM,
                            file_path=fpath,
                            suggestion="Centralize configuration to single source of truth",
                        ))
                    config_values[key] = val
            except (OSError, IOError):
                continue

        return findings
