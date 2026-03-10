"""User Experience Agent — Evaluates UI/UX patterns, usability, and design quality."""

from __future__ import annotations

import os
import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class UserExperienceAgent(BaseAgent):
    name = "user_experience"
    description = "Evaluates UI/UX patterns, loading states, error handling UX, responsive design, and user flows"
    category = "quality"
    priority = 25
    is_gate = False

    UX_PATTERNS = {
        "loading_state": (r"loading|spinner|skeleton|placeholder", "Has loading states"),
        "error_boundary": (r"error.?boundary|error.?handler|catch.*render|fallback", "Has error boundaries"),
        "empty_state": (r"empty.?state|no.?data|no.?results", "Has empty state handling"),
        "responsive": (r"@media|responsive|breakpoint|useMediaQuery|grid|flex", "Has responsive design"),
        "form_validation": (r"validate|validation|required|pattern=|minlength|maxlength", "Has form validation"),
        "toast_notification": (r"toast|notification|snackbar|alert|flash.?message", "Has user notifications"),
        "confirmation_dialog": (r"confirm|dialog|modal.*confirm|are.?you.?sure", "Has confirmation dialogs"),
        "breadcrumb": (r"breadcrumb|nav.*trail", "Has navigation breadcrumbs"),
        "pagination": (r"pagination|page.?size|next.?page|prev.?page|offset|limit", "Has pagination"),
        "search": (r"search|filter|query.*input", "Has search/filter functionality"),
    }

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        ui_files = [f for f in context.source_files
                    if f.endswith((".html", ".jsx", ".tsx", ".vue", ".svelte", ".css", ".scss"))]

        # Check for UX pattern presence/absence
        present_patterns = set()
        for fpath in ui_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                for pattern_name, (regex, _) in self.UX_PATTERNS.items():
                    if re.search(regex, content, re.IGNORECASE):
                        present_patterns.add(pattern_name)
            except (OSError, IOError):
                continue

        missing = set(self.UX_PATTERNS.keys()) - present_patterns
        for pattern_name in missing:
            _, desc = self.UX_PATTERNS[pattern_name]
            findings.append(Finding(
                message=f"Missing UX pattern: {desc.replace('Has ', '')}",
                severity=AgentSeverity.MEDIUM,
                suggestion=f"Add {pattern_name.replace('_', ' ')} pattern to improve UX",
            ))

        # Check for UX anti-patterns
        for fpath in ui_files:
            findings.extend(self._check_antipatterns(fpath))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={
                "ui_files": len(ui_files),
                "ux_patterns_present": len(present_patterns),
                "ux_patterns_missing": len(missing),
                "ux_score": round(len(present_patterns) / max(len(self.UX_PATTERNS), 1) * 100, 1),
            },
            learnings=[f"UX coverage: {len(present_patterns)}/{len(self.UX_PATTERNS)} patterns"],
        )

    def _check_antipatterns(self, fpath: str) -> List[Finding]:
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except (OSError, IOError):
            return findings

        for i, line in enumerate(lines, 1):
            if re.search(r"alert\(['\"]", line):
                findings.append(Finding(
                    message="Using alert() for user messaging — use toast/modal instead",
                    severity=AgentSeverity.LOW,
                    file_path=fpath, line_number=i,
                ))
            if re.search(r"window\.confirm\(", line):
                findings.append(Finding(
                    message="Using window.confirm() — use custom dialog for better UX",
                    severity=AgentSeverity.LOW,
                    file_path=fpath, line_number=i,
                ))
            if re.search(r"display:\s*none.*important", line, re.IGNORECASE):
                findings.append(Finding(
                    message="Using !important to hide content — indicates CSS specificity issue",
                    severity=AgentSeverity.LOW,
                    file_path=fpath, line_number=i,
                ))

        return findings
