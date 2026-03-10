"""Accessibility Agent — WCAG 2.1 AA/AAA compliance for UI and web content."""

from __future__ import annotations

import os
import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class AccessibilityAgent(BaseAgent):
    name = "accessibility"
    description = "Checks WCAG 2.1 AA/AAA compliance, ARIA usage, color contrast, keyboard navigation"
    category = "quality"
    priority = 20
    can_auto_fix = True
    is_gate = True

    # HTML accessibility patterns
    A11Y_CHECKS = [
        (r"<img(?![^>]*alt=)", "Image missing alt attribute (WCAG 1.1.1)", AgentSeverity.HIGH),
        (r"<input(?![^>]*(?:aria-label|aria-labelledby|id=[^>]*<label))", "Input missing accessible label", AgentSeverity.HIGH),
        (r"<a\s+href[^>]*>\s*(?:click here|here|link)\s*</a>", "Non-descriptive link text (WCAG 2.4.4)", AgentSeverity.MEDIUM),
        (r"tabindex=['\"]?-1", "Negative tabindex removes element from tab order", AgentSeverity.MEDIUM),
        (r"<div\s+onclick|<span\s+onclick", "Non-interactive element with click handler — use button", AgentSeverity.HIGH),
        (r"style=['\"][^'\"]*display:\s*none", "Hidden content may still be announced by screen readers", AgentSeverity.LOW),
        (r"<(?:b|i)(?:\s|>)(?!.*<(?:strong|em))", "Use semantic tags (strong/em) instead of b/i", AgentSeverity.LOW),
        (r"<table(?![^>]*role=)", "Table missing role attribute for data/layout distinction", AgentSeverity.MEDIUM),
        (r"aria-hidden=['\"]?true['\"]?\s*(?=.*(?:tabindex|href|onclick))", "Focusable element hidden from assistive tech", AgentSeverity.HIGH),
    ]

    # Heading hierarchy checks
    HEADING_PATTERN = re.compile(r"<h([1-6])")

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        html_files = [f for f in context.source_files
                      if f.endswith((".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte"))]

        for fpath in html_files:
            findings.extend(self._check_file(fpath))

        # Check for missing skip-to-content link
        for fpath in html_files:
            if self._is_page_template(fpath):
                findings.extend(self._check_page_structure(fpath))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={"html_files_checked": len(html_files)},
            learnings=self._learnings_from(findings),
        )

    def _check_file(self, fpath: str) -> List[Finding]:
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except (OSError, IOError):
            return findings

        for i, line in enumerate(lines, 1):
            for pattern, msg, severity in self.A11Y_CHECKS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        message=msg,
                        severity=severity,
                        file_path=fpath,
                        line_number=i,
                        auto_fixable="alt" in msg.lower(),
                    ))

        # Check heading hierarchy
        headings = [(m.start(), int(m.group(1))) for m in self.HEADING_PATTERN.finditer(content)]
        prev_level = 0
        for pos, level in headings:
            line_num = content[:pos].count("\n") + 1
            if level > prev_level + 1 and prev_level > 0:
                findings.append(Finding(
                    message=f"Heading level skipped: h{prev_level} -> h{level} (WCAG 1.3.1)",
                    severity=AgentSeverity.MEDIUM,
                    file_path=fpath,
                    line_number=line_num,
                ))
            prev_level = level

        # Check color contrast indicators
        for i, line in enumerate(lines, 1):
            color_match = re.search(r"color:\s*#([0-9a-fA-F]{3,6})", line)
            if color_match:
                hex_color = color_match.group(1)
                if len(hex_color) == 3:
                    hex_color = "".join(c * 2 for c in hex_color)
                if self._is_low_contrast(hex_color):
                    findings.append(Finding(
                        message=f"Potential low contrast color #{hex_color} (WCAG 1.4.3)",
                        severity=AgentSeverity.MEDIUM,
                        file_path=fpath,
                        line_number=i,
                    ))

        return findings

    def _check_page_structure(self, fpath: str) -> List[Finding]:
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, IOError):
            return findings

        if "skip" not in content.lower() or "main" not in content.lower():
            findings.append(Finding(
                message="Missing skip-to-main-content link (WCAG 2.4.1)",
                severity=AgentSeverity.MEDIUM,
                file_path=fpath,
            ))

        if "<html" in content and 'lang=' not in content.split("</head>")[0] if "</head>" in content else content:
            findings.append(Finding(
                message="HTML element missing lang attribute (WCAG 3.1.1)",
                severity=AgentSeverity.HIGH,
                file_path=fpath,
                auto_fixable=True,
            ))

        return findings

    @staticmethod
    def _is_page_template(fpath: str) -> bool:
        name = os.path.basename(fpath).lower()
        return any(k in name for k in ("index", "layout", "template", "app", "page"))

    @staticmethod
    def _is_low_contrast(hex_color: str) -> bool:
        try:
            r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
            luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b
            # Very light colors on white background
            return luminance > 200
        except (ValueError, IndexError):
            return False

    def _learnings_from(self, findings: List[Finding]) -> List[str]:
        if not findings:
            return ["All accessibility checks passed"]
        categories = {}
        for f in findings:
            key = f.message.split("(")[0].strip()
            categories[key] = categories.get(key, 0) + 1
        return [f"Top a11y issues: {categories}"]

    def fix(self, context: ProjectContext, findings: List[Finding]) -> int:
        fixes = 0
        for f in findings:
            if f.auto_fixable and f.file_path and "alt" in f.message.lower():
                try:
                    with open(f.file_path, "r", encoding="utf-8") as fh:
                        content = fh.read()
                    content = re.sub(
                        r"<img(?!\s[^>]*alt=)",
                        '<img alt=""',
                        content,
                        count=1,
                    )
                    with open(f.file_path, "w", encoding="utf-8") as fh:
                        fh.write(content)
                    fixes += 1
                except (OSError, IOError):
                    continue
        return fixes
