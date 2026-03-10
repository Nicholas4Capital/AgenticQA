"""Code Review Agent — Static analysis, style, patterns, and code quality."""

from __future__ import annotations

import ast
import os
import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class CodeReviewAgent(BaseAgent):
    name = "code_review"
    description = "Analyzes code for quality, patterns, duplication, complexity, and style issues"
    category = "quality"
    priority = 10
    can_auto_fix = True
    is_gate = True
    squad = Squad.CODE_QUALITY
    pipeline_position = 1

    # Patterns that indicate code smells
    SMELL_PATTERNS = [
        (r"# TODO|# FIXME|# HACK|# XXX", "Unresolved TODO/FIXME marker", AgentSeverity.LOW),
        (r"except\s*:", "Bare except clause — swallows all errors", AgentSeverity.MEDIUM),
        (r"import \*", "Wildcard import reduces readability", AgentSeverity.LOW),
        (r"eval\(|exec\(", "Dynamic code execution is a security risk", AgentSeverity.HIGH),
        (r"print\((?!.*#\s*debug)", "Print statement in production code", AgentSeverity.LOW),
        (r"\.format\(.*\%", "Mixed string formatting styles", AgentSeverity.LOW),
        (r"time\.sleep\(\d{2,}", "Long sleep — possible busy wait", AgentSeverity.MEDIUM),
        (r"password\s*=\s*['\"]", "Hardcoded password", AgentSeverity.CRITICAL),
        (r"api_key\s*=\s*['\"]", "Hardcoded API key", AgentSeverity.CRITICAL),
    ]

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        for fpath in context.source_files:
            if not fpath.endswith(".py"):
                continue
            findings.extend(self._review_python_file(fpath))

        for fpath in context.source_files:
            if fpath.endswith((".js", ".ts", ".jsx", ".tsx")):
                findings.extend(self._review_js_file(fpath))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={
                "files_reviewed": len(context.source_files),
                "patterns_checked": len(self.SMELL_PATTERNS),
            },
            learnings=self._extract_learnings(findings),
        )

    def _review_python_file(self, fpath: str) -> List[Finding]:
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except (OSError, IOError):
            return findings

        # Pattern-based smells
        for i, line in enumerate(lines, 1):
            for pattern, msg, severity in self.SMELL_PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        message=msg,
                        severity=severity,
                        file_path=fpath,
                        line_number=i,
                        auto_fixable=severity == AgentSeverity.LOW,
                    ))

        # AST-based complexity analysis
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    complexity = self._cyclomatic_complexity(node)
                    if complexity > 15:
                        findings.append(Finding(
                            message=f"Function '{node.name}' has high complexity ({complexity})",
                            severity=AgentSeverity.MEDIUM,
                            file_path=fpath,
                            line_number=node.lineno,
                            suggestion="Refactor into smaller functions",
                        ))
                    if len(lines) > node.end_lineno - node.lineno + 1 if hasattr(node, "end_lineno") and node.end_lineno else 0:
                        func_len = (node.end_lineno or node.lineno) - node.lineno
                        if func_len > 50:
                            findings.append(Finding(
                                message=f"Function '{node.name}' is {func_len} lines long",
                                severity=AgentSeverity.LOW,
                                file_path=fpath,
                                line_number=node.lineno,
                                suggestion="Consider breaking into smaller functions",
                            ))
        except SyntaxError:
            findings.append(Finding(
                message="Python syntax error",
                severity=AgentSeverity.BLOCKER,
                file_path=fpath,
            ))

        return findings

    def _review_js_file(self, fpath: str) -> List[Finding]:
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, IOError):
            return findings

        for i, line in enumerate(lines, 1):
            if "console.log(" in line and "// debug" not in line.lower():
                findings.append(Finding(
                    message="console.log in production code",
                    severity=AgentSeverity.LOW,
                    file_path=fpath, line_number=i, auto_fixable=True,
                ))
            if "var " in line:
                findings.append(Finding(
                    message="Use const/let instead of var",
                    severity=AgentSeverity.LOW,
                    file_path=fpath, line_number=i, auto_fixable=True,
                ))
            if re.search(r"==(?!=)", line) and "!==" not in line:
                findings.append(Finding(
                    message="Use strict equality (===) instead of loose (==)",
                    severity=AgentSeverity.MEDIUM,
                    file_path=fpath, line_number=i, auto_fixable=True,
                ))
        return findings

    @staticmethod
    def _cyclomatic_complexity(node: ast.FunctionDef) -> int:
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity

    def _extract_learnings(self, findings: List[Finding]) -> List[str]:
        learnings = []
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
        if severity_counts:
            learnings.append(f"Code review severity distribution: {severity_counts}")
        return learnings

    def fix(self, context: ProjectContext, findings: List[Finding]) -> int:
        # Auto-fix simple issues (e.g., remove console.log, var->const)
        fixes = 0
        files_to_fix = {}
        for f in findings:
            if f.auto_fixable and f.file_path and f.line_number:
                if f.file_path not in files_to_fix:
                    files_to_fix[f.file_path] = []
                files_to_fix[f.file_path].append(f)

        for fpath, file_findings in files_to_fix.items():
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
                modified = False
                for finding in sorted(file_findings, key=lambda x: x.line_number or 0, reverse=True):
                    idx = (finding.line_number or 1) - 1
                    if 0 <= idx < len(lines):
                        original = lines[idx]
                        if "var " in finding.message.lower() or "var " in original:
                            lines[idx] = original.replace("var ", "const ", 1)
                            modified = True
                            fixes += 1
                if modified:
                    with open(fpath, "w", encoding="utf-8") as fh:
                        fh.writelines(lines)
            except (OSError, IOError):
                continue
        return fixes
