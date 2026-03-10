"""Functionality Tester Agent — Validates test coverage, test quality, and test results."""

from __future__ import annotations

import os
import re
from typing import Dict, List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class FunctionalityTesterAgent(BaseAgent):
    name = "functionality_tester"
    description = "Validates test coverage, test quality, edge cases, and ensures all features have tests"
    category = "testing"
    priority = 15
    is_gate = True

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        metrics: Dict[str, any] = {}

        # Analyze test files
        test_analysis = self._analyze_tests(context.test_files)
        metrics.update(test_analysis["metrics"])
        findings.extend(test_analysis["findings"])

        # Cross-reference source files with test files
        coverage = self._check_test_coverage(context.source_files, context.test_files)
        metrics.update(coverage["metrics"])
        findings.extend(coverage["findings"])

        # Check test quality patterns
        for fpath in context.test_files:
            findings.extend(self._check_test_quality(fpath))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics=metrics,
            learnings=self._make_learnings(metrics),
        )

    def _analyze_tests(self, test_files: List[str]) -> Dict:
        findings = []
        total_tests = 0
        total_assertions = 0

        for fpath in test_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            # Count test functions/methods
            if fpath.endswith(".py"):
                tests = len(re.findall(r"def test_\w+", content))
                asserts = len(re.findall(r"assert\s|self\.assert|pytest\.raises", content))
            else:
                tests = len(re.findall(r"(?:it|test)\s*\(", content))
                asserts = len(re.findall(r"expect\(|assert\.|should\.", content))

            total_tests += tests
            total_assertions += asserts

            if tests > 0 and asserts / tests < 1:
                findings.append(Finding(
                    message=f"Low assertion density: {asserts}/{tests} assertions per test",
                    severity=AgentSeverity.MEDIUM,
                    file_path=fpath,
                    suggestion="Add more assertions to validate behavior",
                ))

        return {
            "findings": findings,
            "metrics": {
                "total_test_files": len(test_files),
                "total_tests": total_tests,
                "total_assertions": total_assertions,
                "assertion_density": round(total_assertions / max(total_tests, 1), 2),
            },
        }

    def _check_test_coverage(self, source_files: List[str], test_files: List[str]) -> Dict:
        findings = []
        test_names = {os.path.basename(f).lower() for f in test_files}
        uncovered = []

        for src in source_files:
            basename = os.path.basename(src).lower()
            name_no_ext = os.path.splitext(basename)[0]
            possible_tests = [
                f"test_{name_no_ext}",
                f"{name_no_ext}_test",
                f"{name_no_ext}.test",
                f"{name_no_ext}.spec",
            ]
            has_test = any(
                any(pt in tn for pt in possible_tests)
                for tn in test_names
            )
            if not has_test and not self._is_config_or_init(basename):
                uncovered.append(src)

        if uncovered:
            for src in uncovered[:20]:  # Limit report size
                findings.append(Finding(
                    message=f"No test file found for {os.path.basename(src)}",
                    severity=AgentSeverity.MEDIUM,
                    file_path=src,
                    suggestion="Create a corresponding test file",
                ))

        coverage_pct = round(
            (1 - len(uncovered) / max(len(source_files), 1)) * 100, 1
        )
        if coverage_pct < 60:
            findings.append(Finding(
                message=f"Test file coverage is only {coverage_pct}%",
                severity=AgentSeverity.HIGH,
                suggestion="Add tests for uncovered modules",
            ))

        return {
            "findings": findings,
            "metrics": {
                "source_files": len(source_files),
                "uncovered_files": len(uncovered),
                "file_coverage_pct": coverage_pct,
            },
        }

    def _check_test_quality(self, fpath: str) -> List[Finding]:
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except (OSError, IOError):
            return findings

        for i, line in enumerate(lines, 1):
            if re.search(r"\.skip\(|@pytest\.mark\.skip|xfail|xit\(", line):
                findings.append(Finding(
                    message="Skipped test — should be fixed or removed",
                    severity=AgentSeverity.LOW,
                    file_path=fpath, line_number=i,
                ))
            if re.search(r"sleep\(\s*\d{2,}", line):
                findings.append(Finding(
                    message="Long sleep in test — flaky test indicator",
                    severity=AgentSeverity.MEDIUM,
                    file_path=fpath, line_number=i,
                ))

        # Check for edge case patterns
        has_edge_cases = bool(re.search(
            r"edge|boundary|null|undefined|empty|zero|negative|overflow|max|min",
            content, re.IGNORECASE,
        ))
        if not has_edge_cases and len(lines) > 20:
            findings.append(Finding(
                message="No edge case tests detected",
                severity=AgentSeverity.LOW,
                file_path=fpath,
                suggestion="Add tests for boundary conditions and edge cases",
            ))

        return findings

    @staticmethod
    def _is_config_or_init(name: str) -> bool:
        return name in ("__init__.py", "conftest.py", "setup.py", "config.py") or name.startswith(".")

    def _make_learnings(self, metrics: Dict) -> List[str]:
        learnings = []
        if metrics.get("file_coverage_pct", 0) < 80:
            learnings.append(f"Test coverage at {metrics.get('file_coverage_pct')}% — needs improvement")
        if metrics.get("assertion_density", 0) < 2:
            learnings.append("Low assertion density — tests may not be thorough enough")
        return learnings
