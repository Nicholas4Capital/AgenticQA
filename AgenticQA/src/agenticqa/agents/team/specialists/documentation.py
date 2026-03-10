"""Documentation Specialist Agent — Validates docs, docstrings, API docs, and READMEs."""

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
class DocumentationSpecialistAgent(BaseAgent):
    name = "documentation"
    description = "Validates docstring coverage, README quality, API documentation, and changelog maintenance"
    category = "documentation"
    priority = 70
    is_gate = False
    squad = Squad.CODE_QUALITY
    pipeline_position = 4

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        # Check Python docstrings
        py_files = [f for f in context.source_files if f.endswith(".py")]
        doc_stats = self._check_docstrings(py_files)
        findings.extend(doc_stats["findings"])

        # Check for README
        findings.extend(self._check_readme(context.project_root))

        # Check for API documentation
        findings.extend(self._check_api_docs(context.source_files))

        # Check for changelog
        findings.extend(self._check_changelog(context.project_root))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics=doc_stats["metrics"],
            learnings=[f"Docstring coverage: {doc_stats['metrics'].get('coverage_pct', 0)}%"],
        )

    def _check_docstrings(self, py_files: List[str]) -> dict:
        findings = []
        total_public = 0
        documented = 0

        for fpath in py_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
                tree = ast.parse(source)
            except (SyntaxError, OSError):
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if node.name.startswith("_") and node.name != "__init__":
                        continue
                    total_public += 1
                    if (ast.get_docstring(node)):
                        documented += 1
                    else:
                        if isinstance(node, ast.ClassDef):
                            findings.append(Finding(
                                message=f"Class '{node.name}' missing docstring",
                                severity=AgentSeverity.LOW,
                                file_path=fpath, line_number=node.lineno,
                            ))
                        elif not node.name.startswith("test_"):
                            findings.append(Finding(
                                message=f"Public function '{node.name}' missing docstring",
                                severity=AgentSeverity.LOW,
                                file_path=fpath, line_number=node.lineno,
                            ))

        coverage = round(documented / max(total_public, 1) * 100, 1)
        if coverage < 50:
            findings.append(Finding(
                message=f"Docstring coverage is {coverage}% — below 50% threshold",
                severity=AgentSeverity.MEDIUM,
                suggestion="Add docstrings to public classes and functions",
            ))

        return {
            "findings": findings,
            "metrics": {
                "public_symbols": total_public,
                "documented_symbols": documented,
                "coverage_pct": coverage,
                "py_files": len(py_files),
            },
        }

    def _check_readme(self, project_root: str) -> List[Finding]:
        findings = []
        readme_path = None
        for name in ("README.md", "README.rst", "README.txt", "README"):
            path = os.path.join(project_root, name)
            if os.path.exists(path):
                readme_path = path
                break

        if not readme_path:
            findings.append(Finding(
                message="No README file found",
                severity=AgentSeverity.HIGH,
                suggestion="Create a README.md with project overview, setup, and usage",
            ))
            return findings

        try:
            with open(readme_path, "r", encoding="utf-8") as f:
                content = f.read()
        except (OSError, IOError):
            return findings

        sections = {
            "installation": r"install|setup|getting.?started",
            "usage": r"usage|how.?to|example|quick.?start",
            "api": r"api|endpoint|reference",
            "contributing": r"contribut|develop|pull.?request",
            "license": r"license|mit|apache|gpl",
        }

        for section, pattern in sections.items():
            if not re.search(pattern, content, re.IGNORECASE):
                findings.append(Finding(
                    message=f"README missing '{section}' section",
                    severity=AgentSeverity.LOW,
                    file_path=readme_path,
                ))

        return findings

    def _check_api_docs(self, source_files: List[str]) -> List[Finding]:
        findings = []
        has_api = any(
            re.search(r"@(?:app|router)\.", open(f, "r", encoding="utf-8", errors="ignore").read())
            for f in source_files
            if f.endswith((".py", ".js", ".ts"))
            if os.path.isfile(f)
        ) if source_files else False

        if has_api:
            has_openapi = any(
                "openapi" in open(f, "r", encoding="utf-8", errors="ignore").read().lower()
                for f in source_files
                if os.path.isfile(f) and f.endswith((".py", ".json", ".yaml", ".yml"))
            )
            if not has_openapi:
                findings.append(Finding(
                    message="API endpoints found but no OpenAPI/Swagger documentation",
                    severity=AgentSeverity.MEDIUM,
                    suggestion="Add OpenAPI spec or use auto-generation (FastAPI has built-in)",
                ))

        return findings

    def _check_changelog(self, project_root: str) -> List[Finding]:
        findings = []
        changelog_names = ("CHANGELOG.md", "CHANGELOG.rst", "CHANGELOG.txt", "CHANGES.md", "HISTORY.md")
        has_changelog = any(os.path.exists(os.path.join(project_root, name)) for name in changelog_names)

        if not has_changelog:
            findings.append(Finding(
                message="No CHANGELOG file found",
                severity=AgentSeverity.LOW,
                suggestion="Maintain a CHANGELOG.md for version history",
            ))

        return findings
