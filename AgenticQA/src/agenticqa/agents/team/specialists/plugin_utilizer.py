"""Plugin Utilizing Agent — Identifies and validates plugin/extension usage."""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


class PluginUtilizingAgent(BaseAgent):
    """DEPRECATED: Consolidated into IntegrationScoutAgent."""
    name = "plugin_utilizer"
    description = (
        "Validates plugin/extension usage: ESLint plugins, pytest plugins, "
        "middleware, and recommends missing plugins for code quality"
    )
    category = "connectivity"
    priority = 65
    is_gate = False
    squad = Squad.AI_INTEGRATION
    pipeline_position = 3

    RECOMMENDED_PLUGINS = {
        "python": {
            "pytest-cov": {"detect": r"pytest.*cov|coverage", "purpose": "Test coverage"},
            "pytest-xdist": {"detect": r"xdist|parallel.*test|-n auto", "purpose": "Parallel testing"},
            "mypy": {"detect": r"mypy|type.*check", "purpose": "Static type checking"},
            "black": {"detect": r"black|format.*black", "purpose": "Code formatting"},
            "ruff": {"detect": r"ruff", "purpose": "Fast Python linting"},
            "bandit": {"detect": r"bandit|security.*scan", "purpose": "Security scanning"},
            "pre-commit": {"detect": r"pre.?commit", "purpose": "Git hooks"},
        },
        "javascript": {
            "eslint-security": {"detect": r"eslint.*security|no-eval", "purpose": "Security linting"},
            "prettier": {"detect": r"prettier", "purpose": "Code formatting"},
            "husky": {"detect": r"husky|pre.?commit", "purpose": "Git hooks"},
            "lint-staged": {"detect": r"lint.?staged", "purpose": "Staged file linting"},
            "typescript-eslint": {"detect": r"@typescript.?eslint", "purpose": "TypeScript linting"},
            "jest-coverage": {"detect": r"coverage.*threshold|collectCoverage", "purpose": "Test coverage"},
        },
    }

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        # Detect project languages
        has_python = any(f.endswith(".py") for f in context.source_files)
        has_js = any(f.endswith((".js", ".ts", ".jsx", ".tsx")) for f in context.source_files)

        all_content = ""
        for fpath in context.config_files + context.source_files[:50]:  # Limit
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read() + "\n"
            except (OSError, IOError):
                continue

        # Check package.json for JS plugins
        if has_js:
            findings.extend(self._check_js_plugins(context.project_root, all_content))

        # Check Python config for plugins
        if has_python:
            findings.extend(self._check_python_plugins(context.project_root, all_content))

        # Recommend missing plugins
        installed = set()
        missing = set()

        if has_python:
            for plugin, info in self.RECOMMENDED_PLUGINS["python"].items():
                if re.search(info["detect"], all_content, re.IGNORECASE):
                    installed.add(f"py:{plugin}")
                else:
                    missing.add(f"py:{plugin}")
                    findings.append(Finding(
                        message=f"Recommended Python plugin: {plugin} ({info['purpose']})",
                        severity=AgentSeverity.LOW,
                        suggestion=f"pip install {plugin}",
                    ))

        if has_js:
            for plugin, info in self.RECOMMENDED_PLUGINS["javascript"].items():
                if re.search(info["detect"], all_content, re.IGNORECASE):
                    installed.add(f"js:{plugin}")
                else:
                    missing.add(f"js:{plugin}")
                    findings.append(Finding(
                        message=f"Recommended JS plugin: {plugin} ({info['purpose']})",
                        severity=AgentSeverity.LOW,
                        suggestion=f"npm install -D {plugin}",
                    ))

        return AgentResult(
            agent_name=self.name,
            passed=True,  # Advisory
            findings=findings,
            metrics={
                "plugins_installed": len(installed),
                "plugins_recommended": len(missing),
            },
            learnings=[f"Plugins: {len(installed)} installed, {len(missing)} recommended"],
        )

    def _check_js_plugins(self, project_root: str, all_content: str) -> List[Finding]:
        findings = []
        pkg_path = os.path.join(project_root, "package.json")
        if not os.path.exists(pkg_path):
            return findings

        try:
            with open(pkg_path, "r") as f:
                pkg = json.load(f)
        except (json.JSONDecodeError, OSError):
            return findings

        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

        # Check for outdated/deprecated packages
        deprecated = {
            "request": "Use 'node-fetch' or 'axios' instead",
            "moment": "Use 'date-fns' or 'dayjs' instead (moment is in maintenance mode)",
            "tslint": "Use '@typescript-eslint/eslint-plugin' instead",
        }
        for pkg_name, suggestion in deprecated.items():
            if pkg_name in deps:
                findings.append(Finding(
                    message=f"Deprecated package: {pkg_name}",
                    severity=AgentSeverity.MEDIUM,
                    file_path=pkg_path,
                    suggestion=suggestion,
                ))

        return findings

    def _check_python_plugins(self, project_root: str, all_content: str) -> List[Finding]:
        findings = []

        # Check for setup.cfg / pyproject.toml tool configs
        pyproject = os.path.join(project_root, "pyproject.toml")
        if os.path.exists(pyproject):
            try:
                with open(pyproject, "r") as f:
                    content = f.read()
                if "[tool.pytest" not in content and "[tool.mypy" not in content:
                    findings.append(Finding(
                        message="pyproject.toml missing tool configuration sections",
                        severity=AgentSeverity.LOW,
                        suggestion="Add [tool.pytest], [tool.mypy], [tool.ruff] sections",
                    ))
            except OSError:
                pass

        return findings
