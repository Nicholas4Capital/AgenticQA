"""Repeatability & Guardrail Agent — Ensures repeatable outcomes within defined guardrails."""

from __future__ import annotations

import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


class RepeatabilityGuardrailAgent(BaseAgent):
    """DEPRECATED: Consolidated into DeterministicGuardrailsAgent."""
    name = "repeatability_guardrail"
    description = (
        "Ensures repeatable outcomes: config-driven behavior, feature flags, "
        "version pinning, lock files, and consistent environments"
    )
    category = "quality"
    priority = 45
    is_gate = False
    squad = Squad.ARCHITECTURE
    pipeline_position = 3

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        import os

        # Check for lock files
        lock_files = {
            "package-lock.json": "npm",
            "yarn.lock": "yarn",
            "pnpm-lock.yaml": "pnpm",
            "poetry.lock": "poetry",
            "Pipfile.lock": "pipenv",
            "requirements.txt": "pip (pinned)",
        }
        found_locks = []
        for lockfile, manager in lock_files.items():
            if os.path.exists(os.path.join(context.project_root, lockfile)):
                found_locks.append(manager)

        if not found_locks:
            findings.append(Finding(
                message="No dependency lock file found — builds are not repeatable",
                severity=AgentSeverity.HIGH,
                suggestion="Generate a lock file to pin dependency versions",
            ))

        # Check for unpinned dependencies
        findings.extend(self._check_pinned_deps(context))

        # Check for environment consistency
        findings.extend(self._check_env_consistency(context))

        # Check for config-driven behavior vs hardcoded values
        findings.extend(self._check_config_driven(context.source_files))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name, passed=passed, findings=findings,
            metrics={"lock_files": found_locks},
            learnings=[f"Lock files: {found_locks or 'NONE'}"],
        )

    def _check_pinned_deps(self, context: ProjectContext) -> List[Finding]:
        findings = []
        import os

        # Check requirements.txt for unpinned deps
        req_file = os.path.join(context.project_root, "requirements.txt")
        if os.path.exists(req_file):
            try:
                with open(req_file, "r") as f:
                    for i, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith("#") and "==" not in line:
                            if ">=" in line or "~=" in line or not re.search(r"[=<>]", line):
                                findings.append(Finding(
                                    message=f"Unpinned dependency: {line}",
                                    severity=AgentSeverity.MEDIUM,
                                    file_path=req_file, line_number=i,
                                    suggestion="Pin to exact version with ==",
                                ))
            except OSError:
                pass

        # Check package.json for * or latest
        pkg_file = os.path.join(context.project_root, "package.json")
        if os.path.exists(pkg_file):
            try:
                with open(pkg_file, "r") as f:
                    content = f.read()
                if '"*"' in content or '"latest"' in content:
                    findings.append(Finding(
                        message="package.json has wildcard (*) or 'latest' dependency",
                        severity=AgentSeverity.HIGH,
                        file_path=pkg_file,
                        suggestion="Pin to specific semver range",
                    ))
            except OSError:
                pass

        return findings

    def _check_env_consistency(self, context: ProjectContext) -> List[Finding]:
        findings = []
        import os

        env_example = os.path.join(context.project_root, ".env.example")
        env_file = os.path.join(context.project_root, ".env")

        if os.path.exists(env_example):
            try:
                with open(env_example, "r") as f:
                    example_vars = {
                        line.split("=")[0].strip()
                        for line in f if "=" in line and not line.startswith("#")
                    }
            except OSError:
                example_vars = set()

            if os.path.exists(env_file):
                try:
                    with open(env_file, "r") as f:
                        actual_vars = {
                            line.split("=")[0].strip()
                            for line in f if "=" in line and not line.startswith("#")
                        }
                except OSError:
                    actual_vars = set()

                missing = example_vars - actual_vars
                if missing:
                    findings.append(Finding(
                        message=f".env missing vars from .env.example: {', '.join(sorted(missing)[:5])}",
                        severity=AgentSeverity.MEDIUM,
                        suggestion="Add missing environment variables",
                    ))

        # Check for .nvmrc or .python-version
        version_files = [".nvmrc", ".node-version", ".python-version", ".tool-versions"]
        has_version_file = any(
            os.path.exists(os.path.join(context.project_root, f))
            for f in version_files
        )
        if not has_version_file:
            findings.append(Finding(
                message="No runtime version file (.nvmrc, .python-version, etc.)",
                severity=AgentSeverity.LOW,
                suggestion="Pin runtime version for consistent environments",
            ))

        return findings

    def _check_config_driven(self, source_files: List[str]) -> List[Finding]:
        findings = []
        hardcoded_patterns = [
            (r"(?:localhost|127\.0\.0\.1):\d+", "Hardcoded host:port"),
            (r"https?://(?!localhost|127\.0\.0\.1|example\.com)\w+\.\w+", "Hardcoded URL"),
        ]

        for fpath in source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (OSError, IOError):
                continue

            for i, line in enumerate(lines, 1):
                if line.strip().startswith("#") or line.strip().startswith("//"):
                    continue
                for pattern, msg in hardcoded_patterns:
                    if re.search(pattern, line):
                        if "test" not in fpath.lower() and "spec" not in fpath.lower():
                            findings.append(Finding(
                                message=f"{msg} in production code",
                                severity=AgentSeverity.LOW,
                                file_path=fpath, line_number=i,
                                suggestion="Use environment variables or config files",
                            ))
                            break  # One per line is enough

        return findings
