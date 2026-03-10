"""Deterministic & Guardrails Agent (#11) — Squad 3, Position 2.

Consolidated from: deterministic_ensurer + repeatability + guardrail_implementer.
Ensures deterministic behavior, repeatable outcomes, and safety guardrails.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Set

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class DeterministicGuardrailsAgent(BaseAgent):
    """
    Unified agent for determinism, repeatability, and guardrails.

    Covers:
    - Random/seed management, AI temperature, idempotency
    - Lock files, pinned deps, env consistency, config-driven behavior
    - Input validation, rate limiting, circuit breakers, kill switches, dangerous ops
    """

    name = "deterministic_guardrails"
    description = (
        "Determinism, repeatability, and safety guardrails: seed management, "
        "idempotency, lock files, pinned deps, input validation, rate limiting, "
        "circuit breakers, timeouts, and kill switches"
    )
    category = "architecture"
    priority = 12
    is_gate = True
    can_auto_fix = False
    squad = Squad.ARCHITECTURE
    pipeline_position = 2

    # --- Determinism patterns ---
    NON_DETERMINISTIC_PATTERNS = [
        (r"random\(\)|Math\.random\(\)|randint|randrange|choice\(|shuffle\(|sample\(",
         "Random without seed — non-deterministic behavior", AgentSeverity.HIGH),
        (r"uuid[.\w]*\(\)|uuid4\(\)|nanoid|cuid",
         "UUID/random ID generation — ensure this is intentional", AgentSeverity.LOW),
        (r"datetime\.now\(\)|Date\.now\(\)|time\.time\(\)|new Date\(\)",
         "Time-dependent code — mock in tests for determinism", AgentSeverity.LOW),
        (r"os\.environ|process\.env(?!\.[A-Z_]+\s*\|\|)",
         "Environment-dependent behavior — ensure defaults exist", AgentSeverity.MEDIUM),
    ]

    # --- Guardrail checks ---
    GUARDRAIL_CHECKS = {
        "input_validation": (
            r"validate|sanitize|escape|zod|joi|pydantic|marshmallow|cerberus",
            "Input validation framework",
        ),
        "output_encoding": (
            r"escape.?html|sanitize.?html|DOMPurify|bleach|markupsafe",
            "Output encoding/XSS prevention",
        ),
        "rate_limiting": (
            r"rate.?limit|throttle|express.?rate|slowapi|flask.?limiter",
            "Rate limiting",
        ),
        "circuit_breaker": (
            r"circuit.?breaker|pybreaker|opossum|resilience|hystrix",
            "Circuit breaker pattern",
        ),
        "timeout": (
            r"timeout|deadline|cancel.*after|signal\.alarm|AbortController",
            "Request/operation timeouts",
        ),
        "size_limits": (
            r"max.?size|content.?length|payload.*limit|multer.*limit|body.?parser.*limit",
            "Payload size limits",
        ),
        "auth_guard": (
            r"@auth|@login_required|authenticate|isAuthenticated|requireAuth|protect.*route",
            "Authentication guards",
        ),
        "csrf_protection": (
            r"csrf|csrftoken|xsrf|csurf|CSRFProtect",
            "CSRF protection",
        ),
        "content_security": (
            r"content.?security.?policy|csp|helmet|security.*header",
            "Content Security Policy",
        ),
        "kill_switch": (
            r"kill.?switch|feature.?flag|toggle|circuit.*open|disable.*feature|maintenance.?mode",
            "Kill switch / feature flags",
        ),
    }

    # --- Dangerous operations ---
    DANGEROUS_PATTERNS = [
        (r"subprocess\.call|os\.system|child_process\.exec\(",
         "Shell command execution — validate/sanitize input", AgentSeverity.CRITICAL),
        (r"eval\(|exec\(|Function\(",
         "Dynamic code execution — major security risk", AgentSeverity.CRITICAL),
        (r"pickle\.loads|yaml\.load\((?!.*Loader)",
         "Unsafe deserialization — use safe loaders", AgentSeverity.CRITICAL),
        (r"__import__\(|importlib\.import_module\(\s*(?![\'\"])",
         "Dynamic import from user input — injection risk", AgentSeverity.HIGH),
    ]

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        # --- 1. Determinism checks ---
        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.splitlines()
            except (OSError, IOError):
                continue

            for i, line in enumerate(lines, 1):
                for pattern, msg, severity in self.NON_DETERMINISTIC_PATTERNS:
                    if re.search(pattern, line):
                        findings.append(Finding(
                            message=msg, severity=severity,
                            file_path=fpath, line_number=i,
                        ))

            findings.extend(self._check_ai_determinism(fpath, content))
            findings.extend(self._check_idempotency(fpath, content))

        # --- 2. Repeatability checks ---
        lock_files_found = self._check_lock_files(context.project_root)
        if not lock_files_found:
            findings.append(Finding(
                message="No dependency lock file found — builds are not repeatable",
                severity=AgentSeverity.HIGH,
                suggestion="Generate a lock file to pin dependency versions",
            ))
        findings.extend(self._check_pinned_deps(context))
        findings.extend(self._check_env_consistency(context))
        findings.extend(self._check_config_driven(context.source_files))

        # --- 3. Guardrail checks ---
        guardrails_present: Set[str] = set()
        all_content = ""
        for fpath in context.source_files + context.config_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read() + "\n"
            except (OSError, IOError):
                continue

        for name, (regex, desc) in self.GUARDRAIL_CHECKS.items():
            if re.search(regex, all_content, re.IGNORECASE):
                guardrails_present.add(name)
            else:
                severity = (
                    AgentSeverity.CRITICAL if name in ("input_validation", "auth_guard")
                    else AgentSeverity.HIGH if name in ("rate_limiting", "timeout", "output_encoding")
                    else AgentSeverity.MEDIUM
                )
                findings.append(Finding(
                    message=f"Missing guardrail: {desc}",
                    severity=severity,
                    suggestion=f"Implement {name.replace('_', ' ')} guardrail",
                ))

        # --- 4. Dangerous operation checks ---
        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (OSError, IOError):
                continue
            for i, line in enumerate(lines, 1):
                for pattern, msg, severity in self.DANGEROUS_PATTERNS:
                    if re.search(pattern, line):
                        findings.append(Finding(
                            message=msg, severity=severity,
                            file_path=fpath, line_number=i,
                        ))

        guardrail_score = round(
            len(guardrails_present) / max(len(self.GUARDRAIL_CHECKS), 1) * 100, 1
        )
        passed = guardrail_score >= 60 and not any(f.is_blocking for f in findings)

        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={
                "files_checked": len(context.source_files),
                "lock_files": lock_files_found,
                "guardrail_score_pct": guardrail_score,
                "guardrails_present": sorted(guardrails_present),
                "guardrails_missing": sorted(
                    set(self.GUARDRAIL_CHECKS.keys()) - guardrails_present
                ),
            },
            learnings=[
                f"Guardrail coverage: {guardrail_score}%",
                f"Lock files: {lock_files_found or 'NONE'}",
            ],
        )

    # ------------------------------------------------------------------
    # Determinism helpers
    # ------------------------------------------------------------------

    def _check_ai_determinism(self, fpath: str, content: str) -> List[Finding]:
        findings = []
        if not re.search(r"anthropic|openai|llm|model.*invoke|completion", content, re.IGNORECASE):
            return findings

        has_temp = re.search(r"temperature\s*[:=]\s*(\d+\.?\d*)", content)
        if has_temp:
            temp = float(has_temp.group(1))
            if temp > 0:
                findings.append(Finding(
                    message=f"AI temperature={temp} — set to 0 for deterministic outputs",
                    severity=AgentSeverity.MEDIUM,
                    file_path=fpath,
                    suggestion="Use temperature=0 for reproducible AI outputs, or make configurable",
                ))
        else:
            findings.append(Finding(
                message="AI call without explicit temperature setting",
                severity=AgentSeverity.MEDIUM,
                file_path=fpath,
                suggestion="Set temperature=0 for deterministic behavior",
            ))

        if "seed" not in content.lower() and re.search(r"\.create\(|\.invoke\(", content):
            findings.append(Finding(
                message="AI API call without seed parameter — responses may vary",
                severity=AgentSeverity.LOW,
                file_path=fpath,
                suggestion="Add seed parameter if API supports it for reproducibility",
            ))

        return findings

    def _check_idempotency(self, fpath: str, content: str) -> List[Finding]:
        findings = []
        if re.search(r"retry|while.*True|for.*range.*retry", content, re.IGNORECASE):
            if re.search(r"INSERT|create\(|\.add\(|\.append\(.*db|\.save\(", content, re.IGNORECASE):
                if not re.search(r"upsert|on_conflict|IF NOT EXISTS|get_or_create|findOrCreate", content, re.IGNORECASE):
                    findings.append(Finding(
                        message="Non-idempotent write in retry context — may create duplicates",
                        severity=AgentSeverity.HIGH,
                        file_path=fpath,
                        suggestion="Use upsert/get_or_create for idempotent operations",
                    ))
        return findings

    # ------------------------------------------------------------------
    # Repeatability helpers
    # ------------------------------------------------------------------

    def _check_lock_files(self, project_root: str) -> List[str]:
        lock_files = {
            "package-lock.json": "npm", "yarn.lock": "yarn",
            "pnpm-lock.yaml": "pnpm", "poetry.lock": "poetry",
            "Pipfile.lock": "pipenv", "requirements.txt": "pip (pinned)",
        }
        found = []
        for lockfile, manager in lock_files.items():
            if os.path.exists(os.path.join(project_root, lockfile)):
                found.append(manager)
        return found

    def _check_pinned_deps(self, context: ProjectContext) -> List[Finding]:
        findings = []
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

        version_files = [".nvmrc", ".node-version", ".python-version", ".tool-versions"]
        has_version_file = any(
            os.path.exists(os.path.join(context.project_root, f)) for f in version_files
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
                            break

        return findings
