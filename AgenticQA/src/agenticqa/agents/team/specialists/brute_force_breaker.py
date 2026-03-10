"""Brute Force Code Breaker Agent — Aggressively finds bugs, edge cases, and failure modes."""

from __future__ import annotations

import ast
import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class BruteForceCodeBreakerAgent(BaseAgent):
    name = "brute_force_breaker"
    description = (
        "Aggressively hunts for bugs: null derefs, off-by-one errors, race conditions, "
        "resource leaks, type errors, boundary violations, and crash-inducing paths"
    )
    category = "testing"
    priority = 18
    is_gate = True
    squad = Squad.TESTING_RESILIENCE
    pipeline_position = 4

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.splitlines()
            except (OSError, IOError):
                continue

            if fpath.endswith(".py"):
                findings.extend(self._break_python(fpath, lines, content))
            elif fpath.endswith((".js", ".ts", ".jsx", ".tsx")):
                findings.extend(self._break_javascript(fpath, lines))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={"files_attacked": len(context.source_files)},
            learnings=self._summarize(findings),
        )

    def _break_python(self, fpath: str, lines: List[str], content: str) -> List[Finding]:
        findings = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Unguarded dictionary access
            if re.search(r"\w+\[['\"]?\w+['\"]?\]", stripped) and ".get(" not in stripped:
                if not any(k in stripped for k in ("def ", "class ", "import ", "#", "for ", "try:", "except")):
                    if re.search(r"(?:data|config|params|result|response|body|payload|record)\[", stripped):
                        findings.append(Finding(
                            message="Unguarded dict access — use .get() or try/except for KeyError",
                            severity=AgentSeverity.HIGH,
                            file_path=fpath, line_number=i,
                            auto_fixable=True,
                        ))

            # Index access without bounds check
            if re.search(r"\w+\[\s*\d+\s*\]", stripped) and "range" not in stripped:
                if re.search(r"\[\s*[1-9]\d*\s*\]", stripped):  # Non-zero index
                    findings.append(Finding(
                        message="Array index access without bounds check",
                        severity=AgentSeverity.MEDIUM,
                        file_path=fpath, line_number=i,
                    ))

            # Resource leak — open without context manager
            if re.search(r"\w+\s*=\s*open\(", stripped) and "with " not in stripped:
                findings.append(Finding(
                    message="File opened without context manager — potential resource leak",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath, line_number=i,
                    suggestion="Use 'with open(...) as f:' pattern",
                    auto_fixable=False,
                ))

            # None dereference patterns
            if re.search(r"\.(\w+)\s*\(", stripped):
                prev_lines = lines[max(0, i - 5):i - 1]
                for pl in prev_lines:
                    if "= None" in pl or "return None" in pl or "Optional" in pl:
                        findings.append(Finding(
                            message="Potential None dereference — variable may be None",
                            severity=AgentSeverity.HIGH,
                            file_path=fpath, line_number=i,
                            suggestion="Add None check before method call",
                        ))
                        break

            # Race condition indicators
            if re.search(r"threading|multiprocessing|asyncio\.gather|concurrent", stripped):
                if not re.search(r"Lock|Semaphore|Queue|Event|Condition|atomic", content):
                    findings.append(Finding(
                        message="Concurrency without synchronization primitives",
                        severity=AgentSeverity.HIGH,
                        file_path=fpath, line_number=i,
                        suggestion="Use locks/semaphores for shared state access",
                    ))

        # Check for missing type narrowing
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    for arg in node.args.args:
                        if hasattr(arg, "annotation") and arg.annotation:
                            ann = ast.dump(arg.annotation)
                            if "Optional" in ann or "None" in ann:
                                # Check if function body handles None case
                                body_src = ast.get_source_segment(content, node) or ""
                                if f"if {arg.arg}" not in body_src and f"{arg.arg} is not None" not in body_src:
                                    findings.append(Finding(
                                        message=f"Optional param '{arg.arg}' not checked for None in body",
                                        severity=AgentSeverity.MEDIUM,
                                        file_path=fpath, line_number=node.lineno,
                                    ))
        except SyntaxError:
            pass

        return findings

    def _break_javascript(self, fpath: str, lines: List[str]) -> List[Finding]:
        findings = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Unguarded property access chains
            if re.search(r"\w+\.\w+\.\w+\.\w+", stripped) and "?." not in stripped:
                if not stripped.startswith("//") and "import" not in stripped:
                    findings.append(Finding(
                        message="Deep property chain without optional chaining (?.) — crash risk",
                        severity=AgentSeverity.MEDIUM,
                        file_path=fpath, line_number=i,
                        suggestion="Use optional chaining: obj?.prop?.nested",
                    ))

            # parseInt without radix
            if re.search(r"parseInt\(\s*\w+\s*\)", stripped):
                findings.append(Finding(
                    message="parseInt() without radix — may produce unexpected results",
                    severity=AgentSeverity.MEDIUM,
                    file_path=fpath, line_number=i,
                    suggestion="Always specify radix: parseInt(val, 10)",
                ))

            # Async without error handling
            if "await " in stripped and "try" not in stripped:
                context_lines = lines[max(0, i - 3):i + 3]
                if not any("try" in l or "catch" in l for l in context_lines):
                    findings.append(Finding(
                        message="Unhandled await — rejected promise will crash",
                        severity=AgentSeverity.HIGH,
                        file_path=fpath, line_number=i,
                        suggestion="Wrap in try/catch or add .catch() handler",
                    ))

        return findings

    def _summarize(self, findings: List[Finding]) -> List[str]:
        if not findings:
            return ["No crash-inducing patterns found"]
        by_type = {}
        for f in findings:
            key = f.message.split("—")[0].strip()[:50]
            by_type[key] = by_type.get(key, 0) + 1
        top = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:5]
        return [f"Top vulnerabilities: {dict(top)}"]
