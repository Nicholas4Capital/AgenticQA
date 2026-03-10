"""Enterprise Direction Agent — Strategic alignment, roadmap, and architectural direction."""

from __future__ import annotations

import os
import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class EnterpriseDirectionAgent(BaseAgent):
    name = "enterprise_direction"
    description = (
        "Evaluates strategic alignment: architecture consistency, tech debt, "
        "modernization opportunities, scalability patterns, and AI-first direction"
    )
    category = "enterprise"
    priority = 80
    is_gate = False
    squad = Squad.STRATEGY_VISION
    pipeline_position = 3

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        arch_analysis = self._analyze_architecture(context)
        findings.extend(arch_analysis["findings"])

        tech_debt = self._assess_tech_debt(context.source_files)
        findings.extend(tech_debt["findings"])

        ai_first = self._assess_ai_first(context.source_files)
        findings.extend(ai_first["findings"])

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={
                "architecture_score": arch_analysis.get("score", 0),
                "tech_debt_score": tech_debt.get("score", 0),
                "ai_first_score": ai_first.get("score", 0),
            },
            learnings=arch_analysis.get("learnings", []) + ai_first.get("learnings", []),
        )

    def _analyze_architecture(self, context: ProjectContext) -> dict:
        findings = []
        patterns_found = set()

        all_content = ""
        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read() + "\n"
            except (OSError, IOError):
                continue

        arch_patterns = {
            "separation_of_concerns": r"controller|service|repository|model|view|handler|usecase",
            "dependency_injection": r"inject|@Inject|provide|Container|IoC|dependency.*inject",
            "event_driven": r"event.?bus|EventEmitter|publish|subscribe|on\(['\"]",
            "microservices": r"microservice|service.?mesh|grpc|protobuf|api.?gateway",
            "clean_architecture": r"domain|entity|use.?case|repository|interface|port.*adapter",
        }

        for name, regex in arch_patterns.items():
            if re.search(regex, all_content, re.IGNORECASE):
                patterns_found.add(name)

        if "separation_of_concerns" not in patterns_found:
            findings.append(Finding(
                message="No clear separation of concerns detected (MVC, Clean Architecture, etc.)",
                severity=AgentSeverity.HIGH,
                suggestion="Organize code into layers: handlers, services, repositories",
            ))

        score = round(len(patterns_found) / max(len(arch_patterns), 1) * 100, 1)
        return {
            "findings": findings,
            "score": score,
            "learnings": [f"Architecture patterns found: {sorted(patterns_found)}"],
        }

    def _assess_tech_debt(self, source_files: List[str]) -> dict:
        findings = []
        debt_indicators = 0

        for fpath in source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            todos = len(re.findall(r"#\s*TODO|//\s*TODO|#\s*HACK|#\s*FIXME", content))
            debt_indicators += todos

            # Check for deprecated patterns
            if re.search(r"@deprecated|DEPRECATED|deprecated", content):
                debt_indicators += 1

            # Long files
            line_count = content.count("\n")
            if line_count > 500:
                findings.append(Finding(
                    message=f"Large file ({line_count} lines): {os.path.basename(fpath)}",
                    severity=AgentSeverity.LOW,
                    file_path=fpath,
                    suggestion="Consider splitting into smaller, focused modules",
                ))
                debt_indicators += 1

        if debt_indicators > 20:
            findings.append(Finding(
                message=f"High tech debt indicators: {debt_indicators} markers found",
                severity=AgentSeverity.MEDIUM,
                suggestion="Schedule tech debt reduction sprint",
            ))

        # Score inversely proportional to debt (100 = no debt)
        score = max(0, 100 - debt_indicators * 3)
        return {"findings": findings, "score": score}

    def _assess_ai_first(self, source_files: List[str]) -> dict:
        findings = []
        ai_indicators = set()

        all_content = ""
        for fpath in source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read() + "\n"
            except (OSError, IOError):
                continue

        ai_patterns = {
            "llm_integration": r"anthropic|openai|llm|claude|gpt|langchain",
            "agent_framework": r"agent|tool_use|function_call|langgraph|crew",
            "vector_store": r"vector|embedding|weaviate|pinecone|qdrant|chroma",
            "ml_pipeline": r"pipeline|model.*train|inference|predict|transform",
            "ai_observability": r"trace|span|langsmith|wandb|mlflow|experiment",
            "prompt_management": r"prompt.*template|system.*prompt|few.?shot|chain.?of.?thought",
        }

        for name, regex in ai_patterns.items():
            if re.search(regex, all_content, re.IGNORECASE):
                ai_indicators.add(name)
            else:
                findings.append(Finding(
                    message=f"AI-first opportunity: {name.replace('_', ' ')} not detected",
                    severity=AgentSeverity.LOW,
                    suggestion=f"Consider adding {name.replace('_', ' ')} for AI-first architecture",
                ))

        score = round(len(ai_indicators) / max(len(ai_patterns), 1) * 100, 1)
        return {
            "findings": findings,
            "score": score,
            "learnings": [f"AI-first score: {score}% — patterns: {sorted(ai_indicators)}"],
        }
