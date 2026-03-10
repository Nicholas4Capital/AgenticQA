"""AI Implementer & Reviewer Agent — Validates AI/ML integration quality and AI-first patterns."""

from __future__ import annotations

import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class AIImplementerReviewerAgent(BaseAgent):
    name = "ai_implementer"
    description = "Reviews AI/ML integrations: prompt quality, model usage, guardrails, fallbacks, and AI-first patterns"
    category = "intelligence"
    priority = 40
    is_gate = False

    AI_PATTERNS = {
        "prompt_template": (r"prompt|template|system.?message|user.?message", "Prompt management"),
        "model_config": (r"model.*=|engine.*=|temperature|max_tokens|top_p", "Model configuration"),
        "streaming": (r"stream|async.*generate|chunk|sse", "Streaming support"),
        "fallback": (r"fallback|retry|backup.?model|circuit.?breaker", "AI fallback handling"),
        "caching": (r"cache|memoize|semantic.?cache|embedding.?cache", "Response caching"),
        "eval_metrics": (r"eval|benchmark|accuracy|f1.?score|bleu|rouge|perplexity", "Evaluation metrics"),
        "guardrails": (r"guardrail|content.?filter|safety|moderation|constitutional", "AI guardrails"),
        "structured_output": (r"json.?mode|function.?call|tool.?use|structured|pydantic.*model", "Structured output"),
        "embeddings": (r"embedding|vector|similarity|cosine|semantic.?search", "Embedding/vector support"),
        "rag": (r"rag|retriev|knowledge.?base|context.?window|chunk", "RAG implementation"),
    }

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        present = set()

        ai_files = []
        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            # Detect if this is an AI-related file
            if re.search(r"anthropic|openai|llm|langchain|claude|gpt|model.*invoke", content, re.IGNORECASE):
                ai_files.append(fpath)
                findings.extend(self._review_ai_file(fpath, content))

                for name, (regex, _) in self.AI_PATTERNS.items():
                    if re.search(regex, content, re.IGNORECASE):
                        present.add(name)

        # Check for missing AI-first patterns
        missing = set(self.AI_PATTERNS.keys()) - present
        for name in missing:
            _, desc = self.AI_PATTERNS[name]
            severity = AgentSeverity.HIGH if name in ("guardrails", "fallback") else AgentSeverity.MEDIUM
            findings.append(Finding(
                message=f"Missing AI pattern: {desc}",
                severity=severity,
                suggestion=f"Implement {name.replace('_', ' ')} for robust AI integration",
            ))

        ai_score = round(len(present) / max(len(self.AI_PATTERNS), 1) * 100, 1)
        passed = ai_score >= 40 or not ai_files
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={
                "ai_files": len(ai_files),
                "ai_patterns_present": len(present),
                "ai_score_pct": ai_score,
            },
            learnings=[f"AI-first score: {ai_score}% ({len(present)}/{len(self.AI_PATTERNS)} patterns)"],
        )

    def _review_ai_file(self, fpath: str, content: str) -> List[Finding]:
        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            # Check for hardcoded prompts without template management
            if re.search(r"messages?\s*=\s*\[", line) and len(line) > 200:
                findings.append(Finding(
                    message="Long inline prompt — extract to template for maintainability",
                    severity=AgentSeverity.LOW,
                    file_path=fpath, line_number=i,
                ))

            # Check for missing error handling around AI calls
            if re.search(r"\.create\(|\.invoke\(|\.generate\(|\.complete\(", line):
                # Look for try/except in surrounding lines
                context_lines = lines[max(0, i - 5):i + 5]
                has_error_handling = any("try" in l or "except" in l or "catch" in l for l in context_lines)
                if not has_error_handling:
                    findings.append(Finding(
                        message="AI API call without error handling",
                        severity=AgentSeverity.HIGH,
                        file_path=fpath, line_number=i,
                        suggestion="Wrap AI calls in try/except with fallback behavior",
                    ))

            # Check for temperature/config hardcoding
            if re.search(r"temperature\s*=\s*\d", line):
                findings.append(Finding(
                    message="Hardcoded temperature — make configurable",
                    severity=AgentSeverity.LOW,
                    file_path=fpath, line_number=i,
                ))

        return findings
