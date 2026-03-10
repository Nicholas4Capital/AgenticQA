"""Continuous Learning Agent — Aggregates learnings, detects patterns, improves the team."""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Dict, List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class ContinuousLearningAgent(BaseAgent):
    name = "continuous_learner"
    description = "Aggregates learnings across iterations, detects recurring patterns, and suggests team improvements"
    category = "intelligence"
    priority = 90  # Runs near-last to aggregate everything
    is_gate = False
    squad = Squad.STRATEGY_VISION
    pipeline_position = 1

    LEARNINGS_FILE = ".agenticqa_learnings.json"

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        learnings: List[str] = []

        # Aggregate all findings from this and prior iterations
        all_findings = []
        for result in context.prior_results:
            all_findings.extend(result.findings)
        for iteration in context.iteration_history:
            for result in iteration:
                all_findings.extend(result.findings)

        # Detect recurring patterns
        patterns = self._detect_patterns(all_findings)
        for pattern, count in patterns.most_common(10):
            if count >= 3:
                findings.append(Finding(
                    message=f"Recurring issue ({count}x): {pattern}",
                    severity=AgentSeverity.MEDIUM,
                    suggestion=f"Systemic fix needed for: {pattern}",
                ))
                learnings.append(f"Recurring pattern ({count}x): {pattern}")

        # Track improvement over iterations
        improvement = self._track_improvement(context)
        if improvement:
            learnings.append(improvement)

        # Analyze agent effectiveness
        effectiveness = self._agent_effectiveness(context)
        for agent_name, stats in effectiveness.items():
            if stats["fix_rate"] < 0.1 and stats["findings"] > 5:
                findings.append(Finding(
                    message=f"Agent '{agent_name}' finds many issues but fixes few ({stats['fix_rate']:.0%})",
                    severity=AgentSeverity.LOW,
                    suggestion=f"Enhance auto-fix capability for {agent_name}",
                ))

        # Persist learnings
        self._persist_learnings(context, learnings)

        return AgentResult(
            agent_name=self.name,
            passed=True,
            findings=findings,
            metrics={
                "total_learnings": len(context.global_learnings) + len(learnings),
                "recurring_patterns": len(patterns),
                "iterations_analyzed": len(context.iteration_history) + 1,
            },
            learnings=learnings,
        )

    def _detect_patterns(self, findings: List[Finding]) -> Counter:
        # Normalize finding messages to detect recurring patterns
        normalized = []
        for f in findings:
            msg = f.message
            # Remove file-specific details
            msg = msg.split(" in ")[0] if " in " in msg else msg
            msg = msg.split(":")[0] if ":" in msg else msg
            normalized.append(msg.strip()[:80])
        return Counter(normalized)

    def _track_improvement(self, context: ProjectContext) -> str:
        if len(context.iteration_history) < 2:
            return ""

        prev_count = sum(
            len(r.findings) for r in context.iteration_history[-2]
        ) if len(context.iteration_history) >= 2 else 0
        curr_count = sum(len(r.findings) for r in context.prior_results)

        if curr_count < prev_count:
            return f"Improved: {prev_count} -> {curr_count} findings ({prev_count - curr_count} fixed)"
        elif curr_count > prev_count:
            return f"Regression: {prev_count} -> {curr_count} findings ({curr_count - prev_count} new)"
        return f"Stable: {curr_count} findings across iterations"

    def _agent_effectiveness(self, context: ProjectContext) -> Dict[str, Dict]:
        stats = {}
        for result in context.prior_results:
            name = result.agent_name
            if name not in stats:
                stats[name] = {"findings": 0, "fixes": 0, "fix_rate": 0}
            stats[name]["findings"] += len(result.findings)
            stats[name]["fixes"] += result.auto_fixes_applied
            total = stats[name]["findings"]
            stats[name]["fix_rate"] = stats[name]["fixes"] / max(total, 1)
        return stats

    def _persist_learnings(self, context: ProjectContext, new_learnings: List[str]) -> None:
        path = os.path.join(context.project_root, self.LEARNINGS_FILE)
        existing = []
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            existing = []

        all_learnings = existing + new_learnings + context.global_learnings
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for l in all_learnings:
            if l not in seen:
                seen.add(l)
                unique.append(l)

        try:
            with open(path, "w") as f:
                json.dump(unique[-500:], f, indent=2)  # Keep last 500
        except OSError:
            pass
