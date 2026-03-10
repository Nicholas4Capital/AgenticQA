"""
Team Orchestrator — Runs the agent team in continuous improvement loops
until code is launchable or max iterations are reached.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from agenticqa.agents.team.base import AgentResult, BaseAgent, ProjectContext
from agenticqa.agents.team.registry import AgentTeam

logger = logging.getLogger("agenticqa.team.orchestrator")


@dataclass
class LoopConfig:
    """Configuration for the continuous improvement loop."""
    max_iterations: int = 10
    stop_on_launchable: bool = True
    stop_on_no_improvement: bool = True
    # Minimum improvement (fewer findings) to continue looping
    min_improvement_threshold: int = 1
    # Run auto-fixers between iterations
    auto_fix_between_iterations: bool = True
    # Callbacks
    on_iteration_start: Optional[Callable[[int, ProjectContext], None]] = None
    on_iteration_end: Optional[Callable[[int, ProjectContext, List[AgentResult]], None]] = None
    on_agent_complete: Optional[Callable[[BaseAgent, AgentResult], None]] = None
    on_loop_complete: Optional[Callable[["LoopReport"], None]] = None


@dataclass
class LoopReport:
    """Final report after the improvement loop completes."""
    total_iterations: int = 0
    total_duration_ms: float = 0.0
    is_launchable: bool = False
    stop_reason: str = ""
    iteration_summaries: List[Dict[str, Any]] = field(default_factory=list)
    all_learnings: List[str] = field(default_factory=list)
    final_findings_count: int = 0
    final_blocking_count: int = 0
    total_auto_fixes: int = 0
    agent_performance: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {
            "iterations": self.total_iterations,
            "launchable": self.is_launchable,
            "stop_reason": self.stop_reason,
            "duration_ms": self.total_duration_ms,
            "findings": self.final_findings_count,
            "blocking": self.final_blocking_count,
            "auto_fixes": self.total_auto_fixes,
            "learnings": len(self.all_learnings),
        }


class TeamOrchestrator:
    """
    Runs the agent team in a continuous improvement loop.

    The loop:
    1. Runs all agents in priority order against the project
    2. Collects findings and auto-fixes
    3. Checks if the project is launchable (no blocking findings)
    4. If not launchable and improvement is being made, loops again
    5. Stops when launchable, no improvement, or max iterations hit
    """

    def __init__(self, team: AgentTeam, config: Optional[LoopConfig] = None):
        self.team = team
        self.config = config or LoopConfig()
        self._report = LoopReport()

    def run(self, context: ProjectContext) -> LoopReport:
        """Execute the continuous improvement loop."""
        loop_start = time.time()
        prev_finding_count = float("inf")

        for iteration in range(self.config.max_iterations):
            context.iteration = iteration
            logger.info(f"=== Iteration {iteration + 1}/{self.config.max_iterations} ===")

            if self.config.on_iteration_start:
                self.config.on_iteration_start(iteration, context)

            # Run all agents
            iteration_results = self._run_iteration(context)

            # Collect metrics
            total_findings = sum(len(r.findings) for r in iteration_results)
            blocking = sum(len(r.blocking_findings) for r in iteration_results)
            fixes = sum(r.auto_fixes_applied for r in iteration_results)

            self._report.total_auto_fixes += fixes
            self._report.iteration_summaries.append({
                "iteration": iteration,
                "findings": total_findings,
                "blocking": blocking,
                "fixes_applied": fixes,
                "agents_run": len(iteration_results),
            })

            if self.config.on_iteration_end:
                self.config.on_iteration_end(iteration, context, iteration_results)

            # Archive this iteration's results
            context.iteration_history.append(iteration_results)
            context.prior_results = []

            # Collect learnings
            for result in iteration_results:
                self._report.all_learnings.extend(result.learnings)
                context.global_learnings.extend(result.learnings)

            # Track per-agent performance
            for result in iteration_results:
                if result.agent_name not in self._report.agent_performance:
                    self._report.agent_performance[result.agent_name] = {
                        "runs": 0, "total_findings": 0, "total_fixes": 0,
                    }
                perf = self._report.agent_performance[result.agent_name]
                perf["runs"] += 1
                perf["total_findings"] += len(result.findings)
                perf["total_fixes"] += result.auto_fixes_applied

            # Check stop conditions
            self._report.final_findings_count = total_findings
            self._report.final_blocking_count = blocking

            if self.config.stop_on_launchable and blocking == 0:
                self._report.stop_reason = "launchable"
                self._report.is_launchable = True
                logger.info("Project is LAUNCHABLE — no blocking findings.")
                break

            improvement = prev_finding_count - total_findings
            if self.config.stop_on_no_improvement and improvement < self.config.min_improvement_threshold:
                self._report.stop_reason = "no_improvement"
                logger.info(f"No improvement (delta={improvement}). Stopping.")
                break

            prev_finding_count = total_findings
            logger.info(
                f"Iteration {iteration + 1}: {total_findings} findings "
                f"({blocking} blocking), {fixes} fixes applied. Continuing..."
            )
        else:
            self._report.stop_reason = "max_iterations"
            logger.info(f"Reached max iterations ({self.config.max_iterations}).")

        self._report.total_iterations = context.iteration + 1
        self._report.total_duration_ms = (time.time() - loop_start) * 1000

        if self.config.on_loop_complete:
            self.config.on_loop_complete(self._report)

        return self._report

    def _run_iteration(self, context: ProjectContext) -> List[AgentResult]:
        """Run all agents in priority order for one iteration."""
        results = []
        for agent in self.team.agents:
            try:
                logger.info(f"  Running: {agent.name} ({agent.category})")
                result = agent.run(context)
                context.add_result(result)
                results.append(result)

                if self.config.on_agent_complete:
                    self.config.on_agent_complete(agent, result)

                logger.info(
                    f"  {agent.name}: {'PASS' if result.passed else 'FAIL'} "
                    f"({len(result.findings)} findings, "
                    f"{result.auto_fixes_applied} fixes)"
                )
            except Exception as e:
                logger.error(f"  {agent.name} CRASHED: {e}")
                results.append(AgentResult(
                    agent_name=agent.name,
                    passed=False,
                    learnings=[f"Agent crashed: {e}"],
                ))
        return results

    @property
    def report(self) -> LoopReport:
        return self._report
