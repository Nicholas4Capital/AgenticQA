"""
Team Orchestrator — Runs the agent team in continuous improvement loops
with 7-squad sequential gating until code is production-ready.

Squad Pipeline:
  Squad 1 (Code Quality) must PASS → Squad 2 (Testing) must PASS →
  Squad 3 (Architecture) → Squad 4 (AI) → Squad 5 (Domain) →
  Squad 6 (Strategy) → Squad 7 (Governance) = FINAL GATE

If any squad fails, the pipeline loops back with auto-fixes applied.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from agenticqa.agents.team.base import (
    AgentResult, BaseAgent, ProjectContext, Squad, SQUAD_LABELS,
)
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
    # Sequential squad gating — if True, squad N+1 only runs if squad N passes
    squad_gating: bool = True
    # Callbacks
    on_iteration_start: Optional[Callable[[int, ProjectContext], None]] = None
    on_iteration_end: Optional[Callable[[int, ProjectContext, List[AgentResult]], None]] = None
    on_agent_complete: Optional[Callable[[BaseAgent, AgentResult], None]] = None
    on_squad_complete: Optional[Callable[[Squad, List[AgentResult], bool], None]] = None
    on_loop_complete: Optional[Callable[["LoopReport"], None]] = None


@dataclass
class SquadReport:
    """Report for a single squad's execution."""
    squad: int = 1
    squad_name: str = ""
    passed: bool = True
    agents_run: int = 0
    total_findings: int = 0
    blocking_findings: int = 0
    auto_fixes: int = 0
    agent_results: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class LoopReport:
    """Final report after the improvement loop completes."""
    total_iterations: int = 0
    total_duration_ms: float = 0.0
    is_launchable: bool = False
    stop_reason: str = ""
    # Which squad blocked (0 = none, 7 = governance passed = production ready)
    blocked_at_squad: int = 0
    highest_squad_passed: int = 0
    iteration_summaries: List[Dict[str, Any]] = field(default_factory=list)
    squad_reports: List[SquadReport] = field(default_factory=list)
    all_learnings: List[str] = field(default_factory=list)
    all_discrepancies: List[Dict[str, Any]] = field(default_factory=list)
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
            "discrepancies": len(self.all_discrepancies),
            "highest_squad_passed": self.highest_squad_passed,
            "blocked_at_squad": self.blocked_at_squad,
            "squad_results": {
                sr.squad_name: {"passed": sr.passed, "findings": sr.total_findings}
                for sr in self.squad_reports
            },
        }


class TeamOrchestrator:
    """
    Runs the agent team in a continuous improvement loop with squad gating.

    Pipeline:
    1. Group agents by squad (1-7)
    2. Run Squad 1 agents in pipeline_position order
    3. If Squad 1 has blocking findings from gate agents → loop back
    4. If Squad 1 passes → run Squad 2, and so on
    5. Squad 7 (Governance) is the FINAL gate — no code goes to production without it
    6. Loop until all squads pass, no improvement, or max iterations hit
    """

    def __init__(self, team: AgentTeam, config: Optional[LoopConfig] = None):
        self.team = team
        self.config = config or LoopConfig()
        self._report = LoopReport()

    def run(self, context: ProjectContext) -> LoopReport:
        """Execute the continuous improvement loop with squad gating."""
        loop_start = time.time()
        prev_finding_count = float("inf")

        for iteration in range(self.config.max_iterations):
            context.iteration = iteration
            logger.info(f"=== Iteration {iteration + 1}/{self.config.max_iterations} ===")

            if self.config.on_iteration_start:
                self.config.on_iteration_start(iteration, context)

            # Run agents — with or without squad gating
            if self.config.squad_gating:
                iteration_results, squad_reports = self._run_squad_pipeline(context)
            else:
                iteration_results = self._run_flat(context)
                squad_reports = []

            # Collect metrics
            total_findings = sum(len(r.findings) for r in iteration_results)
            blocking = sum(len(r.blocking_findings) for r in iteration_results)
            fixes = sum(r.auto_fixes_applied for r in iteration_results)

            self._report.total_auto_fixes += fixes
            self._report.squad_reports = squad_reports
            self._report.iteration_summaries.append({
                "iteration": iteration,
                "findings": total_findings,
                "blocking": blocking,
                "fixes_applied": fixes,
                "agents_run": len(iteration_results),
                "squads_passed": sum(1 for sr in squad_reports if sr.passed),
                "squads_total": len(squad_reports),
            })

            if self.config.on_iteration_end:
                self.config.on_iteration_end(iteration, context, iteration_results)

            # Archive
            context.iteration_history.append(iteration_results)
            context.prior_results = []

            # Collect learnings and discrepancies
            for result in iteration_results:
                self._report.all_learnings.extend(result.learnings)
                context.global_learnings.extend(result.learnings)
                for disc in result.discrepancies:
                    self._report.all_discrepancies.append(disc.to_dict())

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

            if squad_reports:
                passed_squads = [sr for sr in squad_reports if sr.passed]
                self._report.highest_squad_passed = max(
                    (sr.squad for sr in passed_squads), default=0
                )
                failed_squads = [sr for sr in squad_reports if not sr.passed]
                self._report.blocked_at_squad = min(
                    (sr.squad for sr in failed_squads), default=0
                )

            if self.config.stop_on_launchable and blocking == 0:
                self._report.stop_reason = "launchable"
                self._report.is_launchable = True
                logger.info("PRODUCTION READY — all squads passed, no blocking findings.")
                break

            improvement = prev_finding_count - total_findings
            if self.config.stop_on_no_improvement and improvement < self.config.min_improvement_threshold:
                self._report.stop_reason = "no_improvement"
                logger.info(f"No improvement (delta={improvement}). Stopping.")
                break

            prev_finding_count = total_findings
            logger.info(
                f"Iteration {iteration + 1}: {total_findings} findings "
                f"({blocking} blocking), {fixes} fixes. Continuing..."
            )
        else:
            self._report.stop_reason = "max_iterations"
            logger.info(f"Reached max iterations ({self.config.max_iterations}).")

        self._report.total_iterations = context.iteration + 1
        self._report.total_duration_ms = (time.time() - loop_start) * 1000

        if self.config.on_loop_complete:
            self.config.on_loop_complete(self._report)

        return self._report

    def _run_squad_pipeline(self, context: ProjectContext) -> tuple:
        """Run agents in sequential squad order with gating."""
        all_results: List[AgentResult] = []
        squad_reports: List[SquadReport] = []

        # Group agents by squad
        squads: Dict[int, List[BaseAgent]] = defaultdict(list)
        for agent in self.team.agents:
            squads[agent.squad.value].append(agent)

        # Sort each squad by pipeline_position
        for squad_num in squads:
            squads[squad_num].sort(key=lambda a: a.pipeline_position)

        # Run squads sequentially
        for squad_num in sorted(squads.keys()):
            squad_agents = squads[squad_num]
            squad_name = SQUAD_LABELS.get(Squad(squad_num), f"Squad {squad_num}")
            logger.info(f"\n  --- {squad_name} (Squad {squad_num}) ---")

            squad_results = []
            for agent in squad_agents:
                try:
                    logger.info(f"    [{squad_num}.{agent.pipeline_position}] {agent.name}")
                    result = agent.run(context)
                    context.add_result(result)
                    squad_results.append(result)
                    all_results.append(result)

                    if self.config.on_agent_complete:
                        self.config.on_agent_complete(agent, result)

                    status = "PASS" if result.passed else "FAIL"
                    logger.info(
                        f"    {agent.name}: {status} "
                        f"({len(result.findings)} findings, "
                        f"{result.auto_fixes_applied} fixes)"
                    )
                except Exception as e:
                    logger.error(f"    {agent.name} CRASHED: {e}")
                    crashed = AgentResult(
                        agent_name=agent.name, passed=False,
                        learnings=[f"Agent crashed: {e}"],
                    )
                    squad_results.append(crashed)
                    all_results.append(crashed)

            # Build squad report
            squad_blocking = sum(len(r.blocking_findings) for r in squad_results)
            squad_passed = squad_blocking == 0

            sr = SquadReport(
                squad=squad_num,
                squad_name=squad_name,
                passed=squad_passed,
                agents_run=len(squad_results),
                total_findings=sum(len(r.findings) for r in squad_results),
                blocking_findings=squad_blocking,
                auto_fixes=sum(r.auto_fixes_applied for r in squad_results),
                agent_results=[r.summary() for r in squad_results],
            )
            squad_reports.append(sr)

            if self.config.on_squad_complete:
                self.config.on_squad_complete(Squad(squad_num), squad_results, squad_passed)

            logger.info(
                f"  Squad {squad_num} ({squad_name}): "
                f"{'PASS' if squad_passed else 'BLOCKED'} "
                f"({sr.total_findings} findings, {squad_blocking} blocking)"
            )

            # Gate: if this squad has blocking findings, stop the pipeline
            if not squad_passed:
                logger.info(f"  PIPELINE BLOCKED at Squad {squad_num}. Returning for fixes.")
                break

        return all_results, squad_reports

    def _run_flat(self, context: ProjectContext) -> List[AgentResult]:
        """Run all agents in priority order without squad gating (legacy mode)."""
        results = []
        for agent in self.team.agents:
            try:
                logger.info(f"  Running: {agent.name} ({agent.category})")
                result = agent.run(context)
                context.add_result(result)
                results.append(result)

                if self.config.on_agent_complete:
                    self.config.on_agent_complete(agent, result)
            except Exception as e:
                logger.error(f"  {agent.name} CRASHED: {e}")
                results.append(AgentResult(
                    agent_name=agent.name, passed=False,
                    learnings=[f"Agent crashed: {e}"],
                ))
        return results

    @property
    def report(self) -> LoopReport:
        return self._report
