"""Base agent class and result types for the Agent Team framework."""

from __future__ import annotations

import enum
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class AgentSeverity(enum.Enum):
    """Severity level for findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKER = "blocker"


@dataclass
class Finding:
    """A single finding from an agent's analysis."""
    message: str
    severity: AgentSeverity = AgentSeverity.INFO
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    suggestion: Optional[str] = None
    auto_fixable: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_blocking(self) -> bool:
        return self.severity in (AgentSeverity.CRITICAL, AgentSeverity.BLOCKER)


@dataclass
class AgentResult:
    """Result returned by every agent after execution."""
    agent_name: str
    passed: bool
    findings: List[Finding] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    auto_fixes_applied: int = 0
    duration_ms: float = 0.0
    iteration: int = 0
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    learnings: List[str] = field(default_factory=list)
    suggestions_for_next_run: List[str] = field(default_factory=list)

    @property
    def blocking_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.is_blocking]

    @property
    def fixable_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.auto_fixable]

    def summary(self) -> Dict[str, Any]:
        return {
            "agent": self.agent_name,
            "passed": self.passed,
            "total_findings": len(self.findings),
            "blocking": len(self.blocking_findings),
            "auto_fixable": len(self.fixable_findings),
            "fixes_applied": self.auto_fixes_applied,
            "duration_ms": self.duration_ms,
            "iteration": self.iteration,
        }


class BaseAgent(ABC):
    """
    Base class for all agents in the team.

    Every agent:
    - Has a name, description, and category
    - Can analyze a project context
    - Can optionally auto-fix issues it finds
    - Reports structured findings
    - Tracks learnings across iterations for continuous improvement
    """

    name: str = "base_agent"
    description: str = "Base agent"
    category: str = "general"
    # Agents with higher priority run first (lower number = higher priority)
    priority: int = 50
    # Whether this agent can auto-fix issues
    can_auto_fix: bool = False
    # Whether failures from this agent block deployment
    is_gate: bool = False

    def __init__(self):
        self._learnings: List[str] = []
        self._iteration_count: int = 0
        self._history: List[AgentResult] = []

    @abstractmethod
    def analyze(self, context: "ProjectContext") -> AgentResult:
        """Run the agent's analysis on the project context."""
        ...

    def fix(self, context: "ProjectContext", findings: List[Finding]) -> int:
        """
        Attempt to auto-fix findings. Returns number of fixes applied.
        Override in subclasses that support auto-fix.
        """
        return 0

    def learn(self, result: AgentResult) -> None:
        """Record learnings from this run for future iterations."""
        self._learnings.extend(result.learnings)
        self._history.append(result)
        self._iteration_count += 1

    def run(self, context: "ProjectContext") -> AgentResult:
        """Full execution: analyze, optionally fix, learn, return result."""
        start = time.time()
        result = self.analyze(context)
        result.iteration = self._iteration_count

        if self.can_auto_fix and result.fixable_findings:
            fixes = self.fix(context, result.fixable_findings)
            result.auto_fixes_applied = fixes

        result.duration_ms = (time.time() - start) * 1000
        self.learn(result)
        return result

    @property
    def learnings(self) -> List[str]:
        return list(self._learnings)

    @property
    def history(self) -> List[AgentResult]:
        return list(self._history)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name!r}, category={self.category!r})>"


@dataclass
class ProjectContext:
    """
    Shared context passed to every agent in the team.

    Contains everything agents need to analyze: file paths, source code,
    config, test results, previous agent results, and accumulated learnings.
    """
    project_root: str
    source_files: List[str] = field(default_factory=list)
    test_files: List[str] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)
    # Accumulated results from prior agents in this iteration
    prior_results: List[AgentResult] = field(default_factory=list)
    # Accumulated results from prior iterations
    iteration_history: List[List[AgentResult]] = field(default_factory=list)
    # Global learnings from all agents across all iterations
    global_learnings: List[str] = field(default_factory=list)
    # User-provided configuration overrides
    config: Dict[str, Any] = field(default_factory=dict)
    # Current iteration number
    iteration: int = 0
    # Target branch or environment
    target: str = "production"
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_result(self, result: AgentResult) -> None:
        self.prior_results.append(result)

    def get_results_by_agent(self, agent_name: str) -> List[AgentResult]:
        all_results = list(self.prior_results)
        for iteration_results in self.iteration_history:
            all_results.extend(iteration_results)
        return [r for r in all_results if r.agent_name == agent_name]

    @property
    def all_blocking_findings(self) -> List[Finding]:
        findings = []
        for result in self.prior_results:
            findings.extend(result.blocking_findings)
        return findings

    @property
    def is_launchable(self) -> bool:
        """True if no blocking findings exist from gate agents."""
        return len(self.all_blocking_findings) == 0
