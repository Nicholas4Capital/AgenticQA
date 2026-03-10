"""Base agent class, result types, squad definitions, and discrepancy protocol."""

from __future__ import annotations

import enum
import json
import os
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Squad definitions — sequential pipeline gates
# ---------------------------------------------------------------------------

class Squad(enum.IntEnum):
    """7-squad pipeline. Each squad must PASS before the next runs."""
    CODE_QUALITY = 1          # Every change
    TESTING_RESILIENCE = 2    # Every change
    ARCHITECTURE = 3          # Significant changes
    AI_INTEGRATION = 4        # AI-related changes
    DOMAIN_EXPERTISE = 5      # Domain-specific changes
    STRATEGY_VISION = 6       # Periodic / major changes
    GOVERNANCE = 7            # ALL client-facing — FINAL gate


SQUAD_LABELS = {
    Squad.CODE_QUALITY: "Code Quality",
    Squad.TESTING_RESILIENCE: "Testing & Resilience",
    Squad.ARCHITECTURE: "Architecture & Infrastructure",
    Squad.AI_INTEGRATION: "AI & Integration",
    Squad.DOMAIN_EXPERTISE: "Domain Expertise",
    Squad.STRATEGY_VISION: "Strategy & Vision",
    Squad.GOVERNANCE: "Governance & Regulatory",
}


class AgentSeverity(enum.Enum):
    """Severity level for findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKER = "blocker"


# ---------------------------------------------------------------------------
# Discrepancy protocol
# ---------------------------------------------------------------------------

@dataclass
class Discrepancy:
    """A mismatch between two sources discovered by an agent."""
    id: str = field(default_factory=lambda: f"DISC-{uuid.uuid4().hex[:8]}")
    source_a: str = ""           # e.g. "engine.ts:42"
    source_b: str = ""           # e.g. "CMHC-BIBLE.md:§3.2"
    description: str = ""
    options: List[str] = field(default_factory=lambda: [
        "(a) Fix Source A to match Source B",
        "(b) Fix Source B to match Source A",
        "(c) Accept as intentional deviation",
    ])
    resolution: Optional[str] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[str] = None
    agent_name: str = ""
    status: str = "OPEN"         # OPEN | RESOLVED | ACCEPTED_DEVIATION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_a": self.source_a,
            "source_b": self.source_b,
            "description": self.description,
            "options": self.options,
            "resolution": self.resolution,
            "resolved_by": self.resolved_by,
            "status": self.status,
        }


# ---------------------------------------------------------------------------
# Core data types
# ---------------------------------------------------------------------------

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
    discrepancies: List[Discrepancy] = field(default_factory=list)

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
            "discrepancies": len(self.discrepancies),
        }


class BaseAgent(ABC):
    """
    Base class for all agents in the team.

    Every agent belongs to a Squad (1-7) and follows the standard protocol:
    - Analyze the project context
    - Report structured findings
    - Surface discrepancies (FIND → ASK → RECORD)
    - Optionally auto-fix issues
    - Track learnings across iterations
    - Hand off to the next agent/squad
    """

    name: str = "base_agent"
    description: str = "Base agent"
    category: str = "general"
    squad: Squad = Squad.CODE_QUALITY
    # Pipeline position within the squad (lower = runs first)
    pipeline_position: int = 1
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
        """Attempt to auto-fix findings. Returns number of fixes applied."""
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

        # Log discrepancies to knowledge base
        if result.discrepancies and hasattr(context, 'knowledge_base') and context.knowledge_base:
            for disc in result.discrepancies:
                context.knowledge_base.add_discrepancy(disc)

        self.learn(result)
        return result

    @property
    def learnings(self) -> List[str]:
        return list(self._learnings)

    @property
    def history(self) -> List[AgentResult]:
        return list(self._history)

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__}("
            f"name={self.name!r}, squad={self.squad.name}, "
            f"position={self.pipeline_position})>"
        )


# ---------------------------------------------------------------------------
# Knowledge Base — living document maintained by agents
# ---------------------------------------------------------------------------

class KnowledgeBase:
    """
    Living infrastructure document maintained by agents and updated as they work.
    All agents reference it. Persisted as JSON on disk.

    Tracks:
    - Current infrastructure state
    - Decisions log
    - Known discrepancies
    - Accepted deviations
    - Technical debt registry
    - Agent learning notes
    """

    def __init__(self, path: Optional[str] = None):
        self._path = path or ".agenticqa_knowledge_base.json"
        self._data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        if os.path.exists(self._path):
            try:
                with open(self._path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {
            "last_updated": datetime.now(UTC).isoformat(),
            "updated_by": "system",
            "infrastructure_state": {},
            "decisions_log": [],
            "discrepancies": [],
            "accepted_deviations": [],
            "technical_debt": [],
            "agent_learnings": [],
        }

    def save(self) -> None:
        self._data["last_updated"] = datetime.now(UTC).isoformat()
        try:
            with open(self._path, "w") as f:
                json.dump(self._data, f, indent=2)
        except OSError:
            pass

    def add_discrepancy(self, disc: Discrepancy) -> None:
        self._data["discrepancies"].append(disc.to_dict())
        self.save()

    def add_decision(self, decision: str, context: str, decided_by: str, agents: List[str]) -> None:
        self._data["decisions_log"].append({
            "date": datetime.now(UTC).isoformat(),
            "decision": decision,
            "context": context,
            "decided_by": decided_by,
            "agents_involved": agents,
        })
        self.save()

    def add_tech_debt(self, description: str, severity: str, repos: List[str]) -> None:
        self._data["technical_debt"].append({
            "id": f"TD-{uuid.uuid4().hex[:8]}",
            "description": description,
            "severity": severity,
            "affected_repos": repos,
            "created_at": datetime.now(UTC).isoformat(),
        })
        self.save()

    def add_learning(self, agent_name: str, learning: str) -> None:
        self._data["agent_learnings"].append({
            "agent": agent_name,
            "learning": learning,
            "timestamp": datetime.now(UTC).isoformat(),
        })
        # Keep last 1000
        self._data["agent_learnings"] = self._data["agent_learnings"][-1000:]
        self.save()

    def add_accepted_deviation(
        self, rule: str, deviation: str, rationale: str, approved_by: str
    ) -> None:
        self._data["accepted_deviations"].append({
            "id": f"DEV-{uuid.uuid4().hex[:8]}",
            "rule": rule,
            "deviation": deviation,
            "rationale": rationale,
            "approved_by": approved_by,
            "date": datetime.now(UTC).isoformat(),
        })
        self.save()

    @property
    def open_discrepancies(self) -> List[Dict]:
        return [d for d in self._data["discrepancies"] if d.get("status") == "OPEN"]

    @property
    def data(self) -> Dict[str, Any]:
        return dict(self._data)


# ---------------------------------------------------------------------------
# Project context
# ---------------------------------------------------------------------------

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
    # Knowledge base — living document shared by all agents
    knowledge_base: Optional[KnowledgeBase] = None

    def add_result(self, result: AgentResult) -> None:
        self.prior_results.append(result)

    def get_results_by_agent(self, agent_name: str) -> List[AgentResult]:
        all_results = list(self.prior_results)
        for iteration_results in self.iteration_history:
            all_results.extend(iteration_results)
        return [r for r in all_results if r.agent_name == agent_name]

    def get_results_by_squad(self, squad: Squad) -> List[AgentResult]:
        """Get all results from agents in a specific squad."""
        from agenticqa.agents.team.registry import AgentRegistry
        squad_agents = {
            name for name, cls in AgentRegistry.all_agents().items()
            if cls.squad == squad
        }
        return [r for r in self.prior_results if r.agent_name in squad_agents]

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
