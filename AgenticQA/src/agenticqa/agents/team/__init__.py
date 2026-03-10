"""
AgenticQA Agent Team — A comprehensive multi-agent system for building
production-grade, scalable, unbreakable, and AI-first software.

The team operates in a continuous improvement loop until delivered code
is launchable and near-production quality.
"""

from agenticqa.agents.team.base import BaseAgent, AgentResult, AgentSeverity
from agenticqa.agents.team.registry import AgentRegistry, AgentTeam
from agenticqa.agents.team.orchestrator import TeamOrchestrator, LoopConfig
from agenticqa.agents.team.runner import run_team, create_default_team

__all__ = [
    "BaseAgent",
    "AgentResult",
    "AgentSeverity",
    "AgentRegistry",
    "AgentTeam",
    "TeamOrchestrator",
    "LoopConfig",
    "run_team",
    "create_default_team",
]
