"""Agent registry and team composition."""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from agenticqa.agents.team.base import BaseAgent


class AgentRegistry:
    """
    Central registry for all available agents.

    Agents register themselves here. The orchestrator queries the registry
    to build teams, resolve dependencies, and manage execution order.
    """

    _agents: Dict[str, Type[BaseAgent]] = {}

    @classmethod
    def register(cls, agent_class: Type[BaseAgent]) -> Type[BaseAgent]:
        """Decorator to register an agent class."""
        cls._agents[agent_class.name] = agent_class
        return agent_class

    @classmethod
    def get(cls, name: str) -> Optional[Type[BaseAgent]]:
        return cls._agents.get(name)

    @classmethod
    def all_agents(cls) -> Dict[str, Type[BaseAgent]]:
        return dict(cls._agents)

    @classmethod
    def by_category(cls, category: str) -> List[Type[BaseAgent]]:
        return [a for a in cls._agents.values() if a.category == category]

    @classmethod
    def categories(cls) -> List[str]:
        return list({a.category for a in cls._agents.values()})

    @classmethod
    def clear(cls) -> None:
        cls._agents.clear()


class AgentTeam:
    """
    A configured team of agent instances ready for orchestration.

    Teams can be composed from the registry or built manually.
    Agents are ordered by priority for execution.
    """

    def __init__(self, name: str = "default"):
        self.name = name
        self._agents: List[BaseAgent] = []

    def add(self, agent: BaseAgent) -> "AgentTeam":
        self._agents.append(agent)
        return self

    def add_by_name(self, name: str) -> "AgentTeam":
        agent_cls = AgentRegistry.get(name)
        if agent_cls is None:
            raise ValueError(f"Unknown agent: {name!r}. Available: {list(AgentRegistry.all_agents().keys())}")
        self._agents.append(agent_cls())
        return self

    def add_category(self, category: str) -> "AgentTeam":
        for cls in AgentRegistry.by_category(category):
            self._agents.append(cls())
        return self

    def add_all(self) -> "AgentTeam":
        for cls in AgentRegistry.all_agents().values():
            self._agents.append(cls())
        return self

    @property
    def agents(self) -> List[BaseAgent]:
        return sorted(self._agents, key=lambda a: a.priority)

    @property
    def gate_agents(self) -> List[BaseAgent]:
        return [a for a in self.agents if a.is_gate]

    def __len__(self) -> int:
        return len(self._agents)

    def __repr__(self) -> str:
        names = [a.name for a in self.agents]
        return f"<AgentTeam(name={self.name!r}, agents={names})>"
