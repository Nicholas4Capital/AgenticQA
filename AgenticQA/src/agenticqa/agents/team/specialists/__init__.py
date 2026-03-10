"""
Specialist agents for the AgenticQA Agent Team.

Import all specialists to auto-register them with the AgentRegistry.
"""

# Quality & Code
from agenticqa.agents.team.specialists.code_review import CodeReviewAgent
from agenticqa.agents.team.specialists.accessibility import AccessibilityAgent
from agenticqa.agents.team.specialists.ux import UserExperienceAgent
from agenticqa.agents.team.specialists.functionality_tester import FunctionalityTesterAgent
from agenticqa.agents.team.specialists.implementation_confirmer import ImplementationConfirmerAgent
from agenticqa.agents.team.specialists.calculation_specialist import CalculationSpecialistAgent
from agenticqa.agents.team.specialists.brute_force_breaker import BruteForceCodeBreakerAgent
from agenticqa.agents.team.specialists.deterministic_ensurer import DeterministicEnsurerAgent
from agenticqa.agents.team.specialists.repeatability import RepeatabilityGuardrailAgent

# Infrastructure & Architecture
from agenticqa.agents.team.specialists.api_checker import APICheckerAgent
from agenticqa.agents.team.specialists.database_specialist import DatabaseSpecialistAgent
from agenticqa.agents.team.specialists.infrastructure import InfrastructureArchitectAgent

# Compliance & Guardrails
from agenticqa.agents.team.specialists.cmhc_specialist import CMHCSpecialistAgent
from agenticqa.agents.team.specialists.guardrail_implementer import GuardrailImplementerAgent
from agenticqa.agents.team.specialists.compliance_checker import ComplianceCheckerAgent

# AI & Intelligence
from agenticqa.agents.team.specialists.ai_implementer import AIImplementerReviewerAgent
from agenticqa.agents.team.specialists.continuous_learner import ContinuousLearningAgent
from agenticqa.agents.team.specialists.context_specialist import ContextSpecialistAgent

# Enterprise & Strategy
from agenticqa.agents.team.specialists.enterprise_value import EnterpriseValueCreationAgent
from agenticqa.agents.team.specialists.enterprise_direction import EnterpriseDirectionAgent
from agenticqa.agents.team.specialists.future_features import FutureFeaturesAgent

# Observability & Documentation
from agenticqa.agents.team.specialists.error_logger import ErrorLoggerAgent
from agenticqa.agents.team.specialists.documentation import DocumentationSpecialistAgent

# Connectivity & Tooling
from agenticqa.agents.team.specialists.api_mcp_finder import ComplementaryAPIMCPFinderAgent
from agenticqa.agents.team.specialists.plugin_utilizer import PluginUtilizingAgent
from agenticqa.agents.team.specialists.connection_seeker import ConnectionSeekingAgent

__all__ = [
    "CodeReviewAgent",
    "AccessibilityAgent",
    "UserExperienceAgent",
    "FunctionalityTesterAgent",
    "ImplementationConfirmerAgent",
    "CalculationSpecialistAgent",
    "BruteForceCodeBreakerAgent",
    "DeterministicEnsurerAgent",
    "RepeatabilityGuardrailAgent",
    "APICheckerAgent",
    "DatabaseSpecialistAgent",
    "InfrastructureArchitectAgent",
    "CMHCSpecialistAgent",
    "GuardrailImplementerAgent",
    "ComplianceCheckerAgent",
    "AIImplementerReviewerAgent",
    "ContinuousLearningAgent",
    "ContextSpecialistAgent",
    "EnterpriseValueCreationAgent",
    "EnterpriseDirectionAgent",
    "FutureFeaturesAgent",
    "ErrorLoggerAgent",
    "DocumentationSpecialistAgent",
    "ComplementaryAPIMCPFinderAgent",
    "PluginUtilizingAgent",
    "ConnectionSeekingAgent",
]
