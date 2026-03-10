"""
Specialist agents for the AgenticQA Agent Team.

Import all specialists to auto-register them with the AgentRegistry.

22-Agent Pipeline (7 Squads):
  Squad 1 - Code Quality:       CodeReview, Accessibility, UX, Documentation, ErrorLogger
  Squad 2 - Testing/Resilience: FunctionalityTester, ImplementationConfirmer, Calculation, BruteForce
  Squad 3 - Architecture:       Database, DeterministicGuardrails, Infrastructure
  Squad 4 - AI/Integration:     AIImplementer, IntegrationScout, Context
  Squad 5 - Domain:             CMHC, Compliance, APIChecker
  Squad 6 - Strategy:           ContinuousLearner, EnterpriseStrategy, FutureFeatures
  Squad 7 - Governance:         Governance (FINAL GATE)
"""

# Squad 1 — Code Quality
from agenticqa.agents.team.specialists.code_review import CodeReviewAgent
from agenticqa.agents.team.specialists.accessibility import AccessibilityAgent
from agenticqa.agents.team.specialists.ux import UserExperienceAgent
from agenticqa.agents.team.specialists.documentation import DocumentationSpecialistAgent
from agenticqa.agents.team.specialists.error_logger import ErrorLoggerAgent

# Squad 2 — Testing & Resilience
from agenticqa.agents.team.specialists.functionality_tester import FunctionalityTesterAgent
from agenticqa.agents.team.specialists.implementation_confirmer import ImplementationConfirmerAgent
from agenticqa.agents.team.specialists.calculation_specialist import CalculationSpecialistAgent
from agenticqa.agents.team.specialists.brute_force_breaker import BruteForceCodeBreakerAgent

# Squad 3 — Architecture & Infrastructure
from agenticqa.agents.team.specialists.database_specialist import DatabaseSpecialistAgent
from agenticqa.agents.team.specialists.deterministic_guardrails import DeterministicGuardrailsAgent
from agenticqa.agents.team.specialists.infrastructure import InfrastructureArchitectAgent

# Squad 4 — AI & Integration
from agenticqa.agents.team.specialists.ai_implementer import AIImplementerReviewerAgent
from agenticqa.agents.team.specialists.integration_scout import IntegrationScoutAgent
from agenticqa.agents.team.specialists.context_specialist import ContextSpecialistAgent

# Squad 5 — Domain Expertise
from agenticqa.agents.team.specialists.cmhc_specialist import CMHCSpecialistAgent
from agenticqa.agents.team.specialists.compliance_checker import ComplianceCheckerAgent
from agenticqa.agents.team.specialists.api_checker import APICheckerAgent

# Squad 6 — Strategy & Vision
from agenticqa.agents.team.specialists.continuous_learner import ContinuousLearningAgent
from agenticqa.agents.team.specialists.enterprise_strategy import EnterpriseStrategyAgent
from agenticqa.agents.team.specialists.future_features import FutureFeaturesAgent

# Squad 7 — Governance (FINAL GATE)
from agenticqa.agents.team.specialists.governance import GovernanceAgent

__all__ = [
    # Squad 1
    "CodeReviewAgent",
    "AccessibilityAgent",
    "UserExperienceAgent",
    "DocumentationSpecialistAgent",
    "ErrorLoggerAgent",
    # Squad 2
    "FunctionalityTesterAgent",
    "ImplementationConfirmerAgent",
    "CalculationSpecialistAgent",
    "BruteForceCodeBreakerAgent",
    # Squad 3
    "DatabaseSpecialistAgent",
    "DeterministicGuardrailsAgent",
    "InfrastructureArchitectAgent",
    # Squad 4
    "AIImplementerReviewerAgent",
    "IntegrationScoutAgent",
    "ContextSpecialistAgent",
    # Squad 5
    "CMHCSpecialistAgent",
    "ComplianceCheckerAgent",
    "APICheckerAgent",
    # Squad 6
    "ContinuousLearningAgent",
    "EnterpriseStrategyAgent",
    "FutureFeaturesAgent",
    # Squad 7
    "GovernanceAgent",
]
