"""Tests for the Agent Team framework."""

import os
import tempfile
import textwrap

import pytest

from agenticqa.agents.team.base import (
    AgentResult,
    AgentSeverity,
    BaseAgent,
    Finding,
    ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry, AgentTeam
from agenticqa.agents.team.orchestrator import LoopConfig, TeamOrchestrator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_registry():
    """Save and restore the registry around each test."""
    original = dict(AgentRegistry._agents)
    yield
    AgentRegistry._agents = original


@pytest.fixture
def tmp_project(tmp_path):
    """Create a minimal project structure for testing."""
    src = tmp_path / "src"
    src.mkdir()

    (src / "app.py").write_text(textwrap.dedent("""\
        import os

        def hello(name):
            return f"Hello, {name}!"

        def add(a, b):
            return a + b
    """))

    (src / "utils.py").write_text(textwrap.dedent("""\
        def safe_divide(a, b):
            if b == 0:
                return 0
            return a / b
    """))

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()

    (tests_dir / "test_app.py").write_text(textwrap.dedent("""\
        from src.app import hello, add

        def test_hello():
            assert hello("World") == "Hello, World!"

        def test_add():
            assert add(1, 2) == 3
    """))

    (tmp_path / "package.json").write_text('{"name": "test", "version": "1.0.0"}')
    (tmp_path / "README.md").write_text("# Test Project")

    return tmp_path


def make_context(tmp_project) -> ProjectContext:
    """Build a ProjectContext from the tmp_project fixture."""
    source = [str(p) for p in tmp_project.rglob("*.py") if "test" not in p.name]
    tests = [str(p) for p in tmp_project.rglob("test_*.py")]
    configs = [str(p) for p in tmp_project.rglob("*.json")]
    return ProjectContext(
        project_root=str(tmp_project),
        source_files=source,
        test_files=tests,
        config_files=configs,
    )


# ---------------------------------------------------------------------------
# Base framework tests
# ---------------------------------------------------------------------------

class TestBaseAgent:
    def test_finding_severity(self):
        f = Finding(message="test", severity=AgentSeverity.CRITICAL)
        assert f.is_blocking

    def test_finding_not_blocking(self):
        f = Finding(message="test", severity=AgentSeverity.LOW)
        assert not f.is_blocking

    def test_agent_result_summary(self):
        r = AgentResult(
            agent_name="test_agent",
            passed=True,
            findings=[Finding(message="x", severity=AgentSeverity.LOW)],
        )
        summary = r.summary()
        assert summary["agent"] == "test_agent"
        assert summary["passed"] is True
        assert summary["total_findings"] == 1

    def test_project_context_launchable(self):
        ctx = ProjectContext(project_root="/tmp")
        assert ctx.is_launchable

        ctx.add_result(AgentResult(
            agent_name="a",
            passed=False,
            findings=[Finding(message="blocker", severity=AgentSeverity.CRITICAL)],
        ))
        assert not ctx.is_launchable


class TestRegistry:
    def test_register_and_get(self):
        @AgentRegistry.register
        class DummyAgent(BaseAgent):
            name = "dummy"
            description = "A dummy agent"
            category = "test"

            def analyze(self, context):
                return AgentResult(agent_name=self.name, passed=True)

        assert AgentRegistry.get("dummy") is DummyAgent
        assert "test" in AgentRegistry.categories()

    def test_agent_team_add_by_name(self):
        @AgentRegistry.register
        class DummyAgent2(BaseAgent):
            name = "dummy2"
            description = "Another dummy"
            category = "test"
            priority = 5

            def analyze(self, context):
                return AgentResult(agent_name=self.name, passed=True)

        team = AgentTeam("test")
        team.add_by_name("dummy2")
        assert len(team) == 1
        assert team.agents[0].name == "dummy2"

    def test_unknown_agent_raises(self):
        team = AgentTeam()
        with pytest.raises(ValueError, match="Unknown agent"):
            team.add_by_name("nonexistent_agent_xyz")


class TestOrchestrator:
    def test_single_iteration_pass(self):
        @AgentRegistry.register
        class PassAgent(BaseAgent):
            name = "pass_agent"
            description = "Always passes"
            category = "test"

            def analyze(self, context):
                return AgentResult(agent_name=self.name, passed=True)

        team = AgentTeam()
        team.add_by_name("pass_agent")

        ctx = ProjectContext(project_root="/tmp")
        config = LoopConfig(max_iterations=1)
        orch = TeamOrchestrator(team, config)
        report = orch.run(ctx)

        assert report.is_launchable
        assert report.total_iterations == 1
        assert report.stop_reason == "launchable"

    def test_stops_on_no_improvement(self):
        @AgentRegistry.register
        class FailAgent(BaseAgent):
            name = "fail_agent"
            description = "Always finds issues"
            category = "test"
            is_gate = True

            def analyze(self, context):
                return AgentResult(
                    agent_name=self.name,
                    passed=False,
                    findings=[Finding(message="issue", severity=AgentSeverity.CRITICAL)],
                )

        team = AgentTeam()
        team.add_by_name("fail_agent")

        ctx = ProjectContext(project_root="/tmp")
        config = LoopConfig(max_iterations=5, stop_on_no_improvement=True)
        orch = TeamOrchestrator(team, config)
        report = orch.run(ctx)

        assert not report.is_launchable
        assert report.stop_reason == "no_improvement"
        assert report.total_iterations == 2  # Runs twice to detect no improvement

    def test_max_iterations(self):
        call_count = 0

        @AgentRegistry.register
        class CountAgent(BaseAgent):
            name = "count_agent"
            description = "Counts calls"
            category = "test"

            def analyze(self, context):
                nonlocal call_count
                call_count += 1
                return AgentResult(
                    agent_name=self.name,
                    passed=True,
                    findings=[Finding(message=f"issue-{call_count}", severity=AgentSeverity.LOW)],
                )

        team = AgentTeam()
        team.add_by_name("count_agent")

        ctx = ProjectContext(project_root="/tmp")
        config = LoopConfig(max_iterations=3, stop_on_launchable=False, stop_on_no_improvement=False)
        orch = TeamOrchestrator(team, config)
        report = orch.run(ctx)

        assert report.stop_reason == "max_iterations"
        assert report.total_iterations == 3


# ---------------------------------------------------------------------------
# Specialist agent smoke tests
# ---------------------------------------------------------------------------

class TestSpecialists:
    def test_code_review_agent(self, tmp_project):
        from agenticqa.agents.team.specialists.code_review import CodeReviewAgent
        agent = CodeReviewAgent()
        ctx = make_context(tmp_project)
        result = agent.run(ctx)
        assert result.agent_name == "code_review"
        assert isinstance(result.passed, bool)

    def test_accessibility_agent(self, tmp_project):
        # Add an HTML file
        html = tmp_project / "index.html"
        html.write_text('<html><body><img src="test.png"></body></html>')

        from agenticqa.agents.team.specialists.accessibility import AccessibilityAgent
        agent = AccessibilityAgent()
        ctx = make_context(tmp_project)
        ctx.source_files.append(str(html))
        result = agent.run(ctx)
        assert result.agent_name == "accessibility"
        # Should find missing alt attribute
        assert any("alt" in f.message.lower() for f in result.findings)

    def test_functionality_tester(self, tmp_project):
        from agenticqa.agents.team.specialists.functionality_tester import FunctionalityTesterAgent
        agent = FunctionalityTesterAgent()
        ctx = make_context(tmp_project)
        result = agent.run(ctx)
        assert result.agent_name == "functionality_tester"
        assert "total_tests" in result.metrics

    def test_cmhc_specialist_no_mortgage(self, tmp_project):
        from agenticqa.agents.team.specialists.cmhc_specialist import CMHCSpecialistAgent
        agent = CMHCSpecialistAgent()
        ctx = make_context(tmp_project)
        result = agent.run(ctx)
        # No mortgage files, should pass cleanly
        assert result.passed
        assert result.metrics["mortgage_files"] == 0

    def test_cmhc_specialist_with_mortgage(self, tmp_project):
        mortgage = tmp_project / "mortgage.py"
        mortgage.write_text(textwrap.dedent("""\
            def calculate_mortgage(price, down_payment, amortization=30):
                loan = price - down_payment
                return loan
        """))

        from agenticqa.agents.team.specialists.cmhc_specialist import CMHCSpecialistAgent
        agent = CMHCSpecialistAgent()
        ctx = make_context(tmp_project)
        ctx.source_files.append(str(mortgage))
        result = agent.run(ctx)
        assert result.metrics["mortgage_files"] >= 1
        assert len(result.findings) > 0  # Should find compliance issues

    def test_database_specialist(self, tmp_project):
        db_file = tmp_project / "db.py"
        db_file.write_text(textwrap.dedent("""\
            import sqlite3

            def get_user(user_id):
                conn = sqlite3.connect("test.db")
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
                return cursor.fetchone()
        """))

        from agenticqa.agents.team.specialists.database_specialist import DatabaseSpecialistAgent
        agent = DatabaseSpecialistAgent()
        ctx = make_context(tmp_project)
        ctx.source_files.append(str(db_file))
        result = agent.run(ctx)
        # Should find SQL injection
        assert any("sql" in f.message.lower() or "injection" in f.message.lower()
                    for f in result.findings)

    def test_brute_force_breaker(self, tmp_project):
        buggy = tmp_project / "buggy.py"
        buggy.write_text(textwrap.dedent("""\
            def process(data):
                result = data["key"]
                items = data["items"]
                return items[5]
        """))

        from agenticqa.agents.team.specialists.brute_force_breaker import BruteForceCodeBreakerAgent
        agent = BruteForceCodeBreakerAgent()
        ctx = make_context(tmp_project)
        ctx.source_files.append(str(buggy))
        result = agent.run(ctx)
        assert len(result.findings) > 0

    def test_deterministic_ensurer(self, tmp_project):
        nondeterministic = tmp_project / "rng.py"
        nondeterministic.write_text(textwrap.dedent("""\
            import random

            def roll_dice():
                return random.randint(1, 6)
        """))

        from agenticqa.agents.team.specialists.deterministic_ensurer import DeterministicEnsurerAgent
        agent = DeterministicEnsurerAgent()
        ctx = make_context(tmp_project)
        ctx.source_files.append(str(nondeterministic))
        result = agent.run(ctx)
        assert any("random" in f.message.lower() or "seed" in f.message.lower()
                    for f in result.findings)

    def test_governance_agent(self, tmp_project):
        """Test the governance agent (Squad 7 FINAL GATE)."""
        from agenticqa.agents.team.specialists.governance import GovernanceAgent
        agent = GovernanceAgent()
        ctx = make_context(tmp_project)
        result = agent.run(ctx)
        assert result.agent_name == "governance"
        assert agent.squad.value == 7  # Squad 7 = GOVERNANCE
        assert agent.is_gate is True

    def test_governance_detects_sin(self, tmp_project):
        """Governance should flag unmasked SIN numbers."""
        sin_file = tmp_project / "client.py"
        sin_file.write_text(
            'client_sin = "123-456-789"\n'
            'print(f"Processing SIN: {client_sin}")\n'
        )
        from agenticqa.agents.team.specialists.governance import GovernanceAgent
        agent = GovernanceAgent()
        ctx = make_context(tmp_project)
        ctx.source_files.append(str(sin_file))
        result = agent.run(ctx)
        assert result.metrics["sin_exposures"] > 0

    def test_guardrail_implementer(self, tmp_project):
        from agenticqa.agents.team.specialists.guardrail_implementer import GuardrailImplementerAgent
        agent = GuardrailImplementerAgent()
        ctx = make_context(tmp_project)
        result = agent.run(ctx)
        assert result.agent_name == "guardrail_implementer"
        # Small project will be missing many guardrails
        assert len(result.findings) > 0

    def test_error_logger(self, tmp_project):
        from agenticqa.agents.team.specialists.error_logger import ErrorLoggerAgent
        agent = ErrorLoggerAgent()
        ctx = make_context(tmp_project)
        result = agent.run(ctx)
        assert result.agent_name == "error_logger"

    def test_continuous_learner(self, tmp_project):
        from agenticqa.agents.team.specialists.continuous_learner import ContinuousLearningAgent
        agent = ContinuousLearningAgent()
        ctx = make_context(tmp_project)
        # Add some prior results
        ctx.prior_results.append(AgentResult(
            agent_name="code_review",
            passed=True,
            findings=[Finding(message="issue", severity=AgentSeverity.LOW)],
        ))
        result = agent.run(ctx)
        assert result.passed  # Learner never blocks

    def test_all_agents_registered(self):
        """Verify all 26 agents are registered."""
        import agenticqa.agents.team.specialists  # noqa: F401
        agents = AgentRegistry.all_agents()
        expected = [
            "code_review", "accessibility", "user_experience",
            "functionality_tester", "implementation_confirmer",
            "calculation_specialist", "brute_force_breaker",
            "deterministic_ensurer", "repeatability_guardrail",
            "api_checker", "database_specialist", "infrastructure_architect",
            "cmhc_specialist", "guardrail_implementer", "compliance_checker",
            "ai_implementer", "continuous_learner", "context_specialist",
            "enterprise_value", "enterprise_direction", "future_features",
            "error_logger", "documentation", "api_mcp_finder",
            "plugin_utilizer", "connection_seeker",
            "governance",
        ]
        for name in expected:
            assert name in agents, f"Agent '{name}' not registered"
        assert len(agents) >= 27


# ---------------------------------------------------------------------------
# Integration test
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_full_team_run(self, tmp_project):
        """Run the full team against the tmp project."""
        from agenticqa.agents.team.runner import run_team

        report = run_team(
            project_root=str(tmp_project),
            max_iterations=2,
        )

        assert report.total_iterations >= 1
        assert report.total_duration_ms > 0
        assert report.stop_reason in ("launchable", "no_improvement", "max_iterations")
        assert len(report.iteration_summaries) >= 1

    def test_selective_agents(self, tmp_project):
        """Run only specific agents."""
        from agenticqa.agents.team.runner import run_team

        report = run_team(
            project_root=str(tmp_project),
            max_iterations=1,
            agent_names=["code_review", "functionality_tester"],
        )

        assert report.total_iterations == 1
        agent_names = set(report.agent_performance.keys())
        assert "code_review" in agent_names
        assert "functionality_tester" in agent_names
