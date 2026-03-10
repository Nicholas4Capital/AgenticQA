"""Tests for the 4Capital CMHC Analyst Guided Workflow."""

import pytest

from agenticqa.agents.team.analyst_workflow import (
    AnalystGuidedWorkflow,
    GuidedStep,
    PROMPT_TEMPLATES,
)


@pytest.fixture
def workflow(tmp_path):
    return AnalystGuidedWorkflow(db_path=str(tmp_path / "test.db"))


class TestTemplates:
    def test_list_all_templates(self):
        templates = AnalystGuidedWorkflow.list_templates()
        assert len(templates) >= 10

    def test_list_cmhc_templates(self):
        cmhc = AnalystGuidedWorkflow.list_templates(cmhc_only=True)
        assert len(cmhc) >= 4
        assert all(t["cmhc_relevant"] for t in cmhc)

    def test_list_by_category(self):
        calcs = AnalystGuidedWorkflow.list_templates(category="CMHC Calculations")
        assert len(calcs) >= 3

    def test_get_template(self):
        t = AnalystGuidedWorkflow.get_template("cmhc_mortgage_calc")
        assert t is not None
        assert t.name == "Mortgage Calculator Module"
        assert "property_type" in t.required_fields

    def test_get_unknown_template(self):
        assert AnalystGuidedWorkflow.get_template("nonexistent") is None

    def test_categories(self):
        cats = AnalystGuidedWorkflow.list_categories()
        assert "CMHC Calculations" in cats
        assert "Custom" in cats

    def test_template_render(self):
        t = AnalystGuidedWorkflow.get_template("cmhc_mortgage_calc")
        rendered = t.render({
            "property_type": "single-family",
            "price_range": "$300k-$600k",
        })
        assert "single-family" in rendered
        assert "$300k-$600k" in rendered


class TestGuidedSession:
    def test_create_session(self, workflow):
        session = workflow.create_session(analyst="nick", repo="/tmp/test")
        assert session.id.startswith("gs_")
        assert session.analyst == "nick"
        assert session.current_step == GuidedStep.SELECT_TEMPLATE
        assert len(session.messages) == 1  # Welcome message

    def test_select_template(self, workflow):
        session = workflow.create_session(analyst="nick", repo="/tmp/test")
        result = workflow.select_template(session.id, "cmhc_mortgage_calc")
        assert result["current_step"] == GuidedStep.FILL_FIELDS
        assert session.template_id == "cmhc_mortgage_calc"

    def test_select_invalid_template(self, workflow):
        session = workflow.create_session(analyst="nick", repo="/tmp/test")
        result = workflow.select_template(session.id, "doesnt_exist")
        assert "error" in result

    def test_fill_fields(self, workflow):
        session = workflow.create_session(analyst="nick", repo="/tmp/test")
        workflow.select_template(session.id, "cmhc_mortgage_calc")
        result = workflow.fill_fields(session.id, {
            "property_type": "condo",
            "price_range": "$400k-$800k",
        })
        assert result["current_step"] == GuidedStep.REVIEW_PLAN
        assert "condo" in session.rendered_prompt
        assert "$400k-$800k" in session.rendered_prompt

    def test_fill_fields_missing(self, workflow):
        session = workflow.create_session(analyst="nick", repo="/tmp/test")
        workflow.select_template(session.id, "cmhc_mortgage_calc")
        result = workflow.fill_fields(session.id, {"property_type": "condo"})
        # Still on FILL_FIELDS because price_range is missing
        assert result["current_step"] == GuidedStep.FILL_FIELDS

    def test_confirm_plan(self, workflow):
        session = workflow.create_session(analyst="nick", repo="/tmp/test")
        workflow.select_template(session.id, "cmhc_mortgage_calc")
        workflow.fill_fields(session.id, {
            "property_type": "condo",
            "price_range": "$400k",
        })
        result = workflow.confirm_plan(session.id, confirmed=True)
        assert result["current_step"] == GuidedStep.CONFIRM_AGENTS

    def test_confirm_plan_with_edits(self, workflow):
        session = workflow.create_session(analyst="nick", repo="/tmp/test")
        workflow.select_template(session.id, "cmhc_mortgage_calc")
        workflow.fill_fields(session.id, {
            "property_type": "condo",
            "price_range": "$400k",
        })
        result = workflow.confirm_plan(session.id, confirmed=False, edits="Updated plan text")
        assert session.rendered_prompt == "Updated plan text"
        assert result["current_step"] == GuidedStep.REVIEW_PLAN

    def test_execute_runs_agent_team(self, workflow, tmp_path):
        # Create a real project structure
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("def hello(): return 'hi'")

        session = workflow.create_session(analyst="nick", repo=str(tmp_path))
        workflow.select_template(session.id, "cmhc_insurance_premium")
        # Insurance premium has no required fields
        workflow.confirm_plan(session.id, confirmed=True)
        result = workflow.execute(session.id)

        assert result["current_step"] == GuidedStep.REVIEW_RESULTS
        assert session.validation_report is not None

    def test_list_sessions(self, workflow):
        workflow.create_session(analyst="nick", repo="/tmp/a")
        workflow.create_session(analyst="alex", repo="/tmp/b")
        workflow.create_session(analyst="nick", repo="/tmp/c")

        all_sessions = workflow.list_sessions()
        assert len(all_sessions) == 3

        nick_sessions = workflow.list_sessions(analyst="nick")
        assert len(nick_sessions) == 2

    def test_chat_message_routing(self, workflow):
        session = workflow.create_session(analyst="nick", repo="/tmp/test")

        # Chat at SELECT_TEMPLATE step with template name
        result = workflow.chat_message(session.id, "mortgage calculator")
        # Should have auto-selected the template
        assert session.template_id is not None

    def test_free_form_template(self, workflow):
        session = workflow.create_session(analyst="nick", repo="/tmp/test")
        workflow.select_template(session.id, "free_form")
        result = workflow.fill_fields(session.id, {
            "description": "Add a new report that shows monthly mortgage trends"
        })
        assert "monthly mortgage trends" in session.rendered_prompt


class TestSessionNotFound:
    def test_get_nonexistent(self, workflow):
        assert workflow.get_session("nonexistent") is None

    def test_select_template_bad_session(self, workflow):
        with pytest.raises(ValueError, match="Session not found"):
            workflow.select_template("bad_id", "cmhc_mortgage_calc")


class TestFullFlow:
    def test_end_to_end(self, workflow, tmp_path):
        """Full analyst flow: template → fields → confirm → execute → submit."""
        (tmp_path / "calc.py").write_text("def add(a, b): return a + b")

        session = workflow.create_session(analyst="nick", repo=str(tmp_path))
        assert session.current_step == GuidedStep.SELECT_TEMPLATE

        workflow.select_template(session.id, "cmhc_gds_tds")
        assert session.current_step == GuidedStep.FILL_FIELDS

        workflow.fill_fields(session.id, {
            "input_fields": "income, mortgage, taxes, heating",
            "output_format": "JSON with pass/fail",
        })
        assert session.current_step == GuidedStep.REVIEW_PLAN

        workflow.confirm_plan(session.id, confirmed=True)
        assert session.current_step == GuidedStep.CONFIRM_AGENTS
        assert "cmhc_specialist" in session.selected_agents

        workflow.execute(session.id)
        assert session.current_step == GuidedStep.REVIEW_RESULTS
        assert session.validation_report is not None

        result = workflow.submit_for_review(session.id, reviewer="senior_analyst")
        assert result["current_step"] == GuidedStep.COMPLETE
        assert result["analyst"] == "nick"
        assert result["reviewer"] == "senior_analyst"
