"""
4Capital CMHC Analyst Guided Workflow — Connects the CMHC knowledge chatbot
with the agent team and workflow system so analysts can:

1. Select from pre-built prompt templates (or describe freely)
2. Get guided through requirements gathering
3. Have the agent team validate the implementation plan
4. Create a branch, implement, validate with all 26 agents
5. Submit for review as a PR

All data stays local. No third-party data transmission.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt templates for common CMHC analyst requests
# ---------------------------------------------------------------------------

@dataclass
class PromptTemplate:
    """Pre-built prompt template for analyst selection."""
    id: str
    name: str
    category: str
    description: str
    prompt_template: str
    required_fields: List[str] = field(default_factory=list)
    optional_fields: List[str] = field(default_factory=list)
    agents: List[str] = field(default_factory=list)
    cmhc_relevant: bool = True

    def render(self, fields: Dict[str, str]) -> str:
        result = self.prompt_template
        for key, value in fields.items():
            result = result.replace(f"{{{{{key}}}}}", value)
        return result


# Pre-built templates for CMHC analysts
PROMPT_TEMPLATES: List[PromptTemplate] = [
    # --- Mortgage Calculation Tools ---
    PromptTemplate(
        id="cmhc_mortgage_calc",
        name="Mortgage Calculator Module",
        category="CMHC Calculations",
        description="Create or update a mortgage calculator with CMHC-compliant rules",
        prompt_template=(
            "Build a mortgage calculator module that:\n"
            "- Calculates monthly payments for a {{property_type}} property\n"
            "- Price range: {{price_range}}\n"
            "- Validates CMHC tiered down payment minimums (5%/10%/20%)\n"
            "- Enforces amortization limits (25y insured, 30y uninsured)\n"
            "- Applies stress test rate (higher of contract+2% or 5.25% floor)\n"
            "- Calculates insurance premiums by LTV tier\n"
            "- Additional requirements: {{additional_requirements}}"
        ),
        required_fields=["property_type", "price_range"],
        optional_fields=["additional_requirements"],
        agents=["cmhc_specialist", "calculation_specialist", "code_review", "functionality_tester"],
    ),
    PromptTemplate(
        id="cmhc_gds_tds",
        name="GDS/TDS Ratio Calculator",
        category="CMHC Calculations",
        description="Gross/Total Debt Service ratio calculator with CMHC limits",
        prompt_template=(
            "Build a GDS/TDS ratio calculator that:\n"
            "- Computes GDS = (mortgage + property tax + heating + 50% condo fee) / gross income\n"
            "- Computes TDS = GDS numerator + all other debts / gross income\n"
            "- Enforces CMHC limits: GDS <= 39%, TDS <= 44%\n"
            "- Accepts inputs: {{input_fields}}\n"
            "- Output format: {{output_format}}\n"
            "- {{additional_requirements}}"
        ),
        required_fields=["input_fields", "output_format"],
        optional_fields=["additional_requirements"],
        agents=["cmhc_specialist", "calculation_specialist", "deterministic_ensurer"],
    ),
    PromptTemplate(
        id="cmhc_stress_test",
        name="Stress Test Rate Engine",
        category="CMHC Calculations",
        description="Qualifying rate / stress test calculation engine",
        prompt_template=(
            "Build a stress test rate engine that:\n"
            "- Qualifying rate = max(contract_rate + 2%, 5.25% floor)\n"
            "- Supports variable, fixed, and hybrid rate types\n"
            "- Rate source: {{rate_source}}\n"
            "- Update frequency: {{update_frequency}}\n"
            "- Integration: {{integration_target}}\n"
            "- {{additional_requirements}}"
        ),
        required_fields=["rate_source"],
        optional_fields=["update_frequency", "integration_target", "additional_requirements"],
        agents=["cmhc_specialist", "calculation_specialist", "api_checker", "deterministic_ensurer"],
    ),
    PromptTemplate(
        id="cmhc_insurance_premium",
        name="Insurance Premium Calculator",
        category="CMHC Calculations",
        description="CMHC mortgage insurance premium calculator by LTV tier",
        prompt_template=(
            "Build a CMHC insurance premium calculator that:\n"
            "- Tier 1: 80.01-85% LTV → 2.80% premium\n"
            "- Tier 2: 85.01-90% LTV → 3.10% premium\n"
            "- Tier 3: 90.01-95% LTV → 4.00% premium\n"
            "- Rejects properties over $1M (not CMHC insurable)\n"
            "- Supports premium financing (added to mortgage)\n"
            "- {{additional_requirements}}"
        ),
        required_fields=[],
        optional_fields=["additional_requirements"],
        agents=["cmhc_specialist", "calculation_specialist", "functionality_tester"],
    ),

    # --- API & Integration ---
    PromptTemplate(
        id="new_api_endpoint",
        name="New API Endpoint",
        category="API Development",
        description="Add a new REST API endpoint with validation and tests",
        prompt_template=(
            "Create a new API endpoint:\n"
            "- Method: {{http_method}}\n"
            "- Path: {{api_path}}\n"
            "- Purpose: {{purpose}}\n"
            "- Input schema: {{input_schema}}\n"
            "- Output schema: {{output_schema}}\n"
            "- Auth required: {{auth_required}}\n"
            "- {{additional_requirements}}"
        ),
        required_fields=["http_method", "api_path", "purpose"],
        optional_fields=["input_schema", "output_schema", "auth_required", "additional_requirements"],
        agents=["api_checker", "code_review", "guardrail_implementer", "functionality_tester"],
        cmhc_relevant=False,
    ),
    PromptTemplate(
        id="data_pipeline",
        name="Data Pipeline Component",
        category="Data Engineering",
        description="Build a data ingestion/transformation pipeline",
        prompt_template=(
            "Build a data pipeline that:\n"
            "- Source: {{data_source}}\n"
            "- Transformation: {{transformation}}\n"
            "- Destination: {{destination}}\n"
            "- Schedule: {{schedule}}\n"
            "- Error handling: {{error_handling}}\n"
            "- {{additional_requirements}}"
        ),
        required_fields=["data_source", "transformation", "destination"],
        optional_fields=["schedule", "error_handling", "additional_requirements"],
        agents=["database_specialist", "error_logger", "code_review", "deterministic_ensurer"],
        cmhc_relevant=False,
    ),

    # --- System Enhancement ---
    PromptTemplate(
        id="add_feature",
        name="Add New Feature",
        category="Feature Development",
        description="Add a new feature to the existing system",
        prompt_template=(
            "Add a new feature to the system:\n"
            "- Feature name: {{feature_name}}\n"
            "- Description: {{description}}\n"
            "- Affected modules: {{affected_modules}}\n"
            "- User story: As a {{user_role}}, I want to {{action}} so that {{benefit}}\n"
            "- Acceptance criteria: {{acceptance_criteria}}\n"
            "- {{additional_requirements}}"
        ),
        required_fields=["feature_name", "description"],
        optional_fields=["affected_modules", "user_role", "action", "benefit", "acceptance_criteria", "additional_requirements"],
        agents=["implementation_confirmer", "code_review", "functionality_tester", "accessibility", "user_experience"],
        cmhc_relevant=False,
    ),
    PromptTemplate(
        id="fix_bug",
        name="Bug Fix",
        category="Bug Fixes",
        description="Fix a reported bug with regression tests",
        prompt_template=(
            "Fix the following bug:\n"
            "- Bug description: {{bug_description}}\n"
            "- Steps to reproduce: {{steps_to_reproduce}}\n"
            "- Expected behavior: {{expected_behavior}}\n"
            "- Actual behavior: {{actual_behavior}}\n"
            "- Severity: {{severity}}\n"
            "- {{additional_requirements}}"
        ),
        required_fields=["bug_description", "expected_behavior", "actual_behavior"],
        optional_fields=["steps_to_reproduce", "severity", "additional_requirements"],
        agents=["brute_force_breaker", "code_review", "functionality_tester", "deterministic_ensurer"],
        cmhc_relevant=False,
    ),
    PromptTemplate(
        id="compliance_update",
        name="Compliance Rule Update",
        category="Compliance",
        description="Update compliance rules or add new regulatory requirements",
        prompt_template=(
            "Update compliance rules:\n"
            "- Regulation: {{regulation}}\n"
            "- Change description: {{change_description}}\n"
            "- Effective date: {{effective_date}}\n"
            "- Impacted calculations: {{impacted_calculations}}\n"
            "- {{additional_requirements}}"
        ),
        required_fields=["regulation", "change_description"],
        optional_fields=["effective_date", "impacted_calculations", "additional_requirements"],
        agents=["cmhc_specialist", "compliance_checker", "calculation_specialist", "functionality_tester"],
    ),
    PromptTemplate(
        id="free_form",
        name="Custom Request",
        category="Custom",
        description="Describe your request in your own words — the system will guide you",
        prompt_template="{{description}}",
        required_fields=["description"],
        optional_fields=[],
        agents=[],  # All agents run for free-form
        cmhc_relevant=False,
    ),
]


# ---------------------------------------------------------------------------
# Guided workflow steps
# ---------------------------------------------------------------------------

class GuidedStep:
    """A single step in the guided creation workflow."""
    SELECT_TEMPLATE = "select_template"
    FILL_FIELDS = "fill_fields"
    REVIEW_PLAN = "review_plan"
    CONFIRM_AGENTS = "confirm_agents"
    EXECUTING = "executing"
    VALIDATION = "validation"
    REVIEW_RESULTS = "review_results"
    SUBMIT_PR = "submit_pr"
    COMPLETE = "complete"

    ALL_STEPS = [
        SELECT_TEMPLATE, FILL_FIELDS, REVIEW_PLAN,
        CONFIRM_AGENTS, EXECUTING, VALIDATION,
        REVIEW_RESULTS, SUBMIT_PR, COMPLETE,
    ]


@dataclass
class GuidedSession:
    """State for a guided analyst workflow session."""
    id: str
    analyst: str
    repo: str
    current_step: str = GuidedStep.SELECT_TEMPLATE
    template_id: Optional[str] = None
    field_values: Dict[str, str] = field(default_factory=dict)
    rendered_prompt: Optional[str] = None
    selected_agents: List[str] = field(default_factory=list)
    workflow_request_id: Optional[str] = None
    validation_report: Optional[Dict[str, Any]] = None
    branch_name: Optional[str] = None
    pr_url: Optional[str] = None
    messages: List[Dict[str, str]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Guided workflow controller
# ---------------------------------------------------------------------------

class AnalystGuidedWorkflow:
    """
    Orchestrates the guided workflow for 4Capital CMHC analysts.

    Flow:
    1. Analyst selects a prompt template (or free-form)
    2. System asks for required fields via guided questions
    3. System shows the rendered plan for review
    4. Analyst confirms which agents to run
    5. System creates a workflow request → branch → implements → validates
    6. Agent team runs continuous improvement loop
    7. Analyst reviews results and submits PR

    All data stays local in SQLite. No third-party transmission.
    """

    def __init__(self, workflow_store=None, db_path: Optional[str] = None):
        self._sessions: Dict[str, GuidedSession] = {}
        self._workflow_store = workflow_store

        if self._workflow_store is None:
            try:
                from agenticqa.workflow_requests import PromptWorkflowStore
                self._workflow_store = PromptWorkflowStore(db_path=db_path)
            except Exception:
                logger.warning("PromptWorkflowStore unavailable — workflow execution disabled")

    # -- Template browsing --

    @staticmethod
    def list_templates(category: Optional[str] = None, cmhc_only: bool = False) -> List[Dict[str, Any]]:
        """List available prompt templates for the analyst to choose from."""
        templates = PROMPT_TEMPLATES
        if category:
            templates = [t for t in templates if t.category == category]
        if cmhc_only:
            templates = [t for t in templates if t.cmhc_relevant]
        return [
            {
                "id": t.id,
                "name": t.name,
                "category": t.category,
                "description": t.description,
                "required_fields": t.required_fields,
                "optional_fields": t.optional_fields,
                "cmhc_relevant": t.cmhc_relevant,
            }
            for t in templates
        ]

    @staticmethod
    def get_template(template_id: str) -> Optional[PromptTemplate]:
        for t in PROMPT_TEMPLATES:
            if t.id == template_id:
                return t
        return None

    @staticmethod
    def list_categories() -> List[str]:
        return sorted({t.category for t in PROMPT_TEMPLATES})

    # -- Session management --

    def create_session(self, analyst: str, repo: str) -> GuidedSession:
        """Start a new guided session for an analyst."""
        session = GuidedSession(
            id=f"gs_{uuid.uuid4().hex[:12]}",
            analyst=analyst,
            repo=repo,
        )
        session.messages.append({
            "role": "assistant",
            "content": (
                "Welcome! I'll guide you through creating your request.\n\n"
                "Please select a template to get started, or choose 'Custom Request' "
                "to describe what you need in your own words.\n\n"
                f"Available categories: {', '.join(self.list_categories())}"
            ),
        })
        self._sessions[session.id] = session
        return session

    def get_session(self, session_id: str) -> Optional[GuidedSession]:
        return self._sessions.get(session_id)

    def list_sessions(self, analyst: Optional[str] = None) -> List[Dict[str, Any]]:
        sessions = list(self._sessions.values())
        if analyst:
            sessions = [s for s in sessions if s.analyst == analyst]
        return [s.to_dict() for s in sorted(sessions, key=lambda s: s.updated_at, reverse=True)]

    # -- Step progression --

    def select_template(self, session_id: str, template_id: str) -> Dict[str, Any]:
        """Step 1: Analyst selects a prompt template."""
        session = self._get_session(session_id)
        template = self.get_template(template_id)
        if not template:
            return {"error": f"Unknown template: {template_id}"}

        session.template_id = template_id
        session.selected_agents = list(template.agents) if template.agents else []
        session.current_step = GuidedStep.FILL_FIELDS

        # Build guidance message
        if template.required_fields:
            field_list = "\n".join(f"  - **{f}**: (required)" for f in template.required_fields)
            optional = "\n".join(f"  - **{f}**: (optional)" for f in template.optional_fields) if template.optional_fields else ""
            msg = f"Great choice: **{template.name}**\n\nPlease provide the following:\n{field_list}"
            if optional:
                msg += f"\n\nOptional fields:\n{optional}"
        else:
            session.rendered_prompt = template.render(session.field_values)
            import re as _re
            session.rendered_prompt = _re.sub(r"\{\{[^}]+\}\}", "", session.rendered_prompt).strip()
            msg = f"**{template.name}** selected. No additional fields required.\nReady to review the plan."
            session.current_step = GuidedStep.REVIEW_PLAN

        session.messages.append({"role": "assistant", "content": msg})
        session.updated_at = datetime.now(UTC).isoformat()

        return self._session_response(session)

    def fill_fields(self, session_id: str, fields: Dict[str, str]) -> Dict[str, Any]:
        """Step 2: Analyst provides field values."""
        session = self._get_session(session_id)
        template = self.get_template(session.template_id or "")
        if not template:
            return {"error": "No template selected"}

        session.field_values.update(fields)

        # Check for missing required fields
        missing = [f for f in template.required_fields if f not in session.field_values or not session.field_values[f]]
        if missing:
            msg = f"Still need: {', '.join(missing)}"
            session.messages.append({"role": "assistant", "content": msg})
            return self._session_response(session)

        # Render the prompt
        session.rendered_prompt = template.render(session.field_values)
        # Clean up unfilled optional placeholders
        import re
        session.rendered_prompt = re.sub(r"\{\{[^}]+\}\}", "", session.rendered_prompt).strip()
        session.rendered_prompt = re.sub(r"\n- \s*$", "", session.rendered_prompt, flags=re.MULTILINE)

        session.current_step = GuidedStep.REVIEW_PLAN
        session.messages.append({
            "role": "assistant",
            "content": (
                "Here's your request plan:\n\n"
                f"```\n{session.rendered_prompt}\n```\n\n"
                "Does this look correct? Reply 'confirm' to proceed or provide changes."
            ),
        })
        session.updated_at = datetime.now(UTC).isoformat()

        return self._session_response(session)

    def confirm_plan(self, session_id: str, confirmed: bool = True, edits: Optional[str] = None) -> Dict[str, Any]:
        """Step 3: Analyst confirms or edits the plan."""
        session = self._get_session(session_id)

        if not confirmed and edits:
            session.rendered_prompt = edits
            session.messages.append({"role": "user", "content": f"Updated plan: {edits}"})
            session.messages.append({"role": "assistant", "content": "Plan updated. Confirm to proceed."})
            return self._session_response(session)

        session.current_step = GuidedStep.CONFIRM_AGENTS

        # Show which agents will validate
        template = self.get_template(session.template_id or "")
        if template and template.agents:
            agent_list = "\n".join(f"  - {a}" for a in session.selected_agents)
            msg = f"The following agents will validate your implementation:\n{agent_list}\n\nConfirm to start execution."
        else:
            msg = "All 26 agents will validate your implementation.\nConfirm to start execution."
            # Use all agents for free-form
            from agenticqa.agents.team.registry import AgentRegistry
            import agenticqa.agents.team.specialists  # noqa: F401
            session.selected_agents = list(AgentRegistry.all_agents().keys())

        session.messages.append({"role": "assistant", "content": msg})
        session.updated_at = datetime.now(UTC).isoformat()

        return self._session_response(session)

    def execute(self, session_id: str) -> Dict[str, Any]:
        """Step 4-6: Create workflow request, execute, and validate with agent team."""
        session = self._get_session(session_id)
        session.current_step = GuidedStep.EXECUTING

        if not session.rendered_prompt:
            return {"error": "No plan to execute"}

        # Create the workflow request
        if self._workflow_store:
            metadata = {
                "guided_session_id": session.id,
                "analyst": session.analyst,
                "template_id": session.template_id,
                "selected_agents": session.selected_agents,
                "source": "4capital_analyst_guided",
            }

            request = self._workflow_store.create_and_queue_request(
                prompt=session.rendered_prompt,
                repo=session.repo,
                requester=session.analyst,
                metadata=metadata,
            )
            session.workflow_request_id = request["id"]
            session.branch_name = request.get("branch_name")

            session.messages.append({
                "role": "assistant",
                "content": (
                    f"Workflow request created: `{request['id']}`\n"
                    f"Status: {request['status']}\n"
                    "Implementation is being executed..."
                ),
            })
        else:
            session.messages.append({
                "role": "assistant",
                "content": "Workflow store unavailable — running agent team validation only.",
            })

        # Run the agent team validation
        session.current_step = GuidedStep.VALIDATION
        try:
            from agenticqa.agents.team.runner import run_team
            report = run_team(
                project_root=session.repo,
                max_iterations=5,
                agent_names=session.selected_agents if session.selected_agents else None,
            )
            session.validation_report = report.summary()
            session.current_step = GuidedStep.REVIEW_RESULTS

            status = "LAUNCHABLE" if report.is_launchable else "NEEDS WORK"
            session.messages.append({
                "role": "assistant",
                "content": (
                    f"**Agent Team Validation: {status}**\n\n"
                    f"- Iterations: {report.total_iterations}\n"
                    f"- Findings: {report.final_findings_count} ({report.final_blocking_count} blocking)\n"
                    f"- Auto-fixes applied: {report.total_auto_fixes}\n"
                    f"- Learnings captured: {len(report.all_learnings)}\n"
                    f"- Duration: {report.total_duration_ms:.0f}ms\n\n"
                    + ("Ready to submit for PR review!" if report.is_launchable
                       else "Some issues remain. Review findings and decide whether to submit.")
                ),
            })
        except Exception as e:
            session.validation_report = {"error": str(e)}
            session.current_step = GuidedStep.REVIEW_RESULTS
            session.messages.append({
                "role": "assistant",
                "content": f"Validation encountered an error: {e}\nYou can still submit for manual review.",
            })

        session.updated_at = datetime.now(UTC).isoformat()
        return self._session_response(session)

    def submit_for_review(self, session_id: str, reviewer: Optional[str] = None) -> Dict[str, Any]:
        """Step 7: Submit the branch as a PR for review."""
        session = self._get_session(session_id)
        session.current_step = GuidedStep.SUBMIT_PR

        result = {
            "session_id": session.id,
            "workflow_request_id": session.workflow_request_id,
            "branch_name": session.branch_name,
            "validation_report": session.validation_report,
            "template_used": session.template_id,
            "analyst": session.analyst,
            "reviewer": reviewer,
            "ready_for_pr": True,
        }

        # If workflow store has the request, get its PR URL
        if self._workflow_store and session.workflow_request_id:
            req = self._workflow_store.get_request(session.workflow_request_id)
            if req:
                result["branch_name"] = req.get("branch_name")
                result["pr_url"] = req.get("pr_url")
                session.pr_url = req.get("pr_url")
                session.branch_name = req.get("branch_name")

        session.current_step = GuidedStep.COMPLETE
        session.messages.append({
            "role": "assistant",
            "content": (
                "Submitted for review!\n\n"
                f"- Branch: `{session.branch_name or 'pending'}`\n"
                f"- PR: {session.pr_url or 'will be created by workflow worker'}\n"
                f"- Reviewer: {reviewer or 'team'}\n\n"
                "Your analyst workflow is complete. The agent team learnings "
                "have been saved for future improvements."
            ),
        })
        session.updated_at = datetime.now(UTC).isoformat()

        return self._session_response(session, extra=result)

    def chat_message(self, session_id: str, message: str) -> Dict[str, Any]:
        """Handle a free-form chat message from the analyst at any step."""
        session = self._get_session(session_id)
        session.messages.append({"role": "user", "content": message})

        # Route based on current step
        step = session.current_step
        response = ""

        if step == GuidedStep.SELECT_TEMPLATE:
            # Try to match a template
            lower = message.lower()
            for t in PROMPT_TEMPLATES:
                if t.id in lower or t.name.lower() in lower or any(kw in lower for kw in t.name.lower().split()):
                    return self.select_template(session_id, t.id)
            response = (
                "I didn't recognize that template. Available templates:\n"
                + "\n".join(f"  - `{t.id}`: {t.name}" for t in PROMPT_TEMPLATES)
            )

        elif step == GuidedStep.FILL_FIELDS:
            # Try to parse field=value pairs from the message
            import re
            fields = {}
            for match in re.finditer(r"(\w+)\s*[:=]\s*(.+?)(?:\n|$)", message):
                fields[match.group(1).strip()] = match.group(2).strip()
            if fields:
                return self.fill_fields(session_id, fields)
            response = "Please provide field values in the format: `field_name: value`"

        elif step == GuidedStep.REVIEW_PLAN:
            if message.lower() in ("confirm", "yes", "ok", "approve", "looks good", "lgtm"):
                return self.confirm_plan(session_id, confirmed=True)
            return self.confirm_plan(session_id, confirmed=False, edits=message)

        elif step == GuidedStep.CONFIRM_AGENTS:
            if message.lower() in ("confirm", "yes", "ok", "go", "execute", "run"):
                return self.execute(session_id)
            response = "Reply 'confirm' to start execution, or specify changes."

        elif step == GuidedStep.REVIEW_RESULTS:
            if message.lower() in ("submit", "pr", "review", "send"):
                return self.submit_for_review(session_id)
            response = "Reply 'submit' to create a PR, or ask questions about the results."

        else:
            response = f"Current step: {step}. How can I help?"

        session.messages.append({"role": "assistant", "content": response})
        session.updated_at = datetime.now(UTC).isoformat()
        return self._session_response(session)

    # -- Internal helpers --

    def _get_session(self, session_id: str) -> GuidedSession:
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")
        return session

    def _session_response(self, session: GuidedSession, extra: Optional[Dict] = None) -> Dict[str, Any]:
        result = {
            "session": session.to_dict(),
            "current_step": session.current_step,
            "next_steps": self._next_steps(session),
        }
        if extra:
            result.update(extra)
        return result

    @staticmethod
    def _next_steps(session: GuidedSession) -> List[str]:
        step_guidance = {
            GuidedStep.SELECT_TEMPLATE: ["Browse templates with list_templates()", "Select one with select_template()"],
            GuidedStep.FILL_FIELDS: ["Provide required field values with fill_fields()"],
            GuidedStep.REVIEW_PLAN: ["Confirm the plan or provide edits"],
            GuidedStep.CONFIRM_AGENTS: ["Confirm to start agent execution"],
            GuidedStep.EXECUTING: ["Wait for execution to complete"],
            GuidedStep.VALIDATION: ["Agent team is running validation..."],
            GuidedStep.REVIEW_RESULTS: ["Review findings", "Submit for PR review"],
            GuidedStep.SUBMIT_PR: ["PR is being created..."],
            GuidedStep.COMPLETE: ["Workflow complete!"],
        }
        return step_guidance.get(session.current_step, [])
