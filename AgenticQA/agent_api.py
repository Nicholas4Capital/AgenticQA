"""FastAPI integration for agent orchestration and data store access"""

import asyncio
import signal
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from datetime import UTC, datetime
from pathlib import Path
import os

try:
    from src.agenticqa.security.path_sanitizer import sanitize_repo_path
except ImportError:
    from agenticqa.security.path_sanitizer import sanitize_repo_path

try:
    from src.agenticqa.security.api_middleware import (
        BearerTokenMiddleware,
        OriginValidationMiddleware,
        ResponseScanMiddleware,
        RateLimitMiddleware,
        InputSizeMiddleware,
        PathSanitizationMiddleware,
        SecurityHeadersMiddleware,
    )
except ImportError:
    from agenticqa.security.api_middleware import (
        BearerTokenMiddleware,
        OriginValidationMiddleware,
        ResponseScanMiddleware,
        RateLimitMiddleware,
        InputSizeMiddleware,
        PathSanitizationMiddleware,
        SecurityHeadersMiddleware,
    )

try:
    from src.agenticqa.errors import install_error_handlers
except ImportError:
    from agenticqa.errors import install_error_handlers

from src.agents import AgentOrchestrator
from src.data_store import SecureDataPipeline
try:
    from src.agenticqa.workflow_requests import PromptWorkflowStore
    from src.agenticqa.workflow_worker import WorkflowExecutionWorker
    from src.agenticqa.worker_pool import WorkerPool
    from src.agenticqa.observability import ObservabilityStore
    from src.agenticqa.reliability_evidence import build_evidence_summary, check_tcp, read_latest_jsonl
    from src.agenticqa.repo_profile import detect_repo_profile
    from src.agenticqa.rag.config import RAGConfig
    from src.agenticqa.portability_scorecard import (
        build_portability_roi_report,
        build_portability_scorecard,
        load_baseline,
        save_baseline,
    )
    from src.agenticqa.audit_report import build_audit_report
    from src.agenticqa.ingestion.event_schema import normalize_event as _normalize_ingest_event
    from src.agenticqa.constitutional_gate import (
        check_action as _constitutional_check, get_constitution,
        check_file_scope as _check_file_scope, get_agent_scopes,
    )
    from src.agenticqa.factory import AgentFactory, SUPPORTED_FRAMEWORKS
    from src.agenticqa.factory import SandboxedAgentAdapter
    from src.agenticqa.factory.spec_extractor import NaturalLanguageSpecExtractor, AgentSpec
    from src.agents import RedTeamAgent
except Exception:
    from agenticqa.workflow_requests import PromptWorkflowStore
    from agenticqa.workflow_worker import WorkflowExecutionWorker
    from agenticqa.worker_pool import WorkerPool
    from agenticqa.observability import ObservabilityStore
    from agenticqa.reliability_evidence import build_evidence_summary, check_tcp, read_latest_jsonl
    from agenticqa.repo_profile import detect_repo_profile
    from agenticqa.rag.config import RAGConfig
    from agenticqa.portability_scorecard import (
        build_portability_roi_report,
        build_portability_scorecard,
        load_baseline,
        save_baseline,
    )
    from agenticqa.audit_report import build_audit_report
    from agenticqa.ingestion.event_schema import normalize_event as _normalize_ingest_event
    from agenticqa.constitutional_gate import (
        check_action as _constitutional_check, get_constitution,
        check_file_scope as _check_file_scope, get_agent_scopes,
    )
    from agenticqa.factory import AgentFactory, SUPPORTED_FRAMEWORKS
    from agenticqa.factory import SandboxedAgentAdapter
    from agenticqa.factory.spec_extractor import NaturalLanguageSpecExtractor, AgentSpec
    from agents import RedTeamAgent


# ── Path sanitization helper ────────────────────────────────────────────────
def _safe_repo_path(repo_path: str) -> str:
    """Validate repo_path against allowed roots; raise HTTPException on escape."""
    if os.getenv("AGENTICQA_PATH_SANITIZE_DISABLE") == "1":
        return repo_path
    try:
        return sanitize_repo_path(repo_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Graceful shutdown ───────────────────────────────────────────────────────
_shutdown_event = asyncio.Event()


@asynccontextmanager
async def _lifespan(application: FastAPI):
    """Application lifespan — sets up signal handlers for graceful shutdown."""
    loop = asyncio.get_running_loop()

    def _signal_handler(sig: signal.Signals) -> None:
        print(f"\n[AgenticQA] Received {sig.name}, shutting down gracefully…", file=sys.stderr)
        _shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler, sig)
        except NotImplementedError:
            pass  # Windows doesn't support add_signal_handler

    # Reclaim any stale requests from previous crashes
    reclaimed = workflow_store.reclaim_stale_requests()
    if reclaimed:
        print(f"[AgenticQA] Reclaimed {len(reclaimed)} stale requests: {reclaimed}", file=sys.stderr)

    # Start background worker pool (disabled via AGENTICQA_WORKER_ENABLED=0)
    pool_enabled = os.getenv("AGENTICQA_WORKER_ENABLED", "1") != "0"
    if pool_enabled:
        worker_pool.start()
        print(f"[AgenticQA] Worker pool started (max_workers={worker_pool.max_workers})", file=sys.stderr)
    else:
        print("[AgenticQA] Worker pool disabled via AGENTICQA_WORKER_ENABLED=0", file=sys.stderr)

    print("[AgenticQA] API started — press Ctrl+C for graceful shutdown", file=sys.stderr)
    yield

    if pool_enabled:
        worker_pool.stop()
    print("[AgenticQA] Shutdown complete.", file=sys.stderr)


app = FastAPI(
    title="AgenticQA API",
    version="1.0.0",
    description=(
        "Multi-agent CI/CD quality platform. Orchestrates 8 specialized agents "
        "(QA, Performance, Compliance, DevOps, SRE, SDET, Fullstack, RedTeam) "
        "across security scanning, test coverage analysis, release gating, "
        "red-team adversarial testing, and adaptive learning.\n\n"
        "**Authentication**: Bearer token via `Authorization: Bearer <token>` header. "
        "Health and docs endpoints are unauthenticated.\n\n"
        "**Source**: [github.com/nhomyk/AgenticQA](https://github.com/nhomyk/AgenticQA)"
    ),
    contact={"name": "Nick Homyk", "url": "https://github.com/nhomyk/AgenticQA"},
    license_info={"name": "MIT"},
    openapi_tags=[
        {"name": "Health", "description": "System health probes and dataflow integrity checks."},
        {"name": "System", "description": "Constitutional AI guardrails, agent scopes, and readiness."},
        {"name": "Agents", "description": "Execute agents directly and retrieve execution history."},
        {"name": "Agent Factory", "description": "Natural language to governed agent scaffolding."},
        {"name": "Workflows", "description": "Prompt workflow lifecycle: submit, approve, queue, stream, metrics."},
        {"name": "Chat", "description": "Session-based conversational interface to AgenticQA."},
        {"name": "Pipeline", "description": "Full ADLC pipeline: scan, test, feature, demo, and UI test runs."},
        {"name": "Observability", "description": "Execution traces, quality events, agent complexity, and insights."},
        {"name": "Red Team", "description": "Adversarial scanning, prompt injection detection, and agent trust graphs."},
        {"name": "Security", "description": "CVE reachability, MCP scan, OWASP, secrets, PII, architecture scan."},
        {"name": "Compliance", "description": "HIPAA, EU AI Act, GDPR erasure, legal risk, and obligations timeline."},
        {"name": "Safety", "description": "Human-in-the-loop intercept, approval leases, and warden checks."},
        {"name": "SDET", "description": "LLM-generated test files and coverage gap analysis."},
        {"name": "Datastore", "description": "Artifact search, retrieval, stats, and failure pattern analysis."},
        {"name": "Learning", "description": "Learning metrics snapshots, improvement curves, and repo profiles."},
        {"name": "Developer Intelligence", "description": "Per-developer risk profiles and cross-repo org memory."},
        {"name": "Provenance", "description": "HMAC-signed AI output verification and provenance chains."},
        {"name": "GitHub", "description": "PR inline review comments and summary comment upsert."},
        {"name": "Release", "description": "Release readiness gate and risk scoring."},
        {"name": "Scoring", "description": "PR risk scoring and portability scorecards."},
        {"name": "Remediation", "description": "Auto-fix application and findings extraction."},
        {"name": "Scan Trends", "description": "Scan result history, trend analysis, and org rollup."},
        {"name": "Regression", "description": "Regression comparison and prediction."},
        {"name": "Code Analysis", "description": "Semantic diff and change impact analysis."},
        {"name": "Workspace", "description": "File, mail, links, and workspace safety operations."},
        {"name": "Notifications", "description": "Slack, Teams, and webhook notification dispatch."},
        {"name": "Operator", "description": "Operator configuration and connection testing."},
        {"name": "Onboarding", "description": "Repo onboarding wizard and status tracking."},
        {"name": "Plugin", "description": "Plugin bootstrap and doctor diagnostics."},
        {"name": "Ingest", "description": "Scan result ingestion into the learning system."},
        {"name": "Testing", "description": "Mutation testing and regression prediction."},
        {"name": "Demo", "description": "Demo submission and showcase pipeline."},
        {"name": "Badge", "description": "SVG quality badge generation and scan badge."},
        {"name": "Benchmark", "description": "Performance benchmarking runs."},
        {"name": "Custom Rules", "description": "Custom scan rules: save and execute."},
    ],
    lifespan=_lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ── API Versioning ────────────────────────────────────────────────────────────
# /api/v1/* transparently maps to /api/* so clients can opt into versioned URLs
# while existing /api/* routes keep working (backwards-compatible).

class APIVersionMiddleware(BaseHTTPMiddleware):
    """Rewrite /api/v1/* requests to /api/* for versioned access."""

    async def dispatch(self, request: Request, call_next):
        path = request.scope.get("path", "")
        if path.startswith("/api/v1/"):
            request.scope["path"] = "/api/" + path[8:]  # strip /api/v1/ → /api/
        return await call_next(request)


app.add_middleware(APIVersionMiddleware)


@app.get("/api/health/shutdown-status", tags=["Health"])
async def shutdown_status():
    """Check if the server is in graceful shutdown mode."""
    return {"shutting_down": _shutdown_event.is_set()}

# ── Security middleware stack (outermost = first to run) ──────────────────
# Order matters: middlewares are applied in reverse registration order in
# Starlette — the last added runs first. We want:
#   OriginValidation → BearerToken → ResponseScan → handler
# so we register in the opposite order.
app.add_middleware(ResponseScanMiddleware)
app.add_middleware(PathSanitizationMiddleware)  # CWE-22: repo_path traversal defence
app.add_middleware(BearerTokenMiddleware)
app.add_middleware(OriginValidationMiddleware)
app.add_middleware(RateLimitMiddleware)    # 60 req/min per token; 15 for heavy endpoints
app.add_middleware(InputSizeMiddleware)    # 512 KB body limit; depth-20 JSON limit
app.add_middleware(SecurityHeadersMiddleware)   # OWASP security headers (CSP, HSTS, etc)

# CORS — localhost only (DNS rebinding defence; mirrors docker/mcp-gateway)
_LOCALHOST_ORIGINS = [
    "http://localhost",
    "http://localhost:8501",   # Streamlit dashboard
    "http://localhost:3000",   # dev React / Next.js
    "http://localhost:8000",   # uvicorn self
    "http://localhost:8080",
    "http://127.0.0.1",
    "http://127.0.0.1:8501",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8080",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_LOCALHOST_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Standardized error responses ──────────────────────────────────────────────
install_error_handlers(app)

# ── Static file serving — landing page ───────────────────────────────────────
_PUBLIC_DIR = Path(__file__).parent / "public"
if _PUBLIC_DIR.is_dir():
    app.mount("/public", StaticFiles(directory=str(_PUBLIC_DIR)), name="public")

@app.get("/", response_class=FileResponse, include_in_schema=False)
async def root():
    """Serve the futuristic landing page."""
    return FileResponse(str(_PUBLIC_DIR / "index.html"))

# ── Initialize orchestrator and data store
orchestrator = AgentOrchestrator()
data_pipeline = SecureDataPipeline(use_great_expectations=False)
workflow_store = PromptWorkflowStore()
observability_store = ObservabilityStore()
workflow_worker = WorkflowExecutionWorker(workflow_store, observability_store=observability_store)
worker_pool = WorkerPool(store=workflow_store)


# Request/Response Models
class ExecutionRequest(BaseModel):
    """Request to execute agents"""

    test_results: Optional[Dict[str, Any]] = None
    execution_data: Optional[Dict[str, Any]] = None
    linting_data: Optional[Dict[str, Any]] = None
    compliance_data: Optional[Dict[str, Any]] = None
    deployment_config: Optional[Dict[str, Any]] = None


class ArtifactSearchRequest(BaseModel):
    """Request to search artifacts"""

    artifact_type: Optional[str] = None
    source: Optional[str] = None
    tags: Optional[List[str]] = None


class DataStoreStats(BaseModel):
    """Data store statistics"""

    total_artifacts: int
    by_type: Dict[str, int]
    by_source: Dict[str, int]
    last_updated: Optional[str] = None


class WorkflowRequestCreate(BaseModel):
    """Prompt-driven workflow creation request."""

    prompt: str
    repo: str = "."
    requester: str = "dashboard"
    metadata: Optional[Dict[str, Any]] = None


class WorkflowActionRequest(BaseModel):
    """Action request for an existing workflow item."""

    reason: Optional[str] = None
    requester: Optional[str] = None


class WorkflowRunRequest(BaseModel):
    """Worker execution request options."""

    dry_run: bool = True
    open_pr: bool = True


class PluginRepoRequest(BaseModel):
    """Request for plug-in onboarding operations."""

    repo: str = "."
    force: bool = False


class PortabilityBaselineRequest(BaseModel):
    """Request payload to persist current portability scorecard as baseline."""

    repo: str = "."
    note: str = ""


class ChatSessionCreateRequest(BaseModel):
    """Create a persisted dashboard chat session."""

    repo: str = "."
    requester: str = "dashboard_chat"
    metadata: Optional[Dict[str, Any]] = None


class ChatMessageRequest(BaseModel):
    """Append a message to an existing chat session."""

    role: str
    content: str
    metadata: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None


class ChatTurnRequest(BaseModel):
    """Single chat turn with optional workflow request creation."""

    message: str
    session_id: Optional[str] = None
    repo: str = "."
    requester: str = "dashboard_chat"
    auto_create_workflow: bool = True
    mode: str = "deterministic"
    tool_execution: str = "require_approval"
    metadata: Optional[Dict[str, Any]] = None


class ObservabilityEventsQuery(BaseModel):
    """Optional filters for observability event queries."""

    trace_id: Optional[str] = None
    request_id: Optional[str] = None
    agent: Optional[str] = None
    action: Optional[str] = None
    limit: int = 100


class IngestEventRequest(BaseModel):
    """Single normalized event from any external agent platform."""

    trace_id: str
    agent: str
    action: str
    status: str
    request_id: Optional[str] = None
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    event_type: Optional[str] = None
    step_key: Optional[str] = None
    latency_ms: Optional[float] = None
    decision: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    llm_prompt_tokens: Optional[int] = None
    llm_completion_tokens: Optional[int] = None


class IngestBatchRequest(BaseModel):
    events: List[IngestEventRequest]


def _infer_operator_actions(message: str) -> List[Dict[str, Any]]:
    """Infer a deterministic action plan from plain-language operator input."""
    text = (message or "").lower()
    actions: List[Dict[str, Any]] = []

    if any(token in text for token in ["scorecard", "portability"]):
        actions.append(
            {
                "tool": "get_portability_scorecard",
                "label": "Fetch portability scorecard",
                "risk": "low",
                "requires_approval": False,
                "kind": "read",
            }
        )
    if any(token in text for token in ["baseline", "save baseline"]):
        actions.append(
            {
                "tool": "save_portability_baseline",
                "label": "Save current baseline snapshot",
                "risk": "medium",
                "requires_approval": True,
                "kind": "write",
            }
        )
    if any(token in text for token in ["roi", "report"]):
        actions.append(
            {
                "tool": "get_portability_roi_report",
                "label": "Generate ROI report",
                "risk": "low",
                "requires_approval": False,
                "kind": "read",
            }
        )
    if any(token in text for token in ["approve", "queue", "run", "replay", "cancel"]):
        actions.append(
            {
                "tool": "governed_workflow_transition",
                "label": "Run governed workflow action",
                "risk": "high",
                "requires_approval": True,
                "kind": "write",
            }
        )

    if not actions:
        actions.append(
            {
                "tool": "create_workflow_request",
                "label": "Create workflow request",
                "risk": "medium",
                "requires_approval": True,
                "kind": "write",
            }
        )

    return actions


def _build_chat_assistant_reply(
    message: str,
    workflow_item: Optional[Dict[str, Any]] = None,
    action_plan: Optional[List[Dict[str, Any]]] = None,
    mode: str = "deterministic",
    tool_execution: str = "require_approval",
) -> str:
    """Build deterministic assistant feedback for dashboard chat turns."""
    cleaned = (message or "").strip()
    if mode == "llm":
        mode_text = "LLM mode selected; deterministic fallback is active until provider adapter is configured."
    else:
        mode_text = "Deterministic operator mode active."

    action_count = len(action_plan or [])

    if workflow_item:
        req_id = workflow_item.get("id")
        status = workflow_item.get("status")
        next_action = workflow_item.get("next_action")
        return (
            f"{mode_text} "
            f"Captured your request and saved it as workflow `{req_id}`. "
            f"Current status: {status}. Next action: {next_action}. "
            f"Action plan contains {action_count} governed step(s) with policy `{tool_execution}`. "
            "You can approve/queue it from Prompt Ops controls or keep chatting to submit follow-up changes."
        )
    if not cleaned:
        return "Please enter a prompt to continue."
    return (
        f"{mode_text} Message saved with {action_count} proposed action(s). "
        f"Current policy is `{tool_execution}`. Enable auto-workflow to turn chat prompts into executable workflow requests."
    )


def _resolve_tool_policy(tool_execution: str) -> str:
    policy = (tool_execution or "require_approval").strip().lower()
    if policy not in {"suggest_only", "require_approval", "auto_for_safe"}:
        return "require_approval"
    return policy


def _resolve_chat_mode(mode: str) -> str:
    requested = (mode or "deterministic").strip().lower()
    if requested not in {"deterministic", "llm"}:
        return "deterministic"
    return requested


def _llm_provider_config() -> Dict[str, Any]:
    provider = os.getenv("AGENTICQA_LLM_PROVIDER", "none").strip().lower()
    model = os.getenv("AGENTICQA_LLM_MODEL", "deterministic-fallback")
    base_url = os.getenv("AGENTICQA_LLM_BASE_URL", "")
    has_key = bool(os.getenv("AGENTICQA_LLM_API_KEY"))
    return {
        "provider": provider,
        "model": model,
        "base_url": base_url,
        "configured": provider not in {"", "none"} and has_key,
        "api_key_configured": has_key,
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(UTC).isoformat(),
        "agents_ready": 4,
    }


@app.get("/api/health/dataflow", tags=["Health"])
async def dataflow_health():
    """
    Check all infrastructure nodes in the agent pipeline.

    Returns a structured report showing which nodes are healthy/broken
    and which agents are affected by any broken link.
    """
    try:
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).parent / "src"))
        from agenticqa.monitoring.dataflow_health import DataflowHealthMonitor
        report = DataflowHealthMonitor().check_all()
        d = report.to_dict()
        d["http_status"] = 200 if report.is_healthy else 503
        return d
    except Exception as e:
        return {
            "is_healthy": False,
            "summary": f"Monitor error: {e}",
            "broken_nodes": [],
            "healthy_nodes": [],
            "affected_agents": {},
            "http_status": 500,
        }


@app.get("/api/health/integrity", tags=["Health"])
async def system_integrity():
    """
    Application-level integrity check — verifies ontology, constitutional gate,
    scanners, artifact store, provenance, and ingest pipeline are all wired
    correctly. Complements /api/health/dataflow (infrastructure probes).

    Returns 200 when all checks pass, 503 when any check fails.
    """
    try:
        from agenticqa.monitoring.integrity_checker import SystemIntegrityChecker
        report = SystemIntegrityChecker().check_all()
        d = report.to_dict()
        d["http_status"] = 200 if report.passed else 503
        return d
    except Exception as e:
        return {
            "passed": False,
            "total": 0,
            "passed_count": 0,
            "failed_count": 1,
            "checks": [{"name": "startup", "passed": False, "message": str(e)}],
            "http_status": 500,
        }


@app.get("/api/system/readiness", tags=["System"])
async def system_readiness():
    """Detailed readiness checks for local dependencies and data stores."""
    try:
        home = Path.home() / ".agenticqa"
        vector_provider = RAGConfig.get_vector_provider().value
        weaviate_up = check_tcp("127.0.0.1", 8080)
        qdrant_up = check_tcp("127.0.0.1", 6333)
        checks = {
            "workflow_db_writable": home.exists() or home.parent.exists(),
            "observability_db_writable": home.exists() or home.parent.exists(),
            "neo4j_tcp": check_tcp("127.0.0.1", 7687),
            "weaviate_tcp": weaviate_up,
            "qdrant_tcp": qdrant_up,
            "vector_provider": vector_provider,
            "vector_provider_tcp": qdrant_up if vector_provider == "qdrant" else weaviate_up,
            "vector_store_available": weaviate_up or qdrant_up,
        }
        ready = checks["workflow_db_writable"] and checks["observability_db_writable"]
        return {
            "success": True,
            "ready": bool(ready),
            "checks": checks,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/system/constitution", tags=["System"])
async def get_system_constitution():
    """Return the AgenticQA Agent Constitution.

    Any external agent platform (LangGraph, CrewAI, AutoGen, etc.) can query
    this endpoint to discover the governance rules they must enforce.
    """
    try:
        constitution = get_constitution()
        if not constitution:
            raise HTTPException(status_code=503, detail="Constitution not loaded.")
        return {
            "success": True,
            "version": constitution.get("version", "unknown"),
            "effective_date": constitution.get("effective_date"),
            "platform": constitution.get("platform"),
            "tier_1_count": len(constitution.get("tier_1", [])),
            "tier_2_count": len(constitution.get("tier_2", [])),
            "tier_3_count": len(constitution.get("tier_3", [])),
            "constitution": constitution,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class ConstitutionalCheckRequest(BaseModel):
    action_type: str
    context: Dict[str, Any] = {}


@app.post("/api/system/constitution/check", tags=["System"])
async def constitutional_check(request: ConstitutionalCheckRequest):
    """Pre-action constitutional check for any agent platform.

    Submit a proposed action and its context; receive ALLOW / REQUIRE_APPROVAL / DENY.

    Example request:
        {"action_type": "delete", "context": {"ci_status": "FAILED", "trace_id": "tr-001"}}
    Example response:
        {"verdict": "DENY", "law": "T1-001", "name": "no_destructive_without_ci", "reason": "..."}
    """
    try:
        result = _constitutional_check(
            action_type=request.action_type,
            context=request.context,
        )
        return {"success": True, **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/system/agent-scopes", tags=["System"])
async def get_system_agent_scopes():
    """Return all declared agent file scopes.

    Shows exactly which files each agent is permitted to read and write.
    Any external agent platform can query this to enforce scope restrictions
    before performing file operations.
    """
    try:
        scopes = get_agent_scopes()
        if not scopes:
            raise HTTPException(status_code=503, detail="Agent scopes not loaded.")
        summary = []
        for agent_name, scope in scopes.items():
            if not isinstance(scope, dict):
                continue
            summary.append({
                "agent": agent_name,
                "description": scope.get("description", ""),
                "read_patterns": scope.get("read", []),
                "write_patterns": scope.get("write", []),
                "deny_patterns": scope.get("deny", []),
                "write_count": len(scope.get("write", [])),
                "deny_count": len(scope.get("deny", [])),
                "read_only": len(scope.get("write", [])) == 0,
            })
        return {
            "success": True,
            "agent_count": len(summary),
            "agents": summary,
            "scopes": scopes,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class FileScopeCheckRequest(BaseModel):
    agent: str
    action: str
    file_path: str


@app.post("/api/system/agent-scopes/check", tags=["System"])
async def file_scope_check(request: FileScopeCheckRequest):
    """Check whether an agent is permitted to perform an action on a specific file.

    Example request:
        {"agent": "SDET_Agent", "action": "write", "file_path": ".github/workflows/ci.yml"}
    Example response:
        {"verdict": "DENY", "law": "T1-006", "name": "agent_file_scope_violation", "reason": "..."}
    """
    try:
        result = _check_file_scope(
            agent_name=request.agent,
            action=request.action,
            file_path=request.file_path,
        )
        return {"success": True, **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agents/execute", tags=["Agents"])
async def execute_agents(request: ExecutionRequest):
    """Execute all agents with provided data"""
    # ConstitutionalGate check — same gate used by the RedTeamAgent
    gate_result = _constitutional_check(
        action_type="run_agents",
        context={"source": "api", "data_keys": list(request.dict().keys())},
    )
    if not gate_result.get("allowed", True):
        raise HTTPException(
            status_code=403,
            detail={
                "reason": gate_result.get("reason", "Action blocked by constitutional gate"),
                "gate": "ConstitutionalGate",
            },
        )
    try:
        results = orchestrator.execute_all_agents(request.dict())
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "results": results,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/agents/insights", tags=["Agents"])
async def get_agent_insights():
    """Get pattern insights from all agents"""
    try:
        insights = orchestrator.get_agent_insights()
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "insights": insights,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/agents/{agent_name}/history", tags=["Agents"])
async def get_agent_history(agent_name: str, limit: int = 10):
    """Get execution history for a specific agent"""
    try:
        agent = orchestrator.agents.get(agent_name.lower())
        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent {agent_name} not found")

        history = agent.get_similar_executions(limit=limit)
        return {
            "success": True,
            "agent": agent_name,
            "history": history,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/datastore/search", tags=["Datastore"])
async def search_artifacts(request: ArtifactSearchRequest):
    """Search for artifacts in data store"""
    try:
        artifacts = data_pipeline.artifact_store.search_artifacts(
            artifact_type=request.artifact_type,
            source=request.source,
            tags=request.tags,
        )
        return {
            "success": True,
            "count": len(artifacts),
            "artifacts": artifacts,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/datastore/artifact/{artifact_id}", tags=["Datastore"])
async def get_artifact(artifact_id: str):
    """Retrieve a specific artifact"""
    try:
        artifact = data_pipeline.artifact_store.get_artifact(artifact_id)
        is_valid = data_pipeline.artifact_store.verify_artifact_integrity(artifact_id)
        return {
            "success": True,
            "artifact_id": artifact_id,
            "integrity_verified": is_valid,
            "data": artifact,
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Artifact {artifact_id} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/datastore/stats", tags=["Datastore"])
async def get_datastore_stats():
    """Get data store statistics"""
    try:
        all_artifacts = data_pipeline.artifact_store.search_artifacts()

        # Count by type and source
        by_type = {}
        by_source = {}

        for artifact in all_artifacts:
            artifact_type = artifact.get("artifact_type", "unknown")
            source = artifact.get("source", "unknown")

            by_type[artifact_type] = by_type.get(artifact_type, 0) + 1
            by_source[source] = by_source.get(source, 0) + 1

        return {
            "success": True,
            "total_artifacts": len(all_artifacts),
            "by_type": by_type,
            "by_source": by_source,
            "last_updated": (
                all_artifacts[-1]["timestamp"] if all_artifacts else None
            ),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/datastore/patterns", tags=["Datastore"])
async def get_patterns():
    """Get analyzed patterns from data store"""
    try:
        patterns = data_pipeline.analyze_patterns()
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "patterns": patterns,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/plugin/bootstrap", tags=["Plugin"])
async def plugin_bootstrap(body: PluginRepoRequest):
    """Bootstrap AgenticQA plug-in files for any target repository."""
    try:
        try:
            from src.agenticqa.plugin_onboarding import bootstrap_project
        except Exception:
            from agenticqa.plugin_onboarding import bootstrap_project

        result = bootstrap_project(repo_root=Path(body.repo), force=body.force)
        return {
            "success": True,
            "repo": body.repo,
            "created_files": [str(p) for p in result.created_files],
            "detected_stack": result.detected_stack,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/plugin/doctor", tags=["Plugin"])
async def plugin_doctor(body: PluginRepoRequest):
    """Run onboarding health checks for a target repository."""
    try:
        try:
            from src.agenticqa.plugin_onboarding import run_doctor
        except Exception:
            from agenticqa.plugin_onboarding import run_doctor

        result = run_doctor(repo_root=Path(body.repo))
        return {
            "success": True,
            "repo": body.repo,
            "healthy": result.healthy,
            "checks": result.checks,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/workflows/requests", tags=["Workflows"])
async def create_workflow_request(request: WorkflowRequestCreate):
    """Create a prompt-driven development workflow request."""
    try:
        if not request.prompt.strip():
            raise HTTPException(status_code=400, detail="prompt cannot be empty")

        item = workflow_store.create_request(
            prompt=request.prompt,
            repo=request.repo,
            requester=request.requester,
            metadata=request.metadata,
        )
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "request": item,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/chat/sessions", tags=["Chat"])
async def create_chat_session(body: ChatSessionCreateRequest):
    """Create a new persisted chat session for dashboard operator flow."""
    try:
        session = workflow_store.create_chat_session(
            repo=body.repo,
            requester=body.requester,
            metadata=body.metadata,
        )
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "session": session,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/chat/sessions", tags=["Chat"])
async def list_chat_sessions(limit: int = 25, offset: int = 0):
    """List recent chat sessions with pagination."""
    try:
        all_sessions = workflow_store.list_chat_sessions(limit=limit + offset)
        sessions = all_sessions[offset:offset + limit]
        return {
            "success": True,
            "count": len(sessions),
            "offset": offset,
            "limit": limit,
            "sessions": sessions,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/chat/sessions/{session_id}", tags=["Chat"])
async def get_chat_session(session_id: str, limit: int = 200):
    """Get a chat session with message history."""
    try:
        session = workflow_store.get_chat_session(session_id=session_id, message_limit=limit)
        if not session:
            raise HTTPException(status_code=404, detail="chat session not found")
        return {
            "success": True,
            "session": session,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/chat/sessions/{session_id}/messages", tags=["Chat"])
async def add_chat_message(session_id: str, body: ChatMessageRequest):
    """Append a message to a chat session."""
    try:
        content = (body.content or "").strip()
        if not content:
            raise HTTPException(status_code=400, detail="content cannot be empty")
        message = workflow_store.add_chat_message(
            session_id=session_id,
            role=body.role,
            content=content,
            metadata=body.metadata,
            request_id=body.request_id,
        )
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "message": message,
        }
    except ValueError as e:
        if "chat_session_not_found" in str(e):
            raise HTTPException(status_code=404, detail="chat session not found")
        if "invalid_chat_role" in str(e):
            raise HTTPException(status_code=400, detail="invalid chat role")
        raise HTTPException(status_code=409, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/chat/turn", tags=["Chat"])
async def chat_turn(body: ChatTurnRequest):
    """Persist a chat turn and optionally create a workflow request from the prompt."""
    try:
        message = (body.message or "").strip()
        if not message:
            raise HTTPException(status_code=400, detail="message cannot be empty")

        session = None
        if body.session_id:
            session = workflow_store.get_chat_session(body.session_id, message_limit=1)
            if not session:
                raise HTTPException(status_code=404, detail="chat session not found")
        else:
            session = workflow_store.create_chat_session(
                repo=body.repo,
                requester=body.requester,
                metadata={"source": "chat_turn"},
            )

        session_id = session["id"]
        user_msg = workflow_store.add_chat_message(
            session_id=session_id,
            role="user",
            content=message,
            metadata=body.metadata,
        )

        mode = _resolve_chat_mode(body.mode)
        tool_policy = _resolve_tool_policy(body.tool_execution)
        action_plan = _infer_operator_actions(message)

        allow_write = tool_policy != "suggest_only"

        workflow_item = None
        if body.auto_create_workflow and allow_write:
            workflow_item = workflow_store.create_request(
                prompt=message,
                repo=body.repo,
                requester=body.requester,
                metadata={
                    "source": "dashboard_chat",
                    "chat_session_id": session_id,
                    "operator_mode": mode,
                    "tool_execution": tool_policy,
                    "action_plan": action_plan,
                    **(body.metadata or {}),
                },
            )

        assistant_text = _build_chat_assistant_reply(
            message=message,
            workflow_item=workflow_item,
            action_plan=action_plan,
            mode=mode,
            tool_execution=tool_policy,
        )
        assistant_msg = workflow_store.add_chat_message(
            session_id=session_id,
            role="assistant",
            content=assistant_text,
            metadata={
                "source": "chat_orchestrator",
                "mode": mode,
                "tool_execution": tool_policy,
                "action_plan": action_plan,
            },
            request_id=(workflow_item or {}).get("id") if workflow_item else None,
        )

        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "session_id": session_id,
            "mode": mode,
            "tool_execution": tool_policy,
            "action_plan": action_plan,
            "user_message": user_msg,
            "assistant_message": assistant_msg,
            "workflow_request": workflow_item,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/operator/config", tags=["Operator"])
async def get_operator_config():
    """Return operator console configuration summary (safe/no secrets)."""
    try:
        llm = _llm_provider_config()
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "operator": {
                "default_mode": "deterministic",
                "tool_execution_modes": ["suggest_only", "require_approval", "auto_for_safe"],
                "write_actions_require_approval": True,
            },
            "llm": llm,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/operator/config/test-connection", tags=["Operator"])
async def test_operator_llm_connection():
    """Validate LLM configuration wiring (dry check, no remote call)."""
    try:
        llm = _llm_provider_config()
        ok = bool(llm.get("configured"))
        detail = "configured" if ok else "provider or API key missing"
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "ok": ok,
            "detail": detail,
            "llm": llm,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/workflows/requests", tags=["Workflows"])
async def list_workflow_requests(limit: int = 25, offset: int = 0):
    """List recent workflow requests with pagination."""
    try:
        _limit = min(max(limit, 1), 200)
        all_reqs = workflow_store.list_requests(limit=_limit + offset)
        reqs = all_reqs[offset:offset + _limit]
        return {
            "success": True,
            "count": len(reqs),
            "offset": offset,
            "limit": _limit,
            "requests": reqs,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/workflows/requests/{request_id}", tags=["Workflows"])
async def get_workflow_request(request_id: str):
    """Get a single workflow request with lifecycle events."""
    try:
        item = workflow_store.get_request(request_id)
        if not item:
            raise HTTPException(status_code=404, detail="workflow request not found")
        return {"success": True, "request": item}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/workflows/requests/{request_id}/approve", tags=["Workflows"])
async def approve_workflow_request(request_id: str):
    """Approve a workflow request for execution queueing."""
    try:
        item = workflow_store.approve_request(request_id)
        return {"success": True, "request": item}
    except ValueError as e:
        if "not_found" in str(e):
            raise HTTPException(status_code=404, detail="workflow request not found")
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/workflows/requests/{request_id}/queue", tags=["Workflows"])
async def queue_workflow_request(request_id: str):
    """Queue an approved workflow request for worker pickup."""
    try:
        item = workflow_store.queue_request(request_id)
        return {"success": True, "request": item}
    except ValueError as e:
        if "not_found" in str(e):
            raise HTTPException(status_code=404, detail="workflow request not found")
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/workflows/requests/{request_id}/cancel", tags=["Workflows"])
async def cancel_workflow_request(request_id: str, body: WorkflowActionRequest):
    """Cancel a workflow request."""
    try:
        item = workflow_store.cancel_request(request_id, reason=body.reason or "cancelled_by_user")
        return {"success": True, "request": item}
    except ValueError as e:
        if "not_found" in str(e):
            raise HTTPException(status_code=404, detail="workflow request not found")
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/workflows/requests/{request_id}/replay", tags=["Workflows"])
async def replay_workflow_request(request_id: str, body: WorkflowActionRequest):
    """Replay an existing workflow request with self-heal metadata and queue it immediately."""
    try:
        item = workflow_store.replay_request(
            request_id=request_id,
            requester=body.requester or "replay_api",
        )
        return {"success": True, "request": item}
    except ValueError as e:
        if "not_found" in str(e):
            raise HTTPException(status_code=404, detail="workflow request not found")
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/workflows/metrics", tags=["Workflows"])
async def get_workflow_metrics(limit: int = 200):
    """Return Prompt Ops outcome metrics (MTTR, pass-rate uplift, flaky reduction)."""
    try:
        metrics = workflow_store.get_metrics(lookback_limit=limit)
        return {"success": True, "metrics": metrics}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/workflows/evidence", tags=["Workflows"])
async def get_workflow_evidence(limit: int = 500):
    """Client-facing evidence bundle mapping system claims to measurable signals."""
    try:
        metrics = workflow_store.get_metrics(lookback_limit=limit)
        traces = observability_store.list_traces(limit=100)
        history_path = Path.home() / ".agenticqa" / "benchmarks" / "sdet_trend_history.jsonl"
        latest = read_latest_jsonl(history_path)
        evidence = build_evidence_summary(metrics=metrics, latest_benchmark=latest, trace_count=len(traces))
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "evidence": evidence,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/workflows/portability-scorecard", tags=["Workflows"])
async def get_portability_scorecard(repo: str = ".", limit: int = 500):
    """Build portability scorecard and baseline delta for any target repository."""
    try:
        repo_root = Path(repo).expanduser().resolve()
        profile = detect_repo_profile(repo_root).to_dict()
        metrics = workflow_store.get_metrics(lookback_limit=limit)
        insights = observability_store.get_global_insights(limit=limit)
        baseline = load_baseline(str(repo_root))
        scorecard = build_portability_scorecard(
            repo_profile=profile,
            workflow_metrics=metrics,
            observability_insights=insights,
            baseline=baseline,
        )
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "repo": str(repo_root),
            "scorecard": scorecard,
            "has_baseline": baseline is not None,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/workflows/portability-scorecard/baseline", tags=["Workflows"])
async def save_portability_scorecard_baseline(body: PortabilityBaselineRequest):
    """Persist current portability scorecard as baseline for future delta comparisons."""
    try:
        repo_root = Path(body.repo).expanduser().resolve()
        profile = detect_repo_profile(repo_root).to_dict()
        metrics = workflow_store.get_metrics(lookback_limit=500)
        insights = observability_store.get_global_insights(limit=500)
        scorecard = build_portability_scorecard(
            repo_profile=profile,
            workflow_metrics=metrics,
            observability_insights=insights,
            baseline=load_baseline(str(repo_root)),
        )
        saved = save_baseline(
            repo_root=str(repo_root),
            scorecard=scorecard,
            note=body.note,
        )
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "repo": str(repo_root),
            "baseline": saved,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/workflows/portability-scorecard/roi-report", tags=["Workflows"])
async def get_portability_roi_report(repo: str = ".", limit: int = 500):
    """Export a compact baseline/current/delta ROI report for a repository."""
    try:
        repo_root = Path(repo).expanduser().resolve()
        profile = detect_repo_profile(repo_root).to_dict()
        metrics = workflow_store.get_metrics(lookback_limit=limit)
        insights = observability_store.get_global_insights(limit=limit)
        baseline = load_baseline(str(repo_root))
        scorecard = build_portability_scorecard(
            repo_profile=profile,
            workflow_metrics=metrics,
            observability_insights=insights,
            baseline=baseline,
        )
        report = build_portability_roi_report(
            repo_root=str(repo_root),
            scorecard=scorecard,
            workflow_metrics=metrics,
        )
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "repo": str(repo_root),
            "has_baseline": baseline is not None,
            "report": report,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/workflows/worker/run-next", tags=["Workflows"])
async def run_next_workflow_request(body: WorkflowRunRequest):
    """Run worker execution for the oldest queued workflow request."""
    try:
        item = workflow_worker.run_next(dry_run=body.dry_run, open_pr=body.open_pr)
        if not item:
            return {
                "success": True,
                "message": "no queued requests",
                "request": None,
            }
        return {"success": True, "request": item}
    except ValueError as e:
        if "not_found" in str(e):
            raise HTTPException(status_code=404, detail="workflow request not found")
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/workflows/worker/run/{request_id}", tags=["Workflows"])
async def run_workflow_request(request_id: str, body: WorkflowRunRequest):
    """Run worker execution for a specific queued workflow request."""
    try:
        item = workflow_worker.run_request(
            request_id=request_id,
            dry_run=body.dry_run,
            open_pr=body.open_pr,
        )
        return {"success": True, "request": item}
    except ValueError as e:
        if "not_found" in str(e):
            raise HTTPException(status_code=404, detail="workflow request not found")
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Auto-submit + Queue endpoints ────────────────────────────────────────────

@app.post("/api/workflows/submit", tags=["Workflows"])
async def submit_workflow_request(request: WorkflowRequestCreate):
    """Auto-queue a workflow request — skips manual approval, worker pool picks it up."""
    try:
        item = workflow_store.create_and_queue_request(
            prompt=request.prompt,
            repo=_safe_repo_path(request.repo),
            requester=request.requester,
            metadata=request.metadata,
        )
        return {"success": True, "request": item}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/workflows/queue", tags=["Workflows"])
async def get_workflow_queue():
    """Return pool status and queue snapshot for dashboard."""
    try:
        return {"success": True, **worker_pool.status()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/workflows/requests/{request_id}/status", tags=["Workflows"])
async def get_workflow_request_status(request_id: str):
    """Lightweight polling endpoint — returns just status + key fields."""
    try:
        item = workflow_store.get_request(request_id)
        if not item:
            raise HTTPException(status_code=404, detail="workflow request not found")
        return {
            "success": True,
            "id": item["id"],
            "status": item["status"],
            "worker_id": item.get("worker_id"),
            "branch_name": item.get("branch_name"),
            "commit_sha": item.get("commit_sha"),
            "pr_url": item.get("pr_url"),
            "error_message": item.get("error_message"),
            "updated_at": item.get("updated_at"),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/workflows/requests/{request_id}/stream", tags=["Workflows"])
async def stream_workflow_request_status(request_id: str):
    """SSE endpoint — emits events on status change, closes on terminal state."""
    from starlette.responses import StreamingResponse
    import json as _json

    item = workflow_store.get_request(request_id)
    if not item:
        raise HTTPException(status_code=404, detail="workflow request not found")

    async def _event_generator():
        last_status = None
        terminal = {"COMPLETED", "FAILED", "CANCELLED"}
        while True:
            req = workflow_store.get_request(request_id)
            if not req:
                yield f"data: {_json.dumps({'status': 'NOT_FOUND'})}\n\n"
                return
            current = req["status"]
            if current != last_status:
                payload = {
                    "status": current,
                    "worker_id": req.get("worker_id"),
                    "branch_name": req.get("branch_name"),
                    "commit_sha": req.get("commit_sha"),
                    "pr_url": req.get("pr_url"),
                    "error_message": req.get("error_message"),
                    "updated_at": req.get("updated_at"),
                }
                yield f"data: {_json.dumps(payload)}\n\n"
                last_status = current
                if current in terminal:
                    return
            await asyncio.sleep(1)

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/observability/traces", tags=["Observability"])
async def list_observability_traces(limit: int = 100, offset: int = 0):
    """List recent execution traces with pagination."""
    try:
        all_traces = observability_store.list_traces(limit=limit + offset)
        traces = all_traces[offset:offset + limit]
        return {"success": True, "count": len(traces), "offset": offset, "limit": limit, "traces": traces}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/observability/traces/{trace_id}", tags=["Observability"])
async def get_observability_trace(trace_id: str, limit: int = 500):
    """Get all events for a single trace."""
    try:
        trace = observability_store.get_trace(trace_id=trace_id, limit=limit)
        return {"success": True, "trace": trace}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/observability/traces/{trace_id}/analysis", tags=["Observability"])
async def get_observability_trace_analysis(trace_id: str, limit: int = 1000):
    """Get computed span tree and quality analysis for a single trace."""
    try:
        events = observability_store.list_events(
            limit=limit,
            trace_id=trace_id,
            newest_first=False,
        )
        analysis = observability_store.analyze_trace(trace_id=trace_id, events=events)
        return {
            "success": True,
            "trace_id": trace_id,
            "event_count": len(events),
            "analysis": analysis,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/observability/traces/{trace_id}/counterfactuals", tags=["Observability"])
async def get_observability_counterfactuals(trace_id: str, limit: int = 300):
    """Get counterfactual recommendations for failed/retried actions in a trace."""
    try:
        data = observability_store.get_counterfactual_recommendations(trace_id=trace_id, limit=limit)
        return {
            "success": True,
            "trace_id": trace_id,
            "counterfactuals": data,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/observability/traces/{trace_id}/audit-report", tags=["Observability"])
async def get_observability_audit_report(trace_id: str, format: str = "json", limit: int = 500):
    """Build a shareable AI Decision Audit Report for a single trace.

    Returns structured JSON by default. Use format=markdown to get the pre-rendered PR body.
    Raises 404 if the trace has no recorded events.
    """
    try:
        report = build_audit_report(trace_id=trace_id, obs_store=observability_store, limit=limit)
        if format == "markdown":
            return {
                "success": True,
                "trace_id": trace_id,
                "audit_id": report["audit_id"],
                "markdown_body": report["markdown_body"],
            }
        return {"success": True, "trace_id": trace_id, "report": report}
    except ValueError as e:
        if str(e).startswith("trace_not_found:"):
            raise HTTPException(status_code=404, detail=f"Trace not found: {trace_id}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/observability/events", tags=["Observability"])
async def list_observability_events(
    limit: int = 100,
    offset: int = 0,
    trace_id: Optional[str] = None,
    request_id: Optional[str] = None,
    agent: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    event_type: Optional[str] = None,
):
    """Query raw observability events with optional filters and pagination."""
    try:
        all_events = observability_store.list_events(
            limit=limit + offset,
            trace_id=trace_id,
            request_id=request_id,
            agent=agent,
            action=action,
            status=status,
            event_type=event_type,
        )
        events = all_events[offset:offset + limit]
        return {"success": True, "count": len(events), "offset": offset, "limit": limit, "events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/observability/quality", tags=["Observability"])
async def get_observability_quality(
    limit: int = 100,
    min_completeness: float = 0.95,
    min_decision_quality: float = 0.60,
):
    """Return aggregate trace quality metrics for CI/CD quality gates."""
    try:
        summary = observability_store.get_quality_summary(
            limit=limit,
            min_completeness=min_completeness,
            min_decision_quality=min_decision_quality,
        )
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "quality": summary,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/observability/ingest", tags=["Observability"])
async def ingest_event(event: IngestEventRequest):
    """Ingest a single agent event from any external platform.

    Accepts events from LangGraph, LangChain, CrewAI, AutoGen, OpenAI Agents SDK,
    or any custom agent. All existing observability endpoints (traces, audit-report,
    counterfactuals, complexity trends) work transparently on ingested events.
    """
    try:
        evt = _normalize_ingest_event(event.model_dump())
        observability_store.log_event(
            trace_id=evt.trace_id,
            request_id=evt.request_id,
            agent=evt.agent,
            action=evt.action,
            status=evt.status,
            span_id=evt.span_id,
            parent_span_id=evt.parent_span_id,
            event_type=evt.event_type,
            step_key=evt.step_key,
            latency_ms=evt.latency_ms,
            decision=evt.decision,
            error=evt.error,
            metadata=evt.metadata,
        )
        if evt.llm_prompt_tokens or evt.llm_completion_tokens:
            observability_store.log_complexity_metric(
                agent=evt.agent,
                action=evt.action,
                trace_id=evt.trace_id,
                llm_prompt_tokens=evt.llm_prompt_tokens or 0,
                llm_completion_tokens=evt.llm_completion_tokens or 0,
            )
        return {"success": True, "trace_id": evt.trace_id, "agent": evt.agent, "status": evt.status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/observability/ingest/batch", tags=["Observability"])
async def ingest_events_batch(batch: IngestBatchRequest):
    """Ingest a batch of agent events. Processes all events; returns per-event status."""
    results = []
    errors = 0
    for raw in batch.events:
        try:
            evt = _normalize_ingest_event(raw.model_dump())
            observability_store.log_event(
                trace_id=evt.trace_id,
                request_id=evt.request_id,
                agent=evt.agent,
                action=evt.action,
                status=evt.status,
                span_id=evt.span_id,
                parent_span_id=evt.parent_span_id,
                event_type=evt.event_type,
                step_key=evt.step_key,
                latency_ms=evt.latency_ms,
                decision=evt.decision,
                error=evt.error,
                metadata=evt.metadata,
            )
            if evt.llm_prompt_tokens or evt.llm_completion_tokens:
                observability_store.log_complexity_metric(
                    agent=evt.agent,
                    action=evt.action,
                    trace_id=evt.trace_id,
                    llm_prompt_tokens=evt.llm_prompt_tokens or 0,
                    llm_completion_tokens=evt.llm_completion_tokens or 0,
                )
            results.append({"trace_id": evt.trace_id, "agent": evt.agent, "ok": True})
        except Exception as e:
            errors += 1
            results.append({"ok": False, "error": str(e)})
    return {
        "success": errors == 0,
        "total": len(results),
        "errors": errors,
        "results": results,
    }


@app.get("/api/observability/agent-complexity", tags=["Observability"])
async def get_agent_complexity(agent: Optional[str] = None, window_days: int = 14):
    """Return RAG retrieval complexity trends per agent for degradation detection.

    Tracks rag_docs_retrieved, avg_similarity_score, and patterns_considered over time.
    Anomaly flagged when recent 3-day similarity drops >20% vs window baseline.
    """
    try:
        if agent:
            trends = observability_store.get_complexity_trends(agent=agent, window_days=window_days)
            return {"success": True, "timestamp": datetime.now(UTC).isoformat(), "complexity": trends}
        from datetime import timedelta
        cutoff = (datetime.now(UTC) - timedelta(days=window_days)).isoformat()
        c = observability_store.conn.cursor()
        agents = [
            r[0] for r in c.execute(
                "SELECT DISTINCT agent FROM agent_complexity_metrics WHERE timestamp >= ?", (cutoff,)
            ).fetchall()
        ]
        all_trends = [
            observability_store.get_complexity_trends(agent=a, window_days=window_days)
            for a in agents
        ]
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "agents": agents,
            "complexity": all_trends,
            "anomalies": [t for t in all_trends if t.get("anomaly")],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/observability/insights", tags=["Observability"])
async def get_observability_insights(limit: int = 500):
    """Get aggregate observability insights (quality, failures, policy impact)."""
    try:
        insights = observability_store.get_global_insights(limit=limit)
        return {
            "success": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "insights": insights,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Agent Factory endpoints
# ---------------------------------------------------------------------------

class AgentScaffoldRequest(BaseModel):
    framework: str
    agent_name: str
    capabilities: List[str] = []


@app.get("/api/agent-factory/frameworks", tags=["Agent Factory"])
async def list_agent_frameworks():
    """List all supported agent frameworks for scaffolding."""
    return {
        "success": True,
        "frameworks": list(SUPPORTED_FRAMEWORKS.keys()),
        "count": len(SUPPORTED_FRAMEWORKS),
    }


@app.post("/api/agent-factory/scaffold", tags=["Agent Factory"])
async def scaffold_agent(request: AgentScaffoldRequest):
    """
    Generate governed agent starter code for the requested framework.

    The generated code has AgenticQA's constitutional gate, feedback loop,
    and outcome tracker pre-wired. Save the output as a .py file to use.
    """
    if request.framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported framework '{request.framework}'. "
                   f"Supported: {list(SUPPORTED_FRAMEWORKS.keys())}",
        )
    if not request.agent_name.strip():
        raise HTTPException(status_code=400, detail="agent_name cannot be empty.")

    try:
        factory = AgentFactory()
        result = factory.scaffold(
            framework=request.framework,
            agent_name=request.agent_name.strip(),
            capabilities=request.capabilities,
        )
        return {"success": True, **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class SandboxWrapRequest(BaseModel):
    agent_name: str
    script_path: str
    capabilities: List[str] = []
    allowed_dir: str = "."
    timeout_s: int = 30
    env_passthrough: List[str] = []
    block_on_flag: bool = True


@app.post("/api/agent-factory/sandbox-wrap", tags=["Agent Factory"])
async def sandbox_wrap_agent(request: SandboxWrapRequest):
    """
    Register a sandboxed agent: subprocess isolation + constitutional gate + output scanner.

    The script_path must point to a standalone Python script that reads JSON from stdin
    and writes JSON to stdout. The agent runs in a clean environment (no inherited secrets),
    with cwd locked to allowed_dir and a hard timeout.
    """
    if not request.agent_name.strip():
        raise HTTPException(status_code=400, detail="agent_name cannot be empty.")
    if not request.script_path.strip():
        raise HTTPException(status_code=400, detail="script_path cannot be empty.")

    try:
        wrapper = SandboxedAgentAdapter.wrap(
            script_path=request.script_path.strip(),
            agent_name=request.agent_name.strip(),
            capabilities=request.capabilities,
            allowed_dir=request.allowed_dir,
            timeout_s=request.timeout_s,
            env_passthrough=request.env_passthrough,
            block_on_flag=request.block_on_flag,
        )
        return {
            "success": True,
            "agent_name": wrapper.agent_name,
            "framework": wrapper.framework,
            "governed": True,
            "capabilities": wrapper.capabilities,
            "sandbox": {
                "allowed_dir": request.allowed_dir,
                "timeout_s": request.timeout_s,
                "env_passthrough": request.env_passthrough,
                "block_on_flag": request.block_on_flag,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class FromPromptRequest(BaseModel):
    description: str
    framework: Optional[str] = None  # overrides LLM-inferred framework
    persist: bool = True


@app.post("/api/agent-factory/from-prompt", tags=["Agent Factory"])
async def scaffold_agent_from_prompt(request: FromPromptRequest):
    """
    Natural language → governed agent.

    1. LLM extracts an AgentSpec from the description.
    2. Optional framework override is applied.
    3. AgentFactory scaffolds governed code.
    4. If persist=True, saves to .agenticqa/custom_agents/{agent_name}.py in CWD.
    """
    if not request.description.strip():
        raise HTTPException(status_code=400, detail="description cannot be empty.")

    try:
        spec = NaturalLanguageSpecExtractor().extract(request.description)

        if request.framework:
            if request.framework not in SUPPORTED_FRAMEWORKS:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported framework '{request.framework}'. "
                           f"Supported: {list(SUPPORTED_FRAMEWORKS.keys())}",
                )
            spec.framework = request.framework

        scaffold_result = AgentFactory().scaffold(
            framework=spec.framework,
            agent_name=spec.agent_name,
            capabilities=spec.capabilities,
        )

        # Security scan generated code before persisting
        try:
            from agenticqa.security.agent_skill_scanner import AgentSkillScanner
        except ImportError:
            from src.agenticqa.security.agent_skill_scanner import AgentSkillScanner
        skill_scan = AgentSkillScanner().scan_source(
            scaffold_result["generated_code"],
            filename=f"{spec.agent_name}.py",
        )
        if not skill_scan.is_safe:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "Generated agent code failed security scan",
                    "findings": [
                        {"line": f.lineno, "attack_type": f.attack_type,
                         "severity": f.severity, "detail": f.detail}
                        for f in skill_scan.findings
                    ],
                    "risk_score": round(skill_scan.risk_score, 3),
                },
            )

        persisted_path = None
        if request.persist:
            out_dir = Path(".agenticqa") / "custom_agents"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f"{spec.agent_name}.py"
            out_file.write_text(scaffold_result["generated_code"])
            persisted_path = str(out_file)

        return {
            "success": True,
            "spec": spec.to_dict(),
            "generated_code": scaffold_result["generated_code"],
            "install_hint": scaffold_result["install_hint"],
            "usage": scaffold_result["usage"],
            "persisted_path": persisted_path,
            "security_scan": skill_scan.to_dict(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Red Team Agent
# ---------------------------------------------------------------------------

class RedTeamScanRequest(BaseModel):
    mode: str = "fast"        # "fast" | "thorough"
    target: str = "both"      # "scanner" | "gate" | "both"
    auto_patch: bool = True


@app.post("/api/red-team/scan", tags=["Red Team"])
async def red_team_scan(request: RedTeamScanRequest):
    """Probe governance stack for bypasses and optionally self-patch OutputScanner patterns."""
    if request.mode not in ("fast", "thorough"):
        raise HTTPException(status_code=400, detail="mode must be 'fast' or 'thorough'")
    if request.target not in ("scanner", "gate", "both"):
        raise HTTPException(status_code=400, detail="target must be 'scanner', 'gate', or 'both'")
    try:
        agent = RedTeamAgent()
        result = agent.execute({
            "mode": request.mode,
            "target": request.target,
            "auto_patch": request.auto_patch,
        })
        return {"success": True, **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/redteam/history", tags=["Red Team"])
async def redteam_history(mode: str = "", limit: int = 50, window: int = 10):
    """Return red team scan history, trend curves, and security posture summary."""
    try:
        from data_store.redteam_history import RedTeamHistoryStore
        store = RedTeamHistoryStore()
        mode_filter = mode or None
        history = store.load_history(mode_filter=mode_filter, limit=limit)
        scanner_trend = store.get_trend("scanner_strength", window=window, mode_filter=mode_filter)
        gate_trend = store.get_trend("gate_strength", window=window, mode_filter=mode_filter)
        bypass_trend = store.get_trend("successful_bypasses", window=window, mode_filter=mode_filter)
        summary = store.summary(window=window, mode_filter=mode_filter)
        return {
            "success": True,
            "history": history,
            "trends": {
                "scanner_strength": scanner_trend,
                "gate_strength": gate_trend,
                "successful_bypasses": bypass_trend,
            },
            "summary": summary,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sdet/generated-tests", tags=["SDET"])
async def sdet_generated_tests(repo_path: str = "."):
    """List all LLM-generated test files in .agenticqa/generated_tests/."""
    repo_path = _safe_repo_path(repo_path)
    try:
        from pathlib import Path as _Path
        gen_dir = _Path(repo_path) / ".agenticqa" / "generated_tests"
        if not gen_dir.exists():
            return {"success": True, "files": [], "count": 0}
        files = []
        for test_file in sorted(gen_dir.glob("test_*.py")):
            try:
                files.append({
                    "name": test_file.name,
                    "path": str(test_file),
                    "size_bytes": test_file.stat().st_size,
                    "preview": test_file.read_text()[:500],
                })
            except Exception:
                continue
        return {"success": True, "files": files, "count": len(files)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/developer-profiles", tags=["Developer Intelligence"])
async def developer_profiles(repo_path: str = ".", top_n: int = 10):
    """Return the developer risk leaderboard for the given repo."""
    repo_path = _safe_repo_path(repo_path)
    try:
        import hashlib
        import subprocess as _sp
        from data_store.developer_profile import DeveloperRiskLeaderboard
        try:
            _proc = _sp.run(
                ["git", "remote", "get-url", "origin"],
                capture_output=True, text=True, timeout=5, cwd=repo_path,
            )
            _url = _proc.stdout.strip().lower().rstrip("/").removesuffix(".git")
            repo_id = hashlib.sha1(_url.encode()).hexdigest()[:12] if _url else "unknown"
        except Exception:
            repo_id = hashlib.sha1(repo_path.encode()).hexdigest()[:12]
        board = DeveloperRiskLeaderboard(repo_id)
        return {"success": True, "repo_id": repo_id, "leaderboard": board.top_n(top_n)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/org-memory", tags=["Developer Intelligence"])
async def org_memory(repo_path: str = "."):
    """Return cross-repo org memory for the org owning the given repo."""
    repo_path = _safe_repo_path(repo_path)
    try:
        from data_store.org_memory import OrgMemory
        mem = OrgMemory.for_repo(repo_path)
        return {"success": True, **mem.summary()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/semantic-diff", tags=["Code Analysis"])
async def semantic_diff(
    repo_path: str = ".",
    base: str = "HEAD~1",
    head: str = "HEAD",
):
    """
    Analyze what semantically changed between two git refs.

    Returns high/medium risk removals: null checks, error handlers, auth decorators,
    input validation, timeouts, and assertions.
    """
    repo_path = _safe_repo_path(repo_path)
    try:
        from agenticqa.diff.semantic_diff import SemanticDiffAnalyzer
        result = SemanticDiffAnalyzer().analyze_git_range(base=base, head=head, cwd=repo_path)
        return {"success": True, **result.summary()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/compliance/drift", tags=["Compliance"])
async def compliance_drift(repo_path: str = ".", lookback: int = 10):
    """Return compliance violation drift between the last two runs for this repo."""
    repo_path = _safe_repo_path(repo_path)
    try:
        from agenticqa.compliance.drift_detector import ComplianceDriftDetector
        detector = ComplianceDriftDetector()
        drift = detector.detect_drift(repo_path, lookback=lookback)
        history = detector.history(repo_path, limit=30)
        return {"success": True, "drift": drift, "history": history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/risk-gate", tags=["Release"])
async def risk_gate(
    repo_path: str = ".",
    files: List[str] = Query(default=[]),
    threshold: float = 0.70,
):
    repo_path = _safe_repo_path(repo_path)
    """
    Evaluate changed files against developer risk scores.

    Pass ?files=src/foo.py&files=src/bar.py to check specific files.
    Returns gate=pass|block with per-file risk details.
    """
    try:
        import hashlib
        import subprocess as _sp
        from agenticqa.gates.risk_gate import DeveloperRiskGate
        try:
            _proc = _sp.run(
                ["git", "remote", "get-url", "origin"],
                capture_output=True, text=True, timeout=5, cwd=repo_path,
            )
            _url = _proc.stdout.strip().lower().rstrip("/").removesuffix(".git")
            repo_id = hashlib.sha1(_url.encode()).hexdigest()[:12] if _url else "unknown"
        except Exception:
            repo_id = hashlib.sha1(repo_path.encode()).hexdigest()[:12]
        gate = DeveloperRiskGate(threshold=threshold)
        result = gate.evaluate(files, repo_id=repo_id, cwd=repo_path)
        return {"success": True, "repo_id": repo_id, **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/github/pr-inline-comments", tags=["GitHub"])
async def post_inline_comments(request: dict):
    """Post inline review comments on specific PR diff lines."""
    try:
        from agenticqa.github.pr_commenter import PRCommenter
        commenter = PRCommenter()
        pr_number = request.get("pr_number")
        if not pr_number:
            pr_number = commenter._detect_pr_number()
        if not pr_number:
            return {"success": False, "reason": "no PR detected"}
        posted = commenter.post_inline_comments(
            pr_number=int(pr_number),
            findings=request.get("findings", []),
            commit_sha=request.get("commit_sha"),
        )
        return {"success": True, "posted": posted}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/github/pr-comment", tags=["GitHub"])
async def post_pr_comment_endpoint(request: dict):
    """Post or update AgenticQA CI results as a PR comment."""
    try:
        from agenticqa.github.pr_commenter import CIResultBundle, PRCommenter

        redteam = request.get("redteam") or {}
        sdet = request.get("sdet") or {}
        compliance = request.get("compliance") or {}
        sre = request.get("sre") or {}
        qa = request.get("qa") or {}

        bundle = CIResultBundle(
            run_id=request.get("run_id", "unknown"),
            commit_sha=request.get("commit_sha", "unknown"),
            total_tests=qa.get("total_tests"),
            tests_passed=qa.get("passed"),
            tests_failed=qa.get("failed"),
            coverage_percent=sdet.get("current_coverage"),
            coverage_status=sdet.get("coverage_status"),
            tests_generated=sdet.get("tests_generated"),
            sre_total_errors=sre.get("total_errors"),
            sre_fix_rate=sre.get("fix_rate"),
            sre_fixes_applied=sre.get("fixes_applied"),
            scanner_strength=redteam.get("scanner_strength"),
            gate_strength=redteam.get("gate_strength"),
            successful_bypasses=redteam.get("successful_bypasses"),
            compliance_violations=len(compliance.get("violations", [])) if compliance else None,
            reachable_cves=compliance.get("reachable_cves"),
            cve_risk_score=compliance.get("cve_risk_score"),
        )
        commenter = PRCommenter()
        pr_number = request.get("pr_number")
        success = commenter.post_results(bundle, pr_number=pr_number)
        return {"success": success, "pr_number": pr_number}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/cve-reachability", tags=["Security"])
async def cve_reachability(repo_path: str = "."):
    """Scan the repo for CVEs (pip-audit + npm audit) and determine import-level reachability."""
    repo_path = _safe_repo_path(repo_path)
    try:
        from agenticqa.security.cve_reachability import CVEReachabilityAnalyzer
        analyzer = CVEReachabilityAnalyzer()
        py_result = analyzer.scan_python(repo_path)
        js_result = analyzer.scan_javascript(repo_path)
        return {
            "success": True,
            "python": {
                "total_cves": len(py_result.cves),
                "reachable_cves": [
                    {
                        "package": c.package,
                        "cve_id": c.cve_id,
                        "severity": c.severity,
                        "fixed_version": c.fixed_version,
                        "reachable_via": c.reachable_via,
                    }
                    for c in py_result.reachable_cves
                ],
                "unreachable_count": len(py_result.unreachable_cves),
                "risk_score": py_result.risk_score,
                "scan_error": py_result.scan_error,
            },
            "javascript": {
                "total_cves": len(js_result.cves),
                "reachable_cves": [
                    {
                        "package": c.package,
                        "cve_id": c.cve_id,
                        "severity": c.severity,
                        "fixed_version": c.fixed_version,
                        "reachable_via": c.reachable_via,
                    }
                    for c in js_result.reachable_cves
                ],
                "unreachable_count": len(js_result.unreachable_cves),
                "risk_score": js_result.risk_score,
                "scan_error": js_result.scan_error,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/compliance/legal-risk", tags=["Compliance"])
async def legal_risk_scan(repo_path: str = "."):
    """Scan a repo for legal compliance risks: credentials, PII docs, privilege exposure, SSRF, missing auth."""
    try:
        from agenticqa.security.legal_risk_scanner import LegalRiskScanner
        result = LegalRiskScanner().scan(repo_path)
        return {
            "success": True,
            "risk_score": result.risk_score,
            "total_findings": len(result.findings),
            "critical_findings": len(result.critical_findings),
            "scan_error": result.scan_error,
            "findings": [
                {
                    "file": f.file,
                    "line": f.line,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "message": f.message,
                    "evidence": f.evidence,
                }
                for f in result.findings
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/regression/compare", tags=["Regression"])
async def regression_compare(
    agent: str,
    baseline_model: str,
    candidate_model: str,
    candidate_output: str = "",
    run_id: str = "local",
):
    """Compare a candidate model output against the stored golden snapshot."""
    try:
        from agenticqa.regression.model_regression import ModelRegressionTester
        tester = ModelRegressionTester()
        result = tester.compare(
            agent_name=agent,
            baseline_model=baseline_model,
            candidate_model=candidate_model,
            candidate_output=candidate_output,
            input_data={"agent": agent},
        )
        return {
            "agent": result.agent_name,
            "baseline_model": result.baseline_model,
            "candidate_model": result.candidate_model,
            "similarity_score": result.similarity_score,
            "regression_detected": result.regression_detected,
            "threshold_used": result.threshold_used,
            "has_baseline": result.baseline_snapshot is not None,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/provenance/verify", tags=["Provenance"])
async def provenance_verify(output_hash: str, agent: str):
    """Verify an AI output hash against the provenance log."""
    try:
        from agenticqa.provenance.output_provenance import OutputProvenanceLogger
        result = OutputProvenanceLogger().verify_by_hash(output_hash, agent)
        return {
            "valid": result.valid,
            "reason": result.reason,
            "record": {
                "output_hash": result.record.output_hash,
                "model_id": result.record.model_id,
                "agent_name": result.record.agent_name,
                "timestamp": result.record.timestamp,
                "run_id": result.record.run_id,
                "output_length": result.record.output_length,
            } if result.record else None,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/provenance/chain", tags=["Provenance"])
async def provenance_chain(agent: str, limit: int = 20, offset: int = 0):
    """Return the most-recent provenance records for an agent with pagination."""
    try:
        from agenticqa.provenance.output_provenance import OutputProvenanceLogger
        all_records = OutputProvenanceLogger().get_chain(agent, limit=limit + offset)
        records = all_records[offset:offset + limit]
        return {
            "agent": agent,
            "count": len(records),
            "offset": offset,
            "limit": limit,
            "records": [
                {"output_hash": r.output_hash, "model_id": r.model_id,
                 "timestamp": r.timestamp, "run_id": r.run_id,
                 "output_length": r.output_length}
                for r in records
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/compliance/ai-model-sbom", tags=["Compliance"])
async def ai_model_sbom_scan(repo_path: str = "."):
    """Produce an AI Model SBOM: inventory of all ML models, providers, licenses, and risk flags."""
    try:
        from agenticqa.security.ai_model_sbom import AIModelSBOMScanner
        result = AIModelSBOMScanner().scan(repo_path)
        return {
            "success": True,
            "providers_detected": result.providers_detected,
            "unique_models": len(result.unique_model_ids),
            "unique_model_ids": result.unique_model_ids,
            "license_violations": len(result.license_violations),
            "risk_score": result.risk_score,
            "scan_error": result.scan_error,
            "components": [
                {
                    "model_id": c.model_id,
                    "provider": c.provider,
                    "license": c.license,
                    "risk_flags": c.risk_flags,
                    "source_file": c.source_file,
                    "source_line": c.source_line,
                }
                for c in result.components
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/compliance/hipaa", tags=["Compliance"])
async def hipaa_phi_scan(repo_path: str = "."):
    """Scan repo for HIPAA PHI risks: hardcoded SSN/DOB/MRN, PHI in logs, PHI to LLM, missing audit."""
    try:
        from agenticqa.security.hipaa_phi_scanner import HIPAAPHIScanner
        result = HIPAAPHIScanner().scan(repo_path)
        return {
            "success": True,
            "risk_score": result.risk_score,
            "total_findings": len(result.findings),
            "critical_findings": len(result.critical_findings),
            "scan_error": result.scan_error,
            "findings": [
                {"file": f.file, "line": f.line, "rule_id": f.rule_id,
                 "severity": f.severity, "message": f.message, "evidence": f.evidence}
                for f in result.findings
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/compliance/ai-act", tags=["Compliance"])
async def ai_act_check(repo_path: str = "."):
    """Check EU AI Act conformity: Annex III classification + Art.9/13/14/22 evidence."""
    try:
        from agenticqa.compliance.ai_act import AIActComplianceChecker
        result = AIActComplianceChecker().check(repo_path)
        return {
            "success": True,
            "risk_category": result.risk_category,
            "annex_iii_match": result.annex_iii_match,
            "conformity_score": result.conformity_score,
            "scan_error": result.scan_error,
            "findings": [
                {"article": f.article, "requirement": f.requirement, "status": f.status,
                 "severity": f.severity, "evidence": f.evidence, "remediation": f.remediation}
                for f in result.findings
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/compliance/obligations-timeline", tags=["Compliance"])
async def obligations_timeline(
    repo_path: str = ".",
    eu_conformity_score: float = -1.0,
    hipaa_score: float = -1.0,
    include_met: bool = True,
):
    """
    Generate a deadline-stamped compliance action plan.

    Auto-detects EU AI Act tier and scores by scanning the repo (if scores
    not supplied). Returns obligations sorted by urgency with plain-English
    actions and ISO deadline dates.

    Query params:
      eu_conformity_score  0.0–1.0  (omit to auto-detect from repo)
      hipaa_score          0.0–1.0  (omit to auto-detect from repo)
      include_met          include already-satisfied obligations (default true)
    """
    try:
        from agenticqa.compliance.obligations_timeline import ObligationsTimeline

        # Auto-detect scores if not supplied
        tier = "minimal_risk"
        eu_score = eu_conformity_score
        h_score = hipaa_score

        if eu_score < 0 or h_score < 0:
            try:
                from agenticqa.compliance.ai_act import AIActComplianceChecker
                ai_result = AIActComplianceChecker().check(repo_path)
                tier = ai_result.risk_category
                if eu_score < 0:
                    eu_score = ai_result.conformity_score
            except Exception:
                eu_score = max(eu_score, 0.5)

            try:
                from agenticqa.security.hipaa_phi_scanner import HIPAAPhiScanner
                hipaa_result = HIPAAPhiScanner().scan(repo_path)
                if h_score < 0:
                    findings = hipaa_result.get("findings", [])
                    critical = sum(1 for f in findings if f.get("severity") == "critical")
                    h_score = max(0.0, 1.0 - (critical * 0.15))
            except Exception:
                h_score = max(h_score, 0.5)

        plan = ObligationsTimeline().generate(
            eu_ai_act_tier=tier,
            eu_conformity_score=max(0.0, eu_score),
            hipaa_score=max(0.0, h_score),
            include_met=include_met,
        )
        return {"success": True, **plan.to_dict(), "summary": plan.summary()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/redteam/prompt-injection", tags=["Red Team"])
async def prompt_injection_scan(repo_path: str = "."):
    """Scan repo for prompt injection attack surface."""
    try:
        from agenticqa.security.prompt_injection_scanner import PromptInjectionScanner
        result = PromptInjectionScanner().scan(repo_path)
        return {
            "success": True,
            "surface_score": result.surface_score,
            "total_findings": len(result.findings),
            "scan_error": result.scan_error,
            "findings": [
                {"file": f.file, "line": f.line, "rule_id": f.rule_id,
                 "severity": f.severity, "message": f.message, "evidence": f.evidence}
                for f in result.findings
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/redteam/agent-trust-graph", tags=["Red Team"])
async def agent_trust_graph_scan(repo_path: str = "."):
    """Analyze multi-agent trust graph: circular trust, missing human oversight, privileged tools, escalation paths."""
    try:
        from agenticqa.security.agent_trust_graph import AgentTrustGraphAnalyzer
        result = AgentTrustGraphAnalyzer().analyze(repo_path)
        return {
            "success": True,
            "frameworks_detected": result.frameworks_detected,
            "agent_nodes": len(result.nodes),
            "agent_edges": len(result.edges),
            "violations": len(result.violations),
            "has_human_oversight": result.has_human_oversight,
            "risk_score": result.risk_score,
            "scan_error": result.scan_error,
            "nodes": [
                {"name": n.name, "framework": n.framework, "tools": n.tools,
                 "human_input_mode": n.human_input_mode,
                 "source_file": n.source_file, "source_line": n.source_line}
                for n in result.nodes
            ],
            "edges": [
                {"source": e.source, "target": e.target, "edge_type": e.edge_type,
                 "framework": e.framework, "source_file": e.source_file, "source_line": e.source_line}
                for e in result.edges
            ],
            "trust_violations": [
                {"rule_id": v.rule_id, "severity": v.severity, "message": v.message,
                 "agents_involved": v.agents_involved, "source_file": v.source_file,
                 "source_line": v.source_line, "remediation": v.remediation}
                for v in result.violations
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/mcp-scan", tags=["Security"])
async def mcp_security_scan(repo_path: str = "."):
    """Scan MCP server definitions and implementations for security vulnerabilities."""
    try:
        from agenticqa.security.mcp_scanner import MCPSecurityScanner
        result = MCPSecurityScanner().scan(repo_path)
        return {
            "success": True,
            "files_scanned": result.files_scanned,
            "tools_scanned": result.tools_scanned,
            "servers_scanned": result.servers_scanned,
            "risk_score": result.risk_score,
            "attack_types_detected": result.attack_types_detected,
            "total_findings": len(result.findings),
            "critical_count": len(result.critical_findings),
            "high_count": len(result.high_findings),
            "scan_error": result.scan_error,
            "findings": [
                {
                    "tool_name": f.tool_name,
                    "attack_type": f.attack_type,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "source_file": f.source_file,
                    "line_number": f.line_number,
                    "cwe": f.cwe,
                    "cvss_score": f.cvss_score,
                }
                for f in result.findings
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/data-flow-trace", tags=["Security"])
async def data_flow_trace(repo_path: str = "."):
    """Trace sensitive data (PII/credentials) flows across agent trust boundaries."""
    try:
        from agenticqa.security.data_flow_tracer import CrossAgentDataFlowTracer
        report = CrossAgentDataFlowTracer().trace(repo_path)
        return {
            "success": True,
            "files_scanned": report.files_scanned,
            "agents_analyzed": report.agents_analyzed,
            "tainted_variables_detected": report.tainted_variables_detected,
            "risk_score": report.risk_score,
            "finding_types": report.finding_types,
            "total_findings": len(report.findings),
            "critical_count": len(report.critical_findings),
            "scan_error": report.scan_error,
            "findings": [
                {
                    "finding_type": f.finding_type,
                    "severity": f.severity,
                    "data_type": f.data_type,
                    "description": f.description,
                    "source_agent": f.source_agent,
                    "sink_agent": f.sink_agent,
                    "sanitized": f.sanitized,
                    "source_file": f.source_file,
                    "line_number": f.line_number,
                    "remediation": f.remediation,
                    "trace": [
                        {"agent": h.agent_name, "file": h.source_file,
                         "line": h.line_number, "op": h.operation,
                         "evidence": h.evidence}
                        for h in f.trace
                    ],
                }
                for f in report.findings
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/skill-scan", tags=["Security"])
async def skill_scan(agents_dir: str = ".agenticqa/custom_agents"):
    """
    AST-scan all custom agent skill files for dangerous patterns.

    Returns a per-file report with findings (attack_type, severity, line) and
    an aggregate risk score. Files with critical findings or risk_score >= 0.5
    have is_safe=False and should not be loaded.
    """
    try:
        from agenticqa.security.agent_skill_scanner import AgentSkillScanner
    except ImportError:
        from src.agenticqa.security.agent_skill_scanner import AgentSkillScanner
    try:
        scanner = AgentSkillScanner()
        results = scanner.scan_directory(agents_dir)
        total = len(results)
        safe = sum(1 for r in results if r.is_safe)
        blocked = total - safe
        return {
            "success": True,
            "agents_dir": agents_dir,
            "total_files": total,
            "safe": safe,
            "blocked": blocked,
            "results": [r.to_dict() for r in results],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/temporal/violations", tags=["Learning"])
async def temporal_violations(
    repo_id: str,
    days: int = 30,
    granularity: str = "day",
):
    """Return time-bucketed violation counts from Neo4j temporal graph."""
    try:
        from agenticqa.graph.temporal_graph import TemporalViolationStore
        store = TemporalViolationStore()
        return {
            "success": True,
            "trend": store.get_violation_trend(repo_id, days=days, granularity=granularity),
            "fix_rate": store.get_fix_rate_trend(repo_id, days=days),
            "top_rules": store.get_top_rules_over_time(repo_id, days=days, top_n=10),
            "agents": store.get_agent_comparison(repo_id, days=days),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/learning-metrics", tags=["Learning"])
async def learning_metrics(repo_id: str = "", limit: int = 30):
    """Return per-run learning metrics history and improvement curve."""
    try:
        from data_store.learning_metrics import LearningMetricsSnapshot
        snap = LearningMetricsSnapshot()
        rid = repo_id or None
        history = snap.load_history(repo_id=rid, limit=limit)
        summary = snap.summary(repo_id=rid, window=min(limit, 10))
        curves = {
            metric: snap.get_improvement_curve(metric, repo_id=rid, window=limit)
            for metric in ("fix_rate", "artifact_count", "delegation_pairs")
        }
        return {"success": True, "summary": summary, "history": history, "curves": curves}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/repo-profile", tags=["Learning"])
async def repo_profile_endpoint(repo_path: str = "."):
    """Return the current repo's RepoProfile including run_history for trend charts."""
    try:
        from data_store.repo_profile import RepoProfile
        import hashlib, subprocess as _sp
        try:
            _proc = _sp.run(
                ["git", "remote", "get-url", "origin"],
                capture_output=True, text=True, timeout=5, cwd=repo_path,
            )
            _url = _proc.stdout.strip().lower().rstrip("/").removesuffix(".git")
            repo_id = hashlib.sha1(_url.encode()).hexdigest()[:12] if _url else "unknown"
        except Exception:
            repo_id = hashlib.sha1(repo_path.encode()).hexdigest()[:12]
        profile = RepoProfile(repo_id)
        return {"success": True, "repo_id": repo_id, "profile": profile._data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/export/sarif", tags=["Provenance"])
async def export_sarif(request: Request):
    """
    Convert agent results to SARIF 2.1.0 for GitHub Code Scanning.

    Body: {sre?: {...}, compliance?: {...}, redteam?: {...}, repo_root?: str}
    Returns SARIF JSON (application/json).
    """
    try:
        body = await request.json()
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).parent / "src"))
        from agenticqa.export.sarif import SARIFExporter
        exporter = SARIFExporter(repo_root=body.get("repo_root", "."))
        total = 0
        if body.get("sre"):
            total += exporter.add_sre_result(body["sre"])
        if body.get("compliance"):
            total += exporter.add_compliance_result(body["compliance"])
        if body.get("redteam"):
            total += exporter.add_redteam_result(body["redteam"])
        return {"sarif": exporter.to_dict(), "finding_count": total}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/gdpr/erasure-request", tags=["Compliance"])
async def gdpr_erasure_request(request: Request):
    """
    Create a GDPR Art.17 erasure request for a tenant.
    Body: {"tenant_id": str, "subject_id": str}
    Returns: {"request_id": str, "requested_at": float, "status": "pending"}
    """
    try:
        body = await request.json()
        tenant_id = body.get("tenant_id", "")
        subject_id = body.get("subject_id", "")
        if not tenant_id:
            raise HTTPException(status_code=400, detail="tenant_id is required")
        from agenticqa.security.gdpr_erasure_verifier import GDPREraseVerifier
        req = GDPREraseVerifier().request_erasure(tenant_id=tenant_id, subject_id=subject_id)
        return req.__dict__
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/gdpr/erasure-status/{request_id}", tags=["Compliance"])
async def gdpr_erasure_status(request_id: str):
    """
    Verify that all stores have been purged for a given erasure request.
    Returns ErasureVerificationResult with per-store clean/residual status.
    """
    try:
        from agenticqa.security.gdpr_erasure_verifier import GDPREraseVerifier
        result = GDPREraseVerifier().verify_erasure(request_id)
        return result.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/audit-chain", tags=["Security"])
async def audit_chain_log(
    tenant_id: str = "",
    limit: int = 100,
    offset: int = 0,
):
    """
    Return the verified immutable audit chain (EU AI Act Art.12 compliance log).
    Query: ?tenant_id=xxx&limit=100&offset=0
    """
    try:
        from agenticqa.security.immutable_audit import ImmutableAuditChain
        chain = ImmutableAuditChain()
        ok, violations = chain.verify_chain()
        all_entries = chain.get_compliance_log(
            tenant_id=tenant_id or None,
            limit=limit + offset,
        )
        entries = all_entries[offset:offset + limit]
        return {
            "chain_length": chain.length(),
            "chain_intact": ok,
            "violations": [str(v) for v in violations],
            "count": len(entries),
            "offset": offset,
            "limit": limit,
            "entries": entries,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/classify-intent", tags=["Security"])
async def classify_intent(request: Request):
    """
    Run SemanticIntentClassifier on a text snippet.
    Body: {"text": str}
    Returns: attack_class, probability, confidence, top_terms
    """
    try:
        body = await request.json()
        text = body.get("text", "")
        from agenticqa.security.semantic_classifier import SemanticIntentClassifier
        result = SemanticIntentClassifier().classify(text)
        return {
            "attack_class": result.attack_class,
            "probability": result.probability,
            "confidence": result.confidence,
            "top_terms": result.top_terms,
            "all_scores": result.all_scores,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/ci-scan", tags=["Security"])
async def ci_yaml_scan(path: str = ".github/workflows"):
    """
    Scan GitHub Actions YAML files for injection vulnerabilities.
    Query: ?path=.github/workflows
    """
    try:
        from agenticqa.security.ci_yaml_scanner import CIYAMLInjectionScanner
        results = CIYAMLInjectionScanner().scan_directory(path)
        return {
            "files_scanned": len(results),
            "files_with_findings": sum(1 for r in results if r.findings),
            "critical": sum(
                1 for r in results for f in r.findings if f.severity == "critical"
            ),
            "results": [
                {
                    "path": r.path,
                    "risk_score": r.risk_score,
                    "is_safe": r.is_safe,
                    "findings": [f.__dict__ for f in r.findings],
                }
                for r in results
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/architecture-scan", tags=["Security"])
async def architecture_scan(repo_path: str = "."):
    """
    Scan a repository for integration areas and attack surface.

    Returns plain-English findings, attack vectors per integration,
    test coverage confidence, and attack surface score (0–100).

    Query: ?repo_path=/path/to/repo  (default: current directory)
    """
    try:
        from agenticqa.security.architecture_scanner import ArchitectureScanner
        result = ArchitectureScanner().scan(repo_path)
        payload = {
            "success": True,
            "repo_path": result.repo_path,
            "files_scanned": result.files_scanned,
            "attack_surface_score": result.attack_surface_score,
            "test_coverage_confidence": result.test_coverage_confidence,
            "total_integration_areas": len(result.integration_areas),
            "untested_count": len(result.untested_areas),
            "critical_count": len(result.critical_areas),
            "categories": {k: len(v) for k, v in result.by_category().items()},
            "plain_english_report": result.plain_english_report(),
            "integration_areas": [a.to_dict() for a in result.integration_areas],
            "scan_error": result.scan_error,
        }
        # Auto-save to learning store so scan history feeds the data flywheel
        try:
            from data_store.artifact_store import TestArtifactStore
            _astore = TestArtifactStore(
                os.getenv("AGENTICQA_ARTIFACT_STORE", ".test-artifact-store")
            )
            _astore.store_artifact(
                artifact_data={"artifact_type": "architecture_scan", **result.to_dict()},
                artifact_type="architecture_scan",
                source=repo_path,
                tags=["architecture", "security",
                      f"score_{int(result.attack_surface_score)}"],
            )
        except Exception:
            pass  # non-blocking — scan result returned regardless
        return payload
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── PR Risk Pre-flight Scorer ──────────────────────────────────────────────────

class PRRiskRequest(BaseModel):
    author_email: str
    changed_files: List[str] = []
    diff_lines: str = ""
    repo_path: str = "."


@app.post("/api/scoring/pr-risk", tags=["Scoring"])
async def pr_risk_score(req: PRRiskRequest):
    """
    Score a pull request's risk before CI runs.

    Uses author fix-rate history, org memory of unfixable rules,
    sensitive file detection, dangerous diff patterns, and learning
    metrics trend to return a risk score (0-100) and recommendation
    (LOW RISK | MEDIUM RISK | HIGH RISK).
    """
    try:
        from agenticqa.scoring.pr_risk_scorer import PRRiskScorer
        report = PRRiskScorer().score(
            author_email=req.author_email,
            changed_files=req.changed_files,
            diff_lines=req.diff_lines,
            repo_path=req.repo_path,
        )
        return {"success": True, **report.to_dict()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Webhook Notifications ──────────────────────────────────────────────────────

class WebhookTestRequest(BaseModel):
    url: str
    release_readiness_score: float = 75.0
    recommendation: str = "SHIP IT"
    tests_passed: int = 10
    tests_total: int = 10
    owasp_critical_count: int = 0
    feature_description: str = "Test webhook delivery"
    max_retries: int = 3


@app.post("/api/notifications/webhook-test", tags=["Notifications"])
async def webhook_test(req: WebhookTestRequest):
    """
    Fire a test webhook POST to the given URL.

    Useful for verifying webhook endpoint connectivity before hooking
    AgenticQA into your alerting pipeline.
    """
    try:
        from agenticqa.notifications.webhook import WebhookNotifier, WebhookPayload, WebhookDeliveryError
        payload = WebhookPayload(
            release_readiness_score=req.release_readiness_score,
            recommendation=req.recommendation,
            tests_passed=req.tests_passed,
            tests_total=req.tests_total,
            owasp_critical_count=req.owasp_critical_count,
            feature_description=req.feature_description,
        )
        notifier = WebhookNotifier(url=req.url, max_retries=req.max_retries)
        response = notifier.notify(payload)
        return {"success": True, "url": req.url, "response": response}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as exc:
        from agenticqa.notifications.webhook import WebhookDeliveryError
        if isinstance(exc, WebhookDeliveryError):
            raise HTTPException(status_code=502, detail=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


# ── Agent Safety: Destructive Action Interceptor ──────────────────────────────

_interceptor_singleton = None

def _get_interceptor():
    global _interceptor_singleton
    if _interceptor_singleton is None:
        from agenticqa.security.destructive_action_interceptor import DestructiveActionInterceptor
        _interceptor_singleton = DestructiveActionInterceptor()
    return _interceptor_singleton


class InterceptRequest(BaseModel):
    tool_name: str
    parameters: dict = {}
    agent_id: str = "unknown"
    session_id: str = ""
    context_snippet: str = ""


@app.post("/api/safety/intercept", tags=["Safety"])
async def intercept_action(req: InterceptRequest):
    """Classify and gate a tool call before execution."""
    from agenticqa.security.destructive_action_interceptor import ActionCall
    interceptor = _get_interceptor()
    call = ActionCall(
        tool_name=req.tool_name,
        parameters=req.parameters,
        agent_id=req.agent_id,
        session_id=req.session_id,
        context_snippet=req.context_snippet,
    )
    verdict = interceptor.intercept(call)
    return verdict.to_dict()


@app.get("/api/safety/pending", tags=["Safety"])
async def get_pending_approvals():
    """List all pending approval requests requiring human sign-off."""
    interceptor = _get_interceptor()
    return {"pending": interceptor.get_pending_approvals()}


@app.post("/api/safety/approve/{token}", tags=["Safety"])
async def approve_action(token: str, approved_by: str = "human"):
    """Approve a pending action by its approval token."""
    interceptor = _get_interceptor()
    ok = interceptor.approve(token, approved_by=approved_by)
    if not ok:
        raise HTTPException(status_code=404, detail="Token not found or expired")
    return {"approved": True, "token": token}


@app.post("/api/safety/deny/{token}", tags=["Safety"])
async def deny_action(token: str):
    """Deny and remove a pending approval request."""
    interceptor = _get_interceptor()
    ok = interceptor.deny(token)
    return {"denied": ok, "token": token}


# ── Agent Safety: Scope Lease Manager ────────────────────────────────────────

_lease_mgr_singleton = None

def _get_lease_mgr():
    global _lease_mgr_singleton
    if _lease_mgr_singleton is None:
        from agenticqa.security.scope_lease_manager import AgentScopeLeaseManager
        _lease_mgr_singleton = AgentScopeLeaseManager()
    return _lease_mgr_singleton


class LeaseCreateRequest(BaseModel):
    agent_id: str
    session_id: str = ""
    label: str = "standard"        # standard | readonly | elevated | custom
    max_reads: int = 2147483647
    max_writes: int = 50
    max_deletes: int = 0
    max_executes: int = 0
    lease_ttl_seconds: int = 600


class LeaseCheckRequest(BaseModel):
    lease_id: str
    action: str   # read | write | delete | execute (or tool name alias)


@app.post("/api/safety/lease", tags=["Safety"])
async def create_lease(req: LeaseCreateRequest):
    """Issue a new scope lease for an agent session."""
    from agenticqa.security.scope_lease_manager import LeaseConfig
    mgr = _get_lease_mgr()
    if req.label == "readonly":
        config = LeaseConfig.readonly()
    elif req.label == "elevated":
        config = LeaseConfig.elevated(max_deletes=req.max_deletes, max_executes=req.max_executes)
    else:
        config = LeaseConfig(
            max_reads=req.max_reads,
            max_writes=req.max_writes,
            max_deletes=req.max_deletes,
            max_executes=req.max_executes,
            lease_ttl_seconds=req.lease_ttl_seconds,
            label=req.label,
        )
    lease_id = mgr.create_lease(req.agent_id, req.session_id, config)
    return {"lease_id": lease_id, **mgr.get_lease_status(lease_id)}


@app.get("/api/safety/lease/{lease_id}", tags=["Safety"])
async def get_lease(lease_id: str):
    """Get current status and counters for a lease."""
    mgr = _get_lease_mgr()
    status = mgr.get_lease_status(lease_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Lease {lease_id} not found")
    return status


@app.post("/api/safety/lease/check", tags=["Safety"])
async def check_lease(req: LeaseCheckRequest):
    """Check-and-consume one operation unit from a lease (hard enforcement)."""
    mgr = _get_lease_mgr()
    allowed, reason = mgr.check_and_consume(req.lease_id, req.action)
    if not allowed:
        raise HTTPException(status_code=403, detail=reason)
    return {"allowed": True, "reason": reason}


@app.delete("/api/safety/lease/{lease_id}", tags=["Safety"])
async def revoke_lease(lease_id: str, reason: str = "manual revocation"):
    """Immediately revoke a lease — all further ops blocked."""
    mgr = _get_lease_mgr()
    ok = mgr.revoke_lease(lease_id, reason=reason)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Lease {lease_id} not found")
    return {"revoked": True, "lease_id": lease_id}


@app.get("/api/safety/leases", tags=["Safety"])
async def list_leases():
    """List all active (non-expired, non-revoked) leases."""
    mgr = _get_lease_mgr()
    return {"leases": mgr.list_active_leases()}


# ── Agent Safety: Instruction Persistence Warden ─────────────────────────────

_warden_singleton = None

def _get_warden():
    global _warden_singleton
    if _warden_singleton is None:
        from agenticqa.security.instruction_persistence_warden import InstructionPersistenceWarden
        _warden_singleton = InstructionPersistenceWarden()
    return _warden_singleton


class WardCheckRequest(BaseModel):
    session_id: str
    messages: list = []           # [{role, content}, ...]
    recent_output: str = ""


class GuardrailRegisterRequest(BaseModel):
    session_id: str
    guardrails: list              # [{name, content, drift_signals?, priority?}]


@app.post("/api/safety/warden/register", tags=["Safety"])
async def register_guardrails(req: GuardrailRegisterRequest):
    """Register immutable guardrail blocks for a session."""
    from agenticqa.security.instruction_persistence_warden import GuardrailBlock
    warden = _get_warden()
    blocks = [
        GuardrailBlock(
            name=g.get("name", f"guardrail_{i}"),
            content=g.get("content", ""),
            drift_signals=g.get("drift_signals", []),
            priority=g.get("priority", 0),
        )
        for i, g in enumerate(req.guardrails)
    ]
    warden.register_guardrails(req.session_id, blocks)
    return {"registered": len(blocks), "session_id": req.session_id}


@app.post("/api/safety/warden/check", tags=["Safety"])
async def warden_check(req: WardCheckRequest):
    """Check compaction risk and constraint drift for a session."""
    warden = _get_warden()
    report = warden.check(req.session_id, req.messages, req.recent_output)
    return report.to_dict()


@app.get("/api/safety/warden/prompt/{session_id}", tags=["Safety"])
async def get_reinforced_prompt(session_id: str, base_prompt: str = ""):
    """Get a system prompt with all guardrail blocks re-injected."""
    warden = _get_warden()
    prompt = warden.get_reinforced_system_prompt(session_id, base_prompt)
    return {"session_id": session_id, "reinforced_prompt": prompt}


# ── Release Readiness Scorer ──────────────────────────────────────────────────

try:
    from src.agenticqa.scoring.release_readiness import ReleaseReadinessScorer
except ImportError:
    from agenticqa.scoring.release_readiness import ReleaseReadinessScorer

_readiness_scorer = ReleaseReadinessScorer()


class ReadinessRequest(BaseModel):
    sdet_result: Optional[Dict[str, Any]] = None
    security_findings: Optional[List[Dict[str, Any]]] = None
    cve_result: Optional[Dict[str, Any]] = None
    perf_result: Optional[Dict[str, Any]] = None
    compliance_result: Optional[Dict[str, Any]] = None
    architecture_result: Optional[Dict[str, Any]] = None


@app.post("/api/release-readiness", tags=["Release"])
async def release_readiness(req: ReadinessRequest):
    """
    Aggregate all AgenticQA signals into a single 0-100 Release Readiness Score.
    Returns SHIP IT / REVIEW REQUIRED / DO NOT SHIP with per-signal breakdown.
    Any subset of signals can be provided — missing ones are excluded from scoring.
    """
    report = _readiness_scorer.score(
        sdet_result=req.sdet_result,
        security_findings=req.security_findings,
        cve_result=req.cve_result,
        perf_result=req.perf_result,
        compliance_result=req.compliance_result,
        architecture_result=req.architecture_result,
    )
    return {"success": True, **report.to_dict()}


# ── Intent-to-Code Verifier ───────────────────────────────────────────────────

try:
    from src.agenticqa.security.intent_verifier import IntentToCodeVerifier
except ImportError:
    from agenticqa.security.intent_verifier import IntentToCodeVerifier

_intent_verifier = IntentToCodeVerifier(static_only=True)


class IntentVerifyRequest(BaseModel):
    intent: str
    code_diff: str
    file_path: str = ""
    llm_assisted: bool = False


@app.post("/api/security/intent-verify", tags=["Security"])
async def intent_verify(req: IntentVerifyRequest):
    """
    Verify that an LLM-generated code diff actually implements the stated intent.
    Detects: hallucinated APIs, intent gaps, stub-only implementations, syntax errors.
    Set llm_assisted=true to enable Claude Haiku semantic analysis (requires ANTHROPIC_API_KEY).
    """
    verifier = IntentToCodeVerifier(static_only=not req.llm_assisted)
    result = verifier.verify(
        intent=req.intent,
        code_diff=req.code_diff,
        file_path=req.file_path,
    )
    return {"success": True, **result.to_dict()}


# ── OWASP Top 10 Scanner ──────────────────────────────────────────────────────

try:
    from src.agenticqa.security.owasp_scanner import OWASPScanner
except ImportError:
    from agenticqa.security.owasp_scanner import OWASPScanner


@app.get("/api/security/owasp-scan", tags=["Security"])
async def owasp_scan(repo_path: str = "."):
    """
    Static analysis covering OWASP Top 10 (2021): Injection, Broken Auth,
    Crypto Failures, Misconfiguration, SSRF, Insecure Deserialisation, and more.
    Returns findings grouped by OWASP category with severity and CWE references.
    """
    result = OWASPScanner().scan(repo_path)
    return {"success": True, **result.to_dict()}


# ── Blast Radius Analyzer ─────────────────────────────────────────────────────

try:
    from src.agenticqa.security.blast_radius import BlastRadiusAnalyzer
except ImportError:
    from agenticqa.security.blast_radius import BlastRadiusAnalyzer


class BlastRadiusRequest(BaseModel):
    repo_path: str = "."
    changed_files: List[str] = []


@app.post("/api/security/blast-radius", tags=["Security"])
async def blast_radius(req: BlastRadiusRequest):
    """
    Analyze which modules are affected by a set of changed files.
    Returns directly/transitively affected files, critical paths, and a 0-100 risk score.
    """
    result = BlastRadiusAnalyzer().analyze(req.repo_path, req.changed_files)
    return {"success": True, **result.to_dict()}


# ── Mutation Testing Runner ───────────────────────────────────────────────────

try:
    from src.agenticqa.testing.mutation_runner import MutationRunner
except ImportError:
    from agenticqa.testing.mutation_runner import MutationRunner


class MutationRequest(BaseModel):
    repo_path: str = "."
    target_files: Optional[List[str]] = None


@app.post("/api/testing/mutation", tags=["Testing"])
async def mutation_test(req: MutationRequest):
    """
    Run mutation testing via mutmut and report the kill rate.
    Returns verdict: STRONG | ADEQUATE | WEAK | UNTESTED.
    Falls back to UNTESTED if mutmut is not installed.
    """
    result = MutationRunner().run(repo_path=req.repo_path, target_files=req.target_files)
    return {"success": True, **result.to_dict()}


# ── Secrets History Scanner ───────────────────────────────────────────────────

try:
    from src.agenticqa.security.secrets_scanner import SecretsHistoryScanner
except ImportError:
    from agenticqa.security.secrets_scanner import SecretsHistoryScanner


class SecretsScanRequest(BaseModel):
    repo_path: str = "."
    scan_history: bool = True
    max_commits: int = 100


@app.post("/api/security/secrets-scan", tags=["Security"])
async def secrets_scan(req: SecretsScanRequest):
    """
    Scan git commit history and current HEAD for accidentally committed secrets.
    Detects AWS keys, GitHub tokens, Stripe keys, PEM keys, passwords, and more.
    Pure Python regex — no external tools required.
    """
    result = SecretsHistoryScanner().scan(
        repo_path=req.repo_path,
        scan_history=req.scan_history,
        max_commits=req.max_commits,
    )
    return {"success": True, **result.to_dict()}


# ── Pre-flight Deploy Checklist Generator ─────────────────────────────────────

try:
    from src.agenticqa.security.preflight_checklist import PreflightChecklistGenerator
except ImportError:
    from agenticqa.security.preflight_checklist import PreflightChecklistGenerator


class PreflightChecklistRequest(BaseModel):
    changed_files: List[str] = []
    diff_content: str = ""


@app.post("/api/security/preflight-checklist", tags=["Security"])
async def preflight_checklist(req: PreflightChecklistRequest):
    """
    Generate a personalized deploy checklist based on changed files and diff content.
    Returns MUST / SHOULD / CONSIDER items grouped by category (AUTH, DATABASE, API, etc.).
    """
    result = PreflightChecklistGenerator().generate(
        changed_files=req.changed_files,
        diff_content=req.diff_content,
    )
    return {"success": True, **result.to_dict()}


# ── Container & Infrastructure Security Scanner ───────────────────────────────

try:
    from src.agenticqa.security.container_scanner import ContainerScanner
except ImportError:
    from agenticqa.security.container_scanner import ContainerScanner


@app.get("/api/security/container-scan", tags=["Security"])
async def container_scan(repo_path: str = "."):
    """
    Scan Dockerfiles, docker-compose files, and Kubernetes YAML for security issues.
    Detects: root user, privileged mode, docker.sock mounts, host networking, secrets in ENV, etc.
    Pure static analysis — no external tools.
    """
    result = ContainerScanner().scan(repo_path)
    return {"success": True, **result.to_dict()}


# ── Race Condition & Concurrency Probe ────────────────────────────────────────

try:
    from src.agenticqa.security.race_condition_detector import RaceConditionDetector
except ImportError:
    from agenticqa.security.race_condition_detector import RaceConditionDetector


@app.get("/api/security/race-conditions", tags=["Security"])
async def race_conditions(repo_path: str = "."):
    """
    Static analysis detecting common race condition patterns in Python source code.
    Detects TOCTOU file access, unsynchronized global mutation, double-checked locking,
    session/token TOCTOU, shared file writes, and lazy initialization issues.
    """
    result = RaceConditionDetector().scan(repo_path)
    return {"success": True, **result.to_dict()}


# ── Full Security Scan + Ingestion ────────────────────────────────────────────


@app.post("/api/security/full-scan", tags=["Security"])
async def full_security_scan(repo_path: str = "."):
    """Run all 10 security scanners against a repo. No API key required.

    Returns a unified report with per-scanner results, summary stats,
    and total_critical count for CI gating.
    """
    repo_path = _safe_repo_path(repo_path)
    sys.path.insert(0, str(Path(__file__).parent / "scripts"))
    from scripts.run_client_scan import scan_repo
    results = scan_repo(repo_path)

    scanners_ok = sum(1 for v in results.values() if v["status"] == "ok")
    total_findings = 0
    total_critical = 0
    for v in results.values():
        if v["status"] == "ok":
            r = v["result"]
            total_findings += r.get("total_findings", r.get("findings_count", 0))
            total_critical += r.get("critical", 0)

    return {
        "success": True,
        "summary": {
            "scanners_ok": scanners_ok,
            "scanners_total": len(results),
            "total_findings": total_findings,
            "total_critical": total_critical,
        },
        "scanners": results,
    }


@app.post("/api/ingest/scan-result", tags=["Ingest"])
async def ingest_scan_result(body: dict):
    """Ingest external scanner output into the learning system.

    Accepts output from ``run_client_scan.py`` or any scanner that produces
    ``{summary: {...}, scanners: {...}}`` JSON.
    """
    import time as _time
    import json as _json
    scanners = body.get("scanners", {})
    repo_path = body.get("summary", {}).get("repo_path", "unknown")
    ingested = 0
    for scanner_name, scanner_data in scanners.items():
        if scanner_data.get("status") != "ok":
            continue
        store_dir = Path(".test-artifact-store")
        store_dir.mkdir(exist_ok=True)
        artifact_id = f"scan_{scanner_name}_{int(_time.time())}"
        artifact_path = store_dir / f"{artifact_id}.json"
        artifact_path.write_text(_json.dumps({
            "artifact_type": f"scan_{scanner_name}",
            "scanner_name": scanner_name,
            "repo_path": repo_path,
            "result": scanner_data.get("result", {}),
        }, indent=2))
        ingested += 1
    return {"success": True, "ingested": ingested, "total": len(scanners)}


# ── Regression Prediction / Smart Test Selection ──────────────────────────────

try:
    from src.agenticqa.testing.regression_predictor import RegressionPredictor
except ImportError:
    from agenticqa.testing.regression_predictor import RegressionPredictor


class RegressionPredictRequest(BaseModel):
    repo_path: str = "."
    changed_files: List[str] = []


@app.post("/api/testing/regression-predict", tags=["Testing"])
async def regression_predict(req: RegressionPredictRequest):
    """
    Predict which tests are most likely to fail given a set of changed files.
    Returns tests sorted by relevance score (1.0=exact match, 0.1=no match).
    Priority tests (score >= 0.5) should run first; skip candidates (< 0.1) are safe to defer.
    """
    result = RegressionPredictor().predict(
        repo_path=req.repo_path,
        changed_files=req.changed_files,
    )
    return {"success": True, **result.to_dict()}


# ── Live Pipeline Demo — runs all scanners on pasted LLM-generated code ───────

try:
    from src.agenticqa.security.owasp_scanner import OWASPScanner
    from src.agenticqa.security.secrets_scanner import SecretsHistoryScanner
    from src.agenticqa.security.race_condition_detector import RaceConditionDetector
    from src.agenticqa.security.preflight_checklist import PreflightChecklistGenerator
    from src.agenticqa.security.blast_radius import BlastRadiusAnalyzer
    from src.agenticqa.security.intent_verifier import IntentToCodeVerifier
    from src.agenticqa.scoring.release_readiness import ReleaseReadinessScorer
except ImportError:
    from agenticqa.security.owasp_scanner import OWASPScanner
    from agenticqa.security.secrets_scanner import SecretsHistoryScanner
    from agenticqa.security.race_condition_detector import RaceConditionDetector
    from agenticqa.security.preflight_checklist import PreflightChecklistGenerator
    from agenticqa.security.blast_radius import BlastRadiusAnalyzer
    from agenticqa.security.intent_verifier import IntentToCodeVerifier
    from agenticqa.scoring.release_readiness import ReleaseReadinessScorer


class PipelineDemoRequest(BaseModel):
    intent: str = ""
    code: str
    file_path: str = "feature.py"
    changed_files: Optional[List[str]] = None
    repo_path: str = "."
    llm_assisted: bool = False


@app.post("/api/pipeline/demo", tags=["Pipeline"])
async def pipeline_demo(req: PipelineDemoRequest):
    """
    Run the full AgenticQA pipeline against pasted LLM-generated code.
    Returns intent verification, OWASP findings, secrets, race conditions,
    pre-flight checklist, and final Release Readiness Score — in one call.
    """
    import tempfile, os as _os

    changed_files = req.changed_files or [req.file_path]

    # Write code to a temp directory so file-based scanners work
    with tempfile.TemporaryDirectory() as tmpdir:
        code_path = _os.path.join(tmpdir, _os.path.basename(req.file_path))
        with open(code_path, "w", encoding="utf-8") as fh:
            fh.write(req.code)

        # 1. Intent-to-Code Verifier
        intent_result = None
        if req.intent:
            verifier = IntentToCodeVerifier(static_only=not req.llm_assisted)
            intent_result = verifier.verify(
                intent=req.intent,
                code_diff=req.code,
                file_path=req.file_path,
            ).to_dict()

        # 2. OWASP Top 10 Scanner
        owasp_result = OWASPScanner().scan(tmpdir).to_dict()

        # 3. Secrets Scanner (content-based, no git)
        secrets_findings = SecretsHistoryScanner().scan_content(req.code, req.file_path)
        secrets_result = {
            "findings": [f.to_dict() for f in secrets_findings],
            "has_live_secrets": any(f.still_present for f in secrets_findings),
            "count": len(secrets_findings),
        }

        # 4. Race Condition Detector
        rc_findings = RaceConditionDetector().scan_content(req.code, req.file_path)
        race_result = {
            "findings": [f.to_dict() for f in rc_findings],
            "count": len(rc_findings),
        }

        # 5. Pre-flight Checklist
        checklist = PreflightChecklistGenerator().generate(
            changed_files=changed_files,
            diff_content=req.code,
        )
        checklist_result = checklist.to_dict()

        # 6. Build Release Readiness inputs from scan results
        owasp_findings_for_rr = [
            {"severity": f["severity"]} for f in owasp_result["findings"]
        ] + [
            {"severity": f["severity"]} for f in secrets_result["findings"]
        ]

        n_violations = (
            owasp_result["critical_count"] + len(secrets_result["findings"])
        )
        # Estimate conformity from findings density
        conformity = max(0.1, 1.0 - owasp_result["risk_score"])

        readiness = ReleaseReadinessScorer().score(
            sdet_result=None,           # no test data in demo mode
            security_findings=owasp_findings_for_rr,
            cve_result=None,
            perf_result=None,
            compliance_result={
                "violations": [{}] * n_violations,
                "conformity_score": conformity,
            },
            architecture_result=None,
        )

    return {
        "success": True,
        "intent_verification": intent_result,
        "owasp": owasp_result,
        "secrets": secrets_result,
        "race_conditions": race_result,
        "preflight_checklist": checklist_result,
        "release_readiness": readiness.to_dict(),
        "summary": {
            "owasp_critical": owasp_result["critical_count"],
            "owasp_high": owasp_result["high_count"],
            "owasp_total": len(owasp_result["findings"]),
            "secrets_found": secrets_result["count"],
            "race_conditions_found": race_result["count"],
            "release_score": readiness.overall_score,
            "recommendation": readiness.recommendation,
        },
    }


# ── Full Pipeline Run — idea → code → commit → scan → fix → PR ────────────────

class PipelineRunRequest(BaseModel):
    description: str
    repo_path: str = ""                     # empty = use isolated temp repo
    file_path: str = "src/feature.py"
    api_key: Optional[str] = None           # Anthropic key; falls back to env var
    github_token: Optional[str] = None      # for push + draft PR on SHIP IT
    auto_fix: bool = True                   # let Claude fix issues and retry
    max_retries: int = 2                    # max fix attempts after first scan
    max_ui_retries: int = 2                 # max UI self-heal attempts post-SHIP


@app.post("/api/pipeline/run", tags=["Pipeline"])
async def pipeline_run(req: PipelineRunRequest):
    """
    The complete AgenticQA loop:
      1. Claude generates code from the user's description.
      2. Code is written to a real file and committed to a branch.
      3. All scanners run on the committed code.
      4. If DO NOT SHIP and auto_fix=True: Claude sees the findings,
         rewrites the code, and the loop repeats (up to max_retries).
      5. If SHIP IT and github_token provided: branch is pushed and
         a draft PR is opened for human review.
    """
    import anthropic as _anthropic
    import subprocess as _sp
    import tempfile as _tmp
    import re as _re
    import urllib.request as _urllib
    import json as _json

    api_key = req.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="No Anthropic API key. Add it in the dashboard sidebar under 'LLM Connection'.",
        )

    try:
        client = _anthropic.Anthropic(api_key=api_key)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid API key: {e}")

    # ── Set up git repo ────────────────────────────────────────────────────────
    use_temp = not req.repo_path or req.repo_path.strip() in ("", ".")
    tmpdir_obj = None

    if use_temp:
        tmpdir_obj = _tmp.TemporaryDirectory()
        repo_path = tmpdir_obj.name
        _sp.run(["git", "init"], cwd=repo_path, capture_output=True)
        _sp.run(["git", "config", "user.email", "agenticqa@localhost"], cwd=repo_path, capture_output=True)
        _sp.run(["git", "config", "user.name", "AgenticQA"], cwd=repo_path, capture_output=True)
        _sp.run(["git", "commit", "--allow-empty", "-m", "init"], cwd=repo_path, capture_output=True)
    else:
        repo_path = req.repo_path

    # ── Create feature branch ──────────────────────────────────────────────────
    slug = _re.sub(r"[^a-z0-9]+", "-", req.description.lower())[:40].strip("-")
    from datetime import datetime as _dt
    branch = f"agenticqa/{slug}-{_dt.now().strftime('%Y%m%d%H%M%S')}"
    _sp.run(["git", "checkout", "-b", branch], cwd=repo_path, capture_output=True)

    # ── Language detection ─────────────────────────────────────────────────────
    ext = req.file_path.rsplit(".", 1)[-1] if "." in req.file_path else "py"
    lang = {"py": "Python", "ts": "TypeScript", "js": "JavaScript",
             "go": "Go", "java": "Java", "swift": "Swift"}.get(ext, "Python")

    system_prompt = (
        f"You are a senior {lang} engineer. Write production-quality implementation "
        f"code for the feature the user describes. Output ONLY raw source code — "
        f"no markdown fences, no explanation. File: {req.file_path}"
    )

    # ── Derived names for test files ──────────────────────────────────────────
    import os as _os2
    module_name = _os2.path.splitext(_os2.path.basename(req.file_path))[0]
    test_filename = f"test_{module_name}.py"

    # ── Generate → test → commit → scan → fix loop ────────────────────────────
    iterations: List[dict] = []
    findings_context = ""

    for attempt in range(1, req.max_retries + 2):
        # Build prompt — on retries, include both security and test failures
        if findings_context:
            user_content = (
                f"Your previous implementation had these issues:\n{findings_context}\n\n"
                f"Rewrite the complete file to fix every issue while still implementing:\n{req.description}"
            )
        else:
            user_content = req.description

        # ── 1. Generate implementation code ───────────────────────────────────
        try:
            msg = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=4096,
                system=system_prompt,
                messages=[{"role": "user", "content": user_content}],
            )
            generated_code = msg.content[0].text
        except _anthropic.AuthenticationError:
            raise HTTPException(status_code=401, detail="Invalid Anthropic API key.")
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Code generation failed: {e}")

        # Write implementation
        full_path = _os2.path.join(repo_path, req.file_path)
        _os2.makedirs(_os2.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as fh:
            fh.write(generated_code)

        # ── 2. Generate tests ──────────────────────────────────────────────────
        try:
            test_code = _generate_tests(
                client, req.description, generated_code, module_name, lang,
                file_path=req.file_path, repo_path=repo_path,
            )
        except Exception:
            test_code = f"# Test generation failed\ndef test_placeholder():\n    pass\n"

        test_path = _os2.path.join(repo_path, test_filename)
        with open(test_path, "w", encoding="utf-8") as fh:
            fh.write(test_code)

        # ── 3. Run tests ───────────────────────────────────────────────────────
        test_results = _run_tests(repo_path, test_filename)

        # ── 4. Commit code + tests ─────────────────────────────────────────────
        commit_msg = (
            f"feat: {req.description[:60]}" if attempt == 1
            else f"fix(agenticqa): address findings — attempt {attempt}"
        )
        _sp.run(["git", "add", req.file_path, test_filename], cwd=repo_path, capture_output=True)
        _sp.run(["git", "commit", "-m", commit_msg], cwd=repo_path, capture_output=True)

        # ── 5. Security scan (with test pass rate feeding readiness score) ─────
        sdet_input = {"current_coverage": test_results["pass_rate"] * 100} if test_results["total"] > 0 else None
        scan = _run_pipeline_on_content(
            code=generated_code,
            file_path=req.file_path,
            changed_files=[req.file_path],
            intent=req.description,
            sdet_result=sdet_input,
        )
        scan["tests"] = test_results
        scan["summary"]["tests_passed"] = test_results["passed"]
        scan["summary"]["tests_failed"] = test_results["failed"]
        scan["summary"]["tests_total"] = test_results["total"]
        scan["summary"]["test_status"] = test_results["status"]

        iterations.append({
            "attempt": attempt,
            "generated_code": generated_code,
            "test_code": test_code,
            "commit": commit_msg,
            "summary": scan["summary"],
            "recommendation": scan["release_readiness"]["recommendation"],
            "test_status": test_results["status"],
        })

        recommendation = scan["release_readiness"]["recommendation"]
        tests_ok = test_results["status"] in ("ALL_PASSED", "SKIPPED", "NO_TESTS_COLLECTED")

        if recommendation == "SHIP IT" and tests_ok:
            break
        if not req.auto_fix or attempt >= req.max_retries + 1:
            break

        # ── 6. Build combined findings context for next attempt ────────────────
        owasp_issues = [
            f"- [SECURITY/{f['severity'].upper()}] {f['description']} line {f['line_number']}: {f['evidence'][:80]}"
            for f in scan["owasp"]["findings"]
        ]
        secret_issues = [
            f"- [SECRET] {f['secret_type']}: {f['evidence']}"
            for f in scan["secrets"]["findings"]
        ]
        blocking = [f"- BLOCKING: {b}" for b in scan["release_readiness"].get("blocking_issues", [])]
        test_failures = [
            f"- [TEST FAILED] {t['name']}"
            for t in test_results["tests"] if t["status"] in ("FAILED", "ERROR")
        ]
        if test_results.get("output") and test_failures:
            test_failures.append(f"  Test output:\n{test_results['output'][:600]}")

        findings_context = "\n".join(owasp_issues + secret_issues + blocking + test_failures)

    # ── Post-SHIP: UI self-healing loop ───────────────────────────────────────
    # After the security + functional fix-loop passes (SHIP IT), run framework-
    # aware UI tests.  If they fail, feed the output back to the LLM, let it
    # rewrite the UI code, re-scan, and re-run — up to max_ui_retries times.
    # This closes the loop: the agent is fully autonomous for the UI layer too.
    ui_test_results: dict = {}
    ui_fix_iterations: list = []
    MAX_UI_RETRIES = getattr(req, "max_ui_retries", 2)

    if recommendation == "SHIP IT":
        try:
            from agenticqa.testing.frontend_test_runner import FrontendTestRunner
            from agenticqa.testing.frontend_test_generator import (
                FrameworkDetector, FrontendTestGenerator,
            )

            detection = FrameworkDetector().detect(repo_path, req.file_path or "")
            is_frontend = detection.framework.value not in ("python", "unknown")

            if is_frontend:
                ui_runner = FrontendTestRunner()
                ui_system_prompt = (
                    f"You are a senior {lang} UI engineer. The following UI code has "
                    f"failing tests. Rewrite the complete file to fix every test failure "
                    f"while preserving all original features. "
                    f"Output ONLY raw source code — no markdown, no explanation. "
                    f"File: {req.file_path}"
                )

                # Read current code from disk (may have been rewritten by fix-loop)
                _full_ui_path = _os2.path.join(repo_path, req.file_path or "")
                _ui_code = (
                    open(_full_ui_path, encoding="utf-8").read()
                    if _os2.path.exists(_full_ui_path) else code
                )

                for ui_attempt in range(MAX_UI_RETRIES + 1):
                    # Generate UI tests for current code
                    _ui_gen = FrontendTestGenerator().generate(
                        description=req.description,
                        code=_ui_code,
                        file_path=req.file_path or "",
                        repo_path=repo_path,
                        detection=detection,
                    )
                    ui_test_results = ui_runner.run_generated(
                        _ui_gen, repo_path, timeout=60
                    )
                    ui_fix_iterations.append({
                        "ui_attempt": ui_attempt + 1,
                        "ui_status": ui_test_results.get("status"),
                        "ui_passed": ui_test_results.get("passed", 0),
                        "ui_failed": ui_test_results.get("failed", 0),
                    })

                    ui_status = ui_test_results.get("status", "")
                    if ui_status in ("ALL_PASSED", "NO_TESTS_COLLECTED"):
                        # UI healthy — keep SHIP IT
                        break

                    if ui_attempt >= MAX_UI_RETRIES:
                        # Exhausted retries — escalate
                        recommendation = "REVIEW REQUIRED"
                        ui_test_results["note"] = (
                            f"UI self-healing exhausted after {MAX_UI_RETRIES + 1} "
                            "attempt(s). Human review required for UI layer."
                        )
                        break

                    # ── UI fix: LLM rewrites the failing UI code ──────────────
                    ui_failures = "\n".join(
                        f"- [{t['status']}] {t['name']}: {t.get('output', '')[:200]}"
                        for t in ui_test_results.get("tests", [])
                        if t["status"] in ("FAILED", "ERROR")
                    )
                    if ui_test_results.get("output"):
                        ui_failures += f"\n\nFull test output:\n{ui_test_results['output'][:800]}"

                    try:
                        ui_fix_msg = client.messages.create(
                            model="claude-haiku-4-5-20251001",
                            max_tokens=4096,
                            system=ui_system_prompt,
                            messages=[{
                                "role": "user",
                                "content": (
                                    f"Current UI code:\n```\n{_ui_code}\n```\n\n"
                                    f"Failing UI tests:\n{ui_failures}\n\n"
                                    f"Fix the code so all tests pass."
                                ),
                            }],
                        )
                        _ui_code = ui_fix_msg.content[0].text

                        # Write fixed code + commit
                        with open(_full_ui_path, "w", encoding="utf-8") as _fh:
                            _fh.write(_ui_code)
                        _sp.run(
                            ["git", "add", req.file_path],
                            cwd=repo_path, capture_output=True,
                        )
                        _sp.run(
                            ["git", "commit", "-m",
                             f"fix(ui): self-heal UI tests — attempt {ui_attempt + 1}"],
                            cwd=repo_path, capture_output=True,
                        )

                        # Re-run security scan on fixed UI code (must still pass)
                        _ui_scan = _run_pipeline_on_content(
                            code=_ui_code,
                            file_path=req.file_path or "",
                            changed_files=[req.file_path] if req.file_path else [],
                            intent=req.description,
                        )
                        if _ui_scan["release_readiness"]["recommendation"] != "SHIP IT":
                            # Security regression introduced — stop
                            recommendation = "REVIEW REQUIRED"
                            ui_test_results["note"] = (
                                "UI self-heal introduced a security issue. "
                                "Human review required."
                            )
                            break
                    except Exception:
                        break  # LLM unavailable — best effort

        except Exception:
            pass  # UI loop is best-effort; never masks a valid security SHIP IT

    # ── Push branch + open draft PR if SHIP IT ────────────────────────────────
    final_scan = scan
    pr_url = None
    branch_pushed = False

    if req.github_token and not use_temp and recommendation == "SHIP IT":
        remote_out = _sp.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_path, capture_output=True, text=True,
        )
        remote = remote_out.stdout.strip()
        match = _re.search(r"github\.com[:/]([^/]+)/([^/.]+)", remote)
        if match:
            owner, repo_name = match.group(1), match.group(2)
            push = _sp.run(
                ["git", "push", "origin", branch],
                cwd=repo_path, capture_output=True, text=True,
            )
            if push.returncode == 0:
                branch_pushed = True
                score = final_scan["summary"]["release_score"]
                t_pass = final_scan["summary"].get("tests_passed", "?")
                t_total = final_scan["summary"].get("tests_total", "?")
                pr_body = (
                    f"**Generated and validated by AgenticQA**\n\n"
                    f"**Release Readiness Score: {score}/100 — SHIP IT ✅**\n\n"
                    f"### Feature\n{req.description}\n\n"
                    f"### Scan Summary\n"
                    f"- Tests: {t_pass}/{t_total} passing\n"
                    f"- OWASP Critical: {final_scan['summary']['owasp_critical']}\n"
                    f"- Secrets: {final_scan['summary']['secrets_found']}\n"
                    f"- Race conditions: {final_scan['summary']['race_conditions_found']}\n"
                    f"- Attempts to pass: {len(iterations)}\n"
                )
                pr_payload = _json.dumps({
                    "title": f"feat: {req.description[:72]}",
                    "body": pr_body,
                    "head": branch,
                    "base": "main",
                    "draft": True,
                }).encode()
                pr_req = _urllib.Request(
                    f"https://api.github.com/repos/{owner}/{repo_name}/pulls",
                    data=pr_payload,
                    headers={
                        "Authorization": f"Bearer {req.github_token}",
                        "Accept": "application/vnd.github+json",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                try:
                    with _urllib.urlopen(pr_req, timeout=15) as pr_resp:
                        pr_url = _json.loads(pr_resp.read())["html_url"]
                except Exception:
                    pass  # PR creation is best-effort

    if tmpdir_obj:
        tmpdir_obj.cleanup()

    return {
        "success": True,
        "description": req.description,
        "branch": branch,
        "attempts": len(iterations),
        "recommendation": recommendation,
        "pr_url": pr_url,
        "branch_pushed": branch_pushed,
        "iterations": iterations,
        "ui_test_results": ui_test_results,
        "ui_fix_iterations": ui_fix_iterations,
        "ui_self_healed": len(ui_fix_iterations) > 1 and recommendation == "SHIP IT",
        **final_scan,
    }


# ── Generate-and-Scan — LLM writes code, scanners run immediately ─────────────

class GenerateAndScanRequest(BaseModel):
    description: str                        # what the user wants built
    file_path: str = "src/feature.py"      # gives Claude language/context hints
    model: str = "claude-haiku-4-5-20251001"
    api_key: Optional[str] = None          # user-supplied; falls back to env var


@app.post("/api/pipeline/generate-and-scan", tags=["Pipeline"])
async def generate_and_scan(req: GenerateAndScanRequest):
    """
    1. Send the user's feature description to Claude.
    2. Claude writes the implementation code.
    3. Run all AgenticQA scanners on the generated code.
    4. Return the full report — no copy-pasting by the user.
    """
    import anthropic as _anthropic

    ext = req.file_path.rsplit(".", 1)[-1] if "." in req.file_path else "py"
    lang_map = {"py": "Python", "ts": "TypeScript", "js": "JavaScript",
                "go": "Go", "java": "Java", "swift": "Swift"}
    lang = lang_map.get(ext, "Python")

    system_prompt = (
        f"You are a senior {lang} engineer. Write production-quality implementation code "
        f"for the feature described by the user. Output ONLY the raw source code — no "
        f"markdown fences, no explanation, no comments beyond inline ones. "
        f"The code will be saved to `{req.file_path}`."
    )

    api_key = req.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="No Anthropic API key provided. Add your key in the dashboard sidebar under 'LLM Connection'.",
        )

    try:
        client = _anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model=req.model,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": req.description}],
        )
        generated_code = message.content[0].text
    except _anthropic.AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid ANTHROPIC_API_KEY — check the key and restart the server.")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM code generation failed: {e}")

    result = _run_pipeline_on_content(
        code=generated_code,
        file_path=req.file_path,
        changed_files=[req.file_path],
        intent=req.description,
    )

    return {
        "success": True,
        "description": req.description,
        "generated_code": generated_code,
        "file_path": req.file_path,
        **result,
    }


# ── Git Diff Scanner — scans actual changed code from a repo ──────────────────

class GitDiffScanRequest(BaseModel):
    repo_path: str = "."
    base_ref: str = "HEAD~1"   # branch, commit, or HEAD~N to diff against
    intent: str = ""           # optional: what the LLM was asked to build
    max_diff_bytes: int = 500_000


def _generate_tests(
    client,
    description: str,
    code: str,
    module_name: str,
    lang: str,
    file_path: str = "",
    repo_path: str = ".",
) -> str:
    """
    Generate tests for the generated code.

    For JS/TS/React/Vue/Angular/Svelte files: uses FrontendTestGenerator to
    produce framework-appropriate tests (Jest, Vitest, etc.) without requiring
    an LLM call — returns static template-based tests immediately.

    For Python/FastAPI/Flask/Django/Streamlit: asks Claude Haiku to write
    pytest tests using the full system prompt.
    """
    # ── Frontend frameworks: use the static generator (no API key needed) ──────
    js_ts_exts = {".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte"}
    if file_path and any(file_path.endswith(ext) for ext in js_ts_exts):
        try:
            from agenticqa.testing.frontend_test_generator import (
                FrontendTestGenerator, FrameworkDetector,
            )
            detection = FrameworkDetector().detect(repo_path, file_path)
            gen = FrontendTestGenerator().generate(
                description, code, file_path, repo_path, detection
            )
            return gen.test_code
        except Exception:
            pass   # fall through to LLM path

    # ── Python / server frameworks: LLM-generated tests ───────────────────────
    # Detect framework-specific test guidance
    framework_hints = ""
    if "streamlit" in code.lower() or "import streamlit" in code:
        framework_hints = (
            "This is a Streamlit app. Use streamlit.testing.v1.AppTest to test it. "
            "Write AppTest.from_file() tests that check the app renders without exception.\n"
        )
    elif "FastAPI" in code or "from fastapi" in code:
        framework_hints = (
            "This is a FastAPI app. Use fastapi.testclient.TestClient to test endpoints. "
            "Import the `app` object and wrap it in TestClient.\n"
        )
    elif "Flask" in code or "from flask" in code:
        framework_hints = (
            "This is a Flask app. Use app.test_client() to test routes. "
            "Import the `app` object and call app.config['TESTING'] = True.\n"
        )

    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=4096,
        system=(
            f"You are a senior {lang} test engineer. Write comprehensive tests.\n"
            f"{framework_hints}"
            f"Rules:\n"
            f"1. Import the module as: import {module_name}  (or from {module_name} import ...)\n"
            f"2. Mock ALL external dependencies with unittest.mock.patch:\n"
            f"   - Database calls (sqlite3.connect, psycopg2, SQLAlchemy)\n"
            f"   - HTTP calls (requests.get/post, httpx, urllib)\n"
            f"   - File I/O, environment variables, subprocess calls\n"
            f"3. Cover: happy path, missing/invalid inputs, auth enforcement, edge cases\n"
            f"4. Include at least one test that verifies security behaviour "
            f"(e.g. unauthenticated request returns 401, not 200)\n"
            f"5. Every test function name starts with test_\n"
            f"6. Add sys.path manipulation if needed for imports\n"
            f"7. Output ONLY raw Python — no markdown fences, no prose"
        ),
        messages=[{
            "role": "user",
            "content": f"Feature: {description}\n\nCode to test:\n{code}",
        }],
    )
    return msg.content[0].text


def _run_tests(repo_path: str, test_filename: str) -> dict:
    """Run pytest on test_filename inside repo_path and return structured results."""
    import subprocess as _sp2
    import os as _os2

    # Write conftest.py so imports resolve regardless of nesting
    conftest = (
        "import sys, os\n"
        "sys.path.insert(0, os.path.dirname(__file__))\n"
        "sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))\n"
    )
    with open(_os2.path.join(repo_path, "conftest.py"), "w") as f:
        f.write(conftest)

    try:
        proc = _sp2.run(
            ["python3", "-m", "pytest", test_filename, "-v", "--tb=short", "--no-header", "-q"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        return {"status": "SKIPPED", "reason": "pytest not available", "passed": 0, "failed": 0, "errors": 0, "total": 0, "pass_rate": 0.0, "tests": [], "output": ""}
    except Exception as e:
        return {"status": "ERROR", "reason": str(e), "passed": 0, "failed": 0, "errors": 0, "total": 0, "pass_rate": 0.0, "tests": [], "output": ""}

    stdout = (proc.stdout or "") + (proc.stderr or "")
    passed, failed, errors, tests = 0, 0, 0, []

    for line in stdout.splitlines():
        if " PASSED" in line and "::" in line:
            name = line.split("::")[-1].split(" PASSED")[0].strip()
            tests.append({"name": name, "status": "PASSED"})
            passed += 1
        elif " FAILED" in line and "::" in line:
            name = line.split("::")[-1].split(" FAILED")[0].strip()
            tests.append({"name": name, "status": "FAILED"})
            failed += 1
        elif " ERROR" in line and "::" in line:
            name = line.split("::")[-1].split(" ERROR")[0].strip()
            tests.append({"name": name, "status": "ERROR"})
            errors += 1

    total = passed + failed + errors
    pass_rate = passed / total if total > 0 else 0.0

    if total == 0:
        status = "NO_TESTS_COLLECTED"
    elif failed == 0 and errors == 0:
        status = "ALL_PASSED"
    elif passed == 0:
        status = "ALL_FAILED"
    else:
        status = "PARTIAL"

    return {
        "status": status,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "total": total,
        "pass_rate": pass_rate,
        "tests": tests,
        "output": stdout[:3000],
    }


def _run_pipeline_on_content(
    code: str,
    file_path: str,
    changed_files: List[str],
    intent: str = "",
    sdet_result: Optional[dict] = None,
) -> dict:
    """Shared pipeline runner used by both /api/pipeline/demo and /api/pipeline/scan-diff."""
    import tempfile, os as _os

    with tempfile.TemporaryDirectory() as tmpdir:
        code_path = _os.path.join(tmpdir, _os.path.basename(file_path) or "code.py")
        with open(code_path, "w", encoding="utf-8") as fh:
            fh.write(code)

        intent_result = None
        if intent:
            verifier = IntentToCodeVerifier(static_only=True)
            intent_result = verifier.verify(intent=intent, code_diff=code, file_path=file_path).to_dict()

        owasp_result = OWASPScanner().scan(tmpdir).to_dict()

    secrets_findings = SecretsHistoryScanner().scan_content(code, file_path)
    secrets_result = {
        "findings": [f.to_dict() for f in secrets_findings],
        "has_live_secrets": any(f.still_present for f in secrets_findings),
        "count": len(secrets_findings),
    }

    rc_findings = RaceConditionDetector().scan_content(code, file_path)
    race_result = {"findings": [f.to_dict() for f in rc_findings], "count": len(rc_findings)}

    checklist = PreflightChecklistGenerator().generate(changed_files=changed_files, diff_content=code)

    owasp_findings_for_rr = [{"severity": f["severity"]} for f in owasp_result["findings"]] + \
                             [{"severity": f["severity"]} for f in secrets_result["findings"]]
    n_violations = owasp_result["critical_count"] + len(secrets_result["findings"])
    conformity = max(0.1, 1.0 - owasp_result["risk_score"])

    readiness = ReleaseReadinessScorer().score(
        sdet_result=sdet_result,
        security_findings=owasp_findings_for_rr,
        compliance_result={"violations": [{}] * n_violations, "conformity_score": conformity},
    )

    return {
        "intent_verification": intent_result,
        "owasp": owasp_result,
        "secrets": secrets_result,
        "race_conditions": race_result,
        "preflight_checklist": checklist.to_dict(),
        "release_readiness": readiness.to_dict(),
        "summary": {
            "owasp_critical": owasp_result["critical_count"],
            "owasp_high": owasp_result["high_count"],
            "owasp_total": len(owasp_result["findings"]),
            "secrets_found": secrets_result["count"],
            "race_conditions_found": race_result["count"],
            "release_score": readiness.overall_score,
            "recommendation": readiness.recommendation,
        },
    }


@app.post("/api/pipeline/scan-diff", tags=["Pipeline"])
async def pipeline_scan_diff(req: GitDiffScanRequest):
    """
    Run the full AgenticQA pipeline against actual changed code in a git repo.
    Diffs base_ref..HEAD, extracts added/modified lines, and runs all scanners.
    This is the real CI workflow — no copy-pasting required.
    """
    import subprocess, tempfile, os as _os

    repo = req.repo_path if req.repo_path != "." else _os.getcwd()

    # Get list of changed files
    try:
        files_out = subprocess.run(
            ["git", "diff", "--name-only", req.base_ref],
            cwd=repo, capture_output=True, text=True, timeout=30,
        )
        if files_out.returncode != 0:
            # Try staged changes if base_ref diff fails
            files_out = subprocess.run(
                ["git", "diff", "--name-only", "--cached"],
                cwd=repo, capture_output=True, text=True, timeout=30,
            )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="git diff timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=400, detail="git not found or repo_path is not a git repo")

    changed_files = [f for f in files_out.stdout.strip().splitlines() if f]
    if not changed_files:
        return {"success": True, "message": "No changed files detected", "changed_files": [], "summary": {}}

    # Get the full diff content (added lines only across all changed files)
    try:
        diff_out = subprocess.run(
            ["git", "diff", req.base_ref, "--", *changed_files],
            cwd=repo, capture_output=True, text=True, timeout=60,
        )
        diff_text = diff_out.stdout[:req.max_diff_bytes]
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="git diff content timed out")

    # Extract only added lines from the unified diff
    added_lines = [
        line[1:]  # strip the leading +
        for line in diff_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    code = "\n".join(added_lines)

    if not code.strip():
        return {"success": True, "message": "No added lines in diff", "changed_files": changed_files, "summary": {}}

    # Use first changed file for language/context detection
    primary_file = changed_files[0]

    result = _run_pipeline_on_content(
        code=code,
        file_path=primary_file,
        changed_files=changed_files,
        intent=req.intent,
    )
    return {
        "success": True,
        "repo_path": repo,
        "base_ref": req.base_ref,
        "changed_files": changed_files,
        **result,
    }



# ── Onboarding — first-run client experience ────────────────────────────────────

class OnboardingRunRequest(BaseModel):
    repo_path: str = "."
    github_token: str = ""
    github_repo: str = ""          # "owner/repo" — required for PR creation
    create_pr: bool = False
    max_generated: int = 10


@app.post("/api/onboarding/run", tags=["Onboarding"])
async def onboarding_run(req: OnboardingRunRequest):
    """
    Phase 1–5 first-run onboarding scan.

    Runs ArchitectureScanner + 7 security sweeps + CoverageMapper + test
    generation + baseline snapshot.  Returns the full OnboardingReport as
    a JSON dict.
    """
    from agenticqa.onboarding.repo_onboarder import RepoOnboarder

    try:
        report = RepoOnboarder().run(
            repo_path=req.repo_path,
            github_token=req.github_token,
            github_repo=req.github_repo,
            create_pr=req.create_pr,
            max_generated=req.max_generated,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {"success": True, **report.to_dict()}


@app.get("/api/onboarding/status", tags=["Onboarding"])
async def onboarding_status(repo_path: str = "."):
    """
    Return the stored baseline for a repo (if it exists), without running a
    full scan.  Useful for the dashboard to show the last-known state.
    """
    import hashlib
    import json
    from pathlib import Path

    resolved = str(Path(repo_path).resolve())
    repo_id = hashlib.md5(resolved.encode()).hexdigest()[:12]
    baseline_path = Path.home() / ".agenticqa" / "baselines" / f"{repo_id}.json"

    if not baseline_path.exists():
        return {"success": True, "baseline": None, "repo_id": repo_id}

    try:
        data = json.loads(baseline_path.read_text())
        return {"success": True, "baseline": data, "repo_id": repo_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))



# ── Post-SHIP UI Test Scan ─────────────────────────────────────────────────────
# Runs after a SHIP IT verdict to verify the new feature doesn't break existing
# UI tests.  Can also be called explicitly (e.g. from CD pipeline, post-deploy).

class UITestScanRequest(BaseModel):
    description: str = ""
    code: str = ""
    file_path: str = ""
    repo_path: str = "."
    timeout: int = 60


@app.post("/api/pipeline/ui-test-scan", tags=["Pipeline"])
async def ui_test_scan(req: UITestScanRequest):
    """
    Run framework-aware UI tests against generated (or existing) frontend code.

    Detects the frontend framework (Streamlit, React/Jest, Vue/Vitest, etc.),
    generates headless tests, runs them, and returns pass/fail with detailed output.

    Typical usage:
      1. After a SHIP IT verdict — verify the new feature didn't break the UI.
      2. After deployment — smoke-test the running frontend.
      3. As a standalone CI step.
    """
    from agenticqa.testing.frontend_test_runner import FrontendTestRunner
    from agenticqa.testing.frontend_test_generator import FrameworkDetector

    detection = FrameworkDetector().detect(req.repo_path, req.file_path)

    if detection.framework.value in ("python", "unknown") and not req.code:
        return {
            "success": True,
            "skipped": True,
            "reason": "No frontend framework detected — nothing to UI-test.",
            "framework": detection.framework.value,
        }

    try:
        runner = FrontendTestRunner()
        if req.code:
            result = runner.run(
                description=req.description or f"UI test for {req.file_path}",
                code=req.code,
                file_path=req.file_path,
                repo_path=req.repo_path,
                timeout=req.timeout,
            )
        else:
            # No code provided — generate + run tests for the file at file_path
            from agenticqa.testing.frontend_test_generator import FrontendTestGenerator
            from pathlib import Path
            abs_path = Path(req.repo_path) / req.file_path
            code = abs_path.read_text(encoding="utf-8", errors="ignore")[:8000] if abs_path.exists() else ""
            gen = FrontendTestGenerator().generate(
                description=req.description or f"UI test for {req.file_path}",
                code=code,
                file_path=req.file_path,
                repo_path=req.repo_path,
                detection=detection,
            )
            result = runner.run_generated(gen, req.repo_path, timeout=req.timeout)

        verdict = "✅ UI TESTS PASSED" if result["status"] == "ALL_PASSED" else "⚠️ UI TESTS FAILED"
        return {
            "success": True,
            "verdict": verdict,
            "framework": detection.framework.value,
            **result,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Landing page demo endpoint ────────────────────────────────────────────────

class DemoSubmitRequest(BaseModel):
    description: str
    repo_path: str = "."


@app.post("/api/demo/submit", tags=["Demo"])
async def demo_submit(req: DemoSubmitRequest):
    """
    Lightweight pipeline entry-point for the landing page.

    Steps:
      1. Architecture scan (attack surface score)
      2. Coverage map before
      3. Generate UI code stub
      4. Security scan on generated code
      5. Generate + run UI tests
      6. Coverage map after
      Returns a simplified verdict dict consumed by the landing page JS.
    """
    import time
    import textwrap

    t0 = time.time()

    try:
        from agenticqa.security.architecture_scanner import ArchitectureScanner
        from agenticqa.onboarding.coverage_mapper import CoverageMapper
        from agenticqa.testing.frontend_test_runner import FrontendTestRunner
        from agenticqa.testing.frontend_test_generator import FrameworkDetector, FrontendTestGenerator
    except ImportError:
        from src.agenticqa.security.architecture_scanner import ArchitectureScanner
        from src.agenticqa.onboarding.coverage_mapper import CoverageMapper
        from src.agenticqa.testing.frontend_test_runner import FrontendTestRunner
        from src.agenticqa.testing.frontend_test_generator import FrameworkDetector, FrontendTestGenerator

    repo = req.repo_path or "."

    # 1. Architecture scan
    try:
        arch = ArchitectureScanner().scan(repo)
        attack_surface = arch.attack_surface_score
        files_scanned  = arch.files_scanned
    except Exception:
        attack_surface = 0.0
        files_scanned  = 0

    # 2. Coverage before
    try:
        cov_before = CoverageMapper().scan(repo).coverage_pct
    except Exception:
        cov_before = 0.0

    # 3. UI code stub (same stub used by run_demo.py)
    ui_code = textwrap.dedent("""\
        \"\"\"Streamlit UI for {desc}\"\"\"
        import os, requests, streamlit as st
        API_BASE = os.environ.get("API_BASE", "http://localhost:8000")
        st.title("Feature UI")
        with st.form("form", clear_on_submit=True):
            val = st.text_input("Input")
            if st.form_submit_button("Submit"):
                try:
                    requests.post(f"{{API_BASE}}/api/feature", json={{"value": val}}, timeout=5)
                    st.success("Done!")
                except Exception as exc:
                    st.error(str(exc))
    """).format(desc=req.description[:60])

    ui_file = "ui/feature.py"
    ui_abs  = Path(repo) / ui_file
    try:
        ui_abs.parent.mkdir(parents=True, exist_ok=True)
        ui_abs.write_text(ui_code, encoding="utf-8")
    except Exception:
        pass

    # 4. Security scan
    try:
        scan_result = ArchitectureScanner().scan(repo)
        ui_areas    = [a for a in scan_result.integration_areas
                       if "feature" in a.source_file or a.source_file == ui_file]
        critical_ct = sum(1 for a in ui_areas if a.severity == "critical")
        high_ct     = sum(1 for a in ui_areas if a.severity == "high")
    except Exception:
        critical_ct = 0
        high_ct     = 0

    # 5. UI tests
    ui_status = "NO_TESTS_COLLECTED"
    passed_ct = 0
    total_ct  = 0
    try:
        detection = FrameworkDetector().detect(repo, ui_file)
        gen       = FrontendTestGenerator().generate(
            description=req.description, code=ui_code,
            file_path=ui_file, repo_path=repo, detection=detection,
        )
        ui_result  = FrontendTestRunner().run_generated(gen, repo, timeout=30)
        ui_status  = ui_result.get("status", "NO_TESTS_COLLECTED")
        passed_ct  = ui_result.get("passed", 0)
        total_ct   = ui_result.get("total", 0)
    except Exception:
        pass

    # 6. Coverage after
    try:
        cov_after = CoverageMapper().scan(repo).coverage_pct
    except Exception:
        cov_after = cov_before

    elapsed = round(time.time() - t0, 1)
    verdict = (
        "SHIP IT"
        if critical_ct == 0 and ui_status in ("ALL_PASSED", "NO_TESTS_COLLECTED")
        else "REVIEW REQUIRED"
    )

    return {
        "verdict":      verdict,
        "elapsed_s":    elapsed,
        "files_scanned": files_scanned,
        "security": {
            "critical":       critical_ct,
            "high":           high_ct,
            "attack_surface": round(attack_surface, 1),
        },
        "tests": {
            "passed": passed_ct,
            "total":  total_ct,
            "status": ui_status,
        },
        "coverage": {
            "before": cov_before,
            "after":  cov_after,
        },
    }


# ── Workspace endpoints ──────────────────────────────────────────────────────


@app.get("/api/workspace/files", tags=["Workspace"])
async def workspace_list_files(path: str = ""):
    """List files in the sandboxed workspace."""
    from agenticqa.workspace.file_manager import SandboxedFileManager
    fm = SandboxedFileManager()
    result = fm.list_dir(path)
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    entries = []
    for e in (result.data or []):
        entries.append({
            "name": e.name, "path": e.path, "is_dir": e.is_dir,
            "size": e.size, "modified": e.modified, "mime_type": e.mime_type,
        })
    return {"success": True, "path": path, "entries": entries}


@app.get("/api/workspace/files/read", tags=["Workspace"])
async def workspace_read_file(path: str):
    """Read a text file from the sandboxed workspace."""
    from agenticqa.workspace.file_manager import SandboxedFileManager
    fm = SandboxedFileManager()
    result = fm.read_file(path)
    if not result.success:
        code = 403 if result.blocked_reason == "path_traversal" else 400
        raise HTTPException(status_code=code, detail=result.error)
    return {"success": True, "path": path, "content": result.data}


@app.post("/api/workspace/files/write", tags=["Workspace"])
async def workspace_write_file(body: dict):
    """Write a text file to the sandboxed workspace."""
    path = body.get("path", "")
    content = body.get("content", "")
    if not path:
        raise HTTPException(status_code=400, detail="path is required")

    from agenticqa.workspace.file_manager import SandboxedFileManager
    from agenticqa.workspace.workspace_safety import WorkspaceSafetyGate
    gate = WorkspaceSafetyGate(session_id="api")
    verdict = gate.check("file_write", {"path": path})
    if not verdict.allowed:
        raise HTTPException(status_code=403, detail=verdict.block_reason)

    fm = SandboxedFileManager()
    result = fm.write_file(path, content)
    if not result.success:
        code = 403 if result.blocked_reason else 400
        raise HTTPException(status_code=code, detail=result.error)
    return {"success": True, "path": path}


@app.delete("/api/workspace/files", tags=["Workspace"])
async def workspace_delete_file(path: str):
    """Delete a file from the sandboxed workspace (requires safety check)."""
    from agenticqa.workspace.file_manager import SandboxedFileManager
    from agenticqa.workspace.workspace_safety import WorkspaceSafetyGate
    gate = WorkspaceSafetyGate(session_id="api")
    verdict = gate.check("file_delete", {"path": path})
    if not verdict.allowed:
        if verdict.requires_approval:
            return {
                "success": False,
                "requires_approval": True,
                "approval_token": verdict.approval_token,
                "reason": verdict.block_reason,
            }
        raise HTTPException(status_code=403, detail=verdict.block_reason)

    fm = SandboxedFileManager()
    result = fm.delete_file(path)
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    return {"success": True, "path": path}


@app.post("/api/workspace/files/mkdir", tags=["Workspace"])
async def workspace_mkdir(body: dict):
    """Create a directory in the sandboxed workspace."""
    path = body.get("path", "")
    if not path:
        raise HTTPException(status_code=400, detail="path is required")
    from agenticqa.workspace.file_manager import SandboxedFileManager
    fm = SandboxedFileManager()
    result = fm.mkdir(path)
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    return {"success": True, "path": path}


@app.get("/api/workspace/files/info", tags=["Workspace"])
async def workspace_info():
    """Get workspace usage statistics."""
    from agenticqa.workspace.file_manager import SandboxedFileManager
    fm = SandboxedFileManager()
    return {"success": True, **fm.get_workspace_info()}


# ── Mail endpoints ───────────────────────────────────────────────────────────


@app.get("/api/workspace/mail/folders", tags=["Workspace"])
async def workspace_mail_folders():
    """List IMAP mail folders."""
    from agenticqa.workspace.mail_client import SafeMailClient
    client = SafeMailClient()
    result = client.list_folders()
    client.close()
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    return {"success": True, "folders": result.data}


@app.get("/api/workspace/mail/messages", tags=["Workspace"])
async def workspace_mail_messages(folder: str = "INBOX", limit: int = 25):
    """List recent messages from a folder."""
    from agenticqa.workspace.mail_client import SafeMailClient
    client = SafeMailClient()
    result = client.list_messages(folder=folder, limit=limit)
    client.close()
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    return {"success": True, "folder": folder, "messages": result.data}


@app.get("/api/workspace/mail/read", tags=["Workspace"])
async def workspace_mail_read(uid: str, folder: str = "INBOX"):
    """Read a single email by UID."""
    from agenticqa.workspace.mail_client import SafeMailClient
    client = SafeMailClient()
    result = client.read_message(uid=uid, folder=folder)
    client.close()
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    msg = result.data
    return {
        "success": True,
        "message": {
            "uid": msg.uid, "subject": msg.subject, "sender": msg.sender,
            "to": msg.to, "date": msg.date, "body_plain": msg.body_plain,
            "body_html": msg.body_html, "has_attachments": msg.has_attachments,
            "folder": msg.folder,
        },
    }


@app.post("/api/workspace/mail/send", tags=["Workspace"])
async def workspace_mail_send(body: dict):
    """Send an email (requires safety approval)."""
    to = body.get("to", "")
    subject = body.get("subject", "")
    mail_body = body.get("body", "")
    approved = body.get("approved", False)

    if not to or not subject:
        raise HTTPException(status_code=400, detail="to and subject required")

    from agenticqa.workspace.mail_client import SafeMailClient
    from agenticqa.workspace.workspace_safety import WorkspaceSafetyGate

    gate = WorkspaceSafetyGate(session_id="api")
    verdict = gate.check("mail_send", {"to": to, "subject": subject})
    if not verdict.allowed:
        return {
            "success": False,
            "requires_approval": verdict.requires_approval,
            "approval_token": verdict.approval_token,
            "reason": verdict.block_reason,
        }

    client = SafeMailClient()
    result = client.send_message(to, subject, mail_body, approved=approved)
    client.close()
    if not result.success:
        if result.requires_approval:
            return {"success": False, "requires_approval": True,
                    "reason": result.error}
        raise HTTPException(status_code=400, detail=result.error)
    return {"success": True, "sent_to": to, "subject": subject}


# ── Link endpoints ───────────────────────────────────────────────────────────


@app.post("/api/workspace/links/fetch", tags=["Workspace"])
async def workspace_link_fetch(body: dict):
    """Fetch a URL safely (with SSRF prevention + output scanning)."""
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="url is required")
    from agenticqa.workspace.link_tools import SafeLinkManager
    mgr = SafeLinkManager()
    result = mgr.fetch_url(url)
    if not result.success:
        code = 403 if result.blocked_reason else 400
        raise HTTPException(status_code=code, detail=result.error)
    return {
        "success": True, "url": result.url,
        "status_code": result.status_code,
        "content_type": result.content_type,
        "text": result.text[:50000],  # cap response size
        "scan_flags": result.scan_flags,
    }


@app.get("/api/workspace/links/bookmarks", tags=["Workspace"])
async def workspace_list_bookmarks(tag: Optional[str] = None):
    """List saved bookmarks."""
    from agenticqa.workspace.link_tools import SafeLinkManager
    mgr = SafeLinkManager()
    result = mgr.list_bookmarks(tag=tag)
    return {"success": True, "bookmarks": result.data}


@app.post("/api/workspace/links/bookmarks", tags=["Workspace"])
async def workspace_add_bookmark(body: dict):
    """Add a bookmark."""
    url = body.get("url", "")
    title = body.get("title", "")
    tags = body.get("tags", [])
    if not url:
        raise HTTPException(status_code=400, detail="url is required")
    from agenticqa.workspace.link_tools import SafeLinkManager
    mgr = SafeLinkManager()
    result = mgr.add_bookmark(url, title=title, tags=tags)
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    return {"success": True, **result.data}


@app.delete("/api/workspace/links/bookmarks", tags=["Workspace"])
async def workspace_delete_bookmark(bookmark_id: str):
    """Delete a bookmark by ID."""
    from agenticqa.workspace.link_tools import SafeLinkManager
    mgr = SafeLinkManager()
    result = mgr.delete_bookmark(bookmark_id)
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    return {"success": True}


@app.get("/api/workspace/safety/status", tags=["Workspace"])
async def workspace_safety_status():
    """Get current workspace safety status (lease, pending approvals)."""
    from agenticqa.workspace.workspace_safety import WorkspaceSafetyGate
    gate = WorkspaceSafetyGate(session_id="api")
    return {
        "success": True,
        "lease": gate.get_lease_status(),
        "pending_approvals": gate.get_pending_approvals(),
    }


@app.post("/api/workspace/safety/emergency-stop", tags=["Workspace"])
async def workspace_emergency_stop():
    """Emergency stop — revoke ALL active workspace leases immediately.

    Inspired by Meta/OpenClaw incident (2026-02-23): operator had to
    physically sprint to kill the process.  This endpoint provides a
    single-click kill switch.
    """
    from agenticqa.workspace.workspace_safety import WorkspaceSafetyGate
    gate = WorkspaceSafetyGate(session_id="emergency")
    result = gate.emergency_stop()
    return {"success": True, **result}


@app.get("/api/workspace/safety/invariants", tags=["Workspace"])
async def workspace_safety_invariants():
    """Return safety invariants for prompt re-injection after compaction."""
    from agenticqa.workspace.workspace_safety import (
        WORKSPACE_SAFETY_INVARIANTS,
        get_safety_invariants_prompt,
    )
    return {
        "success": True,
        "invariants": WORKSPACE_SAFETY_INVARIANTS,
        "prompt": get_safety_invariants_prompt(),
    }


# ── PII Redaction endpoints ──────────────────────────────────────────────────


@app.post("/api/security/pii-redact", tags=["Security"])
async def pii_redact(request: Request):
    """Redact PII from agent output (dict/list/string)."""
    from agenticqa.security.pii_redactor import PIIRedactor
    body = await request.json()
    text = body.get("text", "")
    data = body.get("data")
    redactor = PIIRedactor()
    if data is not None:
        report = redactor.redact(data)
    else:
        redacted, events = redactor.redact_text(text)
        report_dict = {
            "redacted_text": redacted,
            "redaction_count": len(events),
            "events": [{"pii_type": e.pii_type, "replacement": e.replacement} for e in events],
        }
        return report_dict
    return {
        "clean": report.clean,
        "redaction_count": report.redaction_count,
        "redacted_output": report.redacted_output,
        "events": [{"pii_type": e.pii_type, "field_path": e.field_path, "replacement": e.replacement} for e in report.events],
    }


@app.post("/api/security/pii-scan", tags=["Security"])
async def pii_scan(request: Request):
    """Detect PII without modifying output (dry run)."""
    from agenticqa.security.pii_redactor import PIIRedactor
    body = await request.json()
    data = body.get("data", body.get("text", ""))
    redactor = PIIRedactor()
    report = redactor.scan_only(data)
    return {
        "clean": report.clean,
        "redaction_count": report.redaction_count,
        "events": [{"pii_type": e.pii_type, "field_path": e.field_path} for e in report.events],
    }


# ── Shadow AI Detection endpoints ───────────────────────────────────────────


@app.post("/api/security/shadow-ai-scan", tags=["Security"])
async def shadow_ai_scan(request: Request):
    """Scan source code for unauthorized AI model usage."""
    from agenticqa.security.shadow_ai_detector import ShadowAIDetector
    body = await request.json()
    text = body.get("text", "")
    approved_models = body.get("approved_models")
    approved_providers = body.get("approved_providers")
    detector = ShadowAIDetector(
        approved_models=set(approved_models) if approved_models else None,
        approved_providers=set(approved_providers) if approved_providers else None,
    )
    report = detector.scan_text(text)
    return {
        "has_shadow_ai": report.has_shadow_ai,
        "total_findings": report.total_findings,
        "providers_found": sorted(report.providers_found),
        "findings": [
            {"rule_id": f.rule_id, "provider": f.provider, "model_id": f.model_id,
             "evidence": f.evidence[:200], "severity": f.severity}
            for f in report.findings
        ],
    }


# ── Cost Tracker endpoints ──────────────────────────────────────────────────


@app.post("/api/security/cost-record", tags=["Security"])
async def cost_record(request: Request):
    """Record an LLM API call for cost tracking."""
    from agenticqa.security.cost_tracker import CostTracker
    body = await request.json()
    tracker = CostTracker()
    record = tracker.record(
        agent_id=body["agent_id"],
        model=body["model"],
        input_tokens=body["input_tokens"],
        output_tokens=body["output_tokens"],
        session_id=body.get("session_id", ""),
        team=body.get("team", ""),
    )
    return {
        "estimated_cost_usd": record.estimated_cost_usd,
        "timestamp": record.timestamp,
    }


@app.post("/api/security/cost-check", tags=["Security"])
async def cost_check(request: Request):
    """Check if an agent has budget remaining."""
    from agenticqa.security.cost_tracker import CostTracker
    body = await request.json()
    tracker = CostTracker()
    result = tracker.check_quota(
        agent_id=body["agent_id"],
        model=body.get("model", ""),
        estimated_tokens=body.get("estimated_tokens", 0),
    )
    return {
        "allowed": result.allowed,
        "current_cost_usd": result.current_cost_usd,
        "remaining_budget_usd": result.remaining_budget_usd,
        "remaining_tokens": result.remaining_tokens,
        "alert": result.alert,
        "block_reason": result.block_reason,
    }


@app.get("/api/security/cost-summary", tags=["Security"])
async def cost_summary():
    """Get cost summaries for all agents."""
    from agenticqa.security.cost_tracker import CostTracker
    tracker = CostTracker()
    return {
        "total_cost_usd": tracker.get_total_cost(),
        "agents": tracker.get_all_summaries(),
    }


# ── Bias Detection endpoints ────────────────────────────────────────────────


@app.post("/api/security/bias-scan", tags=["Security"])
async def bias_scan(request: Request):
    """Scan agent output for bias and fairness concerns."""
    from agenticqa.security.bias_detector import BiasDetector
    body = await request.json()
    text = body.get("text", "")
    data = body.get("data")
    sensitivity = body.get("sensitivity", "standard")
    detector = BiasDetector(sensitivity=sensitivity)
    if data is not None:
        report = detector.scan_dict(data)
    else:
        report = detector.scan(text)
    return {
        "has_bias_risk": report.has_bias_risk,
        "risk_score": report.risk_score,
        "total_findings": report.total_findings,
        "categories_flagged": sorted(report.categories_flagged),
        "protected_attrs_detected": report.protected_attrs_detected,
        "findings": [
            {"rule_id": f.rule_id, "category": f.category, "severity": f.severity,
             "evidence": f.evidence[:200], "recommendation": f.recommendation}
            for f in report.findings
        ],
    }


# ── Indirect Injection Guard endpoints ──────────────────────────────────────


@app.post("/api/security/injection-scan", tags=["Security"])
async def injection_scan(request: Request):
    """Scan document for indirect prompt injection before RAG ingest."""
    from agenticqa.security.indirect_injection_guard import IndirectInjectionGuard
    body = await request.json()
    text = body.get("text", "")
    strict = body.get("strict", False)
    source_type = body.get("source_type", "document")
    source_id = body.get("source_id", "")
    guard = IndirectInjectionGuard(strict=strict)
    result = guard.scan_for_rag_ingest(text, source_type=source_type, source_id=source_id)
    return result


# ── Badge endpoint (shields.io compatible) ─────────────────────────────────

@app.get("/api/badge", tags=["Badge"])
async def badge(label: str = "AgenticQA", status: str = "scanned", color: str = "brightgreen"):
    """Return a shields.io-compatible JSON badge.

    Usage in README:
      ![AgenticQA](https://img.shields.io/endpoint?url=<your-api>/api/badge)

    Or with custom params from a scan result:
      ![AgenticQA](https://img.shields.io/endpoint?url=<your-api>/api/badge?status=low%20risk&color=brightgreen)
    """
    return {
        "schemaVersion": 1,
        "label": label,
        "message": status,
        "color": color,
        "namedLogo": "shield",
    }


@app.get("/api/badge/scan", tags=["Badge"])
async def badge_scan(repo: str = ""):
    """Dynamic badge that reflects the latest cached scan result.

    Reads agenticqa-results.json from the repo if it exists, otherwise returns
    a 'no data' badge. Designed for shields.io endpoint badge integration.
    """
    if not repo:
        return {"schemaVersion": 1, "label": "AgenticQA", "message": "no data", "color": "lightgrey"}

    # Try to load cached results
    results_path = Path(repo) / "agenticqa-results.json"
    if not results_path.exists():
        return {"schemaVersion": 1, "label": "AgenticQA", "message": "not scanned", "color": "lightgrey"}

    try:
        with open(results_path) as f:
            data = json.load(f)
        summary = data.get("summary", {})
        risk = summary.get("risk_level", "unknown")
        findings = summary.get("total_findings", 0)
        critical = summary.get("total_critical", 0)

        color_map = {"critical": "red", "high": "orange", "medium": "yellow", "low": "brightgreen"}
        color = color_map.get(risk, "lightgrey")

        if critical > 0:
            message = f"{critical} critical"
        elif findings > 0:
            message = f"{findings} findings"
        else:
            message = "clean"

        return {"schemaVersion": 1, "label": "AgenticQA", "message": message, "color": color}
    except Exception:
        return {"schemaVersion": 1, "label": "AgenticQA", "message": "error", "color": "red"}


# ── Autonomous Fix PR endpoint ─────────────────────────────────────────────

@app.post("/api/remediation/auto-fix", tags=["Remediation"])
async def auto_fix_pr(request: Request):
    """Generate fixes for scan findings and optionally open a draft PR.

    Body:
        scan_results: dict — output from scan_repo() or GitHub Action
        repo_path: str — path to the git repository
        github_token: str — optional, for PR creation
        base_branch: str — default "main"
        dry_run: bool — default false
    """
    from agenticqa.remediation.auto_fix_pr import generate_fix_pr
    body = await request.json()
    result = generate_fix_pr(
        repo_path=sanitize_repo_path(body.get("repo_path", ".")),
        scan_results=body.get("scan_results", {}),
        github_token=body.get("github_token", ""),
        base_branch=body.get("base_branch", "main"),
        dry_run=body.get("dry_run", False),
    )
    return result.to_dict()


@app.post("/api/remediation/extract-findings", tags=["Remediation"])
async def extract_findings(request: Request):
    """Extract fixable findings from scan results without applying fixes."""
    from agenticqa.remediation.auto_fix_pr import extract_fixable_findings
    body = await request.json()
    patches = extract_fixable_findings(body.get("scan_results", {}))
    return {
        "fixable_count": len(patches),
        "patches": [
            {"file": p.file, "line": p.line, "scanner": p.scanner,
             "rule_id": p.rule_id, "severity": p.severity,
             "description": p.description, "fix": p.fix_description}
            for p in patches
        ],
    }


# ── Scan Trend endpoints ──────────────────────────────────────────────────

@app.post("/api/scan-trend/record", tags=["Scan Trends"])
async def scan_trend_record(request: Request):
    """Record a scan result for trend tracking."""
    from agenticqa.monitoring.scan_trend import ScanTrendAggregator
    body = await request.json()
    agg = ScanTrendAggregator()
    snapshot = agg.record(body.get("scan_output", {}), repo_id=body.get("repo_id", ""))
    return snapshot.to_dict()


@app.get("/api/scan-trend/history", tags=["Scan Trends"])
async def scan_trend_history(repo_id: str = "", limit: int = 50):
    """Get scan history for a repo (or all repos)."""
    from agenticqa.monitoring.scan_trend import ScanTrendAggregator
    agg = ScanTrendAggregator()
    return {"history": agg.history(repo_id=repo_id, limit=limit)}


@app.get("/api/scan-trend/trend", tags=["Scan Trends"])
async def scan_trend_direction(repo_id: str = "", window: int = 10):
    """Get trend direction (improving/stable/worsening)."""
    from agenticqa.monitoring.scan_trend import ScanTrendAggregator
    agg = ScanTrendAggregator()
    return agg.trend(repo_id=repo_id, window=window)


@app.get("/api/scan-trend/org-rollup", tags=["Scan Trends"])
async def scan_trend_org_rollup(limit: int = 100):
    """Aggregate scan data across all repos for org-level view."""
    from agenticqa.monitoring.scan_trend import ScanTrendAggregator
    agg = ScanTrendAggregator()
    return agg.org_rollup(limit=limit)


# ── Load Test endpoints ────────────────────────────────────────────────────

@app.get("/api/loadtest/history", tags=["Load Test"])
async def loadtest_history(limit: int = 50):
    """Get load test run history."""
    from agenticqa.loadtest.results import LoadTestAnalyzer
    analyzer = LoadTestAnalyzer()
    return {"history": analyzer.history(limit=limit)}


@app.get("/api/loadtest/trend", tags=["Load Test"])
async def loadtest_trend(window: int = 10):
    """Get load test performance trend (improving/stable/degrading)."""
    from agenticqa.loadtest.results import LoadTestAnalyzer
    analyzer = LoadTestAnalyzer()
    return analyzer.trend(window=window)


# ── Compliance Report endpoint ─────────────────────────────────────────────

@app.post("/api/compliance/report", tags=["Compliance"])
async def compliance_report(request: Request):
    """Generate a compliance report from scan results.

    Body:
        scan_output: dict — scan results
        repo_id: str
        frameworks: list[str] — optional, default all
        format: str — "json" | "markdown" | "html"
    """
    from agenticqa.compliance.report_generator import ComplianceReportGenerator
    body = await request.json()
    gen = ComplianceReportGenerator()
    report = gen.generate(
        scan_output=body.get("scan_output", {}),
        repo_id=body.get("repo_id", ""),
        frameworks=body.get("frameworks"),
    )
    fmt = body.get("format", "json")
    if fmt == "markdown":
        return {"format": "markdown", "content": gen.to_markdown(report)}
    if fmt == "html":
        from fastapi.responses import HTMLResponse
        return HTMLResponse(gen.to_html(report))
    return report.to_dict()


# ── Security Benchmarking endpoint ─────────────────────────────────────────

@app.post("/api/benchmark", tags=["Benchmark"])
async def security_benchmark(request: Request):
    """Benchmark scan results against known AI frameworks.

    Body:
        scan_output: dict — scan results from scan_repo()
    """
    from agenticqa.scoring.security_benchmark import benchmark_scan
    body = await request.json()
    result = benchmark_scan(body.get("scan_output", {}))
    return result.to_dict()


# ── Custom Rules endpoints ─────────────────────────────────────────────────

@app.post("/api/custom-rules/scan", tags=["Custom Rules"])
async def custom_rules_scan(request: Request):
    """Scan a repo with custom rules.

    Body:
        repo_path: str — path to scan
        rules: list[dict] — optional inline rules
    """
    from agenticqa.security.custom_rules import CustomRuleEngine, CustomRule
    body = await request.json()
    repo_path = sanitize_repo_path(body.get("repo_path", "."))
    engine = CustomRuleEngine()
    engine.load_from_repo(repo_path)
    engine.load_global()
    # Also accept inline rules
    for rd in body.get("rules", []):
        if rd.get("id") and rd.get("pattern"):
            engine.add_rule(CustomRule(
                id=rd["id"], name=rd.get("name", rd["id"]),
                description=rd.get("description", ""), severity=rd.get("severity", "medium"),
                pattern=rd["pattern"], file_pattern=rd.get("file_pattern", "*"),
                message=rd.get("message", ""), tags=rd.get("tags", []),
            ))
    result = engine.scan(repo_path)
    return result.to_dict()


@app.post("/api/custom-rules/save", tags=["Custom Rules"])
async def custom_rules_save(request: Request):
    """Save custom rules to a repo's .agenticqa/custom_rules.json.

    Body:
        repo_path: str
        rules: list[dict]
    """
    from agenticqa.security.custom_rules import CustomRuleEngine, CustomRule
    body = await request.json()
    repo_path = sanitize_repo_path(body.get("repo_path", "."))
    engine = CustomRuleEngine()
    for rd in body.get("rules", []):
        if rd.get("id") and rd.get("pattern"):
            engine.add_rule(CustomRule(
                id=rd["id"], name=rd.get("name", rd["id"]),
                description=rd.get("description", ""), severity=rd.get("severity", "medium"),
                pattern=rd["pattern"], file_pattern=rd.get("file_pattern", "*"),
                message=rd.get("message", ""), tags=rd.get("tags", []),
            ))
    path = engine.save_to_repo(repo_path)
    return {"saved": True, "path": str(path), "rules_count": len(engine.rules)}


# ── Slack / Teams Notification endpoints ───────────────────────────────────

@app.post("/api/notifications/slack", tags=["Notifications"])
async def notify_slack(request: Request):
    """Send scan results to Slack.

    Body:
        scan_output: dict — scan results
        webhook_url: str — optional override (else uses AGENTICQA_SLACK_WEBHOOK_URL)
    """
    from agenticqa.notifications.slack import SlackNotifier
    body = await request.json()
    notifier = SlackNotifier(webhook_url=body.get("webhook_url"))
    result = notifier.notify_scan(body.get("scan_output", {}))
    return {"sent": result.sent, "error": result.error, "platform": result.platform}


@app.post("/api/notifications/teams", tags=["Notifications"])
async def notify_teams(request: Request):
    """Send scan results to Microsoft Teams."""
    from agenticqa.notifications.slack import TeamsNotifier
    body = await request.json()
    notifier = TeamsNotifier(webhook_url=body.get("webhook_url"))
    result = notifier.notify_scan(body.get("scan_output", {}))
    return {"sent": result.sent, "error": result.error, "platform": result.platform}


# ── 4Capital CMHC Analyst Guided Workflow ──────────────────────────────────

try:
    from agenticqa.agents.team.analyst_workflow import AnalystGuidedWorkflow
    _guided_workflow = AnalystGuidedWorkflow(workflow_store=workflow_store)
except Exception:
    try:
        from src.agenticqa.agents.team.analyst_workflow import AnalystGuidedWorkflow
        _guided_workflow = AnalystGuidedWorkflow(workflow_store=workflow_store)
    except Exception:
        _guided_workflow = None


class GuidedSessionCreate(BaseModel):
    analyst: str = "analyst"
    repo: str = "."


class GuidedFieldsInput(BaseModel):
    fields: Dict[str, str]


class GuidedConfirmInput(BaseModel):
    confirmed: bool = True
    edits: Optional[str] = None


class GuidedChatInput(BaseModel):
    message: str


class GuidedSubmitInput(BaseModel):
    reviewer: Optional[str] = None


@app.get("/api/guided/templates", tags=["Guided Workflow"])
async def list_guided_templates(category: Optional[str] = None, cmhc_only: bool = False):
    """List available prompt templates for analyst selection."""
    if not _guided_workflow:
        raise HTTPException(503, "Guided workflow not available")
    return _guided_workflow.list_templates(category=category, cmhc_only=cmhc_only)


@app.get("/api/guided/templates/{template_id}", tags=["Guided Workflow"])
async def get_guided_template(template_id: str):
    """Get details for a specific prompt template."""
    if not _guided_workflow:
        raise HTTPException(503, "Guided workflow not available")
    template = _guided_workflow.get_template(template_id)
    if not template:
        raise HTTPException(404, f"Template not found: {template_id}")
    return {
        "id": template.id,
        "name": template.name,
        "category": template.category,
        "description": template.description,
        "prompt_template": template.prompt_template,
        "required_fields": template.required_fields,
        "optional_fields": template.optional_fields,
        "agents": template.agents,
        "cmhc_relevant": template.cmhc_relevant,
    }


@app.get("/api/guided/categories", tags=["Guided Workflow"])
async def list_guided_categories():
    """List all template categories."""
    if not _guided_workflow:
        raise HTTPException(503, "Guided workflow not available")
    return _guided_workflow.list_categories()


@app.post("/api/guided/sessions", tags=["Guided Workflow"])
async def create_guided_session(body: GuidedSessionCreate):
    """Start a new guided workflow session for an analyst."""
    if not _guided_workflow:
        raise HTTPException(503, "Guided workflow not available")
    session = _guided_workflow.create_session(analyst=body.analyst, repo=body.repo)
    return _guided_workflow._session_response(session)


@app.get("/api/guided/sessions", tags=["Guided Workflow"])
async def list_guided_sessions(analyst: Optional[str] = None):
    """List active guided workflow sessions."""
    if not _guided_workflow:
        raise HTTPException(503, "Guided workflow not available")
    return _guided_workflow.list_sessions(analyst=analyst)


@app.get("/api/guided/sessions/{session_id}", tags=["Guided Workflow"])
async def get_guided_session(session_id: str):
    """Get the current state of a guided session."""
    if not _guided_workflow:
        raise HTTPException(503, "Guided workflow not available")
    session = _guided_workflow.get_session(session_id)
    if not session:
        raise HTTPException(404, f"Session not found: {session_id}")
    return _guided_workflow._session_response(session)


@app.post("/api/guided/sessions/{session_id}/select-template", tags=["Guided Workflow"])
async def guided_select_template(session_id: str, template_id: str):
    """Step 1: Select a prompt template."""
    if not _guided_workflow:
        raise HTTPException(503, "Guided workflow not available")
    try:
        return _guided_workflow.select_template(session_id, template_id)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.post("/api/guided/sessions/{session_id}/fill-fields", tags=["Guided Workflow"])
async def guided_fill_fields(session_id: str, body: GuidedFieldsInput):
    """Step 2: Provide field values for the template."""
    if not _guided_workflow:
        raise HTTPException(503, "Guided workflow not available")
    try:
        return _guided_workflow.fill_fields(session_id, body.fields)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.post("/api/guided/sessions/{session_id}/confirm", tags=["Guided Workflow"])
async def guided_confirm_plan(session_id: str, body: GuidedConfirmInput):
    """Step 3: Confirm or edit the plan."""
    if not _guided_workflow:
        raise HTTPException(503, "Guided workflow not available")
    try:
        return _guided_workflow.confirm_plan(session_id, confirmed=body.confirmed, edits=body.edits)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.post("/api/guided/sessions/{session_id}/execute", tags=["Guided Workflow"])
async def guided_execute(session_id: str):
    """Step 4-6: Execute the workflow and run agent team validation."""
    if not _guided_workflow:
        raise HTTPException(503, "Guided workflow not available")
    try:
        return _guided_workflow.execute(session_id)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.post("/api/guided/sessions/{session_id}/submit", tags=["Guided Workflow"])
async def guided_submit_for_review(session_id: str, body: GuidedSubmitInput):
    """Step 7: Submit for PR review."""
    if not _guided_workflow:
        raise HTTPException(503, "Guided workflow not available")
    try:
        return _guided_workflow.submit_for_review(session_id, reviewer=body.reviewer)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.post("/api/guided/sessions/{session_id}/chat", tags=["Guided Workflow"])
async def guided_chat(session_id: str, body: GuidedChatInput):
    """Send a free-form chat message at any step in the guided workflow."""
    if not _guided_workflow:
        raise HTTPException(503, "Guided workflow not available")
    try:
        return _guided_workflow.chat_message(session_id, body.message)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.get("/api/guided/agents", tags=["Guided Workflow"])
async def list_available_agents():
    """List all agents available for the team."""
    try:
        from agenticqa.agents.team.registry import AgentRegistry
        import agenticqa.agents.team.specialists  # noqa: F401
    except ImportError:
        from src.agenticqa.agents.team.registry import AgentRegistry
        import src.agenticqa.agents.team.specialists  # noqa: F401

    agents = AgentRegistry.all_agents()
    return [
        {
            "name": cls.name,
            "description": cls.description,
            "category": cls.category,
            "priority": cls.priority,
            "is_gate": cls.is_gate,
            "can_auto_fix": cls.can_auto_fix,
        }
        for cls in sorted(agents.values(), key=lambda a: a.priority)
    ]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
