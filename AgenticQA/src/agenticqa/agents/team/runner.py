"""
Team Runner — Entry point for running the agent team against a project.

Usage:
    python -m agenticqa.agents.team.runner /path/to/project
    python -m agenticqa.agents.team.runner . --max-iterations 5
    python -m agenticqa.agents.team.runner . --agents code_review,cmhc_specialist
"""

from __future__ import annotations

import glob
import json
import logging
import os
import sys
from typing import Dict, List, Optional

from agenticqa.agents.team.base import KnowledgeBase, ProjectContext
from agenticqa.agents.team.orchestrator import LoopConfig, LoopReport, TeamOrchestrator
from agenticqa.agents.team.registry import AgentRegistry, AgentTeam

# Import all specialists to trigger registration
import agenticqa.agents.team.specialists  # noqa: F401

logger = logging.getLogger("agenticqa.team.runner")


def discover_files(project_root: str) -> Dict[str, List[str]]:
    """Discover source, test, and config files in the project."""
    source_exts = (".py", ".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte", ".go", ".rs", ".java")
    test_patterns = ("test_*", "*_test.*", "*.test.*", "*.spec.*", "conftest.py")
    config_patterns = (
        "*.json", "*.yaml", "*.yml", "*.toml", "*.ini", "*.cfg",
        ".env*", "Dockerfile*", "docker-compose*",
    )

    source_files = []
    test_files = []
    config_files = []

    skip_dirs = {
        "node_modules", ".git", "__pycache__", ".tox", ".venv", "venv",
        "dist", "build", ".next", ".nuxt", "coverage", ".mypy_cache",
    }

    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for fname in files:
            fpath = os.path.join(root, fname)

            # Test files
            is_test = any(
                fname.startswith("test_") or fname.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))
                for _ in [None]
            ) or "test" in root.split(os.sep)

            if is_test and any(fname.endswith(ext) for ext in source_exts):
                test_files.append(fpath)
            elif any(fname.endswith(ext) for ext in source_exts):
                source_files.append(fpath)

            # Config files
            if any(fname.endswith(ext) for ext in (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg")):
                config_files.append(fpath)
            elif fname.startswith(".env") or fname.startswith("Dockerfile"):
                config_files.append(fpath)

    return {
        "source_files": source_files,
        "test_files": test_files,
        "config_files": config_files,
    }


def create_default_team(agent_names: Optional[List[str]] = None) -> AgentTeam:
    """Create a team with all agents or a specific subset."""
    team = AgentTeam("default")
    if agent_names:
        for name in agent_names:
            team.add_by_name(name)
    else:
        team.add_all()
    return team


def run_team(
    project_root: str,
    max_iterations: int = 10,
    agent_names: Optional[List[str]] = None,
    stop_on_launchable: bool = True,
    config: Optional[Dict] = None,
) -> LoopReport:
    """
    Run the full agent team against a project.

    Args:
        project_root: Path to the project root
        max_iterations: Maximum improvement loop iterations
        agent_names: Optional list of specific agents to run (None = all)
        stop_on_launchable: Stop when no blocking findings remain
        config: Additional configuration

    Returns:
        LoopReport with full results
    """
    project_root = os.path.abspath(project_root)
    files = discover_files(project_root)

    # Initialize the knowledge base — living document shared by all agents
    kb_path = os.path.join(project_root, ".agenticqa_knowledge_base.json")
    knowledge_base = KnowledgeBase(path=kb_path)

    context = ProjectContext(
        project_root=project_root,
        source_files=files["source_files"],
        test_files=files["test_files"],
        config_files=files["config_files"],
        config=config or {},
        knowledge_base=knowledge_base,
    )

    team = create_default_team(agent_names)

    loop_config = LoopConfig(
        max_iterations=max_iterations,
        stop_on_launchable=stop_on_launchable,
        on_iteration_start=_log_iteration_start,
        on_iteration_end=_log_iteration_end,
        on_loop_complete=_log_loop_complete,
    )

    orchestrator = TeamOrchestrator(team, loop_config)

    logger.info(f"Starting agent team: {len(team)} agents, max {max_iterations} iterations")
    logger.info(f"Project: {project_root}")
    logger.info(f"Files: {len(files['source_files'])} source, {len(files['test_files'])} test, {len(files['config_files'])} config")

    report = orchestrator.run(context)

    # Save report
    report_path = os.path.join(project_root, ".agenticqa_report.json")
    try:
        with open(report_path, "w") as f:
            json.dump(report.summary(), f, indent=2)
        logger.info(f"Report saved: {report_path}")
    except OSError:
        pass

    return report


def _log_iteration_start(iteration: int, context: ProjectContext) -> None:
    print(f"\n{'='*60}")
    print(f"  ITERATION {iteration + 1}")
    print(f"{'='*60}")


def _log_iteration_end(iteration: int, context: ProjectContext, results) -> None:
    total = sum(len(r.findings) for r in results)
    blocking = sum(len(r.blocking_findings) for r in results)
    fixes = sum(r.auto_fixes_applied for r in results)
    passed = sum(1 for r in results if r.passed)
    print(f"\n  Summary: {passed}/{len(results)} agents passed | "
          f"{total} findings ({blocking} blocking) | {fixes} auto-fixes")


def _log_loop_complete(report: LoopReport) -> None:
    print(f"\n{'='*60}")
    print(f"  AGENT TEAM COMPLETE")
    print(f"{'='*60}")
    print(f"  Iterations:   {report.total_iterations}")
    print(f"  Launchable:   {'YES' if report.is_launchable else 'NO'}")
    print(f"  Stop reason:  {report.stop_reason}")
    print(f"  Duration:     {report.total_duration_ms:.0f}ms")
    print(f"  Findings:     {report.final_findings_count} ({report.final_blocking_count} blocking)")
    print(f"  Auto-fixes:   {report.total_auto_fixes}")
    print(f"  Learnings:    {len(report.all_learnings)}")
    print(f"{'='*60}\n")


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="AgenticQA Agent Team — Continuous improvement loop for production-ready code"
    )
    parser.add_argument("project_root", nargs="?", default=".",
                        help="Path to project root (default: current directory)")
    parser.add_argument("--max-iterations", "-n", type=int, default=10,
                        help="Maximum improvement iterations (default: 10)")
    parser.add_argument("--agents", "-a", type=str, default=None,
                        help="Comma-separated list of agent names to run")
    parser.add_argument("--list-agents", action="store_true",
                        help="List all available agents")
    parser.add_argument("--no-stop-on-launchable", action="store_true",
                        help="Don't stop when code becomes launchable")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose logging")
    parser.add_argument("--json", action="store_true",
                        help="Output report as JSON")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    if args.list_agents:
        agents = AgentRegistry.all_agents()
        print(f"\nAvailable agents ({len(agents)}):\n")
        for name, cls in sorted(agents.items()):
            gate = " [GATE]" if cls.is_gate else ""
            fix = " [AUTO-FIX]" if cls.can_auto_fix else ""
            print(f"  {name:30s} {cls.category:15s} P{cls.priority:02d}{gate}{fix}")
            print(f"    {cls.description}")
        print()
        return

    agent_names = args.agents.split(",") if args.agents else None

    report = run_team(
        project_root=args.project_root,
        max_iterations=args.max_iterations,
        agent_names=agent_names,
        stop_on_launchable=not args.no_stop_on_launchable,
    )

    if args.json:
        print(json.dumps(report.summary(), indent=2))

    sys.exit(0 if report.is_launchable else 1)


if __name__ == "__main__":
    main()
