"""Future Features Agent — Identifies opportunities, missing features, and roadmap suggestions."""

from __future__ import annotations

import re
from typing import Dict, List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class FutureFeaturesAgent(BaseAgent):
    name = "future_features"
    description = (
        "Identifies missing features, modernization opportunities, "
        "and suggests a prioritized roadmap based on codebase analysis"
    )
    category = "enterprise"
    priority = 85
    is_gate = False

    FEATURE_CATEGORIES = {
        "real_time": {
            "pattern": r"websocket|socket\.io|sse|server.?sent|real.?time|pubsub|push.*notif",
            "desc": "Real-time updates (WebSocket, SSE)",
            "value": "High user engagement",
        },
        "i18n": {
            "pattern": r"i18n|intl|locale|translation|gettext|react.?intl|formatMessage",
            "desc": "Internationalization (i18n)",
            "value": "Global market reach",
        },
        "dark_mode": {
            "pattern": r"dark.?mode|theme.*toggle|color.?scheme|prefers.?color",
            "desc": "Dark mode / theming",
            "value": "User preference & accessibility",
        },
        "offline": {
            "pattern": r"service.?worker|offline|cache.*first|workbox|pwa|manifest\.json",
            "desc": "Offline support / PWA",
            "value": "Works without internet",
        },
        "search": {
            "pattern": r"elasticsearch|algolia|meilisearch|full.?text.*search|typesense",
            "desc": "Full-text search",
            "value": "Content discoverability",
        },
        "notifications": {
            "pattern": r"notification|push.*notif|fcm|apns|web.*push|subscribe.*notif",
            "desc": "Push notifications",
            "value": "User re-engagement",
        },
        "file_upload": {
            "pattern": r"upload|multer|s3.*put|presigned.*url|file.*storage|blob",
            "desc": "File upload & storage",
            "value": "Rich content support",
        },
        "api_sdk": {
            "pattern": r"sdk|client.*library|api.*wrapper|developer.*portal",
            "desc": "Developer SDK / API client",
            "value": "Developer ecosystem",
        },
        "collaboration": {
            "pattern": r"collaborat|real.?time.*edit|presence|cursor.*share|conflict.*resolut",
            "desc": "Real-time collaboration",
            "value": "Team productivity",
        },
        "ai_assistant": {
            "pattern": r"chat.*bot|ai.*assist|copilot|natural.*language.*query|conversational",
            "desc": "AI-powered assistant",
            "value": "Intelligent user experience",
        },
    }

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        all_content = ""
        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read() + "\n"
            except (OSError, IOError):
                continue

        present = set()
        opportunities = []

        for name, info in self.FEATURE_CATEGORIES.items():
            if re.search(info["pattern"], all_content, re.IGNORECASE):
                present.add(name)
            else:
                opportunities.append({
                    "feature": name,
                    "description": info["desc"],
                    "value": info["value"],
                })

        # Prioritize by value
        for opp in opportunities:
            findings.append(Finding(
                message=f"Feature opportunity: {opp['description']}",
                severity=AgentSeverity.LOW,
                suggestion=f"Value: {opp['value']}",
                metadata={"feature": opp["feature"]},
            ))

        # Analyze TODO/roadmap items in code
        todo_features = self._extract_feature_todos(context.source_files)
        for todo in todo_features:
            findings.append(Finding(
                message=f"Roadmap item from code: {todo['text']}",
                severity=AgentSeverity.INFO,
                file_path=todo["file"],
                line_number=todo["line"],
            ))

        return AgentResult(
            agent_name=self.name,
            passed=True,  # This agent is advisory, never blocks
            findings=findings,
            metrics={
                "features_present": len(present),
                "opportunities": len(opportunities),
                "roadmap_items": len(todo_features),
            },
            learnings=[
                f"Features present: {sorted(present)}",
                f"Opportunities: {[o['feature'] for o in opportunities]}",
            ],
        )

    def _extract_feature_todos(self, source_files: List[str]) -> List[Dict]:
        todos = []
        for fpath in source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (OSError, IOError):
                continue

            for i, line in enumerate(lines, 1):
                match = re.search(r"#\s*(?:TODO|FEATURE|ROADMAP|FUTURE):\s*(.+)", line, re.IGNORECASE)
                if match:
                    todos.append({"file": fpath, "line": i, "text": match.group(1).strip()[:100]})

        return todos[:20]  # Limit
