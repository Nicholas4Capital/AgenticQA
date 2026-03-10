"""Infrastructure Scaling & Architecture Engineer Agent."""

from __future__ import annotations

import os
import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class InfrastructureArchitectAgent(BaseAgent):
    name = "infrastructure_architect"
    description = (
        "Evaluates infrastructure patterns: containerization, CI/CD, "
        "horizontal scaling, caching, load balancing, and cloud readiness"
    )
    category = "infrastructure"
    priority = 50
    is_gate = False

    INFRA_PATTERNS = {
        "containerization": (r"Dockerfile|docker-compose|FROM\s+\w+|container|podman", "Container support"),
        "ci_cd": (r"\.github/workflows|\.gitlab-ci|Jenkinsfile|\.circleci|azure-pipelines", "CI/CD pipeline"),
        "env_config": (r"\.env|dotenv|environ|config.*from.*env|process\.env", "Environment-based config"),
        "health_check": (r"/health|/ready|/live|healthz|readiness|liveness", "Health checks"),
        "logging": (r"logger|logging|winston|pino|bunyan|structlog", "Structured logging"),
        "caching": (r"redis|memcache|cache|lru_cache|node-cache|ioredis", "Caching layer"),
        "queue": (r"rabbitmq|celery|bull|kafka|sqs|pubsub|amqp", "Message queue"),
        "monitoring": (r"prometheus|grafana|datadog|newrelic|cloudwatch|metrics", "Monitoring"),
        "secrets": (r"vault|ssm|secret.*manager|keyring|kms", "Secrets management"),
        "cdn_static": (r"cdn|cloudfront|fastly|static.*assets|public.*cache", "CDN/static assets"),
        "horizontal_scale": (r"kubernetes|k8s|ecs|replica|auto.?scale|load.?balance|nginx", "Horizontal scaling"),
        "database_ha": (r"replica|read.?replica|failover|cluster|sharding|replication", "Database HA"),
    }

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        present = set()

        # Scan all source and config files
        all_content = ""
        for fpath in context.source_files + context.config_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read() + "\n"
            except (OSError, IOError):
                continue

        # Also check for infra files in project root
        for name in os.listdir(context.project_root):
            fpath = os.path.join(context.project_root, name)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        all_content += f.read() + "\n"
                except (OSError, IOError):
                    continue

        for name, (regex, desc) in self.INFRA_PATTERNS.items():
            if re.search(regex, all_content, re.IGNORECASE):
                present.add(name)
            else:
                severity = (
                    AgentSeverity.HIGH if name in ("containerization", "ci_cd", "env_config", "health_check")
                    else AgentSeverity.MEDIUM
                )
                findings.append(Finding(
                    message=f"Missing infrastructure pattern: {desc}",
                    severity=severity,
                    suggestion=f"Add {name.replace('_', ' ')} for production readiness",
                ))

        # Check Dockerfile best practices
        findings.extend(self._check_dockerfile(context.project_root))

        score = round(len(present) / max(len(self.INFRA_PATTERNS), 1) * 100, 1)
        passed = score >= 40
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={
                "infra_score_pct": score,
                "patterns_present": sorted(present),
                "patterns_missing": sorted(set(self.INFRA_PATTERNS.keys()) - present),
            },
            learnings=[f"Infrastructure readiness: {score}% ({len(present)}/{len(self.INFRA_PATTERNS)})"],
        )

    def _check_dockerfile(self, project_root: str) -> List[Finding]:
        findings = []
        dockerfile = os.path.join(project_root, "Dockerfile")
        if not os.path.exists(dockerfile):
            return findings

        try:
            with open(dockerfile, "r") as f:
                content = f.read()
        except (OSError, IOError):
            return findings

        if "root" in content.lower() and "USER" not in content:
            findings.append(Finding(
                message="Dockerfile running as root — add non-root USER",
                severity=AgentSeverity.HIGH,
                file_path=dockerfile,
            ))

        if ".dockerignore" not in os.listdir(project_root):
            findings.append(Finding(
                message="No .dockerignore file — builds may include unnecessary files",
                severity=AgentSeverity.LOW,
                suggestion="Create .dockerignore to exclude node_modules, .git, etc.",
            ))

        if "HEALTHCHECK" not in content:
            findings.append(Finding(
                message="Dockerfile missing HEALTHCHECK instruction",
                severity=AgentSeverity.MEDIUM,
                file_path=dockerfile,
            ))

        return findings
