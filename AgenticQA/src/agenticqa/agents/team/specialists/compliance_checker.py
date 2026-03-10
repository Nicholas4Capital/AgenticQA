"""Compliance Checker Agent — GDPR, CCPA, SOC2, HIPAA, and regulatory compliance."""

from __future__ import annotations

import re
from typing import Dict, List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class ComplianceCheckerAgent(BaseAgent):
    name = "compliance_checker"
    description = "Validates GDPR, CCPA, SOC2, HIPAA, and EU AI Act compliance patterns"
    category = "compliance"
    priority = 14
    is_gate = True

    COMPLIANCE_FRAMEWORKS = {
        "gdpr": {
            "consent_management": r"consent|opt.?in|opt.?out|cookie.*consent|gdpr.*consent",
            "data_deletion": r"delete.*data|right.*erasure|forget.*me|data.*retention|purge",
            "data_portability": r"export.*data|portability|download.*data|data.*transfer",
            "privacy_policy": r"privacy.*policy|data.*protection|privacy.*notice",
            "dpo": r"data.*protection.*officer|dpo|privacy.*officer",
            "breach_notification": r"breach.*notification|incident.*report|security.*incident",
        },
        "ccpa": {
            "do_not_sell": r"do.*not.*sell|opt.*out.*sale|ccpa.*opt",
            "disclosure": r"disclosure|categories.*collected|purpose.*collection",
            "data_access": r"access.*request|data.*request|consumer.*right",
        },
        "soc2": {
            "access_control": r"access.*control|rbac|role.*based|least.*privilege",
            "audit_logging": r"audit.*log|audit.*trail|event.*log|security.*log",
            "encryption": r"encrypt|AES|RSA|TLS|SSL|bcrypt|argon|scrypt|crypto",
            "change_management": r"change.*management|approval.*process|review.*required",
            "incident_response": r"incident.*response|escalat|alert.*policy|on.?call",
        },
        "hipaa": {
            "phi_handling": r"phi|protected.*health|patient.*data|medical.*record",
            "access_audit": r"access.*audit|who.*accessed|authorization.*log",
            "encryption_at_rest": r"encrypt.*at.*rest|storage.*encrypt|volume.*encrypt",
            "baa": r"business.*associate|baa|data.*processing.*agreement",
        },
    }

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        framework_scores: Dict[str, float] = {}

        all_content = ""
        for fpath in context.source_files + context.config_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read() + "\n"
            except (OSError, IOError):
                continue

        for framework, requirements in self.COMPLIANCE_FRAMEWORKS.items():
            present = 0
            total = len(requirements)

            for req_name, pattern in requirements.items():
                if re.search(pattern, all_content, re.IGNORECASE):
                    present += 1
                else:
                    severity = AgentSeverity.HIGH if framework in ("gdpr", "soc2") else AgentSeverity.MEDIUM
                    findings.append(Finding(
                        message=f"[{framework.upper()}] Missing: {req_name.replace('_', ' ')}",
                        severity=severity,
                        suggestion=f"Implement {req_name} for {framework.upper()} compliance",
                    ))

            framework_scores[framework] = round(present / max(total, 1) * 100, 1)

        # Check for PII handling
        findings.extend(self._check_pii_handling(context.source_files))

        overall_score = round(sum(framework_scores.values()) / max(len(framework_scores), 1), 1)
        passed = overall_score >= 40
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={
                "overall_compliance_pct": overall_score,
                "framework_scores": framework_scores,
            },
            learnings=[f"Compliance scores: {framework_scores}"],
        )

    def _check_pii_handling(self, source_files: List[str]) -> List[Finding]:
        findings = []
        pii_patterns = [
            (r"(?:email|phone|ssn|social.*security|birth.*date|address)\s*=", "PII field detected"),
            (r"log.*(?:email|phone|ssn|password|credit.*card)", "PII in logs"),
        ]

        for fpath in source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (OSError, IOError):
                continue

            for i, line in enumerate(lines, 1):
                for pattern, msg in pii_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        if "test" not in fpath.lower():
                            findings.append(Finding(
                                message=f"{msg} — ensure proper handling/redaction",
                                severity=AgentSeverity.HIGH,
                                file_path=fpath, line_number=i,
                            ))

        return findings
