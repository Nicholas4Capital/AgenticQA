"""Governance Agent — Squad 7 FINAL GATE.

No code reaches production without passing governance.
Validates PIPEDA, FINTRAC/PCMLTFA, FSRA/MBLAA, CASL compliance,
data classification, SIN handling, breach response readiness,
retention schedules, AI governance, and vendor governance.
"""

from __future__ import annotations

import os
import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Discrepancy, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


# ---------------------------------------------------------------------------
# Regulatory patterns
# ---------------------------------------------------------------------------

# PIPEDA 10 Fair Information Principles
PIPEDA_PRINCIPLES = [
    "accountability",
    "identifying_purposes",
    "consent",
    "limiting_collection",
    "limiting_use_disclosure_retention",
    "accuracy",
    "safeguards",
    "openness",
    "individual_access",
    "challenging_compliance",
]

# Data classification tiers
DATA_TIERS = {
    "RESTRICTED": {
        "patterns": [
            r"(?i)\bsin\b", r"(?i)social.?insurance.?number",
            r"(?i)\bssn\b", r"(?i)social.?security",
            r"(?i)credit.?card", r"(?i)card.?number",
            r"(?i)\bcvv\b", r"(?i)bank.?account",
            r"(?i)routing.?number",
        ],
        "encryption": "AES-256 at rest, TLS 1.3 in transit",
        "access": "named individuals only",
        "retention": "minimum necessary",
    },
    "CONFIDENTIAL": {
        "patterns": [
            r"(?i)income", r"(?i)salary", r"(?i)employment",
            r"(?i)credit.?score", r"(?i)mortgage.?amount",
            r"(?i)down.?payment", r"(?i)debt.?ratio",
            r"(?i)property.?value", r"(?i)appraisal",
        ],
        "encryption": "AES-256 at rest, TLS 1.2+ in transit",
        "access": "role-based, need-to-know",
        "retention": "7 years after relationship end",
    },
    "INTERNAL": {
        "patterns": [
            r"(?i)agent.?notes", r"(?i)internal.?memo",
            r"(?i)case.?notes", r"(?i)workflow.?status",
        ],
        "encryption": "at rest recommended",
        "access": "department-level",
        "retention": "3 years",
    },
}

# SIN masking patterns — SIN should never appear unmasked in logs/UI
SIN_RAW_PATTERNS = [
    r"\b\d{3}[\s-]?\d{3}[\s-]?\d{3}\b",  # 123-456-789 or 123 456 789
]

# FINTRAC reporting thresholds
FINTRAC_THRESHOLDS = {
    "large_cash": 10_000,         # CAD
    "electronic_funds": 10_000,   # CAD
    "suspicious_transaction": 0,  # Any amount
}

# Breach response checklist items
BREACH_RESPONSE_CHECKLIST = [
    "breach_detection",
    "containment_procedure",
    "risk_assessment",
    "notification_72h",      # PIPEDA: 72-hour notification to OPC
    "individual_notification",
    "record_keeping",
    "remediation_plan",
]


@AgentRegistry.register
class GovernanceAgent(BaseAgent):
    """
    FINAL GATE — Squad 7.

    No code reaches production without passing governance.
    Validates Canadian regulatory compliance across:
    - PIPEDA (Personal Information Protection and Electronic Documents Act)
    - FINTRAC/PCMLTFA (Anti-money laundering, KYC)
    - FSRA/MBLAA (Ontario mortgage brokerage licensing)
    - CASL (Canadian Anti-Spam Legislation)
    - Data Classification (RESTRICTED/CONFIDENTIAL/INTERNAL/PUBLIC)
    - SIN Handling Protocol
    - AI Governance
    - Breach Response Readiness
    - Retention Schedules
    - Vendor Governance
    """

    name = "governance"
    description = (
        "FINAL GATE: PIPEDA, FINTRAC, FSRA, CASL, data classification, "
        "SIN handling, breach response, retention, AI governance, vendor governance"
    )
    category = "governance"
    priority = 1
    is_gate = True
    can_auto_fix = False
    squad = Squad.GOVERNANCE
    pipeline_position = 1

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        discrepancies: List[Discrepancy] = []
        metrics = {
            "files_scanned": 0,
            "restricted_data_refs": 0,
            "confidential_data_refs": 0,
            "sin_exposures": 0,
            "consent_mechanisms": 0,
            "encryption_refs": 0,
            "logging_of_pii": 0,
            "aml_patterns": 0,
            "casl_patterns": 0,
        }

        all_files = context.source_files + context.test_files + context.config_files

        for fpath in all_files:
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            metrics["files_scanned"] += 1

            # --- Data Classification Checks ---
            self._check_data_classification(fpath, content, findings, metrics)

            # --- SIN Handling ---
            self._check_sin_handling(fpath, content, findings, metrics)

            # --- PIPEDA Checks ---
            self._check_pipeda(fpath, content, findings, metrics)

            # --- FINTRAC/AML Checks ---
            self._check_fintrac(fpath, content, findings, metrics)

            # --- CASL Checks ---
            self._check_casl(fpath, content, findings, metrics)

            # --- AI Governance ---
            self._check_ai_governance(fpath, content, findings, metrics)

            # --- PII in Logs ---
            self._check_pii_logging(fpath, content, findings, metrics)

        # --- Infrastructure-level Checks ---
        self._check_breach_readiness(context, findings, metrics)
        self._check_retention_policy(context, findings, metrics)
        self._check_vendor_governance(context, findings, metrics)
        self._check_encryption_config(context, findings, metrics)

        # --- Cross-agent discrepancy check ---
        self._check_prior_squad_results(context, findings, discrepancies)

        passed = not any(f.is_blocking for f in findings)
        learnings = []
        if metrics["sin_exposures"] > 0:
            learnings.append(
                f"Found {metrics['sin_exposures']} potential SIN exposures — "
                "all must be masked (XXX-XXX-789 format)"
            )
        if metrics["logging_of_pii"] > 0:
            learnings.append(
                f"Found {metrics['logging_of_pii']} instances of PII in logging statements"
            )

        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics=metrics,
            learnings=learnings,
            discrepancies=discrepancies,
        )

    # ------------------------------------------------------------------
    # Data Classification
    # ------------------------------------------------------------------

    def _check_data_classification(
        self, fpath: str, content: str, findings: List[Finding], metrics: dict
    ) -> None:
        for tier, config in DATA_TIERS.items():
            for pattern in config["patterns"]:
                matches = re.findall(pattern, content)
                if matches:
                    key = "restricted_data_refs" if tier == "RESTRICTED" else "confidential_data_refs"
                    metrics[key] += len(matches)

                    if tier == "RESTRICTED":
                        findings.append(Finding(
                            message=(
                                f"RESTRICTED data reference found ({pattern}). "
                                f"Requires: {config['encryption']}, access: {config['access']}"
                            ),
                            severity=AgentSeverity.HIGH,
                            file_path=fpath,
                            suggestion=(
                                "Ensure field-level encryption, strict RBAC, "
                                "and audit logging for all RESTRICTED data"
                            ),
                        ))

    # ------------------------------------------------------------------
    # SIN Handling
    # ------------------------------------------------------------------

    def _check_sin_handling(
        self, fpath: str, content: str, findings: List[Finding], metrics: dict
    ) -> None:
        # Skip test files for raw SIN checks (test data is expected)
        basename = os.path.basename(fpath)
        if basename.startswith("test_") or "_test." in basename:
            return

        for pattern in SIN_RAW_PATTERNS:
            for match in re.finditer(pattern, content):
                # Check if it's in a masking/hashing context
                line_start = content.rfind("\n", 0, match.start()) + 1
                line_end = content.find("\n", match.end())
                line = content[line_start:line_end] if line_end > 0 else content[line_start:]

                mask_indicators = ["mask", "hash", "encrypt", "redact", "***", "XXX"]
                if not any(ind.lower() in line.lower() for ind in mask_indicators):
                    metrics["sin_exposures"] += 1
                    findings.append(Finding(
                        message=(
                            f"Potential unmasked SIN detected. "
                            f"SINs must use XXX-XXX-789 format in UI/logs, "
                            f"AES-256 encryption at rest, separate storage."
                        ),
                        severity=AgentSeverity.CRITICAL,
                        file_path=fpath,
                        suggestion=(
                            "Implement SIN masking: display only last 3 digits, "
                            "encrypt with AES-256, store in separate secured table, "
                            "log access with audit trail"
                        ),
                    ))

    # ------------------------------------------------------------------
    # PIPEDA
    # ------------------------------------------------------------------

    def _check_pipeda(
        self, fpath: str, content: str, findings: List[Finding], metrics: dict
    ) -> None:
        content_lower = content.lower()

        # Check for consent mechanisms
        consent_patterns = [
            r"(?i)consent", r"(?i)opt[\s_-]?in", r"(?i)opt[\s_-]?out",
            r"(?i)privacy[\s_-]?policy", r"(?i)terms[\s_-]?of[\s_-]?service",
        ]
        for pattern in consent_patterns:
            if re.search(pattern, content):
                metrics["consent_mechanisms"] += 1

        # Check for data collection without purpose limitation
        collection_patterns = [
            r"(?i)collect.*personal", r"(?i)gather.*data",
            r"(?i)store.*user.*info", r"(?i)save.*client.*data",
        ]
        for pattern in collection_patterns:
            if re.search(pattern, content):
                # Verify purpose is documented nearby
                if "purpose" not in content_lower and "reason" not in content_lower:
                    findings.append(Finding(
                        message=(
                            "Data collection without documented purpose (PIPEDA Principle 2: "
                            "Identifying Purposes). Must document why data is collected."
                        ),
                        severity=AgentSeverity.HIGH,
                        file_path=fpath,
                        suggestion="Add purpose documentation for all personal data collection",
                    ))
                    break

    # ------------------------------------------------------------------
    # FINTRAC / AML
    # ------------------------------------------------------------------

    def _check_fintrac(
        self, fpath: str, content: str, findings: List[Finding], metrics: dict
    ) -> None:
        # Look for transaction-related code
        transaction_patterns = [
            r"(?i)transaction", r"(?i)transfer", r"(?i)payment",
            r"(?i)wire", r"(?i)deposit",
        ]

        has_transactions = any(re.search(p, content) for p in transaction_patterns)
        if not has_transactions:
            return

        metrics["aml_patterns"] += 1

        # Check for KYC verification
        kyc_patterns = [r"(?i)kyc", r"(?i)know.?your.?customer", r"(?i)identity.?verif"]
        has_kyc = any(re.search(p, content) for p in kyc_patterns)

        if not has_kyc:
            findings.append(Finding(
                message=(
                    "Transaction handling without KYC verification. "
                    "FINTRAC requires identity verification for transactions >= $10,000 CAD"
                ),
                severity=AgentSeverity.HIGH,
                file_path=fpath,
                suggestion=(
                    "Implement KYC verification: government-issued ID, "
                    "third-party verification, PEP/sanctions screening"
                ),
            ))

        # Check for suspicious transaction reporting
        str_patterns = [r"(?i)suspicious", r"(?i)str\b", r"(?i)large.?cash"]
        has_str = any(re.search(p, content) for p in str_patterns)

        if not has_str and has_transactions:
            findings.append(Finding(
                message=(
                    "No suspicious transaction reporting (STR) mechanism detected. "
                    "FINTRAC requires STR filing for suspicious transactions of any amount."
                ),
                severity=AgentSeverity.MEDIUM,
                file_path=fpath,
                suggestion="Implement STR detection and automated FINTRAC reporting pipeline",
            ))

    # ------------------------------------------------------------------
    # CASL
    # ------------------------------------------------------------------

    def _check_casl(
        self, fpath: str, content: str, findings: List[Finding], metrics: dict
    ) -> None:
        email_patterns = [
            r"(?i)send.?email", r"(?i)send.?message", r"(?i)newsletter",
            r"(?i)marketing.?email", r"(?i)notification.?email",
            r"(?i)smtp", r"(?i)sendgrid", r"(?i)mailgun",
        ]

        has_email = any(re.search(p, content) for p in email_patterns)
        if not has_email:
            return

        metrics["casl_patterns"] += 1

        # Check for unsubscribe mechanism
        unsubscribe_patterns = [r"(?i)unsubscribe", r"(?i)opt[\s_-]?out", r"(?i)preference"]
        has_unsubscribe = any(re.search(p, content) for p in unsubscribe_patterns)

        if not has_unsubscribe:
            findings.append(Finding(
                message=(
                    "Email/messaging without unsubscribe mechanism. "
                    "CASL requires functioning unsubscribe in all commercial electronic messages."
                ),
                severity=AgentSeverity.HIGH,
                file_path=fpath,
                suggestion=(
                    "Add unsubscribe link, process opt-outs within 10 business days, "
                    "include sender identification and physical address"
                ),
            ))

    # ------------------------------------------------------------------
    # AI Governance
    # ------------------------------------------------------------------

    def _check_ai_governance(
        self, fpath: str, content: str, findings: List[Finding], metrics: dict
    ) -> None:
        ai_patterns = [
            r"(?i)openai", r"(?i)anthropic", r"(?i)claude",
            r"(?i)gpt", r"(?i)gemini", r"(?i)llm",
            r"(?i)ai[\s_]model", r"(?i)machine.?learn",
        ]
        has_ai = any(re.search(p, content) for p in ai_patterns)
        if not has_ai:
            return

        content_lower = content.lower()

        # Check for human-in-the-loop for financial decisions
        financial_ai = any(re.search(p, content) for p in [
            r"(?i)mortgage.*ai", r"(?i)ai.*mortgage",
            r"(?i)approv", r"(?i)underwrit",
            r"(?i)risk.*scor", r"(?i)credit.*decision",
        ])

        if financial_ai and "human" not in content_lower and "review" not in content_lower:
            findings.append(Finding(
                message=(
                    "AI used in financial decision-making without human-in-the-loop. "
                    "FSRA requires human oversight for mortgage/lending decisions."
                ),
                severity=AgentSeverity.CRITICAL,
                file_path=fpath,
                suggestion=(
                    "Implement human-in-the-loop: AI suggests, human approves. "
                    "Log all AI recommendations vs. final human decisions."
                ),
            ))

        # Check for AI output logging
        if "log" not in content_lower and "audit" not in content_lower:
            findings.append(Finding(
                message="AI integration without audit logging of inputs/outputs",
                severity=AgentSeverity.MEDIUM,
                file_path=fpath,
                suggestion="Log all AI prompts, responses, and confidence scores for audit trail",
            ))

    # ------------------------------------------------------------------
    # PII in Logging
    # ------------------------------------------------------------------

    def _check_pii_logging(
        self, fpath: str, content: str, findings: List[Finding], metrics: dict
    ) -> None:
        # Look for logging statements that might contain PII
        log_patterns = [
            r"(?i)logger?\.(info|debug|warn|error)\(.*(?:email|phone|sin|ssn|name|address)",
            r"(?i)console\.(log|warn|error)\(.*(?:email|phone|sin|ssn|name|address)",
            r"(?i)print\(.*(?:email|phone|sin|ssn|password|secret)",
        ]

        for pattern in log_patterns:
            for match in re.finditer(pattern, content):
                metrics["logging_of_pii"] += 1
                findings.append(Finding(
                    message="Potential PII in logging statement — PIPEDA requires PII protection in all contexts",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath,
                    suggestion="Redact or mask PII before logging. Use structured logging with PII-safe fields.",
                ))
                break  # One finding per file for this check

    # ------------------------------------------------------------------
    # Infrastructure-level Checks
    # ------------------------------------------------------------------

    def _check_breach_readiness(
        self, context: ProjectContext, findings: List[Finding], metrics: dict
    ) -> None:
        """Check for breach response documentation and mechanisms."""
        all_content = ""
        for fpath in context.source_files + context.config_files:
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        all_content += f.read().lower()
                except OSError:
                    continue

        breach_indicators = ["breach", "incident", "security_event", "data_leak"]
        has_breach_handling = any(ind in all_content for ind in breach_indicators)

        if not has_breach_handling and len(context.source_files) > 5:
            findings.append(Finding(
                message=(
                    "No breach response mechanism detected. "
                    "PIPEDA requires breach notification to OPC within 72 hours "
                    "and notification to affected individuals."
                ),
                severity=AgentSeverity.MEDIUM,
                suggestion=(
                    "Implement breach detection, containment, 72-hour OPC notification, "
                    "individual notification, and record-keeping procedures"
                ),
            ))

    def _check_retention_policy(
        self, context: ProjectContext, findings: List[Finding], metrics: dict
    ) -> None:
        """Check for data retention policy implementation."""
        all_content = ""
        for fpath in context.source_files:
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        all_content += f.read().lower()
                except OSError:
                    continue

        retention_patterns = ["retention", "expire", "ttl", "cleanup", "purge", "archive"]
        has_retention = any(p in all_content for p in retention_patterns)

        if not has_retention and len(context.source_files) > 5:
            findings.append(Finding(
                message=(
                    "No data retention policy detected. "
                    "PIPEDA Principle 5 requires limiting retention to purpose fulfillment. "
                    "FINTRAC requires 5-year minimum for transaction records."
                ),
                severity=AgentSeverity.MEDIUM,
                suggestion="Implement automated retention schedules with configurable TTLs per data tier",
            ))

    def _check_vendor_governance(
        self, context: ProjectContext, findings: List[Finding], metrics: dict
    ) -> None:
        """Check third-party vendor compliance requirements."""
        vendor_indicators = [
            "stripe", "plaid", "equifax", "transunion",
            "sendgrid", "twilio", "aws", "azure", "gcp",
            "supabase", "vercel", "firebase",
        ]

        all_content = ""
        for fpath in context.source_files + context.config_files:
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        all_content += f.read().lower()
                except OSError:
                    continue

        vendors_found = [v for v in vendor_indicators if v in all_content]
        if vendors_found and len(vendors_found) > 2:
            # Check for vendor assessment documentation
            has_vendor_docs = any(
                "vendor" in all_content and ("assessment" in all_content or "agreement" in all_content)
            for _ in [None])

            if not has_vendor_docs:
                findings.append(Finding(
                    message=(
                        f"Multiple third-party vendors detected ({', '.join(vendors_found[:5])}) "
                        f"without vendor governance documentation. "
                        f"PIPEDA requires due diligence on third-party data handling."
                    ),
                    severity=AgentSeverity.MEDIUM,
                    suggestion=(
                        "Maintain vendor registry with: DPA status, data residency (Canada), "
                        "SOC2/ISO27001 compliance, breach notification terms, "
                        "annual review schedule"
                    ),
                ))

    def _check_encryption_config(
        self, context: ProjectContext, findings: List[Finding], metrics: dict
    ) -> None:
        """Check for encryption configuration."""
        all_content = ""
        for fpath in context.source_files + context.config_files:
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        all_content += f.read().lower()
                except OSError:
                    continue

        encryption_patterns = [
            "aes", "encrypt", "crypto", "tls", "ssl",
            "bcrypt", "argon2", "scrypt", "pbkdf2",
        ]
        has_encryption = any(p in all_content for p in encryption_patterns)
        metrics["encryption_refs"] = sum(1 for p in encryption_patterns if p in all_content)

        if not has_encryption and len(context.source_files) > 5:
            findings.append(Finding(
                message=(
                    "No encryption implementation detected. "
                    "PIPEDA Principle 7 (Safeguards) requires appropriate security measures "
                    "proportional to data sensitivity."
                ),
                severity=AgentSeverity.HIGH,
                suggestion=(
                    "Implement: AES-256 for data at rest, TLS 1.3 for transit, "
                    "bcrypt/argon2 for passwords, field-level encryption for RESTRICTED data"
                ),
            ))

    # ------------------------------------------------------------------
    # Cross-agent validation
    # ------------------------------------------------------------------

    def _check_prior_squad_results(
        self,
        context: ProjectContext,
        findings: List[Finding],
        discrepancies: List[Discrepancy],
    ) -> None:
        """Validate that prior squads' findings align with governance requirements."""
        # Check compliance_checker results for consistency
        for result in context.prior_results:
            if result.agent_name == "compliance_checker" and not result.passed:
                findings.append(Finding(
                    message=(
                        f"Compliance checker reported {len(result.blocking_findings)} blocking findings. "
                        f"Governance cannot pass until compliance issues are resolved."
                    ),
                    severity=AgentSeverity.CRITICAL,
                    suggestion="Resolve all compliance_checker blocking findings first",
                ))

            # Cross-validate CMHC specialist
            if result.agent_name == "cmhc_specialist" and not result.passed:
                findings.append(Finding(
                    message=(
                        f"CMHC specialist reported failures. "
                        f"FSRA/MBLAA requires all mortgage calculations to comply with CMHC guidelines."
                    ),
                    severity=AgentSeverity.CRITICAL,
                    suggestion="Resolve all cmhc_specialist findings before governance approval",
                ))

            # Check for unresolved discrepancies from any agent
            if result.discrepancies:
                open_discs = [d for d in result.discrepancies if d.status == "OPEN"]
                if open_discs:
                    for disc in open_discs:
                        discrepancies.append(Discrepancy(
                            source_a=f"Agent: {result.agent_name}",
                            source_b="Governance Review",
                            description=(
                                f"Unresolved discrepancy from {result.agent_name}: "
                                f"{disc.description}"
                            ),
                            agent_name=self.name,
                        ))
