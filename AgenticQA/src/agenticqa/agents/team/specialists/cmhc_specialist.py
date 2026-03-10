"""CMHC Specialist Agent — Canada Mortgage and Housing Corporation compliance checks."""

from __future__ import annotations

import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext, Squad,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class CMHCSpecialistAgent(BaseAgent):
    name = "cmhc_specialist"
    description = (
        "CMHC compliance: mortgage calculations, insurance premiums, "
        "amortization rules, GDS/TDS ratios, stress test rates, "
        "and Canadian housing regulation adherence"
    )
    category = "compliance"
    priority = 15
    is_gate = True
    can_auto_fix = False
    squad = Squad.DOMAIN_EXPERTISE
    pipeline_position = 1

    # CMHC-specific validation rules
    CMHC_RULES = {
        "max_amortization_insured": 25,  # years for insured mortgages
        "max_amortization_uninsured": 30,  # years for uninsured
        "min_down_payment_pct_under_500k": 5,  # percent
        "min_down_payment_pct_500k_to_1m": 10,  # percent for portion above 500k
        "min_down_payment_pct_over_1m": 20,  # percent (not CMHC insurable)
        "max_insurable_price": 1_000_000,  # CAD
        "gds_ratio_max": 39,  # percent gross debt service
        "tds_ratio_max": 44,  # percent total debt service
        "stress_test_buffer": 2,  # percent above contract rate, or floor
        "stress_test_floor": 5.25,  # percent minimum qualifying rate
    }

    # Insurance premium tiers (LTV -> premium %)
    PREMIUM_TIERS = {
        (80.01, 85.00): 2.80,
        (85.01, 90.00): 3.10,
        (90.01, 95.00): 4.00,
    }

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []

        # Find all files that deal with mortgage/housing calculations
        mortgage_files = []
        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            if re.search(
                r"mortgage|amortiz|down.?payment|gds|tds|cmhc|insur.*premium|"
                r"stress.?test|qualifying.?rate|housing|ltv|loan.?to.?value",
                content, re.IGNORECASE,
            ):
                mortgage_files.append((fpath, content))

        if not mortgage_files:
            return AgentResult(
                agent_name=self.name,
                passed=True,
                findings=[],
                metrics={"mortgage_files": 0},
                learnings=["No mortgage-related code found"],
            )

        for fpath, content in mortgage_files:
            findings.extend(self._check_amortization(fpath, content))
            findings.extend(self._check_down_payment(fpath, content))
            findings.extend(self._check_gds_tds(fpath, content))
            findings.extend(self._check_stress_test(fpath, content))
            findings.extend(self._check_premium_calculation(fpath, content))
            findings.extend(self._check_general_compliance(fpath, content))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={
                "mortgage_files": len(mortgage_files),
                "cmhc_rules_checked": len(self.CMHC_RULES),
            },
            learnings=self._extract_learnings(findings, mortgage_files),
        )

    def _check_amortization(self, fpath: str, content: str) -> List[Finding]:
        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            # Check for amortization values
            match = re.search(r"amortiz\w*\s*[:=]\s*(\d+)", line, re.IGNORECASE)
            if match:
                years = int(match.group(1))
                if years > self.CMHC_RULES["max_amortization_uninsured"]:
                    findings.append(Finding(
                        message=f"Amortization {years}y exceeds maximum {self.CMHC_RULES['max_amortization_uninsured']}y",
                        severity=AgentSeverity.CRITICAL,
                        file_path=fpath, line_number=i,
                        suggestion="CMHC max amortization: 25y insured, 30y uninsured",
                    ))

        # Check for amortization validation logic
        if "amortiz" in content.lower():
            if not re.search(r"if.*amortiz.*(?:>|>=|<=|<)\s*(?:25|30)", content, re.IGNORECASE):
                findings.append(Finding(
                    message="Amortization calculation missing validation against CMHC limits",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath,
                    suggestion="Validate amortization <= 25y for insured, <= 30y for uninsured",
                ))

        return findings

    def _check_down_payment(self, fpath: str, content: str) -> List[Finding]:
        findings = []

        if re.search(r"down.?payment|downpayment", content, re.IGNORECASE):
            # Must validate tiered minimum down payment
            has_tiered = re.search(
                r"500.?000|500k|(?:5|10|20)\s*%.*down|min.*down.*(?:5|10|20)",
                content, re.IGNORECASE,
            )
            if not has_tiered:
                findings.append(Finding(
                    message="Down payment calculation missing CMHC tiered minimums",
                    severity=AgentSeverity.CRITICAL,
                    file_path=fpath,
                    suggestion=(
                        "CMHC requires: 5% on first $500k, 10% on $500k-$1M portion, "
                        "20% on $1M+ (not insurable)"
                    ),
                ))

            # Check for $1M+ insurability limit
            if not re.search(r"1.?000.?000|1M|not.*insur|uninsur", content, re.IGNORECASE):
                findings.append(Finding(
                    message="Missing $1M+ CMHC insurability limit check",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath,
                    suggestion="Properties over $1M are not eligible for CMHC insurance",
                ))

        return findings

    def _check_gds_tds(self, fpath: str, content: str) -> List[Finding]:
        findings = []

        if re.search(r"gds|tds|debt.?service", content, re.IGNORECASE):
            # Verify correct ratio limits
            gds_match = re.search(r"gds.*(?:>|>=|<=|<|max|limit)\s*[:=]?\s*(\d+)", content, re.IGNORECASE)
            if gds_match:
                gds_val = int(gds_match.group(1))
                if gds_val != self.CMHC_RULES["gds_ratio_max"]:
                    findings.append(Finding(
                        message=f"GDS ratio limit is {gds_val}% — CMHC standard is {self.CMHC_RULES['gds_ratio_max']}%",
                        severity=AgentSeverity.CRITICAL,
                        file_path=fpath,
                    ))

            tds_match = re.search(r"tds.*(?:>|>=|<=|<|max|limit)\s*[:=]?\s*(\d+)", content, re.IGNORECASE)
            if tds_match:
                tds_val = int(tds_match.group(1))
                if tds_val != self.CMHC_RULES["tds_ratio_max"]:
                    findings.append(Finding(
                        message=f"TDS ratio limit is {tds_val}% — CMHC standard is {self.CMHC_RULES['tds_ratio_max']}%",
                        severity=AgentSeverity.CRITICAL,
                        file_path=fpath,
                    ))

        return findings

    def _check_stress_test(self, fpath: str, content: str) -> List[Finding]:
        findings = []

        if re.search(r"stress.?test|qualifying.?rate|benchmark.?rate", content, re.IGNORECASE):
            # Check for the higher-of logic (contract + 2% or floor)
            has_higher_of = re.search(
                r"max\(|Math\.max|higher|greater.*(?:5\.25|floor|buffer.*2)",
                content, re.IGNORECASE,
            )
            if not has_higher_of:
                findings.append(Finding(
                    message="Stress test missing higher-of logic (contract+2% or 5.25% floor)",
                    severity=AgentSeverity.CRITICAL,
                    file_path=fpath,
                    suggestion="Qualifying rate = max(contract_rate + 2%, 5.25%)",
                ))

            # Verify stress test floor value
            floor_match = re.search(r"(?:floor|minimum|benchmark)\s*[:=]\s*(\d+\.?\d*)", content, re.IGNORECASE)
            if floor_match:
                floor_val = float(floor_match.group(1))
                if abs(floor_val - self.CMHC_RULES["stress_test_floor"]) > 0.01:
                    findings.append(Finding(
                        message=f"Stress test floor is {floor_val}% — current CMHC floor is {self.CMHC_RULES['stress_test_floor']}%",
                        severity=AgentSeverity.HIGH,
                        file_path=fpath,
                        suggestion="Update to current Bank of Canada qualifying rate",
                    ))

        return findings

    def _check_premium_calculation(self, fpath: str, content: str) -> List[Finding]:
        findings = []

        if re.search(r"premium|insur.*(?:rate|cost|fee)", content, re.IGNORECASE):
            # Check for LTV-based tiering
            has_tiered_premium = re.search(
                r"(?:2\.80|3\.10|4\.00|2\.8|3\.1|4\.0).*%|ltv.*(?:80|85|90|95)",
                content, re.IGNORECASE,
            )
            if not has_tiered_premium:
                findings.append(Finding(
                    message="Insurance premium missing LTV-based tiering",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath,
                    suggestion="Premiums: 80-85% LTV=2.80%, 85-90%=3.10%, 90-95%=4.00%",
                ))

        return findings

    def _check_general_compliance(self, fpath: str, content: str) -> List[Finding]:
        findings = []

        # Check for Canadian-specific patterns
        if re.search(r"mortgage|loan", content, re.IGNORECASE):
            if not re.search(r"CAD|CDN|\$.*(?:CA|canadian)|currency.*(?:CA|CDN)", content, re.IGNORECASE):
                if re.search(r"\$\s*\d|USD|usd", content):
                    findings.append(Finding(
                        message="Mortgage calculation may be using USD — ensure CAD currency handling",
                        severity=AgentSeverity.MEDIUM,
                        file_path=fpath,
                    ))

            # Check for property tax inclusion in GDS
            if re.search(r"gds|gross.*debt", content, re.IGNORECASE):
                if not re.search(r"property.?tax|heating|condo.?fee|strata", content, re.IGNORECASE):
                    findings.append(Finding(
                        message="GDS calculation may be missing property tax, heating, or condo fees",
                        severity=AgentSeverity.HIGH,
                        file_path=fpath,
                        suggestion="GDS = (mortgage + tax + heating + 50% condo fee) / income",
                    ))

        return findings

    def _extract_learnings(self, findings: List[Finding], mortgage_files: list) -> List[str]:
        learnings = [f"Analyzed {len(mortgage_files)} mortgage-related files"]
        critical = [f for f in findings if f.severity == AgentSeverity.CRITICAL]
        if critical:
            learnings.append(f"Found {len(critical)} critical CMHC compliance violations")
        return learnings
