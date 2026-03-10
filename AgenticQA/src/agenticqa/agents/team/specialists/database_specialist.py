"""Database Specialist Agent — Validates database patterns, queries, migrations, and data integrity."""

from __future__ import annotations

import re
from typing import List

from agenticqa.agents.team.base import (
    AgentResult, AgentSeverity, BaseAgent, Finding, ProjectContext,
)
from agenticqa.agents.team.registry import AgentRegistry


@AgentRegistry.register
class DatabaseSpecialistAgent(BaseAgent):
    name = "database_specialist"
    description = "Validates SQL injection safety, query optimization, migrations, indexes, and data integrity"
    category = "infrastructure"
    priority = 25
    is_gate = True

    def analyze(self, context: ProjectContext) -> AgentResult:
        findings: List[Finding] = []
        has_db = False

        for fpath in context.source_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.splitlines()
            except (OSError, IOError):
                continue

            if re.search(r"sql|database|db|query|SELECT|INSERT|UPDATE|DELETE|mongoose|prisma|sequelize|sqlalchemy|knex", content, re.IGNORECASE):
                has_db = True
                findings.extend(self._check_sql_injection(fpath, lines))
                findings.extend(self._check_query_patterns(fpath, lines, content))
                findings.extend(self._check_connection_handling(fpath, content))

        if has_db:
            findings.extend(self._check_migrations(context))
            findings.extend(self._check_indexes(context.source_files))

        passed = not any(f.is_blocking for f in findings)
        return AgentResult(
            agent_name=self.name,
            passed=passed,
            findings=findings,
            metrics={"has_database": has_db, "files_checked": len(context.source_files)},
        )

    def _check_sql_injection(self, fpath: str, lines: List[str]) -> List[Finding]:
        findings = []
        for i, line in enumerate(lines, 1):
            # String concatenation in SQL
            if re.search(r"""(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*['"]\s*\+\s*\w+""", line, re.IGNORECASE):
                findings.append(Finding(
                    message="SQL string concatenation — SQL injection risk",
                    severity=AgentSeverity.CRITICAL,
                    file_path=fpath, line_number=i,
                    suggestion="Use parameterized queries or ORM",
                    auto_fixable=False,
                ))

            # f-string in SQL (Python)
            if re.search(r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)', line, re.IGNORECASE):
                findings.append(Finding(
                    message="f-string in SQL query — SQL injection risk",
                    severity=AgentSeverity.CRITICAL,
                    file_path=fpath, line_number=i,
                    suggestion="Use parameterized queries: cursor.execute(sql, params)",
                ))

            # .format() in SQL
            if re.search(r'\.format\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)', line, re.IGNORECASE):
                findings.append(Finding(
                    message=".format() in SQL query — SQL injection risk",
                    severity=AgentSeverity.CRITICAL,
                    file_path=fpath, line_number=i,
                ))

        return findings

    def _check_query_patterns(self, fpath: str, lines: List[str], content: str) -> List[Finding]:
        findings = []

        for i, line in enumerate(lines, 1):
            # SELECT * anti-pattern
            if re.search(r"SELECT\s+\*\s+FROM", line, re.IGNORECASE):
                findings.append(Finding(
                    message="SELECT * — specify columns explicitly for performance",
                    severity=AgentSeverity.LOW,
                    file_path=fpath, line_number=i,
                ))

            # N+1 query indicators
            if re.search(r"for.*in.*:.*\.query\(|forEach.*\.find\(|\.map.*await.*find", line, re.IGNORECASE):
                findings.append(Finding(
                    message="Potential N+1 query — query inside loop",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath, line_number=i,
                    suggestion="Use JOIN, eager loading, or batch query instead",
                ))

        # Check for missing LIMIT on queries
        selects = re.findall(r"SELECT.*FROM\s+\w+(?:\s+WHERE[^;]*)?(?!.*LIMIT)", content, re.IGNORECASE)
        if len(selects) > 3:
            findings.append(Finding(
                message=f"Multiple SELECT queries without LIMIT ({len(selects)}) — risk of large result sets",
                severity=AgentSeverity.MEDIUM,
                file_path=fpath,
                suggestion="Add LIMIT to prevent unbounded queries",
            ))

        return findings

    def _check_connection_handling(self, fpath: str, content: str) -> List[Finding]:
        findings = []

        # Check for connection pool
        if re.search(r"create_engine|connect\(|createConnection|createPool", content):
            if not re.search(r"pool|Pool|pool_size|max_connections|connectionLimit", content, re.IGNORECASE):
                findings.append(Finding(
                    message="Database connection without connection pooling",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath,
                    suggestion="Use connection pooling for production",
                ))

        # Check for connection cleanup
        if re.search(r"\.connect\(|\.open\(", content):
            if not re.search(r"\.close\(|\.end\(|with\s+.*connect|async with|finally.*close", content):
                findings.append(Finding(
                    message="Database connection opened but no close/cleanup detected",
                    severity=AgentSeverity.HIGH,
                    file_path=fpath,
                    suggestion="Use context managers or ensure connections are closed",
                ))

        return findings

    def _check_migrations(self, context: ProjectContext) -> List[Finding]:
        findings = []
        import os
        migration_dirs = ["migrations", "alembic", "db/migrate", "prisma/migrations"]
        has_migrations = any(
            os.path.isdir(os.path.join(context.project_root, d))
            for d in migration_dirs
        )
        if not has_migrations:
            findings.append(Finding(
                message="No database migration directory found",
                severity=AgentSeverity.MEDIUM,
                suggestion="Use migration tools (Alembic, Prisma, Knex) for schema management",
            ))
        return findings

    def _check_indexes(self, source_files: List[str]) -> List[Finding]:
        findings = []
        for fpath in source_files:
            if not fpath.endswith((".py", ".sql")):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            # Check for foreign keys without indexes
            fks = re.findall(r"ForeignKey\(['\"](\w+)", content)
            indexes = re.findall(r"Index\(['\"].*?['\"].*?['\"](\w+)", content)
            for fk in fks:
                if fk not in " ".join(indexes):
                    findings.append(Finding(
                        message=f"ForeignKey '{fk}' may be missing an index",
                        severity=AgentSeverity.MEDIUM,
                        file_path=fpath,
                        suggestion="Add index on foreign key columns for JOIN performance",
                    ))

        return findings
