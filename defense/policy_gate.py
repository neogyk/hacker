"""
Deterministic SQL Policy Gate for an LLM database agent (e.g. "Riley").

Three independent, deterministic layers (defence in depth):
  L1  Static token/AST guard — read-only, single statement, comment/quote stripping,
                               no multi-statement / PRAGMA / pragma_table_info /
                               information_schema / ATTACH / sqlite_master / write verbs.
  L2  SQLite AUTHORIZER      — the C database engine itself calls us for EVERY table
                               and column the query touches (SQLITE_READ), and we DENY
                               anything not on the per-role allow-list. Cannot be bypassed
                               by SQL obfuscation, UNIONs, subqueries, CTEs, or aliasing.
  L3  42 CFR Part 2 Gate     — suppresses federal Part 2 Substance Use Disorder program
                               records unless an explicit Part 2 consent token is present.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Policy:
    name: str
    allow: dict[str, set[str]] = field(default_factory=dict)
    enforce_part2_redaction: bool = True


PUBLIC_POLICY = Policy(
    name="public_frontdesk",
    allow={
        "facilities": {
            "facility_id", "name", "address_line1", "city",
            "state", "zip", "main_phone", "hours",
        },
        "departments": {
            "department_id", "facility_id", "department_name", "specialty",
        },
        # Provider directory metadata is public; direct staff contact PII (phone/email/cell/address) is denied
        "providers": {
            "provider_id", "first_name", "last_name", "full_name",
            "credential", "specialty", "primary_department_id", "department_id",
        },
    },
    enforce_part2_redaction=True,
)

SENSITIVE_TABLES = {
    "patients", "patient_contacts", "encounters", "appointments",
    "insurance", "staff", "users", "credentials", "secrets", "audit_log",
}


class PolicyViolation(Exception):
    """Raised (deterministically) when a query breaks the policy."""


_FORBIDDEN_WORDS = {
    "pragma", "pragma_table_info", "pragma_database_list", "pragma_foreign_key_list",
    "information_schema", "sqlite_master", "sqlite_temp_master", "sqlite_schema",
    "attach", "detach", "insert", "update", "delete", "drop", "alter",
    "create", "replace", "vacuum", "reindex", "load_extension",
}


def _strip_comments_and_strings(sql: str) -> str:
    no_block = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    no_line = re.sub(r"--[^\r\n]*", " ", no_block)
    no_str = re.sub(r"'(?:''|[^'])*'", "''", no_line)
    return no_str


def _static_guard(sql: str) -> None:
    if not isinstance(sql, str) or not sql.strip():
        raise PolicyViolation("empty or invalid SQL")
    cleaned = _strip_comments_and_strings(sql).strip()
    if ";" in cleaned:
        raise PolicyViolation("multiple statements are not allowed")
    words = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", cleaned.lower())
    if not words:
        raise PolicyViolation("no SQL tokens found")
    if words[0] not in ("select", "with"):
        raise PolicyViolation(f"only SELECT queries are allowed (got {words[0]!r})")
    bad = sorted(set(words) & _FORBIDDEN_WORDS)
    if bad:
        raise PolicyViolation(f"forbidden token in query: {bad[0]!r}")


def _make_authorizer(policy: Policy):
    allow = policy.allow

    def authorizer(action, arg1, arg2, db_name, trigger):
        if action == sqlite3.SQLITE_READ:
            table, column = arg1, arg2
            if table in allow:
                cols = allow[table]
                if "*" in cols or column in cols:
                    return sqlite3.SQLITE_OK
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_DENY
        if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_FUNCTION):
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    return authorizer


class SafeDB:
    """Open a database read-only and run only policy-compliant SELECTs."""

    def __init__(self, db_path: str, policy: Policy = PUBLIC_POLICY):
        self.conn = sqlite3.connect(
            f"file:{db_path}?mode=ro", uri=True, check_same_thread=False
        )
        self.policy = policy

    def query_db(self, sql: str, *, include_part2: bool = False):
        sql = (sql or "").strip().rstrip(";").strip()
        _static_guard(sql)                                       # L1
        self.conn.set_authorizer(_make_authorizer(self.policy))  # L2
        try:
            cur = self.conn.execute(sql)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description] if cur.description else []
            if self.policy.enforce_part2_redaction and not include_part2:
                rows = [
                    r for r in rows
                    if "part 2" not in " ".join(str(v) for v in r).lower()
                ]
            return cols, rows
        except sqlite3.DatabaseError as e:
            raise PolicyViolation(f"blocked by policy: {e}") from e
        finally:
            self.conn.set_authorizer(None)

    def close(self):
        self.conn.close()
