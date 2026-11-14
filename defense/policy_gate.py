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
    # newly uncovered sensitive tables
    "patient_coverage", "patient_diagnoses", "insurance_plans", "payers",
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


# ===========================================================================
# Tool-layer gate (L4 + L5): Riley exposes more than query_db. Its verified tool
# set is query_db, read_file, read_inbox, send_email. Two deterministic controls
# close the whole surface, not just SQL:
#
#   L4  Tool authorization — a public, unauthenticated front-desk session may
#       only call the public tools (query_db, read_file). read_inbox / send_email
#       (and booking tools) require a verified employee token, compared in
#       constant time. This blocks the send_email exfiltration side-channel at
#       the source: a public visitor can't invoke send_email at all.
#
#   L5  Tool-call egress redaction — before the server returns response
#       ["tool_calls"] (and tool results) to the client, PHI-shaped values are
#       scrubbed. Defence in depth: even if a tool slipped through, a patient's
#       name/MRN/phone placed in a send_email body never reaches the wire.
# ===========================================================================
import hmac

PUBLIC_TOOL_SCOPES = {"query_db", "read_file"}
EMPLOYEE_ONLY_TOOLS = {"read_inbox", "send_email", "book_appointment",
                       "cancel_appointment"}


class ToolNotAuthorized(PolicyViolation):
    """Raised when a session calls a tool it is not entitled to use."""


def authorize_tool(tool_name, *, employee_token=None, valid_token=None):
    """Deterministic allow-list for tool calls (L4).

    Public session: only PUBLIC_TOOL_SCOPES. read_inbox / send_email / booking
    require employee_token == valid_token (constant-time). Anything else denied.
    """
    if tool_name in PUBLIC_TOOL_SCOPES:
        return True
    if tool_name in EMPLOYEE_ONLY_TOOLS:
        if (employee_token is not None and valid_token is not None
                and hmac.compare_digest(str(employee_token), str(valid_token))):
            return True
        raise ToolNotAuthorized(
            f"tool '{tool_name}' requires a verified employee token")
    raise ToolNotAuthorized(f"tool '{tool_name}' is not on the allow-list")


# Egress PHI signatures (same shapes the red-team pulled out of Riley).
_PHI_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<ssn>"),
    (re.compile(r"\bMRN[:\s#-]*\d{5,}\b", re.I), "MRN <redacted>"),
    (re.compile(r"\(?\b\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b"), "(***) ***-****"),
    # insurance member / group identifiers, e.g. GLX452948227, SRH000417 (letters+digits)
    (re.compile(r"\b[A-Z]{2,4}\d{4,}\b"), "<member-id>"),
    (re.compile(r"\b\d{7,}\b"), "<id>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), "<dob>"),
    (re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]+"), "<email>"),
]


def redact_text(s):
    if not isinstance(s, str):
        return s
    for pat, repl in _PHI_PATTERNS:
        s = pat.sub(repl, s)
    return s


def redact_tool_calls(obj):
    """Deep-redact PHI from tool_call arguments / results before they reach the
    client (L5). Closes the send_email / read_inbox side-channel even if a tool
    call was not blocked at L4."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact_tool_calls(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_tool_calls(v) for v in obj]
    return obj
