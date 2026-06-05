"""
tools.py — fake demo tools for the Phase 1 walking skeleton.

Three tools, one dangerous:
    execute_sql     — runs SQL against a throwaway in-memory SQLite DB.
                      The only tool with irreversible side-effect potential.
    lookup_customer — read-only fake customer lookup (no writes, ever).
    calculator      — pure arithmetic via a safe AST-based evaluator.

WHY in-memory SQLite for execute_sql: it is throwaway (no file, no network),
so a DENYed DROP TABLE leaves no persistent damage even if the gate ever
fails.  The real danger is in the *intent* and the *ordering* — this tool
exists to prove the gate blocks the call before execute_sql() is entered.

WHY AST-based eval for calculator: bare eval() would let the agent run
arbitrary Python.  ast.literal_eval only handles literals; we use ast.parse +
a whitelist visitor so the expression can contain arithmetic operators but
nothing else — tiny, auditable, safe.
"""

from __future__ import annotations

import ast
import operator
import sqlite3
from typing import Any


# ---------------------------------------------------------------------------
# In-memory SQLite database (module-level singleton for the demo)
# ---------------------------------------------------------------------------

# WHY module-level connection: the demo runs in a single process; sharing one
# connection keeps state between calls (e.g. an INSERT is visible to a
# subsequent SELECT).  Tests that need isolation can call _reset_db().
_db_conn: sqlite3.Connection = sqlite3.connect(":memory:")
_db_conn.row_factory = sqlite3.Row


def _reset_db() -> None:
    """Re-initialise the in-memory DB.  Called by tests that need isolation."""
    global _db_conn
    _db_conn = sqlite3.connect(":memory:")
    _db_conn.row_factory = sqlite3.Row
    _seed_db()


def _seed_db() -> None:
    """Create a minimal schema and seed data for the demo."""
    _db_conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS customers (
            id    TEXT PRIMARY KEY,
            name  TEXT NOT NULL,
            email TEXT NOT NULL
        );
        INSERT OR IGNORE INTO customers VALUES
            ('C001', 'Alice',   'alice@example.com'),
            ('C002', 'Bob',     'bob@example.com'),
            ('C003', 'Charlie', 'charlie@example.com');

        CREATE TABLE IF NOT EXISTS orders (
            order_id    TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL,
            amount      REAL NOT NULL
        );
        INSERT OR IGNORE INTO orders VALUES
            ('O001', 'C001', 150.00),
            ('O002', 'C002',  75.50),
            ('O003', 'C001', 200.00);
        """
    )
    _db_conn.commit()


_seed_db()


# ---------------------------------------------------------------------------
# Tool 1: execute_sql  (dangerous)
# ---------------------------------------------------------------------------

def execute_sql(*, sql: str) -> str:
    """Execute SQL against the in-memory demo database and return results.

    The gateway rule targets this tool specifically.  If Aegis is working
    correctly, destructive SQL never reaches this function.
    """
    try:
        cursor = _db_conn.execute(sql)
        _db_conn.commit()
        rows = cursor.fetchall()
        if rows:
            cols = rows[0].keys()
            lines = [", ".join(cols)]
            lines += [", ".join(str(r[c]) for c in cols) for r in rows]
            return "\n".join(lines)
        return f"OK — {cursor.rowcount} row(s) affected."
    except sqlite3.Error as exc:
        return f"[SQL ERROR] {exc}"


# ---------------------------------------------------------------------------
# Tool 2: lookup_customer  (benign — read-only)
# ---------------------------------------------------------------------------

# Fixed fake customer records.  No DB write path exists in this function.
# WHY hardcoded fallback: the demo's lookup_customer is deliberately simple;
# the "read sensitive data" pattern is what matters for the Phase-2 trajectory
# rule, not the data itself.
_CUSTOMER_FALLBACK = {
    "id": "UNKNOWN",
    "name": "Unknown Customer",
    "email": "unknown@example.com",
    "status": "not found",
}


def lookup_customer(*, customer_id: str) -> str:
    """Return a fake customer record as a formatted string (read-only)."""
    row = _db_conn.execute(
        "SELECT id, name, email FROM customers WHERE id = ?", (customer_id,)
    ).fetchone()
    if row:
        return f"id={row['id']}, name={row['name']}, email={row['email']}, status=active"
    return (
        f"id={customer_id}, name=Unknown Customer, "
        "email=unknown@example.com, status=not found"
    )


# ---------------------------------------------------------------------------
# Tool 3: calculator  (benign — pure arithmetic)
# ---------------------------------------------------------------------------

# Supported binary operators.  Only these are whitelisted; anything else raises.
_SAFE_OPS: dict[type, Any] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.FloorDiv: operator.floordiv,
}

_SAFE_UNARY_OPS: dict[type, Any] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def _eval_node(node: ast.AST) -> float:
    """Recursively evaluate an arithmetic AST node.

    WHY a whitelist visitor instead of eval(): eval() executes arbitrary Python.
    This visitor only descends into Constant (numbers), BinOp (arithmetic), and
    UnaryOp (negation/plus) nodes — anything else raises ValueError, making the
    attack surface trivially small.
    """
    if isinstance(node, ast.Expression):
        return _eval_node(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return float(node.value)
        raise ValueError(f"Non-numeric constant: {node.value!r}")
    if isinstance(node, ast.BinOp):
        op_fn = _SAFE_OPS.get(type(node.op))
        if op_fn is None:
            raise ValueError(f"Unsupported operator: {type(node.op).__name__}")
        return op_fn(_eval_node(node.left), _eval_node(node.right))
    if isinstance(node, ast.UnaryOp):
        op_fn = _SAFE_UNARY_OPS.get(type(node.op))
        if op_fn is None:
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")
        return op_fn(_eval_node(node.operand))
    raise ValueError(f"Unsupported expression node: {type(node).__name__}")


def calculator(*, expression: str) -> str:
    """Evaluate a simple arithmetic expression and return the result."""
    try:
        tree = ast.parse(expression.strip(), mode="eval")
        result = _eval_node(tree)
        # Return an integer string when the result is whole, for readability.
        if result == int(result):
            return str(int(result))
        return str(result)
    except (ValueError, ZeroDivisionError, SyntaxError) as exc:
        return f"[CALC ERROR] {exc}"


# ---------------------------------------------------------------------------
# Registry and schema list (consumed by loop.py and the demo runners)
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, Any] = {
    "execute_sql": execute_sql,
    "lookup_customer": lookup_customer,
    "calculator": calculator,
}

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "execute_sql",
        "description": (
            "Execute a SQL statement against the demo database and return "
            "the result rows or a status message."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "The SQL statement to execute.",
                }
            },
            "required": ["sql"],
        },
    },
    {
        "name": "lookup_customer",
        "description": "Look up a customer record by ID and return their details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "customer_id": {
                    "type": "string",
                    "description": "The customer ID to look up (e.g. 'C001').",
                }
            },
            "required": ["customer_id"],
        },
    },
    {
        "name": "calculator",
        "description": "Evaluate a simple arithmetic expression and return the result.",
        "input_schema": {
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": (
                        "An arithmetic expression using +, -, *, /, ** — "
                        "e.g. '(10 + 5) * 3 / 2'."
                    ),
                }
            },
            "required": ["expression"],
        },
    },
]
