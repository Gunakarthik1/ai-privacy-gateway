"""
Role-based token budget enforcer backed by SQLite.
Roles and daily limits:
    free       ->  10,000 tokens / day
    standard   -> 100,000 tokens / day
    enterprise -> unlimited
"""

import sqlite3
import threading
from datetime import date, datetime
from typing import Optional
from .models import BudgetResult, BudgetSummary


ROLE_LIMITS = {
    "free": 10_000,
    "standard": 100_000,
    "enterprise": None,  # None == unlimited
}

DEFAULT_ROLE = "standard"
DB_PATH = "gateway_budget.db"


class BudgetEnforcer:
    """
    Tracks per-API-key token consumption and enforces daily role-based limits.
    Uses SQLite for persistence across restarts.
    """

    def __init__(self, db_path: str = DB_PATH) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS budget_usage (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    api_key     TEXT NOT NULL,
                    usage_date  TEXT NOT NULL,
                    tokens_used INTEGER NOT NULL DEFAULT 0,
                    role        TEXT NOT NULL DEFAULT 'standard',
                    UNIQUE(api_key, usage_date)
                )
                """
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _today() -> str:
        return date.today().isoformat()

    def _get_usage(self, conn: sqlite3.Connection, api_key: str, today: str) -> int:
        row = conn.execute(
            "SELECT tokens_used FROM budget_usage WHERE api_key = ? AND usage_date = ?",
            (api_key, today),
        ).fetchone()
        return row["tokens_used"] if row else 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_budget(self, api_key: str, role: str, estimated_tokens: int) -> BudgetResult:
        """
        Determine whether a request with *estimated_tokens* is within budget.
        Does NOT consume any tokens.
        """
        role = role.lower()
        limit = ROLE_LIMITS.get(role, ROLE_LIMITS[DEFAULT_ROLE])

        if limit is None:
            # Enterprise: unlimited
            return BudgetResult(allowed=True)

        today = self._today()
        with self._lock:
            with self._connect() as conn:
                used = self._get_usage(conn, api_key, today)

        if used + estimated_tokens > limit:
            remaining = max(0, limit - used)
            return BudgetResult(
                allowed=False,
                reason=(
                    f"Daily token budget exceeded for role '{role}'. "
                    f"Used: {used:,}, Limit: {limit:,}, Remaining: {remaining:,}, "
                    f"Requested: {estimated_tokens:,}."
                ),
            )
        return BudgetResult(allowed=True)

    def record_usage(self, api_key: str, role: str, tokens_used: int) -> None:
        """
        Record *tokens_used* against *api_key*'s daily budget.
        Creates a new row for today if none exists; increments otherwise.
        """
        role = role.lower()
        today = self._today()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO budget_usage (api_key, usage_date, tokens_used, role)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(api_key, usage_date)
                    DO UPDATE SET tokens_used = tokens_used + excluded.tokens_used,
                                  role = excluded.role
                    """,
                    (api_key, today, tokens_used, role),
                )
                conn.commit()

    def get_usage_summary(self, api_key: str, role: str = DEFAULT_ROLE) -> BudgetSummary:
        """Return today's usage summary for *api_key*."""
        role = role.lower()
        limit = ROLE_LIMITS.get(role, ROLE_LIMITS[DEFAULT_ROLE])
        today = self._today()

        with self._lock:
            with self._connect() as conn:
                used = self._get_usage(conn, api_key, today)

        is_unlimited = limit is None
        effective_limit = limit if limit is not None else 0
        percent = (used / effective_limit * 100.0) if effective_limit else 0.0

        return BudgetSummary(
            api_key=api_key,
            role=role,
            used_today=used,
            limit=effective_limit,
            percent_used=round(percent, 2),
            is_unlimited=is_unlimited,
        )

    def reset_usage(self, api_key: str) -> None:
        """Delete today's usage row for *api_key* (useful for testing)."""
        today = self._today()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM budget_usage WHERE api_key = ? AND usage_date = ?",
                    (api_key, today),
                )
                conn.commit()
