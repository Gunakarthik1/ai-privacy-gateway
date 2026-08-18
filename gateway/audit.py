"""
Audit logger backed by SQLite.
Every request through the gateway generates an AuditEntry regardless of outcome.
"""

import sqlite3
import hashlib
import threading
import json
from datetime import datetime, timezone
from typing import List, Optional
from .models import AuditEntry, ThreatSummary


DB_PATH = "gateway_audit.db"


class AuditLogger:
    """
    Persists audit entries to SQLite and exposes query helpers for the dashboard.
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
                CREATE TABLE IF NOT EXISTS audit_log (
                    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                    api_key              TEXT NOT NULL,
                    timestamp            TEXT NOT NULL,
                    prompt_hash          TEXT NOT NULL,
                    pii_entities_detected INTEGER NOT NULL DEFAULT 0,
                    injection_risk       TEXT NOT NULL DEFAULT 'low',
                    tokens_in            INTEGER NOT NULL DEFAULT 0,
                    tokens_out           INTEGER NOT NULL DEFAULT 0,
                    latency_ms           REAL NOT NULL DEFAULT 0,
                    action               TEXT NOT NULL DEFAULT 'allowed',
                    upstream_model       TEXT NOT NULL DEFAULT 'unknown',
                    matched_patterns     TEXT
                )
                """
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def hash_prompt(text: str) -> str:
        """SHA-256 hash of the prompt text (hex, first 16 chars)."""
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            id=row["id"],
            api_key=row["api_key"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            prompt_hash=row["prompt_hash"],
            pii_entities_detected=row["pii_entities_detected"],
            injection_risk=row["injection_risk"],
            tokens_in=row["tokens_in"],
            tokens_out=row["tokens_out"],
            latency_ms=row["latency_ms"],
            action=row["action"],
            upstream_model=row["upstream_model"],
            matched_patterns=row["matched_patterns"],
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(
        self,
        api_key: str,
        prompt: str,
        pii_entities_detected: int,
        injection_risk: str,
        tokens_in: int,
        tokens_out: int,
        latency_ms: float,
        action: str,
        upstream_model: str,
        matched_patterns: Optional[List[str]] = None,
    ) -> int:
        """
        Insert an audit record.  Returns the new row id.
        """
        prompt_hash = self.hash_prompt(prompt)
        timestamp = datetime.now(timezone.utc).isoformat()
        patterns_json = json.dumps(matched_patterns) if matched_patterns else None

        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO audit_log
                        (api_key, timestamp, prompt_hash, pii_entities_detected,
                         injection_risk, tokens_in, tokens_out, latency_ms,
                         action, upstream_model, matched_patterns)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        api_key,
                        timestamp,
                        prompt_hash,
                        pii_entities_detected,
                        injection_risk,
                        tokens_in,
                        tokens_out,
                        latency_ms,
                        action,
                        upstream_model,
                        patterns_json,
                    ),
                )
                conn.commit()
                return cur.lastrowid  # type: ignore[return-value]

    def get_recent_logs(self, limit: int = 50) -> List[AuditEntry]:
        """Return up to *limit* most recent audit entries."""
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_threat_summary(self) -> ThreatSummary:
        """Aggregate counters across all stored audit entries."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT
                        COUNT(*)                                        AS total_requests,
                        SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked,
                        SUM(CASE WHEN action = 'masked'  THEN 1 ELSE 0 END) AS masked,
                        SUM(CASE WHEN injection_risk IN ('high','critical') THEN 1 ELSE 0 END)
                                                                        AS injection_attempts,
                        SUM(pii_entities_detected)                      AS pii_detected_count
                    FROM audit_log
                    """
                ).fetchone()

        return ThreatSummary(
            total_requests=row["total_requests"] or 0,
            blocked=row["blocked"] or 0,
            masked=row["masked"] or 0,
            injection_attempts=row["injection_attempts"] or 0,
            pii_detected_count=row["pii_detected_count"] or 0,
        )
