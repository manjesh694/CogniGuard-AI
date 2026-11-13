"""
CogniGuard AI - Atomic Thread-Safe SQLite Storage (WAL Mode)
Author: CogniGuard Engineering Team
Description: Concurrent-safe persistence for security audit logs,
             24/7 daemon detections, and Pro/Enterprise conversion leads.
"""

import os
import queue
import sqlite3
import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.environ.get("COGNIGUARD_DB_PATH") or os.path.join(_AGENT_DIR, "cogniguard.db")

THREAT_VERDICTS = (
    "INTRUSION_DETECTED",
    "HONEYPOT_BREACH",
    "DO_NOT_INSTALL",
    "REVIEW_REQUIRED",
)


class SecurityEventBroadcaster:
    """Thread-safe in-memory pub-sub channel for real-time threat streaming."""

    def __init__(self, max_queue: int = 100):
        self._subscribers: List[queue.Queue] = []
        self._lock = threading.Lock()
        self.max_queue = max_queue

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=self.max_queue)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, event: Dict[str, Any]) -> None:
        with self._lock:
            for q in list(self._subscribers):
                try:
                    q.put_nowait(event)
                except queue.Full:
                    try:
                        q.get_nowait()
                        q.put_nowait(event)
                    except Exception:
                        pass


class CogniGuardStore:
    """Thread-safe SQLite WAL store for audit logs and lead telemetry."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("COGNIGUARD_DB_PATH") or DEFAULT_DB_PATH
        self._lock = threading.Lock()
        self._broadcaster = SecurityEventBroadcaster()
        parent = os.path.dirname(os.path.abspath(self.db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.init_schema()

    def get_broadcaster(self) -> SecurityEventBroadcaster:
        """Return the store's real-time event broadcaster."""
        return self._broadcaster

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def init_schema(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        status TEXT NOT NULL,
                        verdict TEXT NOT NULL,
                        threat_score REAL NOT NULL,
                        action_taken TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        source_url TEXT,
                        file_size INTEGER DEFAULT 0
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_verdict ON audit_logs (verdict);"
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS leads (
                        id TEXT PRIMARY KEY,
                        plan TEXT NOT NULL,
                        email TEXT NOT NULL,
                        company TEXT,
                        seats INTEGER,
                        trial_key TEXT,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_leads_plan ON leads (plan);"
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quarantine (
                        id TEXT PRIMARY KEY,
                        filename TEXT NOT NULL,
                        original_path TEXT NOT NULL,
                        vault_path TEXT NOT NULL,
                        sha256 TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL,
                        threat_score REAL NOT NULL,
                        reason TEXT NOT NULL,
                        status TEXT NOT NULL,
                        quarantined_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine (status);"
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS iocs (
                        sha256 TEXT PRIMARY KEY,
                        label TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        added_at TEXT NOT NULL
                    )
                    """
                )

    def record_audit_event(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        record = {
            "status": entry.get("status", "OK"),
            "verdict": entry["verdict"],
            "threat_score": float(entry["threat_score"]),
            "action_taken": entry["action_taken"],
            "reason": entry.get("reason", ""),
            "timestamp": entry.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filename": entry.get("filename", "unknown"),
            "source_url": entry.get("source_url", ""),
            "file_size": int(entry.get("file_size", 0) or 0),
        }
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_logs
                        (status, verdict, threat_score, action_taken, reason, timestamp, filename, source_url, file_size)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["status"],
                        record["verdict"],
                        record["threat_score"],
                        record["action_taken"],
                        record["reason"],
                        record["timestamp"],
                        record["filename"],
                        record["source_url"],
                        record["file_size"],
                    ),
                )
        if hasattr(self, "_broadcaster") and self._broadcaster:
            self._broadcaster.publish(record)
        return record

    def list_audit_logs(
        self,
        limit: int = 50,
        offset: int = 0,
        verdict: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT status, verdict, threat_score, action_taken, reason, timestamp, filename, source_url, file_size FROM audit_logs"
        params: List[Any] = []
        if verdict:
            query += " WHERE verdict = ?"
            params.append(verdict)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([max(1, min(500, limit)), max(0, offset)])

        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def record_lead(
        self,
        plan: str,
        email: str,
        company: Optional[str] = None,
        seats: Optional[int] = None,
        trial_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        issued_key = trial_key
        if plan == "pro" and not issued_key:
            issued_key = f"CG-PRO-{uuid.uuid4().hex[:6].upper()}"

        record = {
            "id": uuid.uuid4().hex[:10],
            "plan": plan,
            "email": email.strip(),
            "company": company.strip() if company else None,
            "seats": seats,
            "trial_key": issued_key,
            "created_at": datetime.now().isoformat(),
        }
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO leads (id, plan, email, company, seats, trial_key, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["id"],
                        record["plan"],
                        record["email"],
                        record["company"],
                        record["seats"],
                        record["trial_key"],
                        record["created_at"],
                    ),
                )
        return record

    def list_leads(
        self,
        limit: int = 50,
        offset: int = 0,
        plan: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT id, plan, email, company, seats, trial_key, created_at FROM leads"
        params: List[Any] = []
        if plan:
            query += " WHERE plan = ?"
            params.append(plan)
        query += " ORDER BY rowid DESC LIMIT ? OFFSET ?"
        params.extend([max(1, min(500, limit)), max(0, offset)])

        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_telemetry_summary(self, version: str) -> Dict[str, Any]:
        placeholders = ",".join("?" for _ in THREAT_VERDICTS)
        with self._lock:
            with self._connect() as conn:
                audit_row = conn.execute(
                    f"""
                    SELECT
                        COUNT(*) AS total_events,
                        COALESCE(SUM(CASE WHEN verdict IN ({placeholders}) THEN 1 ELSE 0 END), 0) AS threats_blocked
                    FROM audit_logs
                    """,
                    THREAT_VERDICTS,
                ).fetchone()
                lead_row = conn.execute(
                    """
                    SELECT
                        COUNT(*) AS leads_captured,
                        COALESCE(SUM(CASE WHEN plan = 'pro' THEN 1 ELSE 0 END), 0) AS pro_trials,
                        COALESCE(SUM(CASE WHEN plan = 'enterprise' THEN 1 ELSE 0 END), 0) AS enterprise_pilots
                    FROM leads
                    """
                ).fetchone()

        total_events = int(audit_row["total_events"])
        blocked = int(audit_row["threats_blocked"])
        return {
            "status": "OK",
            "version": version,
            "total_events": total_events,
            "threats_blocked": blocked,
            "clean_events": total_events - blocked,
            "leads_captured": int(lead_row["leads_captured"]),
            "pro_trials": int(lead_row["pro_trials"]),
            "enterprise_pilots": int(lead_row["enterprise_pilots"]),
        }

    def record_quarantine_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO quarantine
                        (id, filename, original_path, vault_path, sha256, size_bytes, threat_score, reason, status, quarantined_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item["id"],
                        item["filename"],
                        item["original_path"],
                        item["vault_path"],
                        item["sha256"],
                        int(item["size_bytes"]),
                        float(item["threat_score"]),
                        item["reason"],
                        item["status"],
                        item["quarantined_at"],
                    ),
                )
        return item

    def list_quarantine_items(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT id, filename, original_path, vault_path, sha256, size_bytes, threat_score, reason, status, quarantined_at FROM quarantine"
        params: List[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY rowid DESC LIMIT ? OFFSET ?"
        params.extend([max(1, min(500, limit)), max(0, offset)])
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_quarantine_item(self, qid: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT id, filename, original_path, vault_path, sha256, size_bytes, threat_score, reason, status, quarantined_at FROM quarantine WHERE id = ?",
                    (qid,),
                ).fetchone()
        return dict(row) if row else None

    def update_quarantine_status(self, qid: str, status: str) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute("UPDATE quarantine SET status = ? WHERE id = ?", (status, qid))

    def set_setting(self, key: str, value: str) -> None:
        now = datetime.now().isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                    """,
                    (key, value, now),
                )

    def get_setting(self, key: str) -> Optional[str]:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def add_ioc(self, sha256: str, label: str, severity: str = "CRITICAL") -> Dict[str, Any]:
        clean_hash = sha256.strip().lower()
        record = {
            "sha256": clean_hash,
            "label": label.strip(),
            "severity": severity.upper(),
            "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO iocs (sha256, label, severity, added_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(sha256) DO UPDATE SET
                        label = excluded.label,
                        severity = excluded.severity,
                        added_at = excluded.added_at
                    """,
                    (record["sha256"], record["label"], record["severity"], record["added_at"]),
                )
        return record

    def get_ioc(self, sha256: str) -> Optional[Dict[str, Any]]:
        clean_hash = sha256.strip().lower()
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT sha256, label, severity, added_at FROM iocs WHERE sha256 = ?",
                    (clean_hash,),
                ).fetchone()
        return dict(row) if row else None

    def list_iocs(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT sha256, label, severity, added_at FROM iocs ORDER BY added_at DESC LIMIT ? OFFSET ?",
                    (max(1, min(500, limit)), max(0, offset)),
                ).fetchall()
        return [dict(r) for r in rows]

    def delete_ioc(self, sha256: str) -> bool:
        clean_hash = sha256.strip().lower()
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute("DELETE FROM iocs WHERE sha256 = ?", (clean_hash,))
        return cur.rowcount > 0

    def get_db_stats(self) -> Dict[str, Any]:
        """Return table row counts, file sizes, and WAL state for database health."""
        with self._lock:
            with self._connect() as conn:
                def _count(table: str) -> int:
                    try:
                        row = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()
                        return int(row["c"]) if row else 0
                    except (sqlite3.OperationalError, Exception):
                        return 0

                counts = {
                    "audit_logs": _count("audit_logs"),
                    "leads": _count("leads"),
                    "quarantine": _count("quarantine"),
                    "settings": _count("settings"),
                    "iocs": _count("iocs"),
                }

        db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        wal_path = f"{self.db_path}-wal"
        wal_size = os.path.getsize(wal_path) if os.path.exists(wal_path) else 0

        return {
            "status": "OK",
            "db_path": os.path.abspath(self.db_path),
            "db_size_bytes": db_size,
            "wal_size_bytes": wal_size,
            "tables": counts,
            "timestamp": datetime.now().isoformat(),
        }

    def backup_database(self, dest_path: Optional[str] = None) -> Dict[str, Any]:
        """Perform an atomic point-in-time backup using SQLite's online backup API."""
        if not dest_path:
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            parent = os.path.dirname(os.path.abspath(self.db_path))
            dest_path = os.path.join(parent, f"cogniguard_backup_{timestamp_str}.db")

        dest_abs = os.path.abspath(dest_path)
        dest_parent = os.path.dirname(dest_abs)
        if dest_parent:
            os.makedirs(dest_parent, exist_ok=True)

        with self._lock:
            with self._connect() as src_conn:
                dest_conn = sqlite3.connect(dest_abs)
                try:
                    src_conn.backup(dest_conn)
                finally:
                    dest_conn.close()

        backup_size = os.path.getsize(dest_abs) if os.path.exists(dest_abs) else 0
        return {
            "status": "OK",
            "backup_path": dest_abs,
            "size_bytes": backup_size,
            "timestamp": datetime.now().isoformat(),
        }

    def vacuum_database(self) -> Dict[str, Any]:
        """Reclaim unused pages, optimize B-trees, and compact storage."""
        size_before = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            try:
                conn.execute("VACUUM;")
            finally:
                conn.close()

        size_after = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        return {
            "status": "OK",
            "size_before_bytes": size_before,
            "size_after_bytes": size_after,
            "bytes_reclaimed": max(0, size_before - size_after),
            "timestamp": datetime.now().isoformat(),
        }
