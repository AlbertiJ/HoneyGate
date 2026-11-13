"""
================================================================================
HONEYGATE STORAGE: Persistencia SQLite Única del Daemon (Fuente de Verdad)
Esquema unificado para configuración, sesiones, eventos forenses y aislamiento.
Todas las consultas utilizan parámetros vinculados (?) para prevenir SQL injection.
================================================================================
"""

import os
import json
import time
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_DB_PATH = os.path.join("data", "honeygate.db")

DEFAULT_CONFIG: Dict[str, Any] = {
    "mode": 1,
    "retention_days": 30,
    "max_outbound_per_minute": 10,
    "portal_enabled": True,
    "honeypot_enabled": False,
    "egress_whitelist": [],
    "sybil_max_emails_per_device": 3,
    "sybil_window_seconds": 600,
}

VALID_SESSION_STATUSES = ("active", "closed", "isolated", "en_observacion")
VALID_SEVERITIES = ("info", "normal", "warning", "critical")


class HoneyGateStorage:
    """
    Capa de persistencia SQLite thread-safe para el daemon HoneyGate.
    Almacena configuración operativa, sesiones unificadas (origen/objetivo/sesión),
    eventos forenses y estado de aislamiento perimetral.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        parent_dir = os.path.dirname(os.path.abspath(self.db_path))
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.execute("PRAGMA busy_timeout=5000;")
            self._init_schema()

    def _init_schema(self):
        """Crea las tablas del esquema unificado si no existen e inicializa configuración base."""
        cur = self._conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS daemon_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                mode INTEGER NOT NULL DEFAULT 1 CHECK (mode IN (1, 2, 3)),
                retention_days INTEGER NOT NULL DEFAULT 30,
                max_outbound_per_minute INTEGER NOT NULL DEFAULT 10,
                portal_enabled INTEGER NOT NULL DEFAULT 1,
                honeypot_enabled INTEGER NOT NULL DEFAULT 0,
                egress_whitelist_json TEXT NOT NULL DEFAULT '[]',
                sybil_max_emails_per_device INTEGER NOT NULL DEFAULT 3,
                sybil_window_seconds INTEGER NOT NULL DEFAULT 600,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mode INTEGER NOT NULL DEFAULT 1 CHECK (mode IN (1, 2, 3)),
                device_id TEXT NOT NULL,
                mac TEXT NOT NULL DEFAULT 'UNKNOWN',
                ip TEXT NOT NULL,
                client_port INTEGER NOT NULL DEFAULT 0,
                device_type TEXT NOT NULL DEFAULT 'unknown',
                browser_fingerprint TEXT NOT NULL DEFAULT '',
                network_fingerprint TEXT NOT NULL DEFAULT '',
                dhcp_fingerprint TEXT NOT NULL DEFAULT '',
                dest_ip TEXT NOT NULL DEFAULT '0.0.0.0',
                dest_port INTEGER NOT NULL DEFAULT 0,
                service TEXT NOT NULL DEFAULT 'unknown',
                honeytoken_touched TEXT NOT NULL DEFAULT '',
                visitor_label TEXT NOT NULL DEFAULT '',
                fd INTEGER,
                started_at REAL NOT NULL,
                ended_at REAL,
                duration_sec REAL NOT NULL DEFAULT 0.0,
                bytes_in INTEGER NOT NULL DEFAULT 0,
                bytes_out INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'closed', 'isolated', 'en_observacion')),
                observed_reason TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip);
            CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON sessions(device_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
            CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions(started_at);

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                timestamp REAL NOT NULL,
                created_at TEXT NOT NULL,
                mode INTEGER NOT NULL DEFAULT 1 CHECK (mode IN (1, 2, 3)),
                device_id TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info'
                    CHECK (severity IN ('info', 'normal', 'warning', 'critical')),
                mitre_technique TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
            CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);

            CREATE TABLE IF NOT EXISTS isolated_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                isolated_at REAL NOT NULL
            );
            """
        )

        row = cur.execute("SELECT id FROM daemon_config WHERE id = 1").fetchone()
        if row is None:
            cur.execute(
                """
                INSERT INTO daemon_config (
                    id, mode, retention_days, max_outbound_per_minute,
                    portal_enabled, honeypot_enabled, egress_whitelist_json,
                    sybil_max_emails_per_device, sybil_window_seconds, updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    DEFAULT_CONFIG["mode"],
                    DEFAULT_CONFIG["retention_days"],
                    DEFAULT_CONFIG["max_outbound_per_minute"],
                    1 if DEFAULT_CONFIG["portal_enabled"] else 0,
                    1 if DEFAULT_CONFIG["honeypot_enabled"] else 0,
                    json.dumps(DEFAULT_CONFIG["egress_whitelist"]),
                    DEFAULT_CONFIG["sybil_max_emails_per_device"],
                    DEFAULT_CONFIG["sybil_window_seconds"],
                    time.time(),
                ),
            )
        self._conn.commit()

    def close(self):
        """Cierra la conexión SQLite de forma segura."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    # ------------------------------------------------------------------
    # Configuración
    # ------------------------------------------------------------------

    def get_config(self) -> Dict[str, Any]:
        """Obtiene la configuración actual persistida del daemon."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM daemon_config WHERE id = 1"
            ).fetchone()
            if not row:
                return dict(DEFAULT_CONFIG)
            try:
                whitelist = json.loads(row["egress_whitelist_json"])
                if not isinstance(whitelist, list):
                    whitelist = []
            except Exception:
                whitelist = []
            return {
                "mode": int(row["mode"]),
                "retention_days": int(row["retention_days"]),
                "max_outbound_per_minute": int(row["max_outbound_per_minute"]),
                "portal_enabled": bool(row["portal_enabled"]),
                "honeypot_enabled": bool(row["honeypot_enabled"]),
                "egress_whitelist": whitelist,
                "sybil_max_emails_per_device": int(row["sybil_max_emails_per_device"]),
                "sybil_window_seconds": int(row["sybil_window_seconds"]),
                "updated_at": float(row["updated_at"]),
            }

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Actualiza parcialmente o totalmente la configuración validada en SQLite."""
        with self._lock:
            current = self.get_config()
            merged = dict(current)
            for key in DEFAULT_CONFIG.keys():
                if key in updates:
                    merged[key] = updates[key]

            now = time.time()
            self._conn.execute(
                """
                UPDATE daemon_config SET
                    mode = ?,
                    retention_days = ?,
                    max_outbound_per_minute = ?,
                    portal_enabled = ?,
                    honeypot_enabled = ?,
                    egress_whitelist_json = ?,
                    sybil_max_emails_per_device = ?,
                    sybil_window_seconds = ?,
                    updated_at = ?
                WHERE id = 1
                """,
                (
                    int(merged["mode"]),
                    int(merged["retention_days"]),
                    int(merged["max_outbound_per_minute"]),
                    1 if merged["portal_enabled"] else 0,
                    1 if merged["honeypot_enabled"] else 0,
                    json.dumps(merged["egress_whitelist"]),
                    int(merged["sybil_max_emails_per_device"]),
                    int(merged["sybil_window_seconds"]),
                    now,
                ),
            )
            self._conn.commit()
            return self.get_config()

    # ------------------------------------------------------------------
    # Sesiones (Esquema Unificado)
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_session(row: sqlite3.Row) -> Dict[str, Any]:
        started = float(row["started_at"])
        ended = float(row["ended_at"]) if row["ended_at"] is not None else None
        duration = (
            float(row["duration_sec"])
            if ended is not None
            else round(max(0.0, time.time() - started), 2)
        )
        return {
            "id": int(row["id"]),
            "mode": int(row["mode"]),
            "origin": {
                "device_id": row["device_id"],
                "mac": row["mac"],
                "ip": row["ip"],
                "client_port": int(row["client_port"]),
                "device_type": row["device_type"],
                "fingerprints": {
                    "browser": row["browser_fingerprint"],
                    "network": row["network_fingerprint"],
                    "dhcp": row["dhcp_fingerprint"],
                },
            },
            "target": {
                "dest_ip": row["dest_ip"],
                "dest_port": int(row["dest_port"]),
                "service": row["service"],
                "honeytoken_touched": row["honeytoken_touched"] or None,
            },
            "session": {
                "started_at": started,
                "ended_at": ended,
                "duration_sec": duration,
                "status": row["status"],
                "bytes_in": int(row["bytes_in"]),
                "bytes_out": int(row["bytes_out"]),
                "observed_reason": row["observed_reason"] or None,
            },
            "device_id": row["device_id"],
            "ip": row["ip"],
            "mac": row["mac"],
            "service": row["service"],
            "dest_port": int(row["dest_port"]),
            "status": row["status"],
            "duration_sec": duration,
            "visitor_label": row["visitor_label"] or None,
            "fd": row["fd"],
        }

    def create_session(
        self,
        ip: str,
        mac: str = "UNKNOWN",
        client_port: int = 0,
        device_id: str = "",
        device_type: str = "unknown",
        browser_fingerprint: str = "",
        network_fingerprint: str = "",
        dhcp_fingerprint: str = "",
        dest_ip: str = "0.0.0.0",
        dest_port: int = 0,
        service: str = "unknown",
        honeytoken_touched: str = "",
        visitor_label: str = "",
        fd: Optional[int] = None,
        mode: Optional[int] = None,
        status: str = "active",
    ) -> int:
        """Inserta una nueva sesión en el esquema unificado y retorna su ID."""
        if status not in VALID_SESSION_STATUSES:
            raise ValueError(f"Estado de sesión inválido: {status}")

        with self._lock:
            effective_mode = mode if mode in (1, 2, 3) else self.get_config()["mode"]
            effective_device_id = device_id or f"net:{ip}:{mac}"
            now = time.time()
            cur = self._conn.execute(
                """
                INSERT INTO sessions (
                    mode, device_id, mac, ip, client_port, device_type,
                    browser_fingerprint, network_fingerprint, dhcp_fingerprint,
                    dest_ip, dest_port, service, honeytoken_touched, visitor_label,
                    fd, started_at, ended_at, duration_sec, bytes_in, bytes_out,
                    status, observed_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0.0, 0, 0, ?, '')
                """,
                (
                    effective_mode,
                    effective_device_id,
                    mac,
                    ip,
                    int(client_port),
                    device_type,
                    browser_fingerprint,
                    network_fingerprint,
                    dhcp_fingerprint,
                    dest_ip,
                    int(dest_port),
                    service,
                    honeytoken_touched,
                    visitor_label,
                    fd,
                    now,
                    status,
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def get_session(self, session_id: int) -> Optional[Dict[str, Any]]:
        """Obtiene una sesión por ID."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sessions WHERE id = ?",
                (int(session_id),),
            ).fetchone()
            return self._row_to_session(row) if row else None

    def close_session(
        self,
        session_id: int,
        bytes_in: int = 0,
        bytes_out: int = 0,
        status: str = "closed",
    ) -> Optional[Dict[str, Any]]:
        """Cierra o actualiza métricas finales de una sesión existente."""
        if status not in VALID_SESSION_STATUSES:
            raise ValueError(f"Estado inválido: {status}")
        with self._lock:
            row = self._conn.execute(
                "SELECT started_at, status FROM sessions WHERE id = ?",
                (int(session_id),),
            ).fetchone()
            if not row:
                return None

            now = time.time()
            duration = round(max(0.0, now - float(row["started_at"])), 2)
            # Preservar marca 'en_observacion' si no fue escalada a 'isolated'
            final_status = status
            if row["status"] == "en_observacion" and status == "closed":
                final_status = "en_observacion"

            self._conn.execute(
                """
                UPDATE sessions
                SET ended_at = ?, duration_sec = ?, bytes_in = ?, bytes_out = ?, status = ?
                WHERE id = ?
                """,
                (now, duration, int(bytes_in), int(bytes_out), final_status, int(session_id)),
            )
            self._conn.commit()
            return self.get_session(session_id)

    def mark_session_observed(
        self,
        session_id: int,
        reason: str = "Marcada en observación por operador",
    ) -> Optional[Dict[str, Any]]:
        """Marca una sesión existente como 'en_observacion' y registra el evento forense."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sessions WHERE id = ?",
                (int(session_id),),
            ).fetchone()
            if not row:
                return None

            self._conn.execute(
                """
                UPDATE sessions
                SET status = 'en_observacion', observed_reason = ?
                WHERE id = ?
                """,
                (reason, int(session_id)),
            )
            self._conn.commit()

            self.record_event(
                event_type="SESSION_OBSERVED",
                severity="warning",
                description=f"Sesión #{session_id} ({row['ip']}) marcada en observación: {reason}",
                session_id=int(session_id),
                mode=int(row["mode"]),
                device_id=row["device_id"],
                ip=row["ip"],
                mitre_technique="T1078",
                metadata={"reason": reason, "previous_status": row["status"]},
            )
            return self.get_session(session_id)

    def list_sessions(
        self,
        status: Optional[str] = None,
        ip: Optional[str] = None,
        device_id: Optional[str] = None,
        service: Optional[str] = None,
        mode: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Lista sesiones con filtros parametrizados y paginación."""
        clauses: List[str] = []
        params: List[Any] = []

        if status:
            clauses.append("status = ?")
            params.append(status)
        if ip:
            clauses.append("ip = ?")
            params.append(ip)
        if device_id:
            clauses.append("device_id = ?")
            params.append(device_id)
        if service:
            clauses.append("service = ?")
            params.append(service)
        if mode is not None:
            clauses.append("mode = ?")
            params.append(int(mode))

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._lock:
            count_row = self._conn.execute(
                f"SELECT COUNT(*) AS cnt FROM sessions {where_sql}",
                tuple(params),
            ).fetchone()
            total = int(count_row["cnt"]) if count_row else 0

            rows = self._conn.execute(
                f"""
                SELECT * FROM sessions
                {where_sql}
                ORDER BY started_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                tuple(params + [int(limit), int(offset)]),
            ).fetchall()
            return [self._row_to_session(r) for r in rows], total

    # ------------------------------------------------------------------
    # Eventos Forenses
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Dict[str, Any]:
        try:
            meta = json.loads(row["metadata_json"])
            if not isinstance(meta, dict):
                meta = {}
        except Exception:
            meta = {}
        return {
            "id": int(row["id"]),
            "session_id": int(row["session_id"]) if row["session_id"] is not None else None,
            "timestamp": float(row["timestamp"]),
            "created_at": row["created_at"],
            "mode": int(row["mode"]),
            "device_id": row["device_id"] or None,
            "ip": row["ip"] or None,
            "event_type": row["event_type"],
            "severity": row["severity"],
            "mitre_technique": row["mitre_technique"] or None,
            "description": row["description"],
            "metadata": meta,
        }

    def record_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        session_id: Optional[int] = None,
        mode: Optional[int] = None,
        device_id: str = "",
        ip: str = "",
        mitre_technique: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Persiste un evento forense o operativo en la base SQLite."""
        sev = severity if severity in VALID_SEVERITIES else "info"
        now = time.time()
        created_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        meta_str = json.dumps(metadata or {})

        with self._lock:
            effective_mode = mode if mode in (1, 2, 3) else self.get_config()["mode"]
            cur = self._conn.execute(
                """
                INSERT INTO events (
                    session_id, timestamp, created_at, mode, device_id, ip,
                    event_type, severity, mitre_technique, description, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    now,
                    created_at,
                    effective_mode,
                    device_id or "",
                    ip or "",
                    event_type,
                    sev,
                    mitre_technique or "",
                    description,
                    meta_str,
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def list_events(
        self,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        ip: Optional[str] = None,
        device_id: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        session_id: Optional[int] = None,
        mode: Optional[int] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Consulta eventos con filtros combinables y paginación."""
        clauses: List[str] = []
        params: List[Any] = []

        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if ip:
            clauses.append("ip = ?")
            params.append(ip)
        if device_id:
            clauses.append("device_id = ?")
            params.append(device_id)
        if mitre_technique:
            clauses.append("mitre_technique = ?")
            params.append(mitre_technique)
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(int(session_id))
        if mode is not None:
            clauses.append("mode = ?")
            params.append(int(mode))
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(float(since))
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(float(until))

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._lock:
            count_row = self._conn.execute(
                f"SELECT COUNT(*) AS cnt FROM events {where_sql}",
                tuple(params),
            ).fetchone()
            total = int(count_row["cnt"]) if count_row else 0

            rows = self._conn.execute(
                f"""
                SELECT * FROM events
                {where_sql}
                ORDER BY timestamp DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                tuple(params + [int(limit), int(offset)]),
            ).fetchall()
            return [self._row_to_event(r) for r in rows], total

    # ------------------------------------------------------------------
    # IPs aisladas
    # ------------------------------------------------------------------

    def set_isolated_ip(self, ip: str, reason: str):
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO isolated_ips (ip, reason, isolated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, isolated_at = excluded.isolated_at
                """,
                (ip, reason, time.time()),
            )
            self._conn.commit()

    def remove_isolated_ip(self, ip: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM isolated_ips WHERE ip = ?", (ip,))
            self._conn.commit()
            return cur.rowcount > 0

    def list_isolated_ips(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT ip, reason, isolated_at FROM isolated_ips").fetchall()
            return {
                r["ip"]: {"isolated_at": float(r["isolated_at"]), "reason": r["reason"]}
                for r in rows
            }
