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
import hashlib
import hmac
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple

from honeygate.mitre import get_mitre_engine


DEFAULT_DB_PATH = os.path.join("data", "honeygate.db")

DEFAULT_PORTAL_TEMPLATE: Dict[str, str] = {
    "title": "HoneyGate — Portal Cautivo",
    "subtitle": "Acceso nominal de red. No se solicitan ni almacenan contraseñas.",
    "footer": "",
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "mode": 1,
    "retention_days": 30,
    "max_outbound_per_minute": 10,
    "portal_enabled": True,
    "honeypot_enabled": False,
    "egress_whitelist": [],
    "sybil_max_emails_per_device": 3,
    "sybil_window_seconds": 600,
    "honeytokens": [],
    "portal_template": dict(DEFAULT_PORTAL_TEMPLATE),
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
                honeytokens_json TEXT NOT NULL DEFAULT '[]',
                portal_template_json TEXT NOT NULL DEFAULT '{}',
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
                browser_hash TEXT NOT NULL DEFAULT '',
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
                dhcp_lease_sec INTEGER NOT NULL DEFAULT 300,
                bandwidth_kbps INTEGER NOT NULL DEFAULT 10240,
                mail_verified INTEGER NOT NULL DEFAULT 1,
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

            CREATE TABLE IF NOT EXISTS portal_registrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                created_at REAL NOT NULL,
                device_id TEXT NOT NULL,
                browser_hash TEXT NOT NULL DEFAULT '',
                mac TEXT NOT NULL DEFAULT 'UNKNOWN',
                ip TEXT NOT NULL,
                email_hash TEXT NOT NULL,
                email_domain TEXT NOT NULL DEFAULT '',
                consent_accepted INTEGER NOT NULL DEFAULT 0,
                otp_verified INTEGER NOT NULL DEFAULT 0,
                observed INTEGER NOT NULL DEFAULT 0,
                observed_reason TEXT NOT NULL DEFAULT '',
                dhcp_lease_sec INTEGER NOT NULL DEFAULT 300,
                bandwidth_kbps INTEGER NOT NULL DEFAULT 10240,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_portal_reg_device_time ON portal_registrations(device_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_portal_reg_bhash_time ON portal_registrations(browser_hash, created_at);
            CREATE INDEX IF NOT EXISTS idx_portal_reg_ip_time ON portal_registrations(ip, created_at);

            CREATE TABLE IF NOT EXISTS otp_challenges (
                challenge_id TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                device_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                email_hash TEXT NOT NULL,
                otp_salt TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                verified INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS portal_rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint TEXT NOT NULL,
                key_type TEXT NOT NULL,
                key_value TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_portal_rl_lookup
                ON portal_rate_limits(endpoint, key_type, key_value, created_at);
            """
        )

        # Migración segura si existe una base SQLite creada antes de Fase 3
        existing_cols = {
            row["name"]
            for row in cur.execute("PRAGMA table_info(sessions)").fetchall()
        }
        if "browser_hash" not in existing_cols:
            cur.execute("ALTER TABLE sessions ADD COLUMN browser_hash TEXT NOT NULL DEFAULT ''")
        if "dhcp_lease_sec" not in existing_cols:
            cur.execute("ALTER TABLE sessions ADD COLUMN dhcp_lease_sec INTEGER NOT NULL DEFAULT 300")
        if "bandwidth_kbps" not in existing_cols:
            cur.execute("ALTER TABLE sessions ADD COLUMN bandwidth_kbps INTEGER NOT NULL DEFAULT 10240")
        if "mail_verified" not in existing_cols:
            cur.execute("ALTER TABLE sessions ADD COLUMN mail_verified INTEGER NOT NULL DEFAULT 1")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_browser_hash ON sessions(browser_hash)")

        # Migración segura si existe una base SQLite creada antes de Fase 4
        existing_cfg_cols = {
            row["name"]
            for row in cur.execute("PRAGMA table_info(daemon_config)").fetchall()
        }
        if "honeytokens_json" not in existing_cfg_cols:
            cur.execute("ALTER TABLE daemon_config ADD COLUMN honeytokens_json TEXT NOT NULL DEFAULT '[]'")
        if "portal_template_json" not in existing_cfg_cols:
            cur.execute("ALTER TABLE daemon_config ADD COLUMN portal_template_json TEXT NOT NULL DEFAULT '{}'")

        row = cur.execute("SELECT id FROM daemon_config WHERE id = 1").fetchone()
        if row is None:
            cur.execute(
                """
                INSERT INTO daemon_config (
                    id, mode, retention_days, max_outbound_per_minute,
                    portal_enabled, honeypot_enabled, egress_whitelist_json,
                    sybil_max_emails_per_device, sybil_window_seconds,
                    honeytokens_json, portal_template_json, updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    json.dumps(DEFAULT_CONFIG["honeytokens"]),
                    json.dumps(DEFAULT_CONFIG["portal_template"]),
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
            try:
                honeytokens = json.loads(row["honeytokens_json"])
                if not isinstance(honeytokens, list):
                    honeytokens = []
            except Exception:
                honeytokens = []
            try:
                raw_tpl = json.loads(row["portal_template_json"])
                if not isinstance(raw_tpl, dict):
                    raw_tpl = {}
            except Exception:
                raw_tpl = {}
            portal_template = {
                "title": str(raw_tpl.get("title") or DEFAULT_PORTAL_TEMPLATE["title"]),
                "subtitle": str(raw_tpl.get("subtitle") or DEFAULT_PORTAL_TEMPLATE["subtitle"]),
                "footer": str(raw_tpl.get("footer") or ""),
            }
            return {
                "mode": int(row["mode"]),
                "retention_days": int(row["retention_days"]),
                "max_outbound_per_minute": int(row["max_outbound_per_minute"]),
                "portal_enabled": bool(row["portal_enabled"]),
                "honeypot_enabled": bool(row["honeypot_enabled"]),
                "egress_whitelist": whitelist,
                "sybil_max_emails_per_device": int(row["sybil_max_emails_per_device"]),
                "sybil_window_seconds": int(row["sybil_window_seconds"]),
                "honeytokens": honeytokens,
                "portal_template": portal_template,
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
                    honeytokens_json = ?,
                    portal_template_json = ?,
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
                    json.dumps(merged.get("honeytokens", [])),
                    json.dumps(merged.get("portal_template", DEFAULT_PORTAL_TEMPLATE)),
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
                "dhcp_lease_sec": int(row["dhcp_lease_sec"]),
                "bandwidth_kbps": int(row["bandwidth_kbps"]),
                "mail_verified": (bool(row["mail_verified"]) if row["service"] == "portal-cautivo" else None),
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
        browser_hash: str = "",
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
        dhcp_lease_sec: int = 300,
        bandwidth_kbps: int = 10240,
        mail_verified: bool = True,
        observed_reason: str = "",
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
                    browser_fingerprint, browser_hash, network_fingerprint, dhcp_fingerprint,
                    dest_ip, dest_port, service, honeytoken_touched, visitor_label,
                    fd, started_at, ended_at, duration_sec, bytes_in, bytes_out,
                    dhcp_lease_sec, bandwidth_kbps, mail_verified, status, observed_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0.0, 0, 0, ?, ?, ?, ?, ?)
                """,
                (
                    effective_mode,
                    effective_device_id,
                    mac,
                    ip,
                    int(client_port),
                    device_type,
                    browser_fingerprint,
                    browser_hash,
                    network_fingerprint,
                    dhcp_fingerprint,
                    dest_ip,
                    int(dest_port),
                    service,
                    honeytoken_touched,
                    visitor_label,
                    fd,
                    now,
                    int(dhcp_lease_sec),
                    int(bandwidth_kbps),
                    1 if mail_verified else 0,
                    status,
                    observed_reason,
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
                mitre_technique=get_mitre_engine().resolve_event("SESSION_OBSERVED"),
                metadata={"reason": reason, "previous_status": row["status"]},
            )
            return self.get_session(session_id)

    def mark_session_honeytoken(
        self,
        session_id: int,
        honeytoken_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Registra en SQLite el nombre del honeytoken ficticio accedido durante una sesión."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE sessions SET honeytoken_touched = ? WHERE id = ?",
                (str(honeytoken_name)[:64], int(session_id)),
            )
            self._conn.commit()
            if cur.rowcount <= 0:
                return None
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

    # ------------------------------------------------------------------
    # Portal Cautivo (Modo 1) — Anti-Sybil y Desafíos OTP (sin secrets en claro)
    # ------------------------------------------------------------------

    def record_portal_registration(
        self,
        session_id: Optional[int],
        device_id: str,
        browser_hash: str,
        mac: str,
        ip: str,
        email_hash: str,
        email_domain: str,
        consent_accepted: bool,
        otp_verified: bool,
        observed: bool,
        observed_reason: str,
        dhcp_lease_sec: int,
        bandwidth_kbps: int,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO portal_registrations (
                    session_id, created_at, device_id, browser_hash, mac, ip,
                    email_hash, email_domain, consent_accepted, otp_verified,
                    observed, observed_reason, dhcp_lease_sec, bandwidth_kbps
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    time.time(),
                    device_id,
                    browser_hash or "",
                    mac,
                    ip,
                    email_hash,
                    email_domain,
                    1 if consent_accepted else 0,
                    1 if otp_verified else 0,
                    1 if observed else 0,
                    observed_reason or "",
                    int(dhcp_lease_sec),
                    int(bandwidth_kbps),
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def count_recent_distinct_emails_for_device(self, device_id: str, since_ts: float) -> int:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(DISTINCT email_hash) AS cnt
                FROM portal_registrations
                WHERE device_id = ? AND created_at >= ?
                """,
                (device_id, float(since_ts)),
            ).fetchone()
            return int(row["cnt"]) if row else 0

    def list_recent_email_hashes_for_device(self, device_id: str, since_ts: float) -> List[str]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT DISTINCT email_hash
                FROM portal_registrations
                WHERE device_id = ? AND created_at >= ?
                """,
                (device_id, float(since_ts)),
            ).fetchall()
            return [str(r["email_hash"]) for r in rows]

    def count_recent_registrations_for_ip(self, ip: str, since_ts: float) -> int:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM portal_registrations
                WHERE ip = ? AND created_at >= ?
                """,
                (ip, float(since_ts)),
            ).fetchone()
            return int(row["cnt"]) if row else 0

    def find_mac_rotation(self, browser_hash: str, current_mac: str, since_ts: float) -> Optional[str]:
        if not browser_hash:
            return None
        with self._lock:
            row = self._conn.execute(
                """
                SELECT mac
                FROM portal_registrations
                WHERE browser_hash = ? AND created_at >= ? AND mac != ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (browser_hash, float(since_ts), current_mac),
            ).fetchone()
            if row:
                return str(row["mac"])
            row_sess = self._conn.execute(
                """
                SELECT mac
                FROM sessions
                WHERE browser_hash = ? AND started_at >= ? AND mac != ?
                ORDER BY started_at DESC
                LIMIT 1
                """,
                (browser_hash, float(since_ts), current_mac),
            ).fetchone()
            return str(row_sess["mac"]) if row_sess else None

    def create_otp_challenge(
        self,
        challenge_id: str,
        device_id: str,
        ip: str,
        email_hash: str,
        otp_salt: str,
        otp_hash: str,
        ttl_sec: int = 300,
    ) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO otp_challenges (
                    challenge_id, created_at, expires_at, device_id, ip,
                    email_hash, otp_salt, otp_hash, attempts, verified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
                """,
                (
                    challenge_id,
                    now,
                    now + float(ttl_sec),
                    device_id,
                    ip,
                    email_hash,
                    otp_salt,
                    otp_hash,
                ),
            )
            self._conn.commit()

    def check_and_increment_rate_limit(
        self,
        endpoint: str,
        checks: List[Tuple[str, str, int, int]],
    ) -> Tuple[bool, Optional[str]]:
        """
        Verifica e incrementa contadores persistentes en SQLite para limitar pedidos.
        Cada elemento de `checks` es (key_type, key_value, max_count, window_sec).
        """
        now = time.time()
        with self._lock:
            # Limpieza periódica de entradas antiguas (> 2 horas)
            self._conn.execute(
                "DELETE FROM portal_rate_limits WHERE created_at < ?",
                (now - 7200.0,),
            )
            for key_type, key_value, max_count, window_sec in checks:
                since_ts = now - float(window_sec)
                row = self._conn.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM portal_rate_limits
                    WHERE endpoint = ? AND key_type = ? AND key_value = ? AND created_at >= ?
                    """,
                    (endpoint, key_type, key_value, since_ts),
                ).fetchone()
                cnt = int(row["cnt"]) if row else 0
                if cnt >= int(max_count):
                    return False, (
                        f"Límite de pedidos excedido en {endpoint} "
                        f"({max_count} cada {window_sec // 60} min)"
                    )

            for key_type, key_value, _max_count, _window_sec in checks:
                self._conn.execute(
                    """
                    INSERT INTO portal_rate_limits (endpoint, key_type, key_value, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (endpoint, key_type, key_value, now),
                )
            self._conn.commit()
            return True, None

    def verify_otp_challenge(
        self,
        challenge_id: str,
        email_hash: str,
        otp_code: str,
        max_attempts: int = 3,
    ) -> Tuple[bool, str]:
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM otp_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
            if not row:
                return False, "Desafío OTP inexistente"
            if int(row["verified"]) == 1:
                return False, "El desafío OTP ya fue utilizado"
            if now > float(row["expires_at"]):
                return False, "El código OTP expiró"
            if int(row["attempts"]) >= int(max_attempts):
                return False, "Demasiados intentos fallidos de OTP"
            if not hmac.compare_digest(str(row["email_hash"]), str(email_hash)):
                self._conn.execute(
                    "UPDATE otp_challenges SET attempts = attempts + 1 WHERE challenge_id = ?",
                    (challenge_id,),
                )
                self._conn.commit()
                return False, "Correo no coincide con el desafío OTP"

            expected_hash = str(row["otp_hash"])
            candidate_hash = hashlib.sha256(
                f"{row['otp_salt']}:{otp_code}".encode("utf-8")
            ).hexdigest()
            if not hmac.compare_digest(candidate_hash, expected_hash):
                self._conn.execute(
                    "UPDATE otp_challenges SET attempts = attempts + 1 WHERE challenge_id = ?",
                    (challenge_id,),
                )
                self._conn.commit()
                return False, "Código OTP incorrecto"

            self._conn.execute(
                "UPDATE otp_challenges SET verified = 1, attempts = attempts + 1 WHERE challenge_id = ?",
                (challenge_id,),
            )
            self._conn.commit()
            return True, "OK"

    # ------------------------------------------------------------------
    # Privacidad y Retención (Fase 5 — Ley 25.326 AR)
    # ------------------------------------------------------------------

    def purge_expired_retention(
        self,
        retention_days: Optional[int] = None,
        now_ts: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Elimina sesiones, eventos, desafíos OTP, registros del portal y contadores
        anteriores a `retention_days` y deja un evento de auditoría sin datos personales.
        """
        with self._lock:
            days = int(
                retention_days
                if retention_days is not None
                else self.get_config()["retention_days"]
            )
            if days < 1 or days > 3650:
                raise ValueError("retention_days debe estar entre 1 y 3650")

            now = float(now_ts if now_ts is not None else time.time())
            cutoff = now - (float(days) * 86400.0)

            expired_rows = self._conn.execute(
                "SELECT id FROM sessions WHERE COALESCE(ended_at, started_at) < ?",
                (cutoff,),
            ).fetchall()
            expired_session_ids = [int(r["id"]) for r in expired_rows]

            if expired_session_ids:
                placeholders = ",".join("?" for _ in expired_session_ids)
                ev_cur = self._conn.execute(
                    f"DELETE FROM events WHERE timestamp < ? OR session_id IN ({placeholders})",
                    tuple([cutoff] + expired_session_ids),
                )
                reg_cur = self._conn.execute(
                    f"DELETE FROM portal_registrations WHERE created_at < ? OR session_id IN ({placeholders})",
                    tuple([cutoff] + expired_session_ids),
                )
                sess_cur = self._conn.execute(
                    f"DELETE FROM sessions WHERE id IN ({placeholders})",
                    tuple(expired_session_ids),
                )
            else:
                ev_cur = self._conn.execute(
                    "DELETE FROM events WHERE timestamp < ?",
                    (cutoff,),
                )
                reg_cur = self._conn.execute(
                    "DELETE FROM portal_registrations WHERE created_at < ?",
                    (cutoff,),
                )
                sess_cur = self._conn.execute("DELETE FROM sessions WHERE 1 = 0")

            otp_cur = self._conn.execute(
                "DELETE FROM otp_challenges WHERE created_at < ?",
                (cutoff,),
            )
            rl_cur = self._conn.execute(
                "DELETE FROM portal_rate_limits WHERE created_at < ?",
                (cutoff,),
            )
            self._conn.commit()

            counts = {
                "retention_days": days,
                "sessions_deleted": int(sess_cur.rowcount),
                "events_deleted": int(ev_cur.rowcount),
                "otp_challenges_deleted": int(otp_cur.rowcount),
                "portal_registrations_deleted": int(reg_cur.rowcount),
                "rate_limits_deleted": int(rl_cur.rowcount),
            }

            # Evento de auditoría estrictamente SIN datos personales
            self.record_event(
                event_type="RETENTION_PURGE",
                severity="info",
                device_id="",
                ip="",
                description=(
                    f"Purga por retención ejecutada (>={days} días): "
                    f"{counts['sessions_deleted']} sesiones, "
                    f"{counts['events_deleted']} eventos y "
                    f"{counts['otp_challenges_deleted']} desafíos OTP eliminados"
                ),
                metadata=counts,
            )
            return counts

    def purge_visitor_data(
        self,
        email: Optional[str] = None,
        email_hash: Optional[str] = None,
        device_id: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Elimina sesiones, eventos y desafíos OTP asociados a un visitante
        y registra un evento de auditoría sin ningún dato personal (ni correo, IP, MAC ni device_id).
        """
        clean_email = email.strip().lower() if isinstance(email, str) and email.strip() else None
        clean_hash = email_hash.strip().lower() if isinstance(email_hash, str) and email_hash.strip() else None
        clean_dev = device_id.strip() if isinstance(device_id, str) and device_id.strip() else None
        clean_ip = ip.strip() if isinstance(ip, str) and ip.strip() else None

        if not any((clean_email, clean_hash, clean_dev, clean_ip)):
            raise ValueError("Debe especificar al menos un identificador (email, device_id o ip)")

        with self._lock:
            matched_session_ids = set()

            sess_clauses: List[str] = []
            sess_params: List[Any] = []
            if clean_email:
                sess_clauses.append("LOWER(visitor_label) = ?")
                sess_params.append(clean_email)
            if clean_dev:
                sess_clauses.append("device_id = ?")
                sess_params.append(clean_dev)
            if clean_ip:
                sess_clauses.append("ip = ?")
                sess_params.append(clean_ip)

            if sess_clauses:
                rows = self._conn.execute(
                    f"SELECT id FROM sessions WHERE {' OR '.join(sess_clauses)}",
                    tuple(sess_params),
                ).fetchall()
                matched_session_ids.update(int(r["id"]) for r in rows)

            if clean_hash:
                reg_sess_rows = self._conn.execute(
                    "SELECT session_id FROM portal_registrations WHERE email_hash = ? AND session_id IS NOT NULL",
                    (clean_hash,),
                ).fetchall()
                matched_session_ids.update(int(r["session_id"]) for r in reg_sess_rows)

            ev_clauses: List[str] = []
            ev_params: List[Any] = []
            if matched_session_ids:
                placeholders = ",".join("?" for _ in matched_session_ids)
                ev_clauses.append(f"session_id IN ({placeholders})")
                ev_params.extend(sorted(matched_session_ids))
            if clean_dev:
                ev_clauses.append("device_id = ?")
                ev_params.append(clean_dev)
            if clean_ip:
                ev_clauses.append("ip = ?")
                ev_params.append(clean_ip)

            events_deleted = 0
            if ev_clauses:
                ev_cur = self._conn.execute(
                    f"DELETE FROM events WHERE {' OR '.join(ev_clauses)}",
                    tuple(ev_params),
                )
                events_deleted = int(ev_cur.rowcount)

            otp_clauses: List[str] = []
            otp_params: List[Any] = []
            if clean_hash:
                otp_clauses.append("email_hash = ?")
                otp_params.append(clean_hash)
            if clean_dev:
                otp_clauses.append("device_id = ?")
                otp_params.append(clean_dev)
            if clean_ip:
                otp_clauses.append("ip = ?")
                otp_params.append(clean_ip)

            otp_deleted = 0
            if otp_clauses:
                otp_cur = self._conn.execute(
                    f"DELETE FROM otp_challenges WHERE {' OR '.join(otp_clauses)}",
                    tuple(otp_params),
                )
                otp_deleted = int(otp_cur.rowcount)

            reg_clauses: List[str] = []
            reg_params: List[Any] = []
            if matched_session_ids:
                placeholders = ",".join("?" for _ in matched_session_ids)
                reg_clauses.append(f"session_id IN ({placeholders})")
                reg_params.extend(sorted(matched_session_ids))
            if clean_hash:
                reg_clauses.append("email_hash = ?")
                reg_params.append(clean_hash)
            if clean_dev:
                reg_clauses.append("device_id = ?")
                reg_params.append(clean_dev)
            if clean_ip:
                reg_clauses.append("ip = ?")
                reg_params.append(clean_ip)

            regs_deleted = 0
            if reg_clauses:
                reg_cur = self._conn.execute(
                    f"DELETE FROM portal_registrations WHERE {' OR '.join(reg_clauses)}",
                    tuple(reg_params),
                )
                regs_deleted = int(reg_cur.rowcount)

            rl_clauses: List[str] = []
            rl_params: List[Any] = []
            if clean_hash:
                rl_clauses.append("(key_type = 'email' AND key_value = ?)")
                rl_params.append(clean_hash)
            if clean_ip:
                rl_clauses.append("(key_type = 'ip' AND key_value = ?)")
                rl_params.append(clean_ip)

            rl_deleted = 0
            if rl_clauses:
                rl_cur = self._conn.execute(
                    f"DELETE FROM portal_rate_limits WHERE {' OR '.join(rl_clauses)}",
                    tuple(rl_params),
                )
                rl_deleted = int(rl_cur.rowcount)

            sessions_deleted = 0
            if matched_session_ids:
                placeholders = ",".join("?" for _ in matched_session_ids)
                sess_cur = self._conn.execute(
                    f"DELETE FROM sessions WHERE id IN ({placeholders})",
                    tuple(sorted(matched_session_ids)),
                )
                sessions_deleted = int(sess_cur.rowcount)

            self._conn.commit()

            criteria_types: List[str] = []
            if clean_email or clean_hash:
                criteria_types.append("email")
            if clean_dev:
                criteria_types.append("device_id")
            if clean_ip:
                criteria_types.append("ip")

            counts = {
                "criteria_types": criteria_types,
                "sessions_deleted": sessions_deleted,
                "events_deleted": events_deleted,
                "otp_challenges_deleted": otp_deleted,
                "portal_registrations_deleted": regs_deleted,
                "rate_limits_deleted": rl_deleted,
            }

            # Evento de auditoría estrictamente SIN datos personales
            self.record_event(
                event_type="VISITOR_DATA_PURGED",
                severity="info",
                device_id="",
                ip="",
                description=(
                    f"Borrado de datos de visitante ejecutado: "
                    f"{sessions_deleted} sesiones, {events_deleted} eventos y "
                    f"{otp_deleted} desafíos OTP eliminados"
                ),
                metadata=counts,
            )
            return counts
