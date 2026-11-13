"""
================================================================================
HONEYGATE DASHBOARD API: Servidor Web Asíncrono y Telemetría Forense
Endpoints REST JSON en Memoria y Dashboard Web HTML5/JS en Tiempo Real
Seguridad Reforzada: Anti-XSS, Validación de IPs con ipaddress, Auth Tokens y Localhost por defecto
================================================================================
"""

import os
import re
import math
import json
import secrets
import logging
import threading
import ipaddress
from typing import Any, Dict, List, Optional, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from honeygate.honeywall_core import HoneyGateHoneywall
from honeygate.forensic_monitor import ForensicAlertManager
from honeygate.storage import HoneyGateStorage, VALID_SESSION_STATUSES, VALID_SEVERITIES

logger = logging.getLogger("HoneyGateAPI")

MAX_BODY_BYTES = 65536
RE_OBSERVE_ROUTE = re.compile(r"^/api/sessions/([^/]+)/observe$")
ALLOWED_CONFIG_FIELDS = {
    "mode",
    "retention_days",
    "max_outbound_per_minute",
    "portal_enabled",
    "honeypot_enabled",
    "egress_whitelist",
    "sybil_max_emails_per_device",
    "sybil_window_seconds",
}


HTML_DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HoneyGate // Telemetría & Contención Defensiva</title>
    <style>
        :root {
            --bg-dark: #0a0e14;
            --card-bg: #111822;
            --border: #1e293b;
            --accent-cyan: #00d4ff;
            --accent-green: #00ff66;
            --accent-red: #ff3366;
            --accent-yellow: #ffcc00;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
        body { background: var(--bg-dark); color: var(--text-main); padding: 24px; min-height: 100vh; }
        header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
        .logo-area { display: flex; align-items: center; gap: 12px; }
        .logo-badge { background: linear-gradient(135deg, #00d4ff, #00ff66); color: #000; font-weight: 800; padding: 6px 12px; border-radius: 6px; font-size: 14px; letter-spacing: 1px; }
        .title h1 { font-size: 20px; font-weight: 700; letter-spacing: 0.5px; }
        .title p { font-size: 12px; color: var(--text-muted); }
        .status-badge { display: flex; align-items: center; gap: 8px; background: rgba(0,255,102,0.1); border: 1px solid var(--accent-green); padding: 6px 14px; border-radius: 20px; font-size: 13px; color: var(--accent-green); }
        .pulse { width: 8px; height: 8px; background: var(--accent-green); border-radius: 50%; box-shadow: 0 0 8px var(--accent-green); animation: pulse-anim 1.5s infinite; }
        @keyframes pulse-anim { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }

        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .metric-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }
        .metric-card .label { font-size: 12px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px; letter-spacing: 0.5px; }
        .metric-card .value { font-size: 28px; font-weight: 700; color: var(--text-main); }
        .metric-card.cyan .value { color: var(--accent-cyan); }
        .metric-card.green .value { color: var(--accent-green); }
        .metric-card.red .value { color: var(--accent-red); }
        .metric-card.yellow .value { color: var(--accent-yellow); }

        .dashboard-main { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-bottom: 24px; }
        @media (max-width: 992px) { .dashboard-main { grid-template-columns: 1fr; } }
        .panel { background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }
        .panel h2 { font-size: 16px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; color: var(--text-main); }

        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { text-align: left; padding: 10px 12px; color: var(--text-muted); border-bottom: 1px solid var(--border); font-weight: 600; font-size: 11px; text-transform: uppercase; }
        td { padding: 12px; border-bottom: 1px solid var(--border); }
        tr:hover { background: rgba(255,255,255,0.02); }
        .badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
        .badge.safe { background: rgba(0,255,102,0.15); color: var(--accent-green); }
        .badge.warn { background: rgba(255,204,0,0.15); color: var(--accent-yellow); }
        .badge.crit { background: rgba(255,51,102,0.15); color: var(--accent-red); }

        .btn-action { background: transparent; border: 1px solid var(--accent-red); color: var(--accent-red); padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; transition: all 0.2s; }
        .btn-action:hover { background: var(--accent-red); color: #fff; }
        .btn-unblock { border-color: var(--accent-cyan); color: var(--accent-cyan); }
        .btn-unblock:hover { background: var(--accent-cyan); color: #000; }

        .alerts-stream { max-height: 400px; overflow-y: auto; display: flex; flex-direction: column; gap: 10px; }
        .alert-item { background: #0f141c; border-left: 4px solid var(--border); padding: 12px; border-radius: 4px; font-size: 12px; }
        .alert-item.critical { border-left-color: var(--accent-red); }
        .alert-item.normal { border-left-color: var(--accent-yellow); }
        .alert-header { display: flex; justify-content: space-between; margin-bottom: 4px; font-weight: 600; }
        .alert-time { color: var(--text-muted); font-size: 11px; }
        .alert-body { color: #cbd5e1; word-break: break-all; }

        .rate-bar-container { background: #1e293b; border-radius: 10px; height: 8px; width: 100%; overflow: hidden; margin-top: 6px; }
        .rate-bar { height: 100%; border-radius: 10px; transition: width 0.3s; }
    </style>
</head>
<body>
    <header>
        <div class="logo-area">
            <div class="logo-badge">HONEYGATE</div>
            <div class="title">
                <h1>HoneyGate // Deception & Perimeter Containment Dashboard</h1>
                <p>Framework Defensivo No-Root | Edge-Triggered epoll | inotify Forensics</p>
            </div>
        </div>
        <div class="status-badge">
            <div class="pulse"></div>
            <span>HoneyGate Activo (10 req/min limit)</span>
        </div>
    </header>

    <div class="metrics-grid">
        <div class="metric-card cyan">
            <div class="label">Sesiones Activas (epoll)</div>
            <div class="value" id="val-active">0</div>
        </div>
        <div class="metric-card green">
            <div class="label">Conexiones Históricas</div>
            <div class="value" id="val-total">0</div>
        </div>
        <div class="metric-card red">
            <div class="label">IPs Aisladas (Contención)</div>
            <div class="value" id="val-isolated">0</div>
        </div>
        <div class="metric-card yellow">
            <div class="label">Infracciones Rate-Limit</div>
            <div class="value" id="val-violations">0</div>
        </div>
    </div>

    <div class="dashboard-main">
        <div class="panel">
            <h2>
                <span>Sesiones Activas en Puertos Simulados</span>
                <span style="font-size: 12px; color: var(--text-muted);">Auto-refresh 2s</span>
            </h2>
            <table>
                <thead>
                    <tr>
                        <th>FD</th>
                        <th>IP Origen</th>
                        <th>Puerto</th>
                        <th>MAC Address</th>
                        <th>Tasa Saliente</th>
                        <th>Duración</th>
                        <th>Acción</th>
                    </tr>
                </thead>
                <tbody id="sessions-table-body">
                    <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Cargando telemetría...</td></tr>
                </tbody>
            </table>

            <h2 style="margin-top: 28px; color: var(--accent-red);">
                <span>IPs en Lista de Aislamiento Activo</span>
            </h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Aislada</th>
                        <th>Motivo de Contención</th>
                        <th>Fecha de Aislamiento</th>
                        <th>Acción</th>
                    </tr>
                </thead>
                <tbody id="isolated-table-body">
                    <tr><td colspan="4" style="text-align: center; color: var(--text-muted);">Sin hosts bloqueados.</td></tr>
                </tbody>
            </table>
        </div>

        <div class="panel">
            <h2>
                <span>Alertas Forenses (inotify)</span>
                <span class="badge crit" id="alert-counter">0</span>
            </h2>
            <div class="alerts-stream" id="alerts-container">
                <div style="color: var(--text-muted); font-size: 12px;">Esperando eventos de logs del sistema...</div>
            </div>
        </div>
    </div>

    <script>
        const AUTH_TOKEN = "HONEYGATE_AUTH_TOKEN_VALUE";

        // Función de escape estricto contra ataques XSS
        function escapeHtml(str) {
            if (str === null || str === undefined) return '';
            const div = document.createElement('div');
            div.textContent = String(str);
            return div.innerHTML;
        }

        async function fetchMetrics() {
            try {
                const res = await fetch('/api/status', {
                    headers: { 'X-Auth-Token': AUTH_TOKEN }
                });
                if (!res.ok) return;
                const data = await res.json();

                document.getElementById('val-active').textContent = data.active_sessions.length;
                document.getElementById('val-total').textContent = data.stats.total_connections;
                document.getElementById('val-isolated').textContent = Object.keys(data.isolated_ips).length;
                document.getElementById('val-violations').textContent = data.stats.rate_limit_violations;

                // Render sesiones sanitizado (Anti-XSS)
                const tbody = document.getElementById('sessions-table-body');
                tbody.innerHTML = '';
                if (data.active_sessions.length === 0) {
                    const tr = document.createElement('tr');
                    tr.innerHTML = '<td colspan="7" style="text-align: center; color: #64748b; padding: 20px;">Sin conexiones atacantes activas en este momento.</td>';
                    tbody.appendChild(tr);
                } else {
                    data.active_sessions.forEach(s => {
                        const tr = document.createElement('tr');
                        const rate = Number(s.outbound_rate_min) || 0;
                        const pct = Math.min(100, (rate / 10) * 100);
                        const color = rate >= 8 ? '#ff3366' : (rate >= 5 ? '#ffcc00' : '#00ff66');

                        tr.innerHTML = `
                            <td><code>${escapeHtml(s.fd)}</code></td>
                            <td><strong>${escapeHtml(s.ip)}</strong></td>
                            <td>${escapeHtml(s.port)}</td>
                            <td><code>${escapeHtml(s.mac)}</code></td>
                            <td style="min-width: 100px;">
                                <div style="display: flex; justify-content: space-between; font-size: 11px;">
                                    <span>${rate}/10 req/m</span>
                                </div>
                                <div class="rate-bar-container">
                                    <div class="rate-bar" style="width: ${pct}%; background: ${color};"></div>
                                </div>
                            </td>
                            <td>${escapeHtml(s.duration_sec)}s</td>
                            <td><button class="btn-action" data-ip="${escapeHtml(s.ip)}">Aislar</button></td>
                        `;
                        tr.querySelector('.btn-action').addEventListener('click', () => isolateIP(s.ip));
                        tbody.appendChild(tr);
                    });
                }

                // Render aisladas sanitizado
                const isoBody = document.getElementById('isolated-table-body');
                isoBody.innerHTML = '';
                const isoKeys = Object.keys(data.isolated_ips);
                if (isoKeys.length === 0) {
                    const tr = document.createElement('tr');
                    tr.innerHTML = '<td colspan="4" style="text-align: center; color: #64748b; padding: 12px;">Ninguna IP aislada en contención.</td>';
                    isoBody.appendChild(tr);
                } else {
                    isoKeys.forEach(ip => {
                        const tr = document.createElement('tr');
                        const info = data.isolated_ips[ip];
                        const dateStr = new Date(info.isolated_at * 1000).toLocaleTimeString();
                        tr.innerHTML = `
                            <td><strong style="color: #ff3366;">${escapeHtml(ip)}</strong></td>
                            <td>${escapeHtml(info.reason)}</td>
                            <td>${escapeHtml(dateStr)}</td>
                            <td><button class="btn-action btn-unblock" data-ip="${escapeHtml(ip)}">Desbloquear</button></td>
                        `;
                        tr.querySelector('.btn-unblock').addEventListener('click', () => unblockIP(ip));
                        isoBody.appendChild(tr);
                    });
                }

                // Cargar alertas sanitizado (Anti-XSS con textContent)
                const alertRes = await fetch('/api/alerts', {
                    headers: { 'X-Auth-Token': AUTH_TOKEN }
                });
                if (!alertRes.ok) return;
                const alerts = await alertRes.json();
                document.getElementById('alert-counter').textContent = alerts.length;
                const alertContainer = document.getElementById('alerts-container');
                alertContainer.innerHTML = '';
                if (alerts.length > 0) {
                    alerts.slice().reverse().forEach(a => {
                        const item = document.createElement('div');
                        item.className = 'alert-item ' + (a.severity === 'critical' ? 'critical' : 'normal');

                        const header = document.createElement('div');
                        header.className = 'alert-header';

                        const titleSpan = document.createElement('span');
                        titleSpan.style.color = a.severity === 'critical' ? '#ff3366' : '#ffcc00';
                        titleSpan.textContent = a.title;

                        const timeSpan = document.createElement('span');
                        timeSpan.className = 'alert-time';
                        timeSpan.textContent = (a.date || '').split(' ')[1] || '';

                        header.appendChild(titleSpan);
                        header.appendChild(timeSpan);

                        const body = document.createElement('div');
                        body.className = 'alert-body';
                        body.textContent = a.message;

                        item.appendChild(header);
                        item.appendChild(body);
                        alertContainer.appendChild(item);
                    });
                }
            } catch (err) {
                console.error("Error consultando telemetría:", err);
            }
        }

        async function isolateIP(ip) {
            if (!confirm(`¿Confirmas el aislamiento forzado inmediato de ${ip}?`)) return;
            await fetch('/api/isolate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Auth-Token': AUTH_TOKEN
                },
                body: JSON.stringify({ip: ip, reason: 'Aislamiento manual desde Web Dashboard'})
            });
            fetchMetrics();
        }

        async function unblockIP(ip) {
            await fetch('/api/unblock', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Auth-Token': AUTH_TOKEN
                },
                body: JSON.stringify({ip: ip})
            });
            fetchMetrics();
        }

        setInterval(fetchMetrics, 2000);
        fetchMetrics();
    </script>
</body>
</html>
"""


class HoneyGateHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    Manejador HTTP ligero y concurrente para los endpoints REST JSON y el dashboard web.
    Implementa validación estricta de IPs y autenticación obligatoria con X-Auth-Token
    en todos los endpoints /api/* (falla cerrada con 401 si no hay token configurado).
    """
    honeywall: HoneyGateHoneywall = None
    forensics: ForensicAlertManager = None
    storage: Optional[HoneyGateStorage] = None
    auth_token: Optional[str] = None

    def log_message(self, format, *args):
        # Suprimir logs HTTP verbosos en stdout para mantener la terminal limpia
        pass

    def _is_authorized(self) -> bool:
        """Valida X-Auth-Token con comparación en tiempo constante. Falla cerrado si no hay token."""
        expected = self.auth_token
        if not expected:
            return False
        token = self.headers.get("X-Auth-Token", "")
        if not token:
            return False
        return secrets.compare_digest(token, expected)

    def _read_json_body(self, allow_empty: bool = False) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Lee y valida el tamaño (<= 64 KB) y estructura JSON del cuerpo HTTP."""
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in transfer_encoding:
            self._send_json(
                {"error": "Transfer-Encoding chunked no soportado; envíe Content-Length"},
                status_code=411,
            )
            return False, None

        raw_len = self.headers.get("Content-Length")
        if raw_len is None or raw_len.strip() == "":
            if allow_empty:
                return True, {}
            self._send_json({"error": "Cabecera Content-Length requerida"}, status_code=400)
            return False, None

        try:
            content_length = int(raw_len.strip())
        except ValueError:
            self._send_json({"error": "Content-Length inválido"}, status_code=400)
            return False, None

        if content_length < 0:
            self._send_json({"error": "Content-Length negativo no permitido"}, status_code=400)
            return False, None

        if content_length > MAX_BODY_BYTES:
            self.close_connection = True
            self._send_json(
                {"error": f"Payload demasiado grande (máximo {MAX_BODY_BYTES} bytes)"},
                status_code=413,
            )
            return False, None

        if content_length == 0:
            if allow_empty:
                return True, {}
            self._send_json({"error": "El cuerpo JSON no puede estar vacío"}, status_code=400)
            return False, None

        raw_bytes = self.rfile.read(content_length)
        try:
            decoded = raw_bytes.decode("utf-8")
            parsed = json.loads(decoded)
        except Exception:
            self._send_json({"error": "JSON malformado o codificación UTF-8 inválida"}, status_code=400)
            return False, None

        if not isinstance(parsed, dict):
            self._send_json({"error": "Se esperaba un objeto JSON"}, status_code=400)
            return False, None

        return True, parsed

    @staticmethod
    def _is_strict_int(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _validate_config_payload(cls, payload: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        if not payload:
            return None, "Se requiere al menos un campo de configuración"

        unknown = [k for k in payload.keys() if k not in ALLOWED_CONFIG_FIELDS]
        if unknown:
            return None, f"Campos no permitidos: {', '.join(unknown)}"

        cleaned: Dict[str, Any] = {}

        if "mode" in payload:
            v = payload["mode"]
            if not cls._is_strict_int(v) or v not in (1, 2, 3):
                return None, "El campo 'mode' debe ser 1, 2 o 3"
            cleaned["mode"] = v

        if "retention_days" in payload:
            v = payload["retention_days"]
            if not cls._is_strict_int(v) or not (1 <= v <= 3650):
                return None, "El campo 'retention_days' debe estar entre 1 y 3650"
            cleaned["retention_days"] = v

        if "max_outbound_per_minute" in payload:
            v = payload["max_outbound_per_minute"]
            if not cls._is_strict_int(v) or not (1 <= v <= 10000):
                return None, "El campo 'max_outbound_per_minute' debe estar entre 1 y 10000"
            cleaned["max_outbound_per_minute"] = v

        for bool_field in ("portal_enabled", "honeypot_enabled"):
            if bool_field in payload:
                v = payload[bool_field]
                if not isinstance(v, bool):
                    return None, f"El campo '{bool_field}' debe ser booleano"
                cleaned[bool_field] = v

        if "egress_whitelist" in payload:
            wl = payload["egress_whitelist"]
            if not isinstance(wl, list) or len(wl) > 100:
                return None, "El campo 'egress_whitelist' debe ser una lista de hasta 100 destinos"
            clean_wl: List[str] = []
            for item in wl:
                if not isinstance(item, str):
                    return None, "Cada elemento de 'egress_whitelist' debe ser texto"
                stripped = item.strip()
                if not stripped or len(stripped) > 255 or any(ch in stripped for ch in ("\r", "\n", "\x00")):
                    return None, "Destino inválido en 'egress_whitelist'"
                clean_wl.append(stripped)
            cleaned["egress_whitelist"] = clean_wl

        if "sybil_max_emails_per_device" in payload:
            v = payload["sybil_max_emails_per_device"]
            if not cls._is_strict_int(v) or not (1 <= v <= 100):
                return None, "El campo 'sybil_max_emails_per_device' debe estar entre 1 y 100"
            cleaned["sybil_max_emails_per_device"] = v

        if "sybil_window_seconds" in payload:
            v = payload["sybil_window_seconds"]
            if not cls._is_strict_int(v) or not (10 <= v <= 86400):
                return None, "El campo 'sybil_window_seconds' debe estar entre 10 y 86400"
            cleaned["sybil_window_seconds"] = v

        return cleaned, None

    @staticmethod
    def _validate_reason(raw_reason: Any, default: str) -> Tuple[Optional[str], Optional[str]]:
        if raw_reason is None:
            return default, None
        if not isinstance(raw_reason, str):
            return None, "El campo 'reason' debe ser una cadena de texto"
        if any(ch in raw_reason for ch in ("\r", "\n", "\x00")):
            return None, "El campo 'reason' contiene caracteres no permitidos"
        cleaned = raw_reason.strip()
        if len(cleaned) > 256:
            return None, "El campo 'reason' supera los 256 caracteres"
        return (cleaned if cleaned else default), None

    @staticmethod
    def _parse_pagination(qs: Dict[str, List[str]]) -> Tuple[Optional[Tuple[int, int]], Optional[str]]:
        limit = 50
        offset = 0
        if "limit" in qs:
            try:
                limit = int(qs["limit"][0])
            except ValueError:
                return None, "Parámetro 'limit' inválido"
            if not (1 <= limit <= 500):
                return None, "Parámetro 'limit' debe estar entre 1 y 500"
        if "offset" in qs:
            try:
                offset = int(qs["offset"][0])
            except ValueError:
                return None, "Parámetro 'offset' inválido"
            if not (0 <= offset <= 1000000):
                return None, "Parámetro 'offset' debe estar entre 0 y 1000000"
        return (limit, offset), None

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query, keep_blank_values=False)

        if path == "/" or path == "/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            token = self.auth_token or ""
            rendered = HTML_DASHBOARD_TEMPLATE.replace("__API_TOKEN__", token).replace("HONEYGATE_AUTH_TOKEN_VALUE", token)
            self.wfile.write(rendered.encode("utf-8"))
            return

        if path.startswith("/api/"):
            if not self._is_authorized():
                logger.warning(f"[AUTH-DENIED] Intento de acceso GET sin token válido a {path}")
                self._send_json({"error": "Unauthorized: Invalid or missing X-Auth-Token"}, status_code=401)
                return

            if path == "/api/status" or path == "/api/honeywall":
                snapshot = self.honeywall.get_snapshot()
                if self.storage is not None:
                    snapshot["config"] = self.storage.get_config()
                self._send_json(snapshot)

            elif path == "/api/connections":
                snapshot = self.honeywall.get_snapshot()
                self._send_json(snapshot["active_sessions"])

            elif path == "/api/alerts":
                alerts = self.forensics.get_recent_alerts(limit=50) if self.forensics else []
                self._send_json(alerts)

            elif path == "/api/config":
                if self.storage is None:
                    self._send_json({"error": "Almacenamiento SQLite no inicializado"}, status_code=500)
                    return
                self._send_json(self.storage.get_config())

            elif path == "/api/sessions":
                if self.storage is None:
                    self._send_json({"error": "Almacenamiento SQLite no inicializado"}, status_code=500)
                    return

                pag, err = self._parse_pagination(qs)
                if err:
                    self._send_json({"error": err}, status_code=400)
                    return
                limit, offset = pag

                status_filter = qs["status"][0].strip() if "status" in qs else None
                if status_filter is not None and status_filter not in VALID_SESSION_STATUSES:
                    self._send_json({"error": "Parámetro 'status' inválido"}, status_code=400)
                    return

                ip_filter = None
                if "ip" in qs:
                    try:
                        ip_filter = str(ipaddress.ip_address(qs["ip"][0].strip()))
                    except ValueError:
                        self._send_json({"error": "Parámetro 'ip' inválido"}, status_code=400)
                        return

                mode_filter = None
                if "mode" in qs:
                    try:
                        mode_filter = int(qs["mode"][0])
                    except ValueError:
                        self._send_json({"error": "Parámetro 'mode' inválido"}, status_code=400)
                        return
                    if mode_filter not in (1, 2, 3):
                        self._send_json({"error": "Parámetro 'mode' debe ser 1, 2 o 3"}, status_code=400)
                        return

                device_id_filter = qs["device_id"][0].strip() if "device_id" in qs else None
                if device_id_filter is not None and len(device_id_filter) > 128:
                    self._send_json({"error": "Parámetro 'device_id' demasiado largo"}, status_code=400)
                    return

                service_filter = qs["service"][0].strip() if "service" in qs else None
                if service_filter is not None and len(service_filter) > 64:
                    self._send_json({"error": "Parámetro 'service' demasiado largo"}, status_code=400)
                    return

                sessions, total = self.storage.list_sessions(
                    status=status_filter,
                    ip=ip_filter,
                    device_id=device_id_filter,
                    service=service_filter,
                    mode=mode_filter,
                    limit=limit,
                    offset=offset,
                )
                self._send_json({
                    "sessions": sessions,
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                })

            elif path == "/api/events":
                if self.storage is None:
                    self._send_json({"error": "Almacenamiento SQLite no inicializado"}, status_code=500)
                    return

                pag, err = self._parse_pagination(qs)
                if err:
                    self._send_json({"error": err}, status_code=400)
                    return
                limit, offset = pag

                severity_filter = qs["severity"][0].strip() if "severity" in qs else None
                if severity_filter is not None and severity_filter not in VALID_SEVERITIES:
                    self._send_json({"error": "Parámetro 'severity' inválido"}, status_code=400)
                    return

                ip_filter = None
                if "ip" in qs:
                    try:
                        ip_filter = str(ipaddress.ip_address(qs["ip"][0].strip()))
                    except ValueError:
                        self._send_json({"error": "Parámetro 'ip' inválido"}, status_code=400)
                        return

                mode_filter = None
                if "mode" in qs:
                    try:
                        mode_filter = int(qs["mode"][0])
                    except ValueError:
                        self._send_json({"error": "Parámetro 'mode' inválido"}, status_code=400)
                        return
                    if mode_filter not in (1, 2, 3):
                        self._send_json({"error": "Parámetro 'mode' debe ser 1, 2 o 3"}, status_code=400)
                        return

                session_id_filter = None
                if "session_id" in qs:
                    try:
                        session_id_filter = int(qs["session_id"][0])
                    except ValueError:
                        self._send_json({"error": "Parámetro 'session_id' inválido"}, status_code=400)
                        return
                    if session_id_filter <= 0:
                        self._send_json({"error": "Parámetro 'session_id' debe ser positivo"}, status_code=400)
                        return

                since_filter = None
                if "since" in qs:
                    try:
                        since_filter = float(qs["since"][0])
                    except ValueError:
                        self._send_json({"error": "Parámetro 'since' inválido"}, status_code=400)
                        return
                    if not math.isfinite(since_filter) or since_filter < 0:
                        self._send_json({"error": "Parámetro 'since' inválido"}, status_code=400)
                        return

                until_filter = None
                if "until" in qs:
                    try:
                        until_filter = float(qs["until"][0])
                    except ValueError:
                        self._send_json({"error": "Parámetro 'until' inválido"}, status_code=400)
                        return
                    if not math.isfinite(until_filter) or until_filter < 0:
                        self._send_json({"error": "Parámetro 'until' inválido"}, status_code=400)
                        return

                event_type_filter = qs["event_type"][0].strip() if "event_type" in qs else None
                if event_type_filter is not None and len(event_type_filter) > 128:
                    self._send_json({"error": "Parámetro 'event_type' demasiado largo"}, status_code=400)
                    return

                device_id_filter = qs["device_id"][0].strip() if "device_id" in qs else None
                if device_id_filter is not None and len(device_id_filter) > 128:
                    self._send_json({"error": "Parámetro 'device_id' demasiado largo"}, status_code=400)
                    return

                mitre_filter = qs["mitre_technique"][0].strip() if "mitre_technique" in qs else None
                if mitre_filter is not None and len(mitre_filter) > 64:
                    self._send_json({"error": "Parámetro 'mitre_technique' demasiado largo"}, status_code=400)
                    return

                events, total = self.storage.list_events(
                    severity=severity_filter,
                    event_type=event_type_filter,
                    ip=ip_filter,
                    device_id=device_id_filter,
                    mitre_technique=mitre_filter,
                    session_id=session_id_filter,
                    mode=mode_filter,
                    since=since_filter,
                    until=until_filter,
                    limit=limit,
                    offset=offset,
                )
                self._send_json({
                    "events": events,
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                })

            else:
                self._send_json({"error": "Endpoint no encontrado"}, status_code=404)
        else:
            self.send_response(404)
            self.end_headers()

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/"):
            if not self._is_authorized():
                logger.warning(f"[AUTH-DENIED] Intento de acceso PUT sin token válido a {path}")
                self._send_json({"error": "Unauthorized: Invalid or missing X-Auth-Token"}, status_code=401)
                return

        if path == "/api/config":
            if self.storage is None:
                self._send_json({"error": "Almacenamiento SQLite no inicializado"}, status_code=500)
                return

            ok, payload = self._read_json_body(allow_empty=False)
            if not ok:
                return

            cleaned, err = self._validate_config_payload(payload)
            if err:
                self._send_json({"error": err}, status_code=400)
                return

            updated = self.storage.update_config(cleaned)
            if self.honeywall is not None:
                self.honeywall.MAX_OUTBOUND_PER_MINUTE = int(updated["max_outbound_per_minute"])
            self.storage.record_event(
                event_type="CONFIG_UPDATED",
                severity="info",
                mode=updated["mode"],
                description=f"Configuración actualizada vía API (modo={updated['mode']})",
                metadata=cleaned,
            )
            self._send_json(updated)
        else:
            self._send_json({"error": "Endpoint no encontrado"}, status_code=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/"):
            if not self._is_authorized():
                logger.warning(f"[AUTH-DENIED] Intento de acceso POST sin token válido a {path}")
                self._send_json({"error": "Unauthorized: Invalid or missing X-Auth-Token"}, status_code=401)
                return

        observe_match = RE_OBSERVE_ROUTE.match(path)
        if observe_match:
            if self.storage is None:
                self._send_json({"error": "Almacenamiento SQLite no inicializado"}, status_code=500)
                return

            raw_id = observe_match.group(1)
            try:
                session_id = int(raw_id)
            except ValueError:
                self._send_json({"error": "ID de sesión inválido"}, status_code=400)
                return
            if session_id <= 0:
                self._send_json({"error": "ID de sesión debe ser positivo"}, status_code=400)
                return

            ok, payload = self._read_json_body(allow_empty=True)
            if not ok:
                return

            unknown = [k for k in payload.keys() if k != "reason"]
            if unknown:
                self._send_json({"error": f"Campos no permitidos: {', '.join(unknown)}"}, status_code=400)
                return

            reason, err = self._validate_reason(
                payload.get("reason"),
                default="Marcada en observación por operador",
            )
            if err:
                self._send_json({"error": err}, status_code=400)
                return

            updated = self.storage.mark_session_observed(session_id, reason=reason)
            if updated is None:
                self._send_json({"error": f"Sesión {session_id} no encontrada"}, status_code=404)
                return

            self._send_json({"status": "success", "session": updated})
            return

        if path == "/api/isolate":
            ok, payload = self._read_json_body(allow_empty=False)
            if not ok:
                return

            raw_ip = payload.get("ip")
            if not raw_ip or not isinstance(raw_ip, str):
                self._send_json({"error": "Falta parámetro 'ip' válido"}, status_code=400)
                return

            reason, err = self._validate_reason(payload.get("reason"), default="Aislamiento manual API")
            if err:
                self._send_json({"error": err}, status_code=400)
                return

            # Validación estricta de IP con ipaddress
            try:
                ip_obj = ipaddress.ip_address(raw_ip.strip())
                validated_ip = str(ip_obj)
            except ValueError:
                logger.warning(f"[SECURITY-DROP] Rechazada IP malformada en /api/isolate: {raw_ip}")
                self._send_json({"error": "Dirección IP inválida"}, status_code=400)
                return

            self.honeywall.isolate_ip(validated_ip, reason=reason)
            self._send_json({"status": "success", "isolated_ip": validated_ip})

        elif path == "/api/unblock":
            ok, payload = self._read_json_body(allow_empty=False)
            if not ok:
                return

            raw_ip = payload.get("ip")
            if not raw_ip or not isinstance(raw_ip, str):
                self._send_json({"error": "Falta parámetro 'ip' válido"}, status_code=400)
                return

            # Validación estricta de IP con ipaddress
            try:
                ip_obj = ipaddress.ip_address(raw_ip.strip())
                validated_ip = str(ip_obj)
            except ValueError:
                logger.warning(f"[SECURITY-DROP] Rechazada IP malformada en /api/unblock: {raw_ip}")
                self._send_json({"error": "Dirección IP inválida"}, status_code=400)
                return

            unblocked = self.honeywall.unblock_ip(validated_ip)
            self._send_json({"status": "success", "unblocked": unblocked, "ip": validated_ip})

        else:
            self._send_json({"error": "Endpoint no encontrado"}, status_code=404)

    def _send_json(self, data: Any, status_code: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class AsyncDashboardServer:
    """Servidor web de telemetría forense para HoneyGate (escuchando por defecto en 127.0.0.1)."""
    def __init__(
        self,
        honeywall: HoneyGateHoneywall,
        forensics: ForensicAlertManager,
        host: str = "127.0.0.1",
        port: int = 8888,
        storage: Optional[HoneyGateStorage] = None,
    ):
        self.host = host
        self.port = port
        self.honeywall = honeywall
        self.forensics = forensics
        if storage is not None:
            self.storage = storage
            self._owns_storage = False
        elif getattr(honeywall, "storage", None) is not None:
            self.storage = honeywall.storage
            self._owns_storage = False
        else:
            self.storage = HoneyGateStorage()
            self._owns_storage = True
        self.httpd: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        env_token = os.environ.get("HONEYGATE_API_TOKEN", "").strip()
        self._from_env = bool(env_token)
        self.api_token: str = env_token if env_token else secrets.token_urlsafe(32)
        self._token_logged = False

    def start_background(self) -> threading.Thread:
        """Inicia el servidor web en un hilo secundario."""
        env_token = os.environ.get("HONEYGATE_API_TOKEN", "").strip()
        if env_token:
            self.api_token = env_token
            self._from_env = True

        if not self._token_logged:
            if self._from_env:
                logger.info("[WEB-API] Token X-Auth-Token cargado desde HONEYGATE_API_TOKEN.")
            else:
                logger.info(f"[WEB-API] HONEYGATE_API_TOKEN no definido; token generado para esta sesión: {self.api_token}")
            self._token_logged = True

        bound_honeywall = self.honeywall
        bound_forensics = self.forensics
        bound_storage = self.storage
        bound_token = self.api_token

        class BoundHandler(HoneyGateHTTPRequestHandler):
            honeywall = bound_honeywall
            forensics = bound_forensics
            storage = bound_storage
            auth_token = bound_token

        HTTPServer.allow_reuse_address = True
        self.httpd = HTTPServer((self.host, self.port), BoundHandler)
        logger.info(f"[WEB-API] Dashboard y Endpoints JSON activos en http://{self.host}:{self.port}")

        self.server_thread = threading.Thread(
            target=self.httpd.serve_forever,
            name="HoneyGateWebAPIThread",
            daemon=True
        )
        self.server_thread.start()
        return self.server_thread

    def stop(self):
        """Detiene el servidor HTTP."""
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self._owns_storage and self.storage is not None:
            self.storage.close()
            self._owns_storage = False
