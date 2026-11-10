"""
================================================================================
HONEYGATE DASHBOARD API: Servidor Web Asíncrono y Telemetría Forense
Endpoints REST JSON en Memoria y Dashboard Web HTML5/JS en Tiempo Real
Seguridad Reforzada: Anti-XSS, Validación de IPs con ipaddress, Auth Tokens y Localhost por defecto
================================================================================
"""

import os
import json
import time
import secrets
import logging
import threading
import ipaddress
from typing import Dict, Any, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from undahwoar.honeywall_core import UndahwoarHoneywall
from undahwoar.forensic_monitor import ForensicAlertManager

logger = logging.getLogger("HoneyGateAPI")

# Token de autenticación para endpoints administrativos de mutación
HONEYGATE_AUTH_TOKEN = os.environ.get("HONEYGATE_API_TOKEN") or os.environ.get("HONEYGATE_AUTH_TOKEN") or "hg_sec_token_9981"


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
                const res = await fetch('/api/status');
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
                const alertRes = await fetch('/api/alerts');
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
    Implementa validación estricta de IPs y tokens de autenticación para mutaciones.
    """
    honeywall: UndahwoarHoneywall = None
    forensics: ForensicAlertManager = None
    auth_token: Optional[str] = None

    def log_message(self, format, *args):
        # Suprimir logs HTTP verbosos en stdout para mantener la terminal limpia
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            # Inyectar token de autenticación de forma segura para las llamadas del front-end local
            token = self.auth_token or HONEYGATE_AUTH_TOKEN
            rendered = HTML_DASHBOARD_TEMPLATE.replace("__API_TOKEN__", token).replace("HONEYGATE_AUTH_TOKEN_VALUE", token)
            self.wfile.write(rendered.encode("utf-8"))

        elif path == "/api/status" or path == "/api/honeywall":
            snapshot = self.honeywall.get_snapshot()
            self._send_json(snapshot, allow_cors=True)

        elif path == "/api/connections":
            snapshot = self.honeywall.get_snapshot()
            self._send_json(snapshot["active_sessions"], allow_cors=True)

        elif path == "/api/alerts":
            alerts = self.forensics.get_recent_alerts(limit=50) if self.forensics else []
            self._send_json(alerts, allow_cors=True)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 1. Verificación obligatoria de X-Auth-Token con compare_digest para endpoints administrativos
        if path in ("/api/isolate", "/api/unblock"):
            token = self.headers.get("X-Auth-Token", "")
            expected = self.auth_token or HONEYGATE_AUTH_TOKEN
            if not token or not secrets.compare_digest(token, expected):
                logger.warning(f"[AUTH-DENIED] Intento de acceso sin token válido a {path}")
                self._send_json({"error": "Unauthorized: Invalid or missing X-Auth-Token"}, status_code=401, allow_cors=False)
                return

        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length)
        payload = {}
        try:
            payload = json.loads(post_body.decode("utf-8"))
        except Exception:
            pass

        if path == "/api/isolate":
            raw_ip = payload.get("ip")
            reason = payload.get("reason", "Aislamiento manual API")

            # 2. Validación estricta de IP con ipaddress
            if not raw_ip:
                self._send_json({"error": "Falta parámetro 'ip'"}, status_code=400, allow_cors=False)
                return

            try:
                ip_obj = ipaddress.ip_address(raw_ip)
                validated_ip = str(ip_obj)
            except ValueError:
                logger.warning(f"[SECURITY-DROP] Rechazada IP malformada en /api/isolate: {raw_ip}")
                self._send_json({"error": "Dirección IP inválida"}, status_code=400, allow_cors=False)
                return

            self.honeywall.isolate_ip(validated_ip, reason=reason)
            self._send_json({"status": "success", "isolated_ip": validated_ip}, allow_cors=False)

        elif path == "/api/unblock":
            raw_ip = payload.get("ip")
            if not raw_ip:
                self._send_json({"error": "Falta parámetro 'ip'"}, status_code=400, allow_cors=False)
                return

            # Validación estricta de IP con ipaddress
            try:
                ip_obj = ipaddress.ip_address(raw_ip)
                validated_ip = str(ip_obj)
            except ValueError:
                logger.warning(f"[SECURITY-DROP] Rechazada IP malformada en /api/unblock: {raw_ip}")
                self._send_json({"error": "Dirección IP inválida"}, status_code=400, allow_cors=False)
                return

            unblocked = self.honeywall.unblock_ip(validated_ip)
            self._send_json({"status": "success", "unblocked": unblocked, "ip": validated_ip}, allow_cors=False)

        else:
            self.send_response(404)
            self.end_headers()

    def _send_json(self, data: Any, status_code: int = 200, allow_cors: bool = False):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        if allow_cors:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AsyncDashboardServer:
    """Servidor web de telemetría forense para HoneyGate (escuchando por defecto en 127.0.0.1)."""
    def __init__(self, honeywall: UndahwoarHoneywall, forensics: ForensicAlertManager, host: str = "127.0.0.1", port: int = 8888):
        self.host = host
        self.port = port
        self.honeywall = honeywall
        self.forensics = forensics
        self.httpd: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None

    def start_background(self) -> threading.Thread:
        """Inicia el servidor web en un hilo secundario."""
        self.api_token = os.environ.get("HONEYGATE_API_TOKEN") or os.environ.get("HONEYGATE_AUTH_TOKEN") or HONEYGATE_AUTH_TOKEN
        HoneyGateHTTPRequestHandler.honeywall = self.honeywall
        HoneyGateHTTPRequestHandler.forensics = self.forensics
        HoneyGateHTTPRequestHandler.auth_token = self.api_token

        self.httpd = HTTPServer((self.host, self.port), HoneyGateHTTPRequestHandler)
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
