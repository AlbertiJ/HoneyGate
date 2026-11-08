"""
================================================================================
UNDAHWOAR DASHBOARD API: Servidor Web Asíncrono y Telemetría Forense
Endpoints REST JSON en Memoria y Dashboard Web HTML5/JS en Tiempo Real
================================================================================
"""

import os
import json
import time
import logging
import threading
from typing import Dict, Any, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from undahwoar.honeywall_core import UndahwoarHoneywall
from undahwoar.forensic_monitor import ForensicAlertManager

logger = logging.getLogger("UndahwoarAPI")


HTML_DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Undahwoar Honeywall // Telemetría & Contención</title>
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
            <div class="logo-badge">UNDAHWOAR</div>
            <div class="title">
                <h1>Honeywall & Perimeter Deception Dashboard</h1>
                <p>Framework Defensivo No-Root | Edge-Triggered epoll | inotify Forensics</p>
            </div>
        </div>
        <div class="status-badge">
            <div class="pulse"></div>
            <span>Honeywall Activo (10 req/min limit)</span>
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
        async function fetchMetrics() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                
                document.getElementById('val-active').innerText = data.active_sessions.length;
                document.getElementById('val-total').innerText = data.stats.total_connections;
                document.getElementById('val-isolated').innerText = Object.keys(data.isolated_ips).length;
                document.getElementById('val-violations').innerText = data.stats.rate_limit_violations;

                // Render sesiones
                const tbody = document.getElementById('sessions-table-body');
                if (data.active_sessions.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 20px;">Sin conexiones atacantes activas en este momento.</td></tr>';
                } else {
                    tbody.innerHTML = data.active_sessions.map(s => {
                        const rate = s.outbound_rate_min;
                        const pct = Math.min(100, (rate / 10) * 100);
                        const color = rate >= 8 ? '#ff3366' : (rate >= 5 ? '#ffcc00' : '#00ff66');
                        return `<tr>
                            <td><code>${s.fd}</code></td>
                            <td><strong>${s.ip}</strong></td>
                            <td>${s.port}</td>
                            <td><code>${s.mac}</code></td>
                            <td style="min-width: 100px;">
                                <div style="display: flex; justify-content: space-between; font-size: 11px;">
                                    <span>${rate}/10 req/m</span>
                                </div>
                                <div class="rate-bar-container">
                                    <div class="rate-bar" style="width: ${pct}%; background: ${color};"></div>
                                </div>
                            </td>
                            <td>${s.duration_sec}s</td>
                            <td><button class="btn-action" onclick="isolateIP('${s.ip}')">Aislar</button></td>
                        </tr>`;
                    }).join('');
                }

                // Render aisladas
                const isoBody = document.getElementById('isolated-table-body');
                const isoKeys = Object.keys(data.isolated_ips);
                if (isoKeys.length === 0) {
                    isoBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #64748b; padding: 12px;">Ninguna IP aislada en contención.</td></tr>';
                } else {
                    isoBody.innerHTML = isoKeys.map(ip => {
                        const info = data.isolated_ips[ip];
                        const dateStr = new Date(info.isolated_at * 1000).toLocaleTimeString();
                        return `<tr>
                            <td><strong style="color: #ff3366;">${ip}</strong></td>
                            <td>${info.reason}</td>
                            <td>${dateStr}</td>
                            <td><button class="btn-action btn-unblock" onclick="unblockIP('${ip}')">Desbloquear</button></td>
                        </tr>`;
                    }).join('');
                }

                // Cargar alertas
                const alertRes = await fetch('/api/alerts');
                const alerts = await alertRes.json();
                document.getElementById('alert-counter').innerText = alerts.length;
                const alertContainer = document.getElementById('alerts-container');
                if (alerts.length > 0) {
                    alertContainer.innerHTML = alerts.slice().reverse().map(a => `
                        <div class="alert-item ${a.severity}">
                            <div class="alert-header">
                                <span style="color: ${a.severity === 'critical' ? '#ff3366' : '#ffcc00'};">${a.title}</span>
                                <span class="alert-time">${a.date.split(' ')[1]}</span>
                            </div>
                            <div class="alert-body">${a.message}</div>
                        </div>
                    `).join('');
                }
            } catch (err) {
                console.error("Error consultando telemetría:", err);
            }
        }

        async function isolateIP(ip) {
            if (!confirm(`¿Confirmas el aislamiento forzado inmediato de ${ip}?`)) return;
            await fetch('/api/isolate', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip: ip, reason: 'Aislamiento manual desde Web Dashboard'})
            });
            fetchMetrics();
        }

        async function unblockIP(ip) {
            await fetch('/api/unblock', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
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


class UndahwoarHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    Manejador HTTP ligero y concurrente para los endpoints REST JSON y el dashboard web.
    """
    honeywall: UndahwoarHoneywall = None
    forensics: ForensicAlertManager = None

    def log_message(self, format, *args):
        # Suprimir logs HTTP verbosos en stdout para mantener la terminal limpia para el CLI
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD_TEMPLATE.encode("utf-8"))

        elif path == "/api/status" or path == "/api/honeywall":
            snapshot = self.honeywall.get_snapshot()
            self._send_json(snapshot)

        elif path == "/api/connections":
            snapshot = self.honeywall.get_snapshot()
            self._send_json(snapshot["active_sessions"])

        elif path == "/api/alerts":
            alerts = self.forensics.get_recent_alerts(limit=50) if self.forensics else []
            self._send_json(alerts)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length)
        payload = {}
        try:
            payload = json.loads(post_body.decode("utf-8"))
        except Exception:
            pass

        if path == "/api/isolate":
            ip = payload.get("ip")
            reason = payload.get("reason", "Aislamiento manual API")
            if ip:
                self.honeywall.isolate_ip(ip, reason=reason)
                self._send_json({"status": "success", "isolated_ip": ip})
            else:
                self._send_json({"error": "Falta parámetro 'ip'"}, status_code=400)

        elif path == "/api/unblock":
            ip = payload.get("ip")
            if ip:
                unblocked = self.honeywall.unblock_ip(ip)
                self._send_json({"status": "success", "unblocked": unblocked, "ip": ip})
            else:
                self._send_json({"error": "Falta parámetro 'ip'"}, status_code=400)

        else:
            self.send_response(404)
            self.end_headers()

    def _send_json(self, data: Any, status_code: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AsyncDashboardServer:
    """Servidor web de telemetría forense para Undahwoar."""
    def __init__(self, honeywall: UndahwoarHoneywall, forensics: ForensicAlertManager, host: str = "0.0.0.0", port: int = 8888):
        self.host = host
        self.port = port
        self.honeywall = honeywall
        self.forensics = forensics
        self.httpd: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None

    def start_background(self) -> threading.Thread:
        """Inicia el servidor web en un hilo secundario."""
        UndahwoarHTTPRequestHandler.honeywall = self.honeywall
        UndahwoarHTTPRequestHandler.forensics = self.forensics

        self.httpd = HTTPServer((self.host, self.port), UndahwoarHTTPRequestHandler)
        logger.info(f"[WEB-API] Dashboard y Endpoints JSON activos en http://{self.host}:{self.port}")

        self.server_thread = threading.Thread(
            target=self.httpd.serve_forever,
            name="UndahwoarWebAPIThread",
            daemon=True
        )
        self.server_thread.start()
        return self.server_thread

    def stop(self):
        """Detiene el servidor HTTP."""
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
