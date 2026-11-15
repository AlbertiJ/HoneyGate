#!/usr/bin/env python3
"""
Prueba Unitaria y de Integración Completa para HoneyGate Core y Capa SQLite.
Valida epoll, Honeywall, rate limiting, SQLite storage, endpoints REST,
autenticación, validación de entrada, límite de tamaño y endurecimiento de seguridad.
"""
import io
import os
import re
import hmac
import stat
import json
import time
import socket
import hashlib
import logging
import smtplib
import sqlite3
import tempfile
import urllib.request
import urllib.error
import urllib.parse

from honeygate.honeywall_core import HoneyGateHoneywall, EpollNetworkEngine
from honeygate.forensic_monitor import ForensicAlertManager
from honeygate.dashboard_api import AsyncDashboardServer, MAX_BODY_BYTES
from honeygate.portal import AsyncPortalServer
from honeygate.storage import HoneyGateStorage


def _http_request(
    url: str,
    method: str = "GET",
    headers: dict = None,
    body: dict = None,
    raw_body: bytes = None,
):
    if raw_body is not None:
        data = raw_body
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
    else:
        data = None

    req_headers = dict(headers or {})
    if data is not None and "Content-Type" not in req_headers:
        req_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="ignore")
        except (ConnectionResetError, BrokenPipeError, OSError):
            err_body = ""
        return e.code, dict(e.headers.items()), err_body


def run_tests():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "honeygate_test.db")
        storage = HoneyGateStorage(db_path=db_path)

        print("[TEST] 1. Inicializando HoneyGateHoneywall con SQLite Storage y Epoll Engine...")
        honeywall = HoneyGateHoneywall(storage=storage)
        engine = EpollNetworkEngine(ports=[32222, 38080], honeywall=honeywall)
        engine.start_background()
        time.sleep(0.5)

        try:
            print("[TEST] 2. Verificando conexión de cliente y banner SSH realista...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", 32222))
            banner = s.recv(1024)
            banner_str = banner.decode("utf-8", errors="ignore")
            assert banner_str.strip() == "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2", f"Banner inesperado: {banner_str!r}"
            assert "Deception" not in banner_str, "El banner SSH no debe contener 'Deception'"
            assert "Emulated" not in banner_str, "El banner SSH no debe contener 'Emulated'"
            print(f"       -> Banner SSH limpio verificado: {banner_str.strip()}")

            print("[TEST] 3. Verificando registro en Honeywall y persistencia de sesión en SQLite...")
            snap = honeywall.get_snapshot()
            assert len(snap["active_sessions"]) == 1, "Debe haber 1 sesión activa"
            session_info = snap["active_sessions"][0]
            assert session_info["id"] is not None, "La sesión debe tener storage_id asignado"
            persisted_session_id = session_info["id"]
            print(f"       -> Sesión capturada: ID={persisted_session_id} IP={session_info['ip']} MAC={session_info['mac']}")

            print("[TEST] 4. Probando Rate-Limiting (>10 peticiones salientes)...")
            for i in range(12):
                s.send(f"TEST_PROBE_{i}\n".encode())
                time.sleep(0.05)
                try:
                    resp = s.recv(512)
                    if not resp:
                        print(f"       -> Desconexión confirmada en iteración {i}")
                        break
                except (ConnectionResetError, BrokenPipeError, OSError):
                    print(f"       -> Conexión reseteada/cerrada por Honeywall en iteración {i}")
                    break

            time.sleep(0.3)
            snap2 = honeywall.get_snapshot()
            assert snap2["stats"]["rate_limit_violations"] >= 1, "Debe registrarse violación de rate limit"
            assert "127.0.0.1" in snap2["isolated_ips"], "127.0.0.1 debe estar en isolated_ips"
            print("       -> Contención perimetral y aislamiento verificado exitosamente.")

            print("[TEST] 5. Verificando tokens efímeros distintos sin variable de entorno...")
            prev_env_token = os.environ.pop("HONEYGATE_API_TOKEN", None)
            try:
                forensics = ForensicAlertManager(target_log_files=["logs/test.log"], storage=storage)
                api1 = AsyncDashboardServer(
                    honeywall=honeywall,
                    forensics=forensics,
                    host="127.0.0.1",
                    port=38888,
                    storage=storage,
                )
                api2 = AsyncDashboardServer(
                    honeywall=honeywall,
                    forensics=forensics,
                    host="127.0.0.1",
                    port=38889,
                    storage=storage,
                )
                assert api1.api_token and api2.api_token, "Los tokens generados no pueden estar vacíos"
                assert api1.api_token != api2.api_token, "Dos instancias sin env var deben generar tokens distintos"
                assert len(api1.api_token) >= 32, "El token efímero debe tener entropía suficiente"
                print("       -> Dos instancias generaron tokens efímeros distintos: OK")

                api1.start_background()
                time.sleep(0.4)

                auth_hdr = {"X-Auth-Token": api1.api_token}

                print("[TEST] 6. Verificando endpoints REST base con autenticación obligatoria y sin CORS *...")
                code_dash, _, html_content = _http_request("http://127.0.0.1:38888/")
                assert code_dash == 200 and "HoneyGate" in html_content, "Dashboard HTML debe responder 200"

                code_no_tok, _, _ = _http_request("http://127.0.0.1:38888/api/status")
                assert code_no_tok == 401, f"GET /api/status sin token debe retornar 401, retornó {code_no_tok}"

                code_ok, headers_ok, body_ok = _http_request("http://127.0.0.1:38888/api/status", headers=auth_hdr)
                assert code_ok == 200, f"GET /api/status con token debe retornar 200, retornó {code_ok}"
                assert "access-control-allow-origin" not in {k.lower() for k in headers_ok}
                status_data = json.loads(body_ok)
                assert "stats" in status_data and "isolated_ips" in status_data and "config" in status_data

                for ep in ("/api/connections", "/api/alerts"):
                    c_unauth, _, _ = _http_request(f"http://127.0.0.1:38888{ep}")
                    assert c_unauth == 401, f"GET {ep} sin token debe retornar 401"
                    c_auth, hdrs_auth, _ = _http_request(f"http://127.0.0.1:38888{ep}", headers=auth_hdr)
                    assert c_auth == 200, f"GET {ep} con token debe retornar 200"
                    assert "access-control-allow-origin" not in {k.lower() for k in hdrs_auth}

                code_bad_tok, _, _ = _http_request(
                    "http://127.0.0.1:38888/api/isolate",
                    method="POST",
                    headers={"X-Auth-Token": "token_invalido_123"},
                    body={"ip": "10.0.0.1"},
                )
                assert code_bad_tok == 401

                code_bad_ip, _, _ = _http_request(
                    "http://127.0.0.1:38888/api/isolate",
                    method="POST",
                    headers=auth_hdr,
                    body={"ip": "999.999.999.999"},
                )
                assert 400 <= code_bad_ip < 500

                code_iso_ok, hdrs_iso, _ = _http_request(
                    "http://127.0.0.1:38888/api/isolate",
                    method="POST",
                    headers=auth_hdr,
                    body={"ip": "10.0.0.55", "reason": "Prueba de integración"},
                )
                assert code_iso_ok == 200
                assert "access-control-allow-origin" not in {k.lower() for k in hdrs_iso}
                assert "10.0.0.55" in honeywall.get_snapshot()["isolated_ips"]
                print("       -> Endpoints base y protección CORS/Token: OK")

                print("[TEST] 7. Verificando Fase 1: GET/PUT /api/config + validación + límite de tamaño...")
                c_cfg_unauth, _, _ = _http_request("http://127.0.0.1:38888/api/config")
                assert c_cfg_unauth == 401, "GET /api/config sin token debe retornar 401"

                c_cfg_put_unauth, _, _ = _http_request(
                    "http://127.0.0.1:38888/api/config",
                    method="PUT",
                    body={"mode": 2},
                )
                assert c_cfg_put_unauth == 401, "PUT /api/config sin token debe retornar 401"

                c_cfg_ok, _, cfg_body = _http_request("http://127.0.0.1:38888/api/config", headers=auth_hdr)
                assert c_cfg_ok == 200
                cfg_json = json.loads(cfg_body)
                assert cfg_json["mode"] == 1

                # PUT válido
                c_put_ok, _, put_body = _http_request(
                    "http://127.0.0.1:38888/api/config",
                    method="PUT",
                    headers=auth_hdr,
                    body={
                        "mode": 2,
                        "retention_days": 45,
                        "max_outbound_per_minute": 15,
                        "honeypot_enabled": True,
                        "egress_whitelist": ["10.0.0.10"],
                    },
                )
                assert c_put_ok == 200, f"PUT /api/config válido debe retornar 200, retornó {c_put_ok}: {put_body}"
                updated_cfg = json.loads(put_body)
                assert updated_cfg["mode"] == 2 and updated_cfg["retention_days"] == 45
                assert honeywall.MAX_OUTBOUND_PER_MINUTE == 15

                # PUT inválido (modo fuera de rango, campo desconocido, bool como int, JSON roto)
                for bad_body in (
                    {"mode": 9},
                    {"mode": True},
                    {"retention_days": 0},
                    {"campo_inexistente": 123},
                    {"egress_whitelist": "no_es_lista"},
                ):
                    c_bad, _, _ = _http_request(
                        "http://127.0.0.1:38888/api/config",
                        method="PUT",
                        headers=auth_hdr,
                        body=bad_body,
                    )
                    assert c_bad == 400, f"Payload inválido {bad_body} debe retornar 400, retornó {c_bad}"

                # Cuerpo demasiado grande (> 64 KB) -> 413
                oversized = b'{"mode": 1, "egress_whitelist": ["' + (b"a" * (MAX_BODY_BYTES + 100)) + b'"]}'
                c_big, _, _ = _http_request(
                    "http://127.0.0.1:38888/api/config",
                    method="PUT",
                    headers=auth_hdr,
                    raw_body=oversized,
                )
                assert c_big == 413, f"Payload > {MAX_BODY_BYTES} bytes debe retornar 413, retornó {c_big}"
                print("       -> /api/config (401/200/400/413): OK")

                print("[TEST] 8. Verificando GET /api/sessions, GET /api/events y POST /api/sessions/{id}/observe...")
                # GET /api/sessions sin token -> 401
                c_sess_401, _, _ = _http_request("http://127.0.0.1:38888/api/sessions")
                assert c_sess_401 == 401

                # GET /api/sessions con filtro inválido -> 400
                c_sess_400, _, _ = _http_request("http://127.0.0.1:38888/api/sessions?ip=not_an_ip", headers=auth_hdr)
                assert c_sess_400 == 400
                c_sess_lim_400, _, _ = _http_request("http://127.0.0.1:38888/api/sessions?limit=9999", headers=auth_hdr)
                assert c_sess_lim_400 == 400

                # GET /api/sessions válido
                c_sess_200, _, sess_body = _http_request(
                    "http://127.0.0.1:38888/api/sessions?ip=127.0.0.1&limit=10&offset=0",
                    headers=auth_hdr,
                )
                assert c_sess_200 == 200
                sess_data = json.loads(sess_body)
                assert sess_data["total"] >= 1 and len(sess_data["sessions"]) >= 1
                assert sess_data["sessions"][0]["origin"]["ip"] == "127.0.0.1"

                # POST /api/sessions/{id}/observe sin token -> 401
                c_obs_401, _, _ = _http_request(
                    f"http://127.0.0.1:38888/api/sessions/{persisted_session_id}/observe",
                    method="POST",
                    body={"reason": "Prueba"},
                )
                assert c_obs_401 == 401

                # ID inválido -> 400, ID inexistente -> 404
                c_obs_400, _, _ = _http_request(
                    "http://127.0.0.1:38888/api/sessions/abc/observe",
                    method="POST",
                    headers=auth_hdr,
                    body={},
                )
                assert c_obs_400 == 400

                c_obs_404, _, _ = _http_request(
                    "http://127.0.0.1:38888/api/sessions/999999/observe",
                    method="POST",
                    headers=auth_hdr,
                    body={"reason": "No existe"},
                )
                assert c_obs_404 == 404

                # Marcar sesión válida como en_observacion -> 200
                c_obs_200, _, obs_body = _http_request(
                    f"http://127.0.0.1:38888/api/sessions/{persisted_session_id}/observe",
                    method="POST",
                    headers=auth_hdr,
                    body={"reason": "Comportamiento sospechoso en prueba"},
                )
                assert c_obs_200 == 200
                obs_json = json.loads(obs_body)
                assert obs_json["session"]["status"] == "en_observacion"

                # GET /api/events sin token -> 401
                c_ev_401, _, _ = _http_request("http://127.0.0.1:38888/api/events")
                assert c_ev_401 == 401

                # GET /api/events con filtro inválido -> 400
                c_ev_400, _, _ = _http_request("http://127.0.0.1:38888/api/events?severity=unknown", headers=auth_hdr)
                assert c_ev_400 == 400

                # GET /api/events filtrando por SESSION_OBSERVED y paginación
                c_ev_200, _, ev_body = _http_request(
                    "http://127.0.0.1:38888/api/events?event_type=SESSION_OBSERVED&limit=5&offset=0",
                    headers=auth_hdr,
                )
                assert c_ev_200 == 200
                ev_data = json.loads(ev_body)
                assert ev_data["total"] >= 1
                assert ev_data["events"][0]["session_id"] == persisted_session_id
                print("       -> /api/sessions, /api/events y /observe: OK")

                api1.stop()
            finally:
                if prev_env_token is not None:
                    os.environ["HONEYGATE_API_TOKEN"] = prev_env_token

            print("[TEST] 9. Verificando persistencia real en disco al reabrir HoneyGateStorage...")
            storage.close()
            reopened = HoneyGateStorage(db_path=db_path)
            try:
                cfg_reloaded = reopened.get_config()
                assert cfg_reloaded["mode"] == 2 and cfg_reloaded["retention_days"] == 45
                reloaded_session = reopened.get_session(persisted_session_id)
                assert reloaded_session is not None and reloaded_session["status"] == "en_observacion"
                reloaded_events, ev_total = reopened.list_events(event_type="CONFIG_UPDATED")
                assert ev_total >= 1 and len(reloaded_events) >= 1
                print("       -> Persistencia SQLite tras reinicio verificada: OK")
            finally:
                reopened.close()

            print("[TEST] 11. Verificando Fase 3: Portal Cautivo Modo 1, Anti-Sybil, XSS, SMTP y privacidad de logs...")
            portal_db_path = os.path.join(tmpdir, "portal_test.db")
            p_storage = HoneyGateStorage(db_path=portal_db_path)
            p_storage.update_config({
                "mode": 1,
                "portal_enabled": True,
                "sybil_max_emails_per_device": 2,
                "sybil_window_seconds": 600,
            })
            p_honeywall = HoneyGateHoneywall(storage=p_storage)
            p_forensics = ForensicAlertManager(target_log_files=["logs/test_portal.log"], storage=p_storage)

            # Capturar logs en memoria para comprobar privacidad estricta
            log_stream = io.StringIO()
            mem_handler = logging.StreamHandler(log_stream)
            root_logger = logging.getLogger()
            root_logger.addHandler(mem_handler)

            prev_token_env = os.environ.pop("HONEYGATE_API_TOKEN", None)
            prev_lab_env = os.environ.pop("HONEYGATE_PORTAL_LAB_MODE", None)
            prev_opt_env = os.environ.pop("HONEYGATE_PORTAL_OTP_OPTIONAL", None)
            prev_secret_env = os.environ.pop("HONEYGATE_PORTAL_SECRET", None)
            prev_smtp_host = os.environ.pop("HONEYGATE_SMTP_HOST", None)
            prev_smtp_pass = os.environ.pop("HONEYGATE_SMTP_PASS", None)
            prev_smtp_user = os.environ.pop("HONEYGATE_SMTP_USER", None)

            portal_secret_file = os.path.join(tmpdir, "portal_secret")

            # Mac resolver controlado para probar rotación de MAC con misma huella de navegador
            simulated_mac = {"val": "aa:bb:cc:11:22:33"}
            p_admin = AsyncDashboardServer(
                honeywall=p_honeywall,
                forensics=p_forensics,
                host="127.0.0.1",
                port=38890,
                storage=p_storage,
            )
            p_portal = AsyncPortalServer(
                storage=p_storage,
                host="127.0.0.1",
                port=38090,
                mac_resolver=lambda _ip: simulated_mac["val"],
                portal_secret_path=portal_secret_file,
            )
            p_admin.start_background()
            p_portal.start_background()
            time.sleep(0.4)

            try:
                p_auth_hdr = {"X-Auth-Token": p_admin.api_token}

                # 11.1 Puerto separado, sin token de API, sin password input, /api/* bloqueado y sin lease/bw sugerido
                c_pget, _, portal_html = _http_request("http://127.0.0.1:38090/")
                assert c_pget == 200
                assert p_admin.api_token not in portal_html, "El portal NUNCA debe contener el token de la API"
                assert "X-Auth-Token" not in portal_html
                assert "/api/" not in portal_html, "El portal no puede llamar a /api/*"
                assert 'type="password"' not in portal_html.lower(), "El portal nunca pide contraseña"
                assert 'action="/portal/otp/request"' in portal_html, "OTP debe ser obligatorio por defecto"
                assert "/portal/register" not in portal_html, "Registro sin OTP no debe exponerse por defecto"
                assert "Ley 25.326" in portal_html and "Ley 26.388" in portal_html

                for blocked_ep in ("/api/status", "/api/config", "/api/sessions", "/api/events"):
                    c_block, _, _ = _http_request(f"http://127.0.0.1:38090{blocked_ep}")
                    assert c_block == 404, f"Portal no debe exponer {blocked_ep}, retornó {c_block}"

                # 11.2 OTP obligatorio por defecto: /portal/register debe rechazarse con 403 sin HONEYGATE_PORTAL_OTP_OPTIONAL=1
                c_reg_blocked, _, reg_blocked_body = _http_request(
                    "http://127.0.0.1:38090/portal/register",
                    method="POST",
                    headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Linux; Android 14)"},
                    body={"email": "bypass@empresa.org", "consent": True},
                )
                assert c_reg_blocked == 403, f"Sin HONEYGATE_PORTAL_OTP_OPTIONAL=1 debe retornar 403, retornó {c_reg_blocked}"
                assert json.loads(reg_blocked_body)["otp_required"] is True

                # Consentimiento obligatorio Ley 25.326 en /portal/otp/request
                c_noconsent, _, _ = _http_request(
                    "http://127.0.0.1:38090/portal/otp/request",
                    method="POST",
                    headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Linux; Android 14)"},
                    body={"email": "sinconsent@empresa.org", "consent": False},
                )
                assert c_noconsent == 400

                # 11.3 Fail-closed sin SMTP ni modo lab, luego registro completo vía OTP + SMTP,
                # HMAC-SHA256 en otp_challenges (secreto 0600), verificación de device_id y ausencia de lease/bw en portal
                c_otp_fail, _, _ = _http_request(
                    "http://127.0.0.1:38090/portal/otp/request",
                    method="POST",
                    headers={"Accept": "application/json"},
                    body={"email": "otp.sin.config@empresa.org", "consent": True},
                )
                assert c_otp_fail == 503

                secret_visitor_email = "visitante.privado@empresa.org"
                captured_smtp = {"password": None, "otp": None, "recipient": None}
                smtp_secret_pw = "smtp_clave_ultra_secreta_987"

                class FakeSMTP:
                    def __init__(self, host, port, timeout=10):
                        pass
                    def __enter__(self):
                        return self
                    def __exit__(self, *args):
                        return False
                    def ehlo(self):
                        pass
                    def starttls(self):
                        pass
                    def login(self, user, password):
                        captured_smtp["password"] = password
                    def send_message(self, msg):
                        captured_smtp["recipient"] = msg["To"]
                        m = re.search(r"\b(\d{6})\b", msg.get_content())
                        captured_smtp["otp"] = m.group(1) if m else None

                orig_smtp = smtplib.SMTP
                smtplib.SMTP = FakeSMTP
                try:
                    os.environ["HONEYGATE_SMTP_HOST"] = "smtp.local.test"
                    os.environ["HONEYGATE_SMTP_PORT"] = "587"
                    os.environ["HONEYGATE_SMTP_USER"] = "mailer@local.test"
                    os.environ["HONEYGATE_SMTP_PASS"] = smtp_secret_pw

                    c_otp_smtp, _, otp_smtp_body = _http_request(
                        "http://127.0.0.1:38090/portal/otp/request",
                        method="POST",
                        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Linux; Android 14)"},
                        body={"email": secret_visitor_email, "consent": True},
                    )
                    assert c_otp_smtp == 202
                    otp_smtp_json = json.loads(otp_smtp_body)
                    assert otp_smtp_json["max_attempts"] == 3
                    assert captured_smtp["password"] == smtp_secret_pw
                    assert captured_smtp["recipient"] == secret_visitor_email
                    assert captured_smtp["otp"] is not None

                    # Verificar archivo portal_secret con permisos 0600 y HMAC-SHA256 real en otp_challenges
                    assert os.path.exists(portal_secret_file), "Debe generarse portal_secret automáticamente"
                    assert stat.S_IMODE(os.stat(portal_secret_file).st_mode) == 0o600, "portal_secret debe tener permisos 0600"
                    with open(portal_secret_file, "r", encoding="utf-8") as sf:
                        portal_secret_bytes = sf.read().strip().encode("utf-8")
                    expected_hmac = hmac.new(
                        portal_secret_bytes,
                        secret_visitor_email.encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()
                    bare_sha256 = hashlib.sha256(secret_visitor_email.encode("utf-8")).hexdigest()
                    with sqlite3.connect(portal_db_path) as sconn:
                        row_ch = sconn.execute(
                            "SELECT email_hash FROM otp_challenges WHERE challenge_id = ?",
                            (otp_smtp_json["challenge_id"],),
                        ).fetchone()
                    assert row_ch is not None
                    assert row_ch[0] == expected_hmac, "otp_challenges.email_hash debe usar HMAC-SHA256 con secreto del servidor"
                    assert row_ch[0] != bare_sha256

                    # Validar OTP y registrar sesión con telemetry real
                    c_ver_ok, _, ver_ok_body = _http_request(
                        "http://127.0.0.1:38090/portal/otp/verify",
                        method="POST",
                        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Linux; Android 14)"},
                        body={
                            "challenge_id": otp_smtp_json["challenge_id"],
                            "email": secret_visitor_email,
                            "otp_code": captured_smtp["otp"],
                            "consent": True,
                            "screen": "1080x2400x24",
                            "timezone": "America/Argentina/Buenos_Aires",
                            "language": "es-AR",
                            "canvas_hash": "c1a2b3d4",
                            "fonts_hash": "f9e8d7c6",
                        },
                    )
                    assert c_ver_ok == 200, f"Validación OTP correcta debe retornar 200, retornó {c_ver_ok}: {ver_ok_body}"
                    reg1 = json.loads(ver_ok_body)
                    assert reg1["accepted"] and reg1["status"] == "active"
                    assert reg1["otp_verified"] is True and reg1["mail_verified"] is True
                    assert "dhcp_lease_sec" not in reg1 and "bandwidth_kbps" not in reg1, (
                        "El portal NO debe entregar dhcp_lease_sec ni bandwidth_kbps al visitante"
                    )

                    # Verificar render HTML del portal (tampoco muestra lease/bw)
                    c_html_ok, _, otp_req_html = _http_request(
                        "http://127.0.0.1:38090/portal/otp/request",
                        method="POST",
                        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Linux; Android 14)"},
                        raw_body=f"email={urllib.parse.quote('visitante.html@empresa.org')}&consent=1".encode("utf-8"),
                    )
                    assert c_html_ok == 202
                    cid_html = re.search(r'name="challenge_id" value="([^"]+)"', otp_req_html).group(1)
                    c_ver_html, _, ver_html_body = _http_request(
                        "http://127.0.0.1:38090/portal/otp/verify",
                        method="POST",
                        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Linux; Android 14)"},
                        raw_body=(
                            f"challenge_id={urllib.parse.quote(cid_html)}"
                            f"&email={urllib.parse.quote('visitante.html@empresa.org')}"
                            f"&otp_code={captured_smtp['otp']}&consent=1"
                        ).encode("utf-8"),
                    )
                    assert c_ver_html == 200
                    assert "Lease DHCP" not in ver_html_body and "Ancho de banda" not in ver_html_body
                    assert "10240" not in ver_html_body and "300s" not in ver_html_body

                    # Verificar máximo 3 intentos por desafío OTP (el 4to intento falla aunque el código sea válido)
                    c_otp_max, _, otp_max_body = _http_request(
                        "http://127.0.0.1:38090/portal/otp/request",
                        method="POST",
                        headers={"Accept": "application/json"},
                        body={"email": "maxintentos@empresa.org", "consent": True},
                    )
                    assert c_otp_max == 202
                    cid_max = json.loads(otp_max_body)["challenge_id"]
                    real_otp_max = captured_smtp["otp"]
                    wrong_otp = "000000" if real_otp_max != "000000" else "111111"
                    for _attempt in range(3):
                        c_bad, _, _ = _http_request(
                            "http://127.0.0.1:38090/portal/otp/verify",
                            method="POST",
                            headers={"Accept": "application/json"},
                            body={
                                "challenge_id": cid_max,
                                "email": "maxintentos@empresa.org",
                                "otp_code": wrong_otp,
                                "consent": True,
                            },
                        )
                        assert c_bad == 401
                    c_fourth, _, fourth_body = _http_request(
                        "http://127.0.0.1:38090/portal/otp/verify",
                        method="POST",
                        headers={"Accept": "application/json"},
                        body={
                            "challenge_id": cid_max,
                            "email": "maxintentos@empresa.org",
                            "otp_code": real_otp_max,
                            "consent": True,
                        },
                    )
                    assert c_fourth == 401, "Después de 3 intentos fallidos el desafío OTP debe quedar bloqueado"
                    assert "Demasiados intentos" in json.loads(fourth_body)["error"]
                finally:
                    smtplib.SMTP = orig_smtp
                    os.environ.pop("HONEYGATE_SMTP_HOST", None)
                    os.environ.pop("HONEYGATE_SMTP_PORT", None)
                    os.environ.pop("HONEYGATE_SMTP_USER", None)
                    os.environ.pop("HONEYGATE_SMTP_PASS", None)

                # Verificar que en modo normal ni el mail, ni el OTP, ni la contraseña SMTP están en logs o SQLite
                normal_logs = log_stream.getvalue()
                assert secret_visitor_email not in normal_logs, "Email de visitante NO debe aparecer en logs normales"
                assert captured_smtp["otp"] not in normal_logs, "OTP NO debe aparecer en logs en modo normal"
                assert smtp_secret_pw not in normal_logs, "Contraseña SMTP NO debe aparecer en logs"

                with open(portal_db_path, "rb") as dbf:
                    db_raw = dbf.read()
                assert smtp_secret_pw.encode("utf-8") not in db_raw, "Contraseña SMTP NO puede guardarse en SQLite"
                assert captured_smtp["otp"].encode("utf-8") not in db_raw, "OTP en claro NO puede guardarse en SQLite"

                # Comprobar en /api/sessions los fingerprints reales/vacíos y los valores sugeridos en SQLite
                _, _, p_sess_body = _http_request(
                    "http://127.0.0.1:38890/api/sessions?limit=10",
                    headers=p_auth_hdr,
                )
                sessions_list = json.loads(p_sess_body)["sessions"]
                p_sess = next(s for s in sessions_list if s.get("visitor_label") == secret_visitor_email)
                browser_fp = json.loads(p_sess["origin"]["fingerprints"]["browser"])
                network_fp = json.loads(p_sess["origin"]["fingerprints"]["network"])
                assert p_sess["origin"]["mac"] == "aa:bb:cc:11:22:33"
                assert "Android" in browser_fp["user_agent"]
                assert browser_fp["screen"] == "1080x2400x24"
                assert "User-Agent" in network_fp["http_header_order"]
                assert network_fp["ja3"] == "" and network_fp["ja4"] == "", "JA3/JA4 no medidos deben quedar vacíos"
                assert p_sess["origin"]["fingerprints"]["dhcp"] == "", "DHCP Option 55 no medido debe quedar vacío"
                assert p_sess["session"]["mail_verified"] is True
                assert p_sess["session"]["dhcp_lease_sec"] == 300 and p_sess["session"]["bandwidth_kbps"] == 10240

                # 11.4 Modo laboratorio con HONEYGATE_PORTAL_OTP_OPTIONAL=1 -> sesión marcada "mail sin verificar" + Anti-Sybil
                os.environ["HONEYGATE_PORTAL_OTP_OPTIONAL"] = "1"
                try:
                    # Dominio desechable rechazado (sin aislar IP)
                    c_disp, _, _ = _http_request(
                        "http://127.0.0.1:38090/portal/register",
                        method="POST",
                        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Linux; Android 14)"},
                        body={"email": "desechable@mailinator.com", "consent": True},
                    )
                    assert c_disp == 400
                    assert "127.0.0.1" not in p_honeywall.get_snapshot()["isolated_ips"]

                    # Registro sin OTP permitido explícitamente -> marcado mail_verified=False ("mail sin verificar")
                    c_opt_reg, _, opt_reg_body = _http_request(
                        "http://127.0.0.1:38090/portal/register",
                        method="POST",
                        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Linux; Android 14)"},
                        body={
                            "email": "sinotp.lab@empresa.org",
                            "consent": True,
                            "screen": "1080x2400x24",
                            "timezone": "America/Argentina/Buenos_Aires",
                            "language": "es-AR",
                            "canvas_hash": "c1a2b3d4",
                            "fonts_hash": "f9e8d7c6",
                        },
                    )
                    assert c_opt_reg == 200
                    opt_reg_json = json.loads(opt_reg_body)
                    assert opt_reg_json["mail_verified"] is False
                    assert opt_reg_json["mail_status"] == "mail sin verificar"
                    assert "dhcp_lease_sec" not in opt_reg_json and "bandwidth_kbps" not in opt_reg_json

                    _, _, opt_sess_body = _http_request(
                        "http://127.0.0.1:38890/api/sessions?limit=10",
                        headers=p_auth_hdr,
                    )
                    opt_sess = next(
                        s for s in json.loads(opt_sess_body)["sessions"]
                        if s.get("visitor_label") == "sinotp.lab@empresa.org"
                    )
                    assert opt_sess["session"]["mail_verified"] is False

                    # Exceder sybil_max_emails_per_device (2) -> en_observacion con lease y bw reducidos sugeridos
                    c_syb, _, syb_body = _http_request(
                        "http://127.0.0.1:38090/portal/register",
                        method="POST",
                        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Linux; Android 14)"},
                        body={
                            "email": "tercero.sybil@empresa.org",
                            "consent": True,
                            "screen": "1080x2400x24",
                            "timezone": "America/Argentina/Buenos_Aires",
                            "language": "es-AR",
                            "canvas_hash": "c1a2b3d4",
                            "fonts_hash": "f9e8d7c6",
                        },
                    )
                    assert c_syb == 200
                    syb_json = json.loads(syb_body)
                    assert syb_json["status"] == "en_observacion"
                    assert "dhcp_lease_sec" not in syb_json and "bandwidth_kbps" not in syb_json
                    assert "127.0.0.1" not in p_honeywall.get_snapshot()["isolated_ips"]

                    _, _, syb_sess_body = _http_request(
                        "http://127.0.0.1:38890/api/sessions?limit=10",
                        headers=p_auth_hdr,
                    )
                    syb_sess = next(
                        s for s in json.loads(syb_sess_body)["sessions"]
                        if s.get("visitor_label") == "tercero.sybil@empresa.org"
                    )
                    assert syb_sess["session"]["dhcp_lease_sec"] == 60 and syb_sess["session"]["bandwidth_kbps"] == 256

                    # Rotación de MAC con misma huella de navegador -> en_observacion
                    simulated_mac["val"] = "de:ad:be:ef:00:99"
                    c_rot, _, rot_body = _http_request(
                        "http://127.0.0.1:38090/portal/register",
                        method="POST",
                        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Linux; Android 14)"},
                        body={
                            "email": "rotacion.mac@empresa.org",
                            "consent": True,
                            "screen": "1080x2400x24",
                            "timezone": "America/Argentina/Buenos_Aires",
                            "language": "es-AR",
                            "canvas_hash": "c1a2b3d4",
                            "fonts_hash": "f9e8d7c6",
                        },
                    )
                    assert c_rot == 200
                    rot_json = json.loads(rot_body)
                    assert rot_json["status"] == "en_observacion"
                    assert "Rotación de MAC" in rot_json["observed_reason"]
                finally:
                    os.environ.pop("HONEYGATE_PORTAL_OTP_OPTIONAL", None)

                # 11.5 Escape XSS en portal y panel admin + etiquetas sugeridas y 'mail sin verificar' en panel
                xss_raw = '"><script>alert(1)</script>'
                c_xss_portal, _, xss_portal_html = _http_request(
                    "http://127.0.0.1:38090/portal/otp/request",
                    method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    raw_body=f"email={urllib.parse.quote(xss_raw)}&consent=1".encode("utf-8"),
                )
                assert c_xss_portal == 400
                assert "<script>alert(1)</script>" not in xss_portal_html
                assert "&lt;script&gt;alert(1)&lt;/script&gt;" in xss_portal_html

                _, _, dash_html = _http_request("http://127.0.0.1:38890/")
                assert ".replace(/\"/g, '&quot;')" in dash_html and "escapeHtml(item.visitor_label)" in dash_html
                assert "sugerido (no aplicado por el daemon)" in dash_html
                assert "mail sin verificar" in dash_html

                # 11.6 Modo laboratorio explícito: loguea OTP pero sigue sin loguear el email del visitante
                os.environ["HONEYGATE_PORTAL_LAB_MODE"] = "1"
                try:
                    c_lab, _, lab_body = _http_request(
                        "http://127.0.0.1:38090/portal/otp/request",
                        method="POST",
                        headers={"Accept": "application/json"},
                        body={"email": "lab.visitor@empresa.org", "consent": True},
                    )
                    assert c_lab == 202
                    lab_cid = json.loads(lab_body)["challenge_id"]
                    all_logs = log_stream.getvalue()
                    assert f"[PORTAL-LAB] OTP generado para desafio={lab_cid}" in all_logs
                    assert "lab.visitor@empresa.org" not in all_logs, "Mail del visitante no se loguea ni en modo lab"
                finally:
                    os.environ.pop("HONEYGATE_PORTAL_LAB_MODE", None)

                # 11.7 Rate limits persistidos en SQLite con respuesta 429:
                #   - /portal/otp/request: max 3 por mail cada 15 min y max 10 por IP cada hora
                #   - /portal/register: max 20 por IP cada hora
                rl_db_path = os.path.join(tmpdir, "portal_rl_test.db")
                rl_storage = HoneyGateStorage(db_path=rl_db_path)
                rl_storage.update_config({"mode": 1, "portal_enabled": True})
                rl_portal = AsyncPortalServer(
                    storage=rl_storage,
                    host="127.0.0.1",
                    port=38091,
                    portal_secret_path=portal_secret_file,
                )
                os.environ["HONEYGATE_PORTAL_LAB_MODE"] = "1"
                rl_portal.start_background()
                time.sleep(0.25)
                try:
                    # 3 por mail destino cada 15 minutos -> el 4to retorna 429
                    for _i in range(3):
                        c_em, _, _ = _http_request(
                            "http://127.0.0.1:38091/portal/otp/request",
                            method="POST",
                            headers={"Accept": "application/json"},
                            body={"email": "repetido@empresa.org", "consent": True},
                        )
                        assert c_em == 202
                    c_em_429, _, _ = _http_request(
                        "http://127.0.0.1:38091/portal/otp/request",
                        method="POST",
                        headers={"Accept": "application/json"},
                        body={"email": "repetido@empresa.org", "consent": True},
                    )
                    assert c_em_429 == 429, f"4to OTP al mismo mail debe dar 429, dio {c_em_429}"

                    # Reiniciar almacenamiento y servidor para verificar persistencia en SQLite de los contadores
                    rl_portal.stop()
                    rl_storage.close()
                    rl_storage2 = HoneyGateStorage(db_path=rl_db_path)
                    rl_portal2 = AsyncPortalServer(
                        storage=rl_storage2,
                        host="127.0.0.1",
                        port=38092,
                        portal_secret_path=portal_secret_file,
                    )
                    rl_portal2.start_background()
                    time.sleep(0.25)
                    try:
                        # Ya hubo 3 aceptados desde 127.0.0.1 en /portal/otp/request; otros 7 mails distintos llegan a 10
                        for idx in range(7):
                            c_ip_ok, _, _ = _http_request(
                                "http://127.0.0.1:38092/portal/otp/request",
                                method="POST",
                                headers={"Accept": "application/json"},
                                body={"email": f"distinto{idx}@empresa.org", "consent": True},
                            )
                            assert c_ip_ok == 202, f"Pedido #{4 + idx} desde IP debe aceptarse, dio {c_ip_ok}"
                        # El #11 desde misma IP en /portal/otp/request debe devolver 429 aunque sea mail nuevo
                        c_ip_429, _, _ = _http_request(
                            "http://127.0.0.1:38092/portal/otp/request",
                            method="POST",
                            headers={"Accept": "application/json"},
                            body={"email": "distinto_overflow@empresa.org", "consent": True},
                        )
                        assert c_ip_429 == 429, f"11vo OTP desde misma IP debe dar 429, dio {c_ip_429}"

                        # /portal/register: máximo 20 por IP cada hora -> el #21 debe devolver 429
                        for idx in range(20):
                            c_reg_lim, _, _ = _http_request(
                                "http://127.0.0.1:38092/portal/register",
                                method="POST",
                                headers={"Accept": "application/json"},
                                body={"email": f"reg{idx}@empresa.org", "consent": True},
                            )
                            assert c_reg_lim == 403, f"Registro #{idx + 1} antes del límite debe dar 403 (OTP obligatorio), dio {c_reg_lim}"
                        c_reg_429, _, _ = _http_request(
                            "http://127.0.0.1:38092/portal/register",
                            method="POST",
                            headers={"Accept": "application/json"},
                            body={"email": "reg21@empresa.org", "consent": True},
                        )
                        assert c_reg_429 == 429, f"21vo /portal/register desde misma IP debe dar 429, dio {c_reg_429}"
                    finally:
                        rl_portal2.stop()
                        rl_storage2.close()
                finally:
                    os.environ.pop("HONEYGATE_PORTAL_LAB_MODE", None)

                # 11.8 Modo 2 deshabilita el portal (503)
                p_storage.update_config({"mode": 2})
                c_m2, _, _ = _http_request("http://127.0.0.1:38090/")
                assert c_m2 == 503
                print("       -> Portal Cautivo Modo 1, OTP obligatorio, 3 intentos, 429 SQLite, HMAC 0600, Anti-Sybil y XSS: OK")
            finally:
                root_logger.removeHandler(mem_handler)
                p_portal.stop()
                p_admin.stop()
                p_storage.close()
                if prev_token_env is not None:
                    os.environ["HONEYGATE_API_TOKEN"] = prev_token_env
                if prev_lab_env is not None:
                    os.environ["HONEYGATE_PORTAL_LAB_MODE"] = prev_lab_env
                if prev_opt_env is not None:
                    os.environ["HONEYGATE_PORTAL_OTP_OPTIONAL"] = prev_opt_env
                if prev_secret_env is not None:
                    os.environ["HONEYGATE_PORTAL_SECRET"] = prev_secret_env
                if prev_smtp_host is not None:
                    os.environ["HONEYGATE_SMTP_HOST"] = prev_smtp_host
                if prev_smtp_pass is not None:
                    os.environ["HONEYGATE_SMTP_PASS"] = prev_smtp_pass
                if prev_smtp_user is not None:
                    os.environ["HONEYGATE_SMTP_USER"] = prev_smtp_user

        finally:
            engine.stop()

    print("[TEST] 10. Verificando ausencia total del token fijo antiguo en el repositorio...")
    forbidden = "hg_sec_" + "token"
    skip_dirs = {".git", ".gradle", "build", "__pycache__", "logs", "data", ".kotlin", ".build-outputs"}
    hits = []
    root_dir = os.path.dirname(os.path.abspath(__file__))
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    if forbidden in fh.read():
                        hits.append(fpath)
            except OSError:
                pass
    assert not hits, f"Se encontraron apariciones prohibidas del token fijo en: {hits}"
    print("       -> Ningún archivo del proyecto contiene el token fijo antiguo: OK")

    print("\n\033[1;32m[✓] TODAS LAS PRUEBAS DE INTEGRACIÓN Y SEGURIDAD PASARON EXITOSAMENTE.\033[0m")


if __name__ == "__main__":
    run_tests()
