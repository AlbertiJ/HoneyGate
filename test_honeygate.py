#!/usr/bin/env python3
"""
Prueba Unitaria y de Integración Completa para HoneyGate Core y Capa SQLite.
Valida epoll, Honeywall, rate limiting, SQLite storage, endpoints REST,
autenticación, validación de entrada, límite de tamaño y endurecimiento de seguridad.
"""
import os
import json
import time
import socket
import tempfile
import urllib.request
import urllib.error

from honeygate.honeywall_core import HoneyGateHoneywall, EpollNetworkEngine
from honeygate.forensic_monitor import ForensicAlertManager
from honeygate.dashboard_api import AsyncDashboardServer, MAX_BODY_BYTES
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
