#!/usr/bin/env python3
"""
Prueba Unitaria y de Integración Completa para HoneyGate Core.
Valida epoll, Honeywall, rate limiting, inotify, API endpoints y endurecimiento de seguridad.
"""
import os
import time
import socket
import urllib.request
import urllib.error
import json

from honeygate.honeywall_core import HoneyGateHoneywall, EpollNetworkEngine
from honeygate.forensic_monitor import ForensicAlertManager
from honeygate.dashboard_api import AsyncDashboardServer


def _http_request(url: str, method: str = "GET", headers: dict = None, body: dict = None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req_headers = dict(headers or {})
    if body is not None and "Content-Type" not in req_headers:
        req_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read().decode("utf-8", errors="ignore")


def run_tests():
    print("[TEST] 1. Inicializando HoneyGateHoneywall y Epoll Engine...")
    honeywall = HoneyGateHoneywall()
    engine = EpollNetworkEngine(ports=[32222, 38080], honeywall=honeywall)
    engine.start_background()
    time.sleep(0.5)

    print("[TEST] 2. Verificando conexión de cliente y banner SSH realista...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 32222))
    banner = s.recv(1024)
    banner_str = banner.decode("utf-8", errors="ignore")
    assert banner_str.strip() == "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2", f"Banner inesperado: {banner_str!r}"
    assert "Deception" not in banner_str, "El banner SSH no debe contener 'Deception'"
    assert "Emulated" not in banner_str, "El banner SSH no debe contener 'Emulated'"
    print(f"       -> Banner SSH limpio verificado: {banner_str.strip()}")

    print("[TEST] 3. Verificando registro en Honeywall...")
    snap = honeywall.get_snapshot()
    assert len(snap["active_sessions"]) == 1, "Debe haber 1 sesión activa"
    session_info = snap["active_sessions"][0]
    print(f"       -> Sesión capturada: IP={session_info['ip']} MAC={session_info['mac']} FD={session_info['fd']}")

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
        forensics = ForensicAlertManager(target_log_files=["logs/test.log"])
        api1 = AsyncDashboardServer(honeywall=honeywall, forensics=forensics, host="127.0.0.1", port=38888)
        api2 = AsyncDashboardServer(honeywall=honeywall, forensics=forensics, host="127.0.0.1", port=38889)
        assert api1.api_token and api2.api_token, "Los tokens generados no pueden estar vacíos"
        assert api1.api_token != api2.api_token, "Dos instancias sin env var deben generar tokens distintos"
        assert len(api1.api_token) >= 32, "El token efímero debe tener entropía suficiente"
        print("       -> Dos instancias generaron tokens efímeros distintos: OK")

        api1.start_background()
        time.sleep(0.4)

        print("[TEST] 6. Verificando endpoints REST con autenticación obligatoria y sin CORS *...")
        # Dashboard HTML accesible sin token
        code_dash, _, html_content = _http_request("http://127.0.0.1:38888/")
        assert code_dash == 200 and "HoneyGate" in html_content, "Dashboard HTML debe responder 200"
        print("       -> Dashboard HTML OK con branding HoneyGate.")

        # GET /api/status sin token -> 401
        code_no_tok, _, _ = _http_request("http://127.0.0.1:38888/api/status")
        assert code_no_tok == 401, f"GET /api/status sin token debe retornar 401, retornó {code_no_tok}"
        print("       -> GET /api/status sin token -> 401: OK")

        # GET /api/status con token -> 200 y sin cabecera Access-Control-Allow-Origin
        code_ok, headers_ok, body_ok = _http_request(
            "http://127.0.0.1:38888/api/status",
            headers={"X-Auth-Token": api1.api_token}
        )
        assert code_ok == 200, f"GET /api/status con token debe retornar 200, retornó {code_ok}"
        lower_headers = {k.lower(): v for k, v in headers_ok.items()}
        assert "access-control-allow-origin" not in lower_headers, "No debe incluir Access-Control-Allow-Origin"
        status_data = json.loads(body_ok)
        assert "stats" in status_data and "isolated_ips" in status_data
        print("       -> GET /api/status con token -> 200 sin Access-Control-Allow-Origin: OK")

        # GET /api/connections y /api/alerts sin token -> 401; con token -> 200
        for ep in ("/api/connections", "/api/alerts"):
            c_unauth, _, _ = _http_request(f"http://127.0.0.1:38888{ep}")
            assert c_unauth == 401, f"GET {ep} sin token debe retornar 401"
            c_auth, hdrs_auth, _ = _http_request(
                f"http://127.0.0.1:38888{ep}",
                headers={"X-Auth-Token": api1.api_token}
            )
            assert c_auth == 200, f"GET {ep} con token debe retornar 200"
            assert "access-control-allow-origin" not in {k.lower() for k in hdrs_auth}
        print("       -> GET /api/connections y /api/alerts protegidos con X-Auth-Token: OK")

        # POST /api/isolate con token incorrecto -> 401
        code_bad_tok, _, _ = _http_request(
            "http://127.0.0.1:38888/api/isolate",
            method="POST",
            headers={"X-Auth-Token": "token_invalido_123"},
            body={"ip": "10.0.0.1"}
        )
        assert code_bad_tok == 401, f"POST /api/isolate con token incorrecto debe retornar 401, retornó {code_bad_tok}"
        print("       -> POST /api/isolate con token incorrecto -> 401: OK")

        # POST /api/isolate con token correcto + IP inválida -> 4xx
        code_bad_ip, _, _ = _http_request(
            "http://127.0.0.1:38888/api/isolate",
            method="POST",
            headers={"X-Auth-Token": api1.api_token},
            body={"ip": "999.999.999.999"}
        )
        assert 400 <= code_bad_ip < 500, f"IP inválida debe retornar 4xx, retornó {code_bad_ip}"
        print(f"       -> POST /api/isolate con IP inválida -> {code_bad_ip}: OK")

        # POST /api/isolate con token correcto + IP válida -> 200
        code_iso_ok, hdrs_iso, _ = _http_request(
            "http://127.0.0.1:38888/api/isolate",
            method="POST",
            headers={"X-Auth-Token": api1.api_token},
            body={"ip": "10.0.0.55", "reason": "Prueba de integración"}
        )
        assert code_iso_ok == 200, f"POST /api/isolate válido debe retornar 200, retornó {code_iso_ok}"
        assert "access-control-allow-origin" not in {k.lower() for k in hdrs_iso}
        assert "10.0.0.55" in honeywall.get_snapshot()["isolated_ips"]
        print("       -> POST /api/isolate token válido + IP válida -> 200: OK")

        api1.stop()
    finally:
        if prev_env_token is not None:
            os.environ["HONEYGATE_API_TOKEN"] = prev_env_token

    print("[TEST] 7. Verificando ausencia total del token fijo antiguo en el repositorio...")
    forbidden = "hg_sec_" + "token"
    skip_dirs = {".git", ".gradle", "build", "__pycache__", "logs", ".kotlin", ".build-outputs"}
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

    # Cleanup
    engine.stop()
    print("\n\033[1;32m[✓] TODAS LAS PRUEBAS DE INTEGRACIÓN Y SEGURIDAD PASARON EXITOSAMENTE.\033[0m")


if __name__ == "__main__":
    run_tests()
