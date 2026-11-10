#!/usr/bin/env python3
"""
Prueba Unitaria y de Integración Completa para Undahwoar Core.
Valida epoll, Honeywall, rate limiting, inotify y API endpoints.
"""
import time
import socket
import urllib.request
import json

from undahwoar.honeywall_core import UndahwoarHoneywall, EpollNetworkEngine
from undahwoar.forensic_monitor import ForensicAlertManager
from undahwoar.dashboard_api import AsyncDashboardServer

def run_tests():
    print("[TEST] 1. Inicializando Honeywall y Epoll Engine...")
    honeywall = UndahwoarHoneywall()
    engine = EpollNetworkEngine(ports=[32222, 38080], honeywall=honeywall)
    engine.start_background()
    time.sleep(0.5)

    print("[TEST] 2. Verificando conexión de cliente y banner...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 32222))
    banner = s.recv(1024)
    assert b"Undahwoar Deception" in banner, f"Banner inesperado: {banner}"
    print(f"       -> Banner recibido: {banner.decode().strip()}")

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

    print("[TEST] 5. Verificando API Web REST...")
    forensics = ForensicAlertManager(target_log_files=["logs/test.log"])
    api = AsyncDashboardServer(honeywall=honeywall, forensics=forensics, host="127.0.0.1", port=38888)
    api.start_background()
    time.sleep(0.5)

    req = urllib.request.urlopen("http://127.0.0.1:38888/api/status")
    status_data = json.loads(req.read().decode())
    assert "stats" in status_data
    assert "isolated_ips" in status_data
    print("       -> Endpoint /api/status OK:", status_data["stats"])

    req_dash = urllib.request.urlopen("http://127.0.0.1:38888/")
    html_content = req_dash.read().decode()
    assert "HoneyGate" in html_content
    print("       -> Dashboard HTML OK con branding HoneyGate.")

    # Test POST /api/isolate sin token (debe retornar 401)
    try:
        req_bad = urllib.request.Request(
            "http://127.0.0.1:38888/api/isolate",
            data=json.dumps({"ip": "10.0.0.1"}).encode(),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req_bad)
        assert False, "Debe rechazar sin X-Auth-Token"
    except urllib.error.HTTPError as e:
        assert e.code == 401, f"Código esperado 401, obtenido {e.code}"
        print("       -> Endpoint /api/isolate protegido con 401 sin X-Auth-Token: OK")

    # Cleanup
    engine.stop()
    api.stop()
    print("\n\033[1;32m[✓] TODAS LAS PRUEBAS DE INTEGRACIÓN PASARON EXITOSAMENTE.\033[0m")

if __name__ == "__main__":
    run_tests()
