#!/usr/bin/env python3
"""
================================================================================
HONEYGATE HONEYWALL: Framework Unificado de Decepción y Contención Perimetral
Lanzador Principal Integrado (Epoll Core + Honeywall + CLI + inotify + Web API)
================================================================================
"""

import os
import sys
import time
import signal
import logging

from honeygate.honeywall_core import HoneyGateHoneywall, EpollNetworkEngine
from honeygate.cli_console import InteractiveCLI
from honeygate.forensic_monitor import ForensicAlertManager, DesktopNotificationDispatcher
from honeygate.dashboard_api import AsyncDashboardServer
from honeygate.portal import AsyncPortalServer
from honeygate.storage import HoneyGateStorage

logger = logging.getLogger("HoneyGateMain")


def main():
    # Asegurar directorios de ejecución
    os.makedirs("logs", exist_ok=True)
    os.makedirs("modules", exist_ok=True)
    os.makedirs("data", exist_ok=True)

    print("\033[1;36m[+] Iniciando Framework Defensivo HoneyGate (Non-Root User Space)...\033[0m")

    # 0. Capa de persistencia única en SQLite
    storage = HoneyGateStorage(db_path="data/honeygate.db")

    # 1. Instanciar Honeywall con callback para notificaciones de alerta inmediata
    def on_honeywall_alert(title: str, message: str, urgency: str):
        DesktopNotificationDispatcher.dispatch(title, message, urgency)

    honeywall = HoneyGateHoneywall(alert_callback=on_honeywall_alert, storage=storage)

    # 2. Inicializar Motor de Sockets epoll en Puertos Altos (>1024) en 127.0.0.1 por defecto
    # 2222 (SSH), 2323 (Telnet), 8080 (HTTP), 8443 (HTTPS), 3306 (MySQL)
    epoll_host = os.environ.get("HONEYGATE_EPOLL_HOST", "127.0.0.1").strip() or "127.0.0.1"
    simulation_ports = [2222, 2323, 8080, 8443, 3306]
    epoll_engine = EpollNetworkEngine(ports=simulation_ports, honeywall=honeywall, host=epoll_host)
    epoll_engine.start_background()

    # 3. Inicializar Monitor Forense inotify para logs locales y cowrie.json
    log_targets = ["logs/honeywall.log", "logs/cowrie.json", "cowrie.json"]
    forensics = ForensicAlertManager(target_log_files=log_targets, storage=storage)
    forensics.start_background()

    # 4. Inicializar Servidor Web y API de Telemetría Asíncrona (127.0.0.1 seguro por defecto)
    api_host = os.environ.get("HONEYGATE_API_HOST", "127.0.0.1").strip() or "127.0.0.1"
    api_port = int(os.environ.get("HONEYGATE_API_PORT", "8888"))
    web_api = AsyncDashboardServer(
        honeywall=honeywall,
        forensics=forensics,
        host=api_host,
        port=api_port,
        storage=storage,
    )
    web_api.start_background()

    # 4b. Portal Cautivo Modo 1 en puerto independiente (sin acceso a token ni /api/*)
    portal_host = os.environ.get("HONEYGATE_PORTAL_HOST", "127.0.0.1").strip() or "127.0.0.1"
    portal_port = int(os.environ.get("HONEYGATE_PORTAL_PORT", "8090"))
    if portal_port == api_port:
        raise ValueError("El puerto del portal cautivo debe ser distinto al del panel de administración")
    portal_server = AsyncPortalServer(
        storage=storage,
        host=portal_host,
        port=portal_port,
        alert_callback=on_honeywall_alert,
    )
    portal_server.start_background()

    # Manejador de señales de terminación
    def handle_shutdown(signum, frame):
        print("\n\033[1;33m[*] Señal de detención recibida. Limpiando descriptores...\033[0m")
        epoll_engine.stop()
        forensics.stop()
        portal_server.stop()
        web_api.stop()
        storage.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    # 5. Iniciar Consola Interactiva Avanzada CLI en Hilo Secundario
    cli = InteractiveCLI(honeywall=honeywall, epoll_engine=epoll_engine)
    cli_thread = cli.start_in_background()

    # Mantener el proceso principal activo esperando la finalización del hilo CLI
    try:
        while cli.is_running and cli_thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        handle_shutdown(None, None)

    print("\033[1;32m[+] Framework HoneyGate finalizado correctamente.\033[0m")


if __name__ == "__main__":
    main()
