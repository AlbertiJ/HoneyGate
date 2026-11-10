#!/usr/bin/env python3
"""
================================================================================
UNDAHWOAR HONEYWALL: Framework Unificado de Decepción y Contención Perimetral
Lanzador Principal Integrado (Epoll Core + Honeywall + CLI + inotify + Web API)
================================================================================
"""

import os
import sys
import time
import signal
import logging

from undahwoar.honeywall_core import UndahwoarHoneywall, EpollNetworkEngine
from undahwoar.cli_console import InteractiveCLI
from undahwoar.forensic_monitor import ForensicAlertManager, DesktopNotificationDispatcher
from undahwoar.dashboard_api import AsyncDashboardServer

logger = logging.getLogger("HoneyGateMain")


def main():
    # Asegurar directorios de ejecución
    os.makedirs("logs", exist_ok=True)
    os.makedirs("modules", exist_ok=True)

    print("\033[1;36m[+] Iniciando Framework Defensivo HoneyGate (Non-Root User Space)...\033[0m")

    # 1. Instanciar Honeywall con callback para notificaciones de alerta inmediata
    def on_honeywall_alert(title: str, message: str, urgency: str):
        DesktopNotificationDispatcher.dispatch(title, message, urgency)

    honeywall = UndahwoarHoneywall(alert_callback=on_honeywall_alert)

    # 2. Inicializar Motor de Sockets epoll en Puertos Altos (>1024)
    # 2222 (SSH Simulado), 8080 (HTTP Simulado), 8443 (HTTPS Simulado)
    simulation_ports = [2222, 8080, 8443]
    epoll_engine = EpollNetworkEngine(ports=simulation_ports, honeywall=honeywall)
    epoll_engine.start_background()

    # 3. Inicializar Monitor Forense inotify para logs locales y cowrie.json
    log_targets = ["logs/honeywall.log", "logs/cowrie.json", "cowrie.json"]
    forensics = ForensicAlertManager(target_log_files=log_targets)
    forensics.start_background()

    # 4. Inicializar Servidor Web y API de Telemetría Asíncrona (127.0.0.1 seguro por defecto)
    web_api = AsyncDashboardServer(honeywall=honeywall, forensics=forensics, host="127.0.0.1", port=8888)
    web_api.start_background()

    # Manejador de señales de terminación
    def handle_shutdown(signum, frame):
        print("\n\033[1;33m[*] Señal de detención recibida. Limpiando descriptores...\033[0m")
        epoll_engine.stop()
        forensics.stop()
        web_api.stop()
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

    print("\033[1;32m[+] Framework Undahwoar finalizado correctamente.\033[0m")


if __name__ == "__main__":
    main()
