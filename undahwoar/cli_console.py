"""
================================================================================
UNDAHWOAR CLI: Consola Interactiva Avanzada No Bloqueante
Módulo Concurrente Thread-Safe con Autocompletado Predictivo de 3 Niveles
Desarrollado para entornos Kali Linux (Terminal / WSL2)
================================================================================
"""

import os
import sys
import glob
import time
import queue
import socket
import struct
import logging
import threading
import subprocess
from typing import Optional, List, Dict, Any

# Intentar importar prompt_toolkit con degradación elegante a terminal interactivo
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.styles import Style
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.shortcuts import print_formatted_text
    from prompt_toolkit.history import InMemoryHistory
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False
    # Definición mínima de Completer para tipado estático
    class Completer:
        pass
    class Completion:
        pass

from undahwoar.honeywall_core import UndahwoarHoneywall

logger = logging.getLogger("UndahwoarCLI")


class UndahwoarDynamicCompleter(Completer):
    """
    Motor de Autocompletado Inteligente en Tiempo Real de Tres Niveles:
    1. Comandos de Gestión del Honeywall (status, honeywall-stats, isolate <ip>, logs, exit).
    2. Comandos de Auditoría del Sistema en Espacio de Usuario (/proc/net/tcp, /proc/net/arp, nmcli).
    3. Scripts de Laboratorio y Capacitación indexados dinámicamente desde ./modules/*.py.
    """
    def __init__(self, honeywall: UndahwoarHoneywall, modules_dir: str = "./modules"):
        self.honeywall = honeywall
        self.modules_dir = os.path.abspath(modules_dir)
        
        # 1. Diccionario de Comandos de Gestión y descripciones
        self.mgmt_commands = {
            "status": "Muestra estado del motor epoll y métricas en tiempo real",
            "honeywall-stats": "Despliega estadísticas del Honeywall y umbral de contención",
            "connections": "Lista todas las sesiones activas en puertos simulados con MAC/IP",
            "isolate": "Aísla perimetralmente una dirección IP expulsando sus conexiones",
            "unblock": "Remueve una IP de la lista negra de contención",
            "audit": "Ejecuta auditoría de red de espacio de usuario (/proc/net/tcp, /proc/net/arp)",
            "run-module": "Ejecuta un script de prueba o capacitación de ./modules/",
            "logs": "Muestra las últimas entradas del log forense",
            "clear": "Limpia la pantalla de la terminal",
            "help": "Muestra el manual de comandos defensivos",
            "exit": "Cierra la consola y finaliza el framework",
        }

        # 2. Rutas lógicas de auditoría de espacio de usuario (Non-Root)
        self.audit_targets = {
            "/proc/net/tcp": "Inspecciona la tabla de sockets TCP activos del kernel",
            "/proc/net/arp": "Muestra la tabla de resolución ARP y direcciones MAC",
            "/proc/net/dev": "Estadísticas de paquetes por interfaz de red física/virtual",
            "nmcli": "Auditoría de conexiones NetworkManager si está disponible",
            "ports": "Lista puertos altos en escucha por el Honeywall",
        }

    def get_completions(self, document, complete_event):
        """Genera sugerencias en tiempo real mientras el operador escribe en la consola."""
        text_before_cursor = document.text_before_cursor
        words = text_before_cursor.split()

        # Caso A: Cursor en el primer token -> Autocompletar Comandos de Gestión y Auditoría
        if len(words) == 0 or (len(words) == 1 and not text_before_cursor.endswith(" ")):
            prefix = words[0] if words else ""
            
            # Nivel 1: Comandos de Gestión
            for cmd, desc in self.mgmt_commands.items():
                if cmd.startswith(prefix.lower()):
                    yield Completion(cmd, start_position=-len(prefix), display=cmd, display_meta=f"[Gestión] {desc}")

            # Nivel 2: Comandos de Auditoría directa (/proc/...)
            for target, desc in self.audit_targets.items():
                if target.startswith(prefix):
                    yield Completion(target, start_position=-len(prefix), display=target, display_meta=f"[Kernel/Proc] {desc}")

        # Caso B: Autocompletado del segundo argumento dependiente del comando
        elif len(words) >= 1:
            first_cmd = words[0].lower()
            prefix = words[1] if len(words) == 2 and not text_before_cursor.endswith(" ") else ""

            # Nivel 1 (Sub-argumentos): 'isolate <ip>' -> Sugerir IPs de conexiones activas
            if first_cmd == "isolate":
                snapshot = self.honeywall.get_snapshot()
                active_ips = {s["ip"]: f"FD={s['fd']}, Port={s['port']}, Rate={s['outbound_rate_min']} req/m" 
                              for s in snapshot["active_sessions"]}
                for ip, meta in active_ips.items():
                    if ip.startswith(prefix):
                        yield Completion(ip, start_position=-len(prefix), display=ip, display_meta=f"[Activa] {meta}")

            # Nivel 1 (Sub-argumentos): 'unblock <ip>' -> Sugerir IPs actualmente aisladas
            elif first_cmd == "unblock":
                snapshot = self.honeywall.get_snapshot()
                for ip, info in snapshot["isolated_ips"].items():
                    if ip.startswith(prefix):
                        reason = info.get("reason", "Bloqueada")
                        yield Completion(ip, start_position=-len(prefix), display=ip, display_meta=f"[Aislada] {reason}")

            # Nivel 2: 'audit <target>' -> Sugerir /proc/net/tcp, etc.
            elif first_cmd == "audit":
                for target, desc in self.audit_targets.items():
                    if target.startswith(prefix):
                        yield Completion(target, start_position=-len(prefix), display=target, display_meta=f"[Audit] {desc}")

            # Nivel 3: 'run-module <script.py>' -> Indexación dinámica de ./modules/*.py
            elif first_cmd == "run-module":
                module_files = self._scan_modules_directory()
                for mod_name, file_path in module_files.items():
                    if mod_name.startswith(prefix) or file_path.startswith(prefix):
                        yield Completion(
                            mod_name,
                            start_position=-len(prefix),
                            display=mod_name,
                            display_meta=f"[Lab Script] {os.path.basename(file_path)}"
                        )

    def _scan_modules_directory(self) -> Dict[str, str]:
        """
        Escanea el directorio local ./modules/ en tiempo real.
        Garantiza que cualquier archivo .py agregado dinámicamente sea sugerido inmediatamente.
        """
        modules = {}
        if os.path.exists(self.modules_dir):
            for file_path in glob.glob(os.path.join(self.modules_dir, "*.py")):
                basename = os.path.basename(file_path)
                modules[basename] = file_path
                modules[f"./modules/{basename}"] = file_path
        return modules


class UserSpaceAuditHelper:
    """
    Herramienta de Auditoría de Red para Espacio de Usuario (Non-Root).
    Parsea directamente pseudoarchivos de /proc/net sin invocar herramientas externas que requieran root.
    """
    @staticmethod
    def parse_proc_net_tcp() -> List[Dict[str, Any]]:
        """
        Parsea /proc/net/tcp traduciendo IPs y puertos hexadecimales a formato legible humano.
        Identifica estados de conexión del socket (ESTABLISHED, LISTEN, TIME_WAIT).
        """
        states = {
            "01": "ESTABLISHED",
            "02": "SYN_SENT",
            "03": "SYN_RECV",
            "04": "FIN_WAIT1",
            "05": "FIN_WAIT2",
            "06": "TIME_WAIT",
            "07": "CLOSE",
            "08": "CLOSE_WAIT",
            "09": "LAST_ACK",
            "0A": "LISTEN",
            "0B": "CLOSING",
        }
        results = []
        try:
            with open("/proc/net/tcp", "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) >= 10:
                    local_ip, local_port = UserSpaceAuditHelper._hex_to_ip_port(parts[1])
                    remote_ip, remote_port = UserSpaceAuditHelper._hex_to_ip_port(parts[2])
                    st_hex = parts[3]
                    state = states.get(st_hex, f"UNKNOWN({st_hex})")
                    inode = parts[9]
                    results.append({
                        "local": f"{local_ip}:{local_port}",
                        "remote": f"{remote_ip}:{remote_port}",
                        "state": state,
                        "inode": inode,
                    })
        except Exception as e:
            logger.error(f"Error parseando /proc/net/tcp: {e}")
        return results

    @staticmethod
    def _hex_to_ip_port(hex_str: str) -> Tuple[str, int]:
        """Convierte una dirección '0100007F:0050' en ('127.0.0.1', 80)."""
        try:
            ip_hex, port_hex = hex_str.split(":")
            ip_int = int(ip_hex, 16)
            # Little-endian unpack para IPv4
            ip_str = socket.inet_ntoa(struct.pack("<L", ip_int))
            port_int = int(port_hex, 16)
            return ip_str, port_int
        except Exception:
            return "0.0.0.0", 0

    @staticmethod
    def parse_proc_net_arp() -> List[Dict[str, str]]:
        """Lee y estructura la tabla de resolución ARP local de /proc/net/arp."""
        entries = []
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    entries.append({
                        "ip": parts[0],
                        "hw_type": parts[1],
                        "flags": parts[2],
                        "mac": parts[3],
                        "mask": parts[4],
                        "device": parts[5],
                    })
        except Exception as e:
            logger.error(f"Error leyendo /proc/net/arp: {e}")
        return entries


class InteractiveCLI:
    """
    Consola Interactiva Avanzada No Bloqueante.
    Ejecutada concurrentemente en un hilo dedicado (threading.Thread).
    Comunica eventos de forma thread-safe mediante queue.Queue y cerrojos reentrantes.
    """
    def __init__(self, honeywall: UndahwoarHoneywall, epoll_engine=None):
        self.honeywall = honeywall
        self.epoll_engine = epoll_engine
        self.command_queue: queue.Queue = queue.Queue()
        self.is_running = False
        self.cli_thread: Optional[threading.Thread] = None
        self.completer = UndahwoarDynamicCompleter(honeywall)

    def start_in_background(self) -> threading.Thread:
        """Lanza la consola interactiva en un hilo secundario dedicado para no bloquear epoll."""
        self.is_running = True
        self.cli_thread = threading.Thread(
            target=self._run_cli_loop,
            name="UndahwoarCLIThread",
            daemon=True
        )
        self.cli_thread.start()
        return self.cli_thread

    def _run_cli_loop(self):
        """Bucle interactivo principal de la consola con prompt_toolkit y estilos Kali."""
        # Pequeña pausa inicial para permitir que el motor epoll inicialice sus descriptores
        time.sleep(0.3)
        self._print_banner()

        if PROMPT_TOOLKIT_AVAILABLE:
            self._run_prompt_toolkit_session()
        else:
            self._run_fallback_session()

    def _print_banner(self):
        """Despliega el banner defensivo en la terminal de Kali Linux."""
        banner = """
\033[1;36m╔══════════════════════════════════════════════════════════════════════════╗
║  \033[1;32mUNDAHWOAR DEFENSIVE HONEYWALL FRAMEWORK\033[1;36m - Kali Linux Deception Core  ║
║  \033[0;37mEdge-Triggered epoll | Non-Root User Space | Rate-Limiting Container   \033[1;36m║
╚══════════════════════════════════════════════════════════════════════════╝\033[0m
        """
        print(banner)
        print("\033[1;33m[*] Escribe 'help' para comandos o presiona [Tab] para autocompletado inteligente.\033[0m\n")

    def _get_bottom_toolbar(self):
        """Genera una barra de estado dinámica inferior con métricas activas."""
        snapshot = self.honeywall.get_snapshot()
        active_count = len(snapshot["active_sessions"])
        isolated_count = len(snapshot["isolated_ips"])
        violations = snapshot["stats"]["rate_limit_violations"]
        return HTML(
            f" <b><style fg='#00d4ff'>[UNDAHWOAR]</style></b> "
            f"Activas: <b><style fg='#00ff66'>{active_count}</style></b> | "
            f"Aisladas: <b><style fg='#ff3366'>{isolated_count}</style></b> | "
            f"Violaciones Rate-Limit: <b><style fg='#ffcc00'>{violations}</style></b> | "
            f"Límite: <b>10 req/min</b>"
        )

    def _run_prompt_toolkit_session(self):
        """Ejecuta la sesión avanzada de prompt_toolkit con colores e historial en memoria."""
        style = Style.from_dict({
            "prompt": "ansicyan bold",
            "bottom-toolbar": "bg:#111b24 fg:#ffffff",
            "completion-menu.completion": "bg:#1e293b fg:#e2e8f0",
            "completion-menu.completion.current": "bg:#0284c7 fg:#ffffff bold",
            "scrollbar.background": "bg:#0f172a",
            "scrollbar.button": "bg:#38bdf8",
        })

        session = PromptSession(
            history=InMemoryHistory(),
            completer=self.completer,
            style=style,
            bottom_toolbar=self._get_bottom_toolbar,
        )

        while self.is_running:
            try:
                user_input = session.prompt(HTML("<b><style fg='#00ff66'>undahwoar@kali</style></b>:<b><style fg='#00d4ff'>~#</style></b> "))
                cmd = user_input.strip()
                if not cmd:
                    continue

                if cmd.lower() in ("exit", "quit"):
                    print("\033[1;33m[*] Finalizando consola interactiva Undahwoar...\033[0m")
                    self.is_running = False
                    if self.epoll_engine:
                        self.epoll_engine.stop()
                    break

                self.execute_command(cmd)

            except (KeyboardInterrupt, EOFError):
                print("\n\033[1;33m[*] Interrupción recibida. Saliendo...\033[0m")
                self.is_running = False
                break
            except Exception as e:
                print(f"\033[1;31m[!] Error en consola: {e}\033[0m")

    def _run_fallback_session(self):
        """Modo de ejecución alternativo estándar en caso de no contar con prompt_toolkit."""
        while self.is_running:
            try:
                cmd = input("\033[1;32mundahwoar@kali\033[0m:\033[1;36m~#\033[0m ").strip()
                if not cmd:
                    continue
                if cmd.lower() in ("exit", "quit"):
                    self.is_running = False
                    break
                self.execute_command(cmd)
            except (KeyboardInterrupt, EOFError):
                self.is_running = False
                break

    def execute_command(self, cmd_line: str):
        """Interpreta y ejecuta los comandos interactivos de forma segura y thread-safe."""
        parts = cmd_line.split()
        if not parts:
            return
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "help":
            self._cmd_help()
        elif cmd == "status":
            self._cmd_status()
        elif cmd == "honeywall-stats":
            self._cmd_honeywall_stats()
        elif cmd == "connections":
            self._cmd_connections()
        elif cmd == "isolate":
            self._cmd_isolate(args)
        elif cmd == "unblock":
            self._cmd_unblock(args)
        elif cmd == "audit" or cmd.startswith("/proc/"):
            target = args[0] if (cmd == "audit" and args) else cmd
            self._cmd_audit(target)
        elif cmd == "run-module":
            self._cmd_run_module(args)
        elif cmd == "logs":
            self._cmd_logs(args)
        elif cmd == "clear":
            os.system("clear")
        else:
            print(f"\033[1;31m[!] Comando no reconocido: '{cmd}'. Escriba 'help' para la lista.\033[0m")

    def _cmd_help(self):
        print("\n\033[1;36m=== MANUAL DE COMANDOS UNDAHWOAR ===\033[0m")
        for c, d in self.completer.mgmt_commands.items():
            print(f"  \033[1;32m{c:<16}\033[0m : {d}")
        print("\n\033[1;33m[Auditoría en Espacio de Usuario]:\033[0m")
        for target, d in self.completer.audit_targets.items():
            print(f"  \033[1;34maudit {target:<10}\033[0m : {d}")
        print("\n\033[1;35m[Scripts de Laboratorio]:\033[0m")
        print("  \033[1;35mrun-module <file>\033[0m : Ejecuta módulos interactivos de ./modules/\n")

    def _cmd_status(self):
        snapshot = self.honeywall.get_snapshot()
        st = snapshot["stats"]
        print("\n\033[1;36m=== ESTADO DEL SISTEMA UNDAHWOAR ===\033[0m")
        print(f" • Conexiones Totales Históricas : \033[1;32m{st['total_connections']}\033[0m")
        print(f" • Conexiones Activas Ahora      : \033[1;33m{len(snapshot['active_sessions'])}\033[0m")
        print(f" • IPs Aisladas Perimetralmente  : \033[1;31m{len(snapshot['isolated_ips'])}\033[0m")
        print(f" • Violaciones de Rate-Limiting : \033[1;31m{st['rate_limit_violations']}\033[0m")
        print(f" • Tráfico Inbound Acumulado     : {st['bytes_in_total']} bytes")
        print(f" • Tráfico Outbound Acumulado    : {st['bytes_out_total']} bytes")
        if self.epoll_engine:
            print(f" • Puertos epoll en escucha      : \033[1;34m{self.epoll_engine.ports}\033[0m\n")

    def _cmd_honeywall_stats(self):
        snapshot = self.honeywall.get_snapshot()
        print("\n\033[1;36m=== TELEMETRÍA DEL HONEYWALL (UNDAHWOAR) ===\033[0m")
        print(f" • Umbral de Tasa Saliente Máxima: \033[1;31m{snapshot['max_outbound_threshold']} req/minuto\033[0m")
        print(f" • Acción ante Infracción        : \033[1;31mshutdown(SHUT_RDWR) + close() + Aislamiento de IP\033[0m")
        isolated = snapshot["isolated_ips"]
        if isolated:
            print("\n \033[1;31m[IPs Aisladas]:\033[0m")
            for ip, data in isolated.items():
                date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data['isolated_at']))
                print(f"   - {ip} | Motivo: {data['reason']} | Hora: {date_str}")
        else:
            print(" • Sin hosts en lista de aislamiento actualmente.")
        print()

    def _cmd_connections(self):
        snapshot = self.honeywall.get_snapshot()
        sessions = snapshot["active_sessions"]
        print(f"\n\033[1;36m=== SESIONES ACTIVAS ({len(sessions)}) ===\033[0m")
        if not sessions:
            print(" (No hay conexiones activas en este momento)\n")
            return

        header = f" {'FD':<4} {'IP ORIGEN':<16} {'PUERTO':<7} {'MAC':<18} {'TASA/MIN':<10} {'DURACIÓN'}"
        print("\033[1;37m" + header + "\033[0m")
        print("-" * len(header))
        for s in sessions:
            rate_color = "\033[1;31m" if s["outbound_rate_min"] >= 8 else "\033[1;32m"
            print(f" {s['fd']:<4} {s['ip']:<16} {s['port']:<7} {s['mac']:<18} "
                  f"{rate_color}{s['outbound_rate_min']:<10}\033[0m {s['duration_sec']}s")
        print()

    def _cmd_isolate(self, args: List[str]):
        if not args:
            print("\033[1;31m[!] Uso: isolate <IP_ADDRESS>\033[0m")
            return
        ip = args[0]
        self.honeywall.isolate_ip(ip, reason="Aislamiento manual forzado desde CLI")
        print(f"\033[1;32m[+] IP {ip} ha sido aislada exitosamente y sus descriptores cerrados.\033[0m")

    def _cmd_unblock(self, args: List[str]):
        if not args:
            print("\033[1;31m[!] Uso: unblock <IP_ADDRESS>\033[0m")
            return
        ip = args[0]
        if self.honeywall.unblock_ip(ip):
            print(f"\033[1;32m[+] IP {ip} removida de la lista negra de contención.\033[0m")
        else:
            print(f"\033[1;33m[*] La IP {ip} no se encontraba en la lista de aislamiento.\033[0m")

    def _cmd_audit(self, target: str):
        print(f"\n\033[1;34m[*] Ejecutando auditoría en espacio de usuario: {target}\033[0m")
        if target in ("/proc/net/tcp", "tcp"):
            results = UserSpaceAuditHelper.parse_proc_net_tcp()
            print(f" Conexiones TCP identificadas en el kernel: {len(results)}")
            for r in results[:15]:
                print(f"  [{r['state']:<11}] Local: {r['local']:<21} Remoto: {r['remote']:<21} Inode: {r['inode']}")
            if len(results) > 15:
                print(f"  ... y {len(results) - 15} conexiones más.")
        elif target in ("/proc/net/arp", "arp"):
            entries = UserSpaceAuditHelper.parse_proc_net_arp()
            print(f" Entradas en caché ARP: {len(entries)}")
            for e in entries:
                print(f"  IP: {e['ip']:<16} MAC: {e['mac']:<18} Interfaz: {e['device']}")
        elif target in ("ports",):
            if self.epoll_engine:
                print(f"  Puertos configurados en epoll: {self.epoll_engine.ports}")
        else:
            print(f"\033[1;31m[!] Objetivo de auditoría desconocido: {target}\033[0m")
        print()

    def _cmd_run_module(self, args: List[str]):
        if not args:
            print("\033[1;31m[!] Uso: run-module <nombre_script.py>\033[0m")
            return
        script_arg = args[0]
        if not script_arg.endswith(".py"):
            script_arg += ".py"
        
        # Resolver ruta en ./modules/
        if os.path.exists(script_arg):
            target_path = script_arg
        else:
            target_path = os.path.join(self.completer.modules_dir, script_arg)

        if not os.path.exists(target_path):
            print(f"\033[1;31m[!] Script no encontrado: {target_path}\033[0m")
            return

        print(f"\033[1;35m[*] Lanzando módulo de laboratorio: {target_path}...\033[0m")
        try:
            res = subprocess.run([sys.executable, target_path], capture_output=True, text=True, timeout=15)
            print("\033[1;37m--- Salida del Módulo ---")
            print(res.stdout)
            if res.stderr:
                print(f"\033[1;31m{res.stderr}\033[0m")
            print("-------------------------\033[0m")
        except subprocess.TimeoutExpired:
            print("\033[1;31m[!] El módulo excedió el tiempo límite de ejecución (15s).\033[0m")
        except Exception as e:
            print(f"\033[1;31m[!] Error ejecutando script: {e}\033[0m")

    def _cmd_logs(self, args: List[str]):
        log_file = "logs/honeywall.log"
        if not os.path.exists(log_file):
            print("No se registran logs forenses aún.")
            return
        n = int(args[0]) if args and args[0].isdigit() else 10
        print(f"\n\033[1;36m=== ÚLTIMOS {n} EVENTOS FORENSES ===\033[0m")
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines[-n:]:
                print("  " + line.strip())
        except Exception as e:
            print(f"Error leyendo log: {e}")
        print()
