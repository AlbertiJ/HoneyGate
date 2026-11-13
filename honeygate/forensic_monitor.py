"""
================================================================================
HONEYGATE FORENSICS: Subsistema de Monitoreo Basado en Eventos inotify y Alertas
Llamadas Nativas al Kernel de Linux vía ctypes | Expresiones Regulares | notify-send
================================================================================
"""

import os
import re
import sys
import json
import time
import ctypes
import select
import struct
import logging
import threading
import subprocess
from typing import List, Tuple, Dict, Any, Optional, Callable

logger = logging.getLogger("HoneyGateForensics")

# Constantes del Kernel de Linux para inotify (definidas en <sys/inotify.h>)
IN_MODIFY = 0x00000002       # Archivo fue modificado
IN_ATTRIB = 0x00000004       # Metadatos cambiados (permisos, timestamps)
IN_CLOSE_WRITE = 0x00000008  # Archivo abierto para escritura fue cerrado
IN_MOVE_SELF = 0x00000800    # Archivo observado fue movido
IN_DELETE_SELF = 0x00000400  # Archivo observado fue eliminado
IN_NONBLOCK = 0x00000800     # Bandera para descriptor no bloqueante
IN_CLOEXEC = 0x00080000      # Cerrar descriptor al ejecutar execve

# Tamaño mínimo del encabezado struct inotify_event
# struct inotify_event { int wd; uint32_t mask; uint32_t cookie; uint32_t len; char name[]; }
EVENT_HEADER_FORMAT = "iIII"
EVENT_HEADER_SIZE = struct.calcsize(EVENT_HEADER_FORMAT)


class NativeInotifyWatcher:
    """
    Envoltorio de bajo nivel para las llamadas al sistema nativas inotify del kernel de Linux.
    Utiliza ctypes para interactuar directamente con libc.so.6 sin librerías externas pesadas.
    """
    def __init__(self):
        try:
            self.libc = ctypes.CDLL("libc.so.6", use_errno=True)
        except OSError:
            # Fallback para arquitecturas o entornos donde libc tiene otro enlace
            self.libc = ctypes.CDLL(None, use_errno=True)

        self._init1 = self.libc.inotify_init1
        self._init1.argtypes = [ctypes.c_int]
        self._init1.restype = ctypes.c_int

        self._add_watch = self.libc.inotify_add_watch
        self._add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self._add_watch.restype = ctypes.c_int

        self._rm_watch = self.libc.inotify_rm_watch
        self._rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
        self._rm_watch.restype = ctypes.c_int

        # Crear descriptor inotify en modo no bloqueante
        self.fd = self._init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"Error al inicializar inotify_init1 (errno={errno})")

        self.watch_descriptors: Dict[str, int] = {}
        logger.info(f"[INOTIFY-INIT] Descriptor inotify inicializado en kernel (FD={self.fd}).")

    def add_watch(self, path: str, mask: int = (IN_MODIFY | IN_CLOSE_WRITE)) -> int:
        """Registra un archivo o directorio para ser supervisado por inotify."""
        path_bytes = os.path.abspath(path).encode("utf-8")
        wd = self._add_watch(self.fd, path_bytes, mask)
        if wd < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"Error en inotify_add_watch para '{path}' (errno={errno})")
        self.watch_descriptors[path] = wd
        logger.info(f"[INOTIFY-WATCH] Vigilancia activa en '{path}' (WD={wd}, Mask=0x{mask:X}).")
        return wd

    def read_events(self) -> List[Tuple[int, int, str]]:
        """
        Lee eventos inotify disponibles en el descriptor sin bloquear.
        Retorna una lista de tuplas (wd, mask, name).
        """
        events = []
        try:
            raw_bytes = os.read(self.fd, 4096)
        except BlockingIOError:
            return events
        except OSError:
            return events

        offset = 0
        while offset + EVENT_HEADER_SIZE <= len(raw_bytes):
            wd, mask, cookie, length = struct.unpack_from(
                EVENT_HEADER_FORMAT, raw_bytes, offset
            )
            offset += EVENT_HEADER_SIZE
            name = ""
            if length > 0 and offset + length <= len(raw_bytes):
                name_bytes = raw_bytes[offset:offset + length].split(b"\x00", 1)[0]
                name = name_bytes.decode("utf-8", errors="ignore")
                offset += length
            events.append((wd, mask, name))
        return events

    def close(self):
        """Cierra el descriptor de inotify en el kernel."""
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1


class DesktopNotificationDispatcher:
    """
    Despachador de notificaciones gráficas de escritorio para Kali Linux.
    Ejecuta subprocesos nativos hacia la utilidad 'notify-send' del sistema.
    """
    @staticmethod
    def dispatch(title: str, message: str, urgency: str = "normal", icon: str = "security-high"):
        """
        Envía una notificación gráfica visual al escritorio de Kali Linux.
        Niveles de urgencia: 'low', 'normal', 'critical'.
        """
        try:
            # Comando nativo de Linux
            cmd = [
                "notify-send",
                "-u", urgency,
                "-a", "HoneyGate Honeywall",
                "-i", icon,
                title,
                message,
            ]
            # Ejecución en segundo plano sin bloquear el hilo forense
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            logger.info(f"[NOTIFY-SEND] Notificación despachada: [{urgency.upper()}] {title} - {message}")
        except FileNotFoundError:
            # En caso de entornos mínimos o WSL2 sin notify-send instalado
            logger.debug("[NOTIFY-SEND] 'notify-send' no disponible en este entorno gráfico.")
        except Exception as e:
            logger.debug(f"[NOTIFY-SEND] Error despachando notificación: {e}")


class ForensicAlertManager:
    """
    Analizador Forense en Tiempo Real.
    Supervisa logs mediante inotify, procesa líneas con expresiones regulares
    y despacha alertas visuales automáticas.
    """
    # Expresiones regulares para la identificación de incidentes críticos
    RE_FAILED_PASSWORD = re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
        re.IGNORECASE
    )
    RE_ACCEPTED_PASSWORD = re.compile(
        r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
        re.IGNORECASE
    )
    RE_HONEYWALL_CONTAINMENT = re.compile(
        r"\[CRITICAL\] \[HONEYGATE-CONTAINMENT\] IP=(?P<ip>\S+) .*? (?P<reason>.*)",
        re.IGNORECASE
    )

    def __init__(
        self,
        target_log_files: List[str],
        alert_history_limit: int = 200,
        storage: Optional[Any] = None,
    ):
        self.target_files = target_log_files
        self.history_limit = alert_history_limit
        self.storage = storage
        self.alerts_history: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        self.file_pointers: Dict[str, int] = {}
        self.inotify_watcher: Optional[NativeInotifyWatcher] = None
        self.is_running = False
        self.monitor_thread: Optional[threading.Thread] = None

    def initialize(self):
        """Prepara los archivos a vigilar y crea el descriptor inotify."""
        self.inotify_watcher = NativeInotifyWatcher()
        for file_path in self.target_files:
            abs_path = os.path.abspath(file_path)
            # Asegurar que el archivo exista para poder suscribir el watch
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            if not os.path.exists(abs_path):
                with open(abs_path, "a", encoding="utf-8") as f:
                    f.write(f"# Log forense inicializado: {time.ctime()}\n")

            # Posicionar el puntero al final del archivo para procesar únicamente eventos nuevos
            self.file_pointers[abs_path] = os.path.getsize(abs_path)
            self.inotify_watcher.add_watch(abs_path, mask=(IN_MODIFY | IN_CLOSE_WRITE))

    def start_background(self) -> threading.Thread:
        """Inicia el hilo supervisor de inotify de forma asíncrona."""
        self.is_running = True
        self.monitor_thread = threading.Thread(
            target=self._run_inotify_loop,
            name="HoneyGateForensicsThread",
            daemon=True
        )
        self.monitor_thread.start()
        return self.monitor_thread

    def _run_inotify_loop(self):
        """
        Bucle de eventos inotify sin consumo excesivo de CPU (espera pasiva en epoll/select).
        """
        self.initialize()
        poll_obj = select.epoll()
        poll_obj.register(self.inotify_watcher.fd, select.EPOLLIN)
        logger.info("[FORENSICS-LOOP] Monitor inotify activo en escucha de modificaciones de logs.")

        while self.is_running:
            try:
                # Esperar hasta 1 segundo por eventos inotify; sin busy-looping
                events = poll_obj.poll(timeout=1.0)
                if not events:
                    continue

                # Leer y drenar eventos inotify del kernel
                raw_events = self.inotify_watcher.read_events()
                for wd, mask, name in raw_events:
                    if mask & (IN_MODIFY | IN_CLOSE_WRITE):
                        self._process_modified_files()

            except Exception as e:
                logger.error(f"[FORENSICS-ERROR] Error en bucle inotify: {e}")

        poll_obj.close()
        if self.inotify_watcher:
            self.inotify_watcher.close()

    def _process_modified_files(self):
        """Lee únicamente los nuevos bytes añadidos a los archivos observados y aplica regex."""
        for file_path, last_pos in list(self.file_pointers.items()):
            if not os.path.exists(file_path):
                continue
            current_size = os.path.getsize(file_path)
            if current_size > last_pos:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(last_pos)
                        new_lines = f.readlines()
                        self.file_pointers[file_path] = f.tell()

                    for line in new_lines:
                        self.analyze_log_line(line.strip(), source=os.path.basename(file_path))
                except Exception as e:
                    logger.debug(f"Error procesando modificación en {file_path}: {e}")

    def analyze_log_line(self, line: str, source: str = "honeypot.log"):
        """
        Evalúa una línea de log contra los patrones forenses críticos y despacha alertas.
        """
        if not line:
            return

        # 1. Detección de Contención por Rate-Limiting en el Honeywall
        match_containment = self.RE_HONEYWALL_CONTAINMENT.search(line)
        if match_containment:
            ip = match_containment.group("ip")
            reason = match_containment.group("reason")
            self._register_alert(
                severity="critical",
                event_type="HONEYWALL_CONTAINMENT",
                title="ALERTA CRÍTICA: Pivoteo Detectado",
                message=f"IP atacante {ip} bloqueada por Honeywall: {reason}",
                data={"ip": ip, "reason": reason, "raw": line, "source": source}
            )
            return

        # 2. Detección de Falla de Autenticación ("Failed password")
        match_failed = self.RE_FAILED_PASSWORD.search(line)
        if match_failed:
            user = match_failed.group("user")
            ip = match_failed.group("ip")
            port = match_failed.group("port")
            self._register_alert(
                severity="normal",
                event_type="AUTH_FAILED",
                title="Intento de Acceso No Autorizado",
                message=f"Falla de contraseña para usuario '{user}' desde {ip}:{port}",
                data={"user": user, "ip": ip, "port": port, "raw": line, "source": source}
            )
            return

        # 3. Detección de Autenticación Aceptada ("Accepted password" - Compromiso o Decepción)
        match_accepted = self.RE_ACCEPTED_PASSWORD.search(line)
        if match_accepted:
            user = match_accepted.group("user")
            ip = match_accepted.group("ip")
            port = match_accepted.group("port")
            self._register_alert(
                severity="critical",
                event_type="AUTH_ACCEPTED",
                title="ALERTA DE SEGURIDAD: Sesión Iniciada",
                message=f"Autenticación aceptada para '{user}' desde {ip}:{port} en Honeypot",
                data={"user": user, "ip": ip, "port": port, "raw": line, "source": source}
            )
            return

        # 4. Formato JSON de Cowrie Honeypot
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                event_id = data.get("eventid", "")
                src_ip = data.get("src_ip", "UNKNOWN")
                if "login.failed" in event_id:
                    self._register_alert(
                        severity="normal",
                        event_type="COWRIE_LOGIN_FAILED",
                        title="Honeypot: Intento de Fuerza Bruta",
                        message=f"Credenciales inválidas desde {src_ip}: {data.get('username')}/{data.get('password')}",
                        data=data
                    )
                elif "login.success" in event_id:
                    self._register_alert(
                        severity="critical",
                        event_type="COWRIE_LOGIN_SUCCESS",
                        title="Honeypot: Intrusión Deceptiva",
                        message=f"Atacante ingresó al Honeypot desde {src_ip} con usuario {data.get('username')}",
                        data=data
                    )
            except Exception:
                pass

    def _register_alert(self, severity: str, event_type: str, title: str, message: str, data: Dict[str, Any]):
        """Almacena la alerta en el buffer y despacha la notificación visual a Kali."""
        alert_obj = {
            "timestamp": time.time(),
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": severity,
            "event_type": event_type,
            "title": title,
            "message": message,
            "data": data,
        }
        with self._lock:
            self.alerts_history.append(alert_obj)
            if len(self.alerts_history) > self.history_limit:
                self.alerts_history.pop(0)

        if self.storage is not None:
            src_ip = str(data.get("ip") or data.get("src_ip") or "")
            mitre = "T1110" if "FAILED" in event_type else ("T1078" if "ACCEPTED" in event_type or "SUCCESS" in event_type else "")
            self.storage.record_event(
                event_type=event_type,
                severity=severity,
                ip=src_ip,
                mitre_technique=mitre,
                description=f"{title}: {message}",
                metadata=data,
            )

        logger.warning(f"[FORENSIC-TRIGGER] [{severity.upper()}] {title}: {message}")

        # Despachar notificación gráfica con notify-send
        DesktopNotificationDispatcher.dispatch(
            title=title,
            message=message,
            urgency=severity,
            icon="security-high" if severity == "critical" else "dialog-warning"
        )

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retorna una copia thread-safe de las alertas más recientes."""
        with self._lock:
            return list(self.alerts_history[-limit:])

    def stop(self):
        """Detiene la vigilancia."""
        self.is_running = False
