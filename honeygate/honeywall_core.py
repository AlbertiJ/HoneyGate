"""
================================================================================
HONEYGATE HONEYWALL: Core Lógico de Red y Capa de Contención Perimetral
Framework de Decepción y Monitoreo Defensivo en Espacio de Usuario (Non-Root)
Compatible con Kali Linux y entornos WSL2
================================================================================
"""

import os
import sys
import time
import socket
import select
import selectors
import logging
import threading
from collections import deque
from typing import Dict, Tuple, Optional, List, Any, Callable

try:
    import fcntl
except ImportError:  # Windows no dispone de fcntl
    fcntl = None

from honeygate.deception import (
    EmulatedServiceEngine,
    MAX_COMMANDS_PER_SESSION,
    MAX_LINE_BYTES,
    MAX_SESSION_DURATION_SEC,
    build_mysql_err_packet,
    sanitize_captured_text,
)
from honeygate.mitre import get_mitre_engine

# Configuración de Logging Forense
# INVARIANTE 7: asegurar logs/ antes de configurar los handlers (evita fallar al importar)
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/honeywall.log", mode="a", encoding="utf-8")
    ]
)
logger = logging.getLogger("HoneyGateCore")


class HoneywallSecurityException(Exception):
    """Excepción generada ante violaciones de contención perimetral."""
    pass


class ConnectionSession:
    """
    Estructura de datos para representar una sesión activa capturada por el Honeywall.
    Trackea descriptores, timestamps, volumen de datos y tramas salientes.
    """
    def __init__(
        self,
        fd: int,
        sock: socket.socket,
        client_ip: str,
        client_port: int,
        mac: str = "UNKNOWN",
        dest_ip: str = "0.0.0.0",
        dest_port: int = 0,
        service: str = "unknown",
    ):
        self.fd: int = fd
        self.sock: socket.socket = sock
        self.client_ip: str = client_ip
        self.client_port: int = client_port
        self.mac: str = mac
        self.dest_ip: str = dest_ip
        self.dest_port: int = dest_port
        self.service: str = service
        self.storage_id: Optional[int] = None
        self.connected_at: float = time.time()
        self.last_activity: float = time.time()
        self.bytes_in: int = 0
        self.bytes_out: int = 0
        # Cola de marcas de tiempo de tramas/peticiones salientes para el cálculo de tasa por minuto
        self.outbound_timestamps: deque = deque()
        self.is_isolated: bool = False
        self.violation_reason: Optional[str] = None
        self.commands_count: int = 0
        self.honeytoken_touched: Optional[str] = None
        self.inbound_buffer: bytearray = bytearray()
        self.outbound_buffer: bytearray = bytearray()

    def record_outbound_frame(self, frame_size: int = 1) -> int:
        """
        Registra una trama saliente en la ventana deslizante de 60 segundos.
        Retorna la cantidad de peticiones/tramas emitidas en el último minuto.
        """
        now = time.time()
        self.last_activity = now
        self.bytes_out += frame_size
        self.outbound_timestamps.append(now)

        # Limpiar marcas de tiempo con antigüedad superior a 60 segundos
        cutoff = now - 60.0
        while self.outbound_timestamps and self.outbound_timestamps[0] < cutoff:
            self.outbound_timestamps.popleft()

        return len(self.outbound_timestamps)

    def get_outbound_rate_per_minute(self) -> int:
        """Calcula el número de tramas salientes en los últimos 60 segundos."""
        now = time.time()
        cutoff = now - 60.0
        while self.outbound_timestamps and self.outbound_timestamps[0] < cutoff:
            self.outbound_timestamps.popleft()
        return len(self.outbound_timestamps)


class HoneyGateHoneywall:
    """
    Controlador de Mitigación Perimetral (HoneyGate Honeywall).
    Supervisa conexiones activas, detecta pivoteo/escaneos, ejecuta rate-limiting estricto
    y acciona desconexiones forzadas mediante llamadas al sistema nativas de Linux.
    """
    MAX_OUTBOUND_PER_MINUTE: int = 10  # Umbral estricto contra pivoteo/escaneo

    def __init__(
        self,
        alert_callback: Optional[Callable[[str, str, str], None]] = None,
        storage: Optional[Any] = None,
        port_services: Optional[Dict[int, str]] = None,
    ):
        self._lock = threading.RLock()
        self.storage = storage
        self.port_services: Dict[int, str] = dict(port_services) if port_services else {}
        # Sesiones activas indexadas por descriptor de archivo (fd)
        self.sessions_by_fd: Dict[int, ConnectionSession] = {}
        # Mapeo de (IP, MAC) -> lista de descriptores de archivos asociados
        self.sessions_by_host: Dict[Tuple[str, str], List[int]] = {}
        # Lista negra de IPs aisladas perimetralmente
        self.isolated_ips: Dict[str, Dict[str, Any]] = {}
        # Historial de eventos y estadísticas
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "isolated_count": 0,
            "rate_limit_violations": 0,
            "bytes_in_total": 0,
            "bytes_out_total": 0,
        }
        self.alert_callback = alert_callback
        if self.storage is not None:
            self.isolated_ips = self.storage.list_isolated_ips()
            self.stats["isolated_count"] = len(self.isolated_ips)
            cfg = self.storage.get_config()
            self.MAX_OUTBOUND_PER_MINUTE = int(cfg.get("max_outbound_per_minute", self.MAX_OUTBOUND_PER_MINUTE))

    @staticmethod
    def resolve_mac_address(ip_address: str) -> str:
        """
        Obtiene la dirección MAC asociada a una IP consultando /proc/net/arp en espacio de usuario.
        Evita requerir privilegios de root (sudo).
        """
        try:
            if ip_address in ("127.0.0.1", "::1"):
                return "00:00:00:00:00:00"
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                lines = f.readlines()
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip_address:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            return mac
        except (OSError, IOError):
            pass
        return "UNKNOWN"

    def _service_for_port(self, port: int) -> str:
        if port in self.port_services:
            return self.port_services[port]
        mapping = {
            2222: "ssh",
            32222: "ssh",
            2323: "telnet",
            32323: "telnet",
            8080: "http",
            38080: "http",
            8443: "https",
            38443: "https",
            3306: "mysql",
            33306: "mysql",
        }
        return mapping.get(port, f"tcp/{port}" if port > 0 else "unknown")

    def register_connection(self, fd: int, sock: socket.socket, client_ip: str, client_port: int) -> ConnectionSession:
        """
        Registra una nueva conexión en el Honeywall indexándola por IP y MAC.
        Verifica inmediatamente si la IP de origen se encuentra en la lista de aislamiento.
        """
        with self._lock:
            mac = self.resolve_mac_address(client_ip)
            dest_ip = "0.0.0.0"
            dest_port = 0
            try:
                sock_addr = sock.getsockname()
                if isinstance(sock_addr, tuple) and len(sock_addr) >= 2:
                    dest_ip = str(sock_addr[0])
                    dest_port = int(sock_addr[1])
            except OSError:
                pass
            service = self._service_for_port(dest_port)

            # Si la IP ya estaba aislada por violaciones previas, expulsar de inmediato
            if client_ip in self.isolated_ips:
                logger.warning(
                    f"[HONEYGATE-DROP] Intento de conexión desde IP aislada: {client_ip}:{client_port} (MAC: {mac})."
                )
                if self.storage is not None:
                    self.storage.record_event(
                        event_type="ISOLATED_CONNECTION_DROPPED",
                        severity="warning",
                        ip=client_ip,
                        description=f"Conexión rechazada de IP aislada {client_ip}:{client_port} hacia {service}",
                        metadata={"client_port": client_port, "dest_port": dest_port, "service": service},
                    )
                self._force_disconnect_native(fd, sock, "IP en lista de aislamiento activo")
                raise HoneywallSecurityException(f"IP {client_ip} aislada previamente")

            session = ConnectionSession(
                fd, sock, client_ip, client_port, mac,
                dest_ip=dest_ip, dest_port=dest_port, service=service,
            )
            self.sessions_by_fd[fd] = session

            host_key = (client_ip, mac)
            if host_key not in self.sessions_by_host:
                self.sessions_by_host[host_key] = []
            self.sessions_by_host[host_key].append(fd)

            self.stats["total_connections"] += 1
            self.stats["active_connections"] = len(self.sessions_by_fd)

            if self.storage is not None:
                session.storage_id = self.storage.create_session(
                    ip=client_ip,
                    mac=mac,
                    client_port=client_port,
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    service=service,
                    fd=fd,
                    status="active",
                )
                self.storage.record_event(
                    event_type="CONNECTION_ACCEPTED",
                    severity="info",
                    session_id=session.storage_id,
                    device_id=f"net:{client_ip}:{mac}",
                    ip=client_ip,
                    description=f"Conexión registrada desde {client_ip}:{client_port} hacia {service} ({dest_port})",
                    metadata={"fd": fd, "dest_port": dest_port, "service": service},
                )

            logger.info(
                f"[HONEYWALL-ACCEPT] Conexión registrada: FD={fd} -> {client_ip}:{client_port} "
                f"[MAC: {mac}]. Total activas: {self.stats['active_connections']}"
            )
            return session

    def evaluate_outbound_traffic(self, fd: int, frame_size: int = 1) -> bool:
        """
        Evalúa el flujo de salida. Si la sesión supera 10 peticiones salientes por minuto,
        ejecuta la desconexión inmediata y el aislamiento perimetral.
        Retorna True si la sesión es legítima, o False si fue mitigada y cerrada.
        """
        with self._lock:
            session = self.sessions_by_fd.get(fd)
            if not session:
                return False

            outbound_rate = session.record_outbound_frame(frame_size)
            self.stats["bytes_out_total"] += frame_size

            # Verificación del umbral de tasa límite
            if outbound_rate > self.MAX_OUTBOUND_PER_MINUTE:
                self.stats["rate_limit_violations"] += 1
                violation_msg = (
                    f"Sesión excedió límite de seguridad: {outbound_rate} tramas/min "
                    f"(Máximo permitido: {self.MAX_OUTBOUND_PER_MINUTE}). Posible escaneo/pivoteo."
                )
                logger.error(
                    f"[CRITICAL] [HONEYGATE-CONTAINMENT] IP={session.client_ip} (FD={fd}) -> {violation_msg}"
                )

                # Aislar la IP globalmente
                self.isolate_ip(
                    session.client_ip,
                    reason=f"Exceso de tasa saliente ({outbound_rate} tramas/min)"
                )

                # Ejecutar desconexión forzada inmediata mediante syscalls nativas
                self.terminate_session(fd, reason=violation_msg)

                if self.alert_callback:
                    self.alert_callback(
                        "Alerta Crítica Honeywall",
                        f"IP {session.client_ip} aislada por pivoteo ({outbound_rate} req/min)",
                        "critical"
                    )
                return False

            return True

    def isolate_ip(self, ip_address: str, reason: str = "Aislamiento manual por operador"):
        """Aísla una dirección IP cerrando todas sus conexiones activas y bloqueando accesos futuros."""
        with self._lock:
            self.isolated_ips[ip_address] = {
                "isolated_at": time.time(),
                "reason": reason,
            }
            self.stats["isolated_count"] = len(self.isolated_ips)
            if self.storage is not None:
                self.storage.set_isolated_ip(ip_address, reason)
                mitre_id = (
                    get_mitre_engine().resolve_event("IP_ISOLATED_RATE_LIMIT")
                    if "tasa" in reason.lower()
                    else get_mitre_engine().resolve_event("IP_ISOLATED_MANUAL")
                )
                self.storage.record_event(
                    event_type="IP_ISOLATED",
                    severity="critical",
                    ip=ip_address,
                    mitre_technique=mitre_id,
                    description=f"IP {ip_address} aislada: {reason}",
                    metadata={"reason": reason},
                )
            logger.warning(f"[HONEYGATE-ISOLATE] IP {ip_address} agregada a lista de contención. Motivo: {reason}")

            # Desconectar todas las conexiones abiertas por esta IP
            fds_to_close = [
                s.fd for s in self.sessions_by_fd.values()
                if s.client_ip == ip_address
            ]
            for fd in fds_to_close:
                self.terminate_session(fd, reason=f"Aislamiento de host: {reason}")

    def unblock_ip(self, ip_address: str) -> bool:
        """Remueve una IP de la lista negra de aislamiento."""
        with self._lock:
            removed = False
            if ip_address in self.isolated_ips:
                del self.isolated_ips[ip_address]
                self.stats["isolated_count"] = len(self.isolated_ips)
                removed = True
            if self.storage is not None:
                removed = self.storage.remove_isolated_ip(ip_address) or removed
                if removed:
                    self.storage.record_event(
                        event_type="IP_UNBLOCKED",
                        severity="info",
                        ip=ip_address,
                        description=f"IP {ip_address} desbloqueada de la lista de contención",
                    )
            if removed:
                logger.info(f"[HONEYGATE-UNBLOCK] IP {ip_address} desbloqueada satisfactoriamente.")
            return removed

    def terminate_session(self, fd: int, reason: str = "Cierre estándar"):
        """
        Ejecuta el cierre controlado y forzado de una sesión con llamadas nativas de Linux.
        Invocando shutdown(SHUT_RDWR) y close() sobre el descriptor de socket.
        """
        with self._lock:
            session = self.sessions_by_fd.pop(fd, None)
            if not session:
                return

            host_key = (session.client_ip, session.mac)
            if host_key in self.sessions_by_host and fd in self.sessions_by_host[host_key]:
                self.sessions_by_host[host_key].remove(fd)
                if not self.sessions_by_host[host_key]:
                    del self.sessions_by_host[host_key]

            self.stats["active_connections"] = len(self.sessions_by_fd)
            session.is_isolated = True
            session.violation_reason = reason

            if self.storage is not None and session.storage_id is not None:
                final_status = "isolated" if session.client_ip in self.isolated_ips else "closed"
                self.storage.close_session(
                    session.storage_id,
                    bytes_in=session.bytes_in,
                    bytes_out=session.bytes_out,
                    status=final_status,
                )

            self._force_disconnect_native(fd, session.sock, reason)

    def _force_disconnect_native(self, fd: int, sock: socket.socket, reason: str):
        """
        Aplica las llamadas al sistema nativas de bajo nivel:
        shutdown(socket.SHUT_RDWR) y posterior cierre del descriptor.
        Maneja estrictamente OSError, BrokenPipeError y ConnectionResetError.
        """
        logger.info(f"[HONEYWALL-SHUTDOWN] Ejecutando shutdown nativo para FD={fd}. Razón: {reason}")
        try:
            # Syscall nativa de Linux para suspender lecturas y escrituras de socket
            sock.shutdown(socket.SHUT_RDWR)
        except (BrokenPipeError, ConnectionResetError):
            # La conexión ya fue interrumpida por el extremo remoto
            pass
        except OSError as e:
            # EBADF, ENOTCONN u otros errores normales en sockets no conectados
            logger.debug(f"[SHUTDOWN-DEBUG] Error no crítico en shutdown FD={fd}: {e}")
        finally:
            try:
                sock.close()
            except OSError as e:
                logger.debug(f"[CLOSE-DEBUG] Error en close FD={fd}: {e}")

    def get_snapshot(self) -> Dict[str, Any]:
        """Obtiene una instantánea thread-safe del estado actual del Honeywall."""
        with self._lock:
            active_list = []
            for s in self.sessions_by_fd.values():
                active_list.append({
                    "id": s.storage_id,
                    "fd": s.fd,
                    "ip": s.client_ip,
                    "port": s.client_port,
                    "dest_port": s.dest_port,
                    "service": s.service,
                    "mac": s.mac,
                    "connected_at": s.connected_at,
                    "duration_sec": round(time.time() - s.connected_at, 2),
                    "bytes_in": s.bytes_in,
                    "bytes_out": s.bytes_out,
                    "outbound_rate_min": s.get_outbound_rate_per_minute(),
                })
            mode = self.storage.get_config()["mode"] if self.storage is not None else 1
            return {
                "mode": mode,
                "stats": dict(self.stats),
                "active_sessions": active_list,
                "isolated_ips": dict(self.isolated_ips),
                "max_outbound_threshold": self.MAX_OUTBOUND_PER_MINUTE,
            }


class EpollNetworkEngine:
    """
    Motor de E/S Asíncrona de Bajo Nivel.
    Usa select.epoll Edge-Triggered (EPOLLET) y fcntl en Linux/WSL2, con fallback
    portable basado en selectors.DefaultSelector en Windows y macOS.
    """
    def __init__(
        self,
        ports: List[int],
        honeywall: HoneyGateHoneywall,
        host: Optional[str] = None,
        max_line_bytes: int = MAX_LINE_BYTES,
        max_commands_per_session: int = MAX_COMMANDS_PER_SESSION,
        max_session_duration_sec: float = MAX_SESSION_DURATION_SEC,
        force_portable_selector: bool = False,
    ):
        self.ports = ports
        self.honeywall = honeywall
        env_host = os.environ.get("HONEYGATE_EPOLL_HOST", "").strip()
        self.host = (host.strip() if isinstance(host, str) and host.strip() else (env_host or "127.0.0.1"))
        self.max_line_bytes = max(32, int(max_line_bytes))
        self.max_commands_per_session = max(1, int(max_commands_per_session))
        self.max_session_duration_sec = max(0.05, float(max_session_duration_sec))
        self.use_epoll = (
            (not force_portable_selector)
            and hasattr(select, "epoll")
            and hasattr(select, "EPOLLIN")
        )
        if self.use_epoll:
            self.epoll = select.epoll()
            self.selector = None
            self.backend_name = "epoll"
        else:
            self.epoll = None
            self.selector = selectors.DefaultSelector()
            self.backend_name = "selectors"
        self.server_sockets: Dict[int, socket.socket] = {}
        self._tracked_sockets: Dict[int, socket.socket] = {}
        self.is_running = False
        self.server_thread: Optional[threading.Thread] = None

    @staticmethod
    def set_socket_nonblocking(sock: socket.socket):
        """
        Configura el socket como no bloqueante usando fcntl en POSIX o setblocking(False) en Windows.
        """
        if fcntl is not None and hasattr(os, "O_NONBLOCK"):
            fd = sock.fileno()
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        else:
            sock.setblocking(False)

    def _register_socket(self, fd: int, sock: socket.socket, include_write: bool = False):
        self._tracked_sockets[fd] = sock
        if self.use_epoll:
            mask = select.EPOLLIN | select.EPOLLET | select.EPOLLPRI | select.EPOLLERR | select.EPOLLHUP
            if include_write:
                mask |= select.EPOLLOUT
            self.epoll.register(fd, mask)
        else:
            events = selectors.EVENT_READ | (selectors.EVENT_WRITE if include_write else 0)
            self.selector.register(sock, events, data=fd)

    def _modify_socket(self, fd: int, include_write: bool = False):
        if self.use_epoll:
            mask = select.EPOLLIN | select.EPOLLET | select.EPOLLERR | select.EPOLLHUP
            if not include_write:
                mask |= select.EPOLLPRI
            else:
                mask |= select.EPOLLOUT
            self.epoll.modify(fd, mask)
        else:
            sock = self._tracked_sockets.get(fd)
            if sock is not None:
                events = selectors.EVENT_READ | (selectors.EVENT_WRITE if include_write else 0)
                self.selector.modify(sock, events, data=fd)

    def _unregister_socket(self, fd: int):
        sock = self._tracked_sockets.pop(fd, None)
        if self.use_epoll:
            try:
                self.epoll.unregister(fd)
            except OSError:
                pass
        else:
            try:
                self.selector.unregister(fd)
            except (KeyError, ValueError, OSError):
                if sock is not None:
                    try:
                        self.selector.unregister(sock)
                    except (KeyError, ValueError, OSError):
                        pass

    def _prune_closed_selector_fds(self):
        if self.use_epoll or self.selector is None:
            return
        for fd, sock in list(self._tracked_sockets.items()):
            try:
                if sock.fileno() < 0:
                    self._unregister_socket(fd)
            except OSError:
                self._unregister_socket(fd)

    def _init_server_sockets(self):
        """Inicializa los sockets de escucha en puertos altos no privilegiados (>1024)."""
        for port in self.ports:
            if port <= 1024:
                raise ValueError(f"El puerto {port} requiere privilegios root. Use puertos altos (>1024).")

            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, port))
            server_sock.listen(128)

            self.set_socket_nonblocking(server_sock)

            server_fd = server_sock.fileno()
            self.server_sockets[server_fd] = server_sock

            self._register_socket(server_fd, server_sock, include_write=False)
            mode_label = "Edge-Triggered (epoll)" if self.use_epoll else "portable (selectors)"
            logger.info(f"[EPOLL-INIT] Escuchando en {self.host}:{port} (FD={server_fd}) en modo {mode_label}.")

    def _sweep_expired_sessions(self):
        """Cierra sesiones emuladas que superaron la duración máxima permitida."""
        now = time.time()
        with self.honeywall._lock:
            expired = [
                s for s in self.honeywall.sessions_by_fd.values()
                if (now - s.connected_at) > self.max_session_duration_sec
            ]
        for s in expired:
            if self.honeywall.storage is not None:
                self.honeywall.storage.record_event(
                    event_type="DECEPTION_SESSION_TIMEOUT",
                    severity="warning",
                    session_id=s.storage_id,
                    device_id=f"net:{s.client_ip}:{s.mac}",
                    ip=s.client_ip,
                    mitre_technique=get_mitre_engine().resolve_event("DECEPTION_SESSION_TIMEOUT"),
                    description=(
                        f"Sesión emulada #{s.storage_id or s.fd} cerrada por límite de duración "
                        f"({self.max_session_duration_sec}s) en {s.service}:{s.dest_port}"
                    ),
                    metadata={"service": s.service, "dest_port": s.dest_port},
                )
            if s.service not in ("http", "https"):
                try:
                    s.sock.send(b"Session timed out.\r\n")
                except OSError:
                    pass
            self._unregister_and_close(s.fd, "Duración máxima de sesión emulada alcanzada")

    def run_event_loop(self):
        """
        Bucle de eventos principal (epoll Edge-Triggered en Linux, selectors en Windows/macOS).
        """
        self._init_server_sockets()
        self.is_running = True
        logger.info(f"[EPOLL-LOOP] Bucle de red asíncrono ({self.backend_name}) iniciado.")

        try:
            while self.is_running:
                if self.use_epoll:
                    try:
                        events = self.epoll.poll(timeout=0.1)
                    except InterruptedError:
                        continue

                    self._sweep_expired_sessions()

                    for fd, event in events:
                        if fd in self.server_sockets:
                            self._handle_server_accept(fd)
                        elif event & (select.EPOLLHUP | select.EPOLLERR):
                            self._handle_client_error(fd)
                        elif event & select.EPOLLIN:
                            self._handle_client_read(fd)
                        elif event & select.EPOLLOUT:
                            self._handle_client_write(fd)
                else:
                    try:
                        events = self.selector.select(timeout=0.1)
                    except InterruptedError:
                        continue
                    except (OSError, ValueError):
                        self._prune_closed_selector_fds()
                        time.sleep(0.05)
                        continue

                    self._sweep_expired_sessions()

                    for key, mask in events:
                        fd = key.data
                        if fd in self.server_sockets:
                            self._handle_server_accept(fd)
                        else:
                            if mask & selectors.EVENT_READ:
                                self._handle_client_read(fd)
                            if (mask & selectors.EVENT_WRITE) and fd in self.honeywall.sessions_by_fd:
                                self._handle_client_write(fd)

        except Exception as e:
            logger.exception(f"[EPOLL-FATAL] Excepción imprevista en event loop: {e}")
        finally:
            self._cleanup()

    def _handle_server_accept(self, server_fd: int):
        """
        Acepta todas las conexiones entrantes en el socket servidor hasta vaciar la cola.
        """
        server_sock = self.server_sockets[server_fd]
        while True:
            try:
                client_sock, (client_ip, client_port) = server_sock.accept()
            except BlockingIOError:
                break
            except OSError:
                break

            self.set_socket_nonblocking(client_sock)
            client_fd = client_sock.fileno()

            try:
                session = self.honeywall.register_connection(client_fd, client_sock, client_ip, client_port)
                self._register_socket(client_fd, client_sock, include_write=False)

                # Enviar banner estático realista por servicio (sin revelar señuelo ni abrir red)
                banner = EmulatedServiceEngine.banner_for_service(session.service)
                if banner:
                    try:
                        client_sock.send(banner)
                        # Evaluar tráfico de salida en Honeywall
                        self.honeywall.evaluate_outbound_traffic(client_fd, frame_size=len(banner))
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        pass

            except HoneywallSecurityException:
                # La IP ya estaba en lista negra; socket ya fue cerrado por Honeywall
                pass

    def _send_deception_bytes(self, session: ConnectionSession, payload: bytes) -> bool:
        """Envía bytes de respuesta estática respetando el rate-limiter del Honeywall."""
        if not payload:
            return True
        client_fd = session.fd
        if not self.honeywall.evaluate_outbound_traffic(client_fd, frame_size=len(payload)):
            self._unregister_socket(client_fd)
            return False
        try:
            session.sock.send(payload)
        except BlockingIOError:
            try:
                self._modify_socket(client_fd, include_write=True)
            except (KeyError, ValueError, OSError):
                pass
        except (BrokenPipeError, ConnectionResetError, OSError):
            self._unregister_and_close(client_fd, "Error enviando respuesta emulada")
            return False
        return True

    def _dispatch_deception_line(self, session: ConnectionSession, raw_line: bytes) -> bool:
        """
        Evalúa una línea ya acotada mediante tabla fija (sin ejecutar ni abrir red saliente),
        registra el evento como texto plano sanitizado y aplica límites de comandos y duración.
        """
        now = time.time()
        if (now - session.connected_at) > self.max_session_duration_sec:
            if self.honeywall.storage is not None:
                self.honeywall.storage.record_event(
                    event_type="DECEPTION_SESSION_TIMEOUT",
                    severity="warning",
                    session_id=session.storage_id,
                    device_id=f"net:{session.client_ip}:{session.mac}",
                    ip=session.client_ip,
                    mitre_technique=get_mitre_engine().resolve_event("DECEPTION_SESSION_TIMEOUT"),
                    description=f"Sesión #{session.storage_id or session.fd} cerrada por timeout ({self.max_session_duration_sec}s)",
                    metadata={"service": session.service, "dest_port": session.dest_port},
                )
            if session.service not in ("http", "https"):
                self._send_deception_bytes(session, b"Session timed out.\r\n")
            self._unregister_and_close(session.fd, "Duración máxima de sesión excedida")
            return False

        if session.commands_count >= self.max_commands_per_session:
            if self.honeywall.storage is not None:
                self.honeywall.storage.record_event(
                    event_type="DECEPTION_COMMAND_LIMIT_EXCEEDED",
                    severity="warning",
                    session_id=session.storage_id,
                    device_id=f"net:{session.client_ip}:{session.mac}",
                    ip=session.client_ip,
                    mitre_technique=get_mitre_engine().resolve_event("DECEPTION_COMMAND_LIMIT_EXCEEDED"),
                    description=(
                        f"Límite de {self.max_commands_per_session} comandos alcanzado en "
                        f"{session.service}:{session.dest_port}"
                    ),
                    metadata={"service": session.service, "dest_port": session.dest_port},
                )
            if session.service not in ("http", "https"):
                self._send_deception_bytes(session, b"Maximum commands per session exceeded.\r\n")
            self._unregister_and_close(session.fd, "Límite de comandos por sesión alcanzado")
            return False

        session.commands_count += 1
        honeytokens: List[Dict[str, str]] = []
        if self.honeywall.storage is not None:
            honeytokens = self.honeywall.storage.get_config().get("honeytokens", [])

        response, evt_meta = EmulatedServiceEngine.evaluate_input(
            service=session.service,
            raw_line=raw_line,
            honeytokens=honeytokens,
        )

        captured_text = evt_meta.get("captured_text", "")
        touched_ht = evt_meta.get("honeytoken_touched")
        ev_type = evt_meta.get("event_type", "DECEPTION_COMMAND_CAPTURED")
        sev = evt_meta.get("severity", "normal")
        mitre = evt_meta.get("mitre_technique", "")

        if self.honeywall.storage is not None and (captured_text or session.service in ("http", "https", "mysql")):
            if touched_ht:
                prefix = f"Honeytoken ficticio '{touched_ht}' accedido"
            elif ev_type == "DECEPTION_EGRESS_BLOCKED":
                prefix = "Intento de conexión saliente o ejecución bloqueado en señuelo"
            elif session.service in ("http", "https"):
                prefix = "Sonda HTTP capturada en servicio emulado"
            else:
                prefix = "Entrada capturada en servicio emulado"

            desc = f"{prefix} ({session.service}:{session.dest_port}): {captured_text}".strip()
            self.honeywall.storage.record_event(
                event_type=ev_type,
                severity=sev,
                session_id=session.storage_id,
                device_id=f"net:{session.client_ip}:{session.mac}",
                ip=session.client_ip,
                mitre_technique=mitre,
                description=desc,
                metadata={
                    "service": session.service,
                    "dest_port": session.dest_port,
                    "command": captured_text,
                    "honeytoken_touched": touched_ht,
                },
            )
            if touched_ht and session.storage_id is not None:
                session.honeytoken_touched = touched_ht
                self.honeywall.storage.mark_session_honeytoken(session.storage_id, touched_ht)

        if self.honeywall.alert_callback:
            if touched_ht:
                self.honeywall.alert_callback(
                    "Honeytoken Ficticio Accedido",
                    f"IP {session.client_ip} tocó honeytoken '{touched_ht}' en {session.service}:{session.dest_port}",
                    "critical",
                )
            elif ev_type == "DECEPTION_EGRESS_BLOCKED":
                self.honeywall.alert_callback(
                    "Egreso Bloqueado en Señuelo",
                    f"IP {session.client_ip} intentó salida/ejecución bloqueada: {captured_text[:80]}",
                    "critical",
                )

        if not self._send_deception_bytes(session, response):
            return False

        if session.service in ("ssh", "telnet") and captured_text.strip().lower() in ("exit", "quit"):
            self._unregister_and_close(session.fd, "Cierre solicitado por cliente emulado")
            return False

        return True

    def _process_session_buffer(self, session: ConnectionSession) -> bool:
        """Aplica límite por línea y despacha entradas completas sin ejecutar ni abrir red."""
        if session.service in ("http", "https"):
            # Verificar que ninguna línea HTTP supere MAX_LINE_BYTES
            for part in bytes(session.inbound_buffer).split(b"\n"):
                if len(part.rstrip(b"\r")) > self.max_line_bytes:
                    clipped = sanitize_captured_text(part[:self.max_line_bytes], max_len=self.max_line_bytes)
                    if self.honeywall.storage is not None:
                        self.honeywall.storage.record_event(
                            event_type="DECEPTION_LINE_LIMIT_EXCEEDED",
                            severity="warning",
                            session_id=session.storage_id,
                            device_id=f"net:{session.client_ip}:{session.mac}",
                            ip=session.client_ip,
                            mitre_technique=get_mitre_engine().resolve_event("DECEPTION_LINE_LIMIT_EXCEEDED_HTTP"),
                            description=f"Línea HTTP excede {self.max_line_bytes} bytes: {clipped}",
                            metadata={
                                "service": session.service,
                                "dest_port": session.dest_port,
                                "command": clipped,
                            },
                        )
                    session.inbound_buffer.clear()
                    self._send_deception_bytes(
                        session,
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 27\r\nConnection: close\r\n\r\nLine length limit exceeded.",
                    )
                    self._unregister_and_close(session.fd, "Línea HTTP excede límite máximo")
                    return False

            end_idx = session.inbound_buffer.find(b"\r\n\r\n")
            sep_len = 4
            if end_idx == -1:
                end_idx = session.inbound_buffer.find(b"\n\n")
                sep_len = 2
            if end_idx == -1 and b"\n" in session.inbound_buffer:
                # Permitir línea simple `GET /ruta\n` cuando no se envían cabeceras adicionales
                first_nl = session.inbound_buffer.find(b"\n")
                first_line = bytes(session.inbound_buffer[:first_nl]).rstrip(b"\r")
                if b"HTTP/" not in first_line:
                    end_idx = first_nl
                    sep_len = 1

            if end_idx != -1:
                block = bytes(session.inbound_buffer[:end_idx])
                del session.inbound_buffer[:end_idx + sep_len]
                request_line = block.split(b"\n", 1)[0].rstrip(b"\r")
                keep = self._dispatch_deception_line(session, request_line)
                if keep:
                    self._unregister_and_close(session.fd, "Respuesta HTTP emulada completada")
                return False
            return True

        # Servicio MySQL emulado: soporta tramas binarias del protocolo (header 4B) y sondas de texto
        if session.service == "mysql":
            while len(session.inbound_buffer) >= 4:
                pkt_len = int.from_bytes(session.inbound_buffer[:3], "little")
                if pkt_len <= 0 or pkt_len > self.max_line_bytes:
                    break
                total_len = 4 + pkt_len
                if len(session.inbound_buffer) < total_len:
                    return True
                pkt_payload = bytes(session.inbound_buffer[4:total_len])
                del session.inbound_buffer[:total_len]
                if not self._dispatch_deception_line(session, pkt_payload):
                    return False

        # Servicios orientados a líneas (SSH, Telnet, sondas texto en MySQL, etc.)
        while b"\n" in session.inbound_buffer:
            nl_idx = session.inbound_buffer.find(b"\n")
            raw_line = bytes(session.inbound_buffer[:nl_idx]).rstrip(b"\r")
            del session.inbound_buffer[:nl_idx + 1]

            if len(raw_line) > self.max_line_bytes:
                clipped = sanitize_captured_text(raw_line[:self.max_line_bytes], max_len=self.max_line_bytes)
                if self.honeywall.storage is not None:
                    self.honeywall.storage.record_event(
                        event_type="DECEPTION_LINE_LIMIT_EXCEEDED",
                        severity="warning",
                        session_id=session.storage_id,
                        device_id=f"net:{session.client_ip}:{session.mac}",
                        ip=session.client_ip,
                        mitre_technique=get_mitre_engine().resolve_event("DECEPTION_LINE_LIMIT_EXCEEDED_SHELL"),
                        description=f"Línea recibida excede {self.max_line_bytes} bytes: {clipped}",
                        metadata={
                            "service": session.service,
                            "dest_port": session.dest_port,
                            "command": clipped,
                        },
                    )
                limit_payload = (
                    build_mysql_err_packet(1153, "08S01", "Got a packet bigger than max_allowed_packet", sequence_id=2)
                    if session.service == "mysql"
                    else b"Line length limit exceeded.\r\n"
                )
                if not self._send_deception_bytes(session, limit_payload):
                    return False
                continue

            if not self._dispatch_deception_line(session, raw_line):
                return False

        if len(session.inbound_buffer) > self.max_line_bytes:
            clipped = sanitize_captured_text(bytes(session.inbound_buffer[:self.max_line_bytes]), max_len=self.max_line_bytes)
            session.inbound_buffer.clear()
            if self.honeywall.storage is not None:
                self.honeywall.storage.record_event(
                    event_type="DECEPTION_LINE_LIMIT_EXCEEDED",
                    severity="warning",
                    session_id=session.storage_id,
                    device_id=f"net:{session.client_ip}:{session.mac}",
                    ip=session.client_ip,
                    mitre_technique=get_mitre_engine().resolve_event("DECEPTION_LINE_LIMIT_EXCEEDED_SHELL"),
                    description=f"Entrada sin salto de línea excede {self.max_line_bytes} bytes: {clipped}",
                    metadata={
                        "service": session.service,
                        "dest_port": session.dest_port,
                        "command": clipped,
                    },
                )
            limit_payload = (
                build_mysql_err_packet(1153, "08S01", "Got a packet bigger than max_allowed_packet", sequence_id=2)
                if session.service == "mysql"
                else b"Line length limit exceeded.\r\n"
            )
            return self._send_deception_bytes(session, limit_payload)

        return True

    def _handle_client_read(self, client_fd: int):
        """
        Lee datos del cliente hasta vaciar el buffer (EAGAIN) en modo Edge-Triggered.
        Procesa comandos en servicios emulados con límites estrictos y sin ejecución ni egresos.
        """
        session = self.honeywall.sessions_by_fd.get(client_fd)
        if not session:
            return

        while True:
            try:
                data = session.sock.recv(4096)
                if not data:
                    # Conexión cerrada por el extremo remoto
                    self._unregister_and_close(client_fd, "Conexión terminada por el cliente")
                    break

                session.bytes_in += len(data)
                self.honeywall.stats["bytes_in_total"] += len(data)
                session.last_activity = time.time()
                session.inbound_buffer.extend(data)

                if not self._process_session_buffer(session):
                    break

            except BlockingIOError:
                # Socket vacío en modo Edge-Triggered (EAGAIN); lectura completa
                break
            except (BrokenPipeError, ConnectionResetError) as e:
                self._unregister_and_close(client_fd, f"Falla de tubería o reseteo remoto: {e}")
                break
            except OSError as e:
                self._unregister_and_close(client_fd, f"Error del sistema operativo: {e}")
                break

    def _handle_client_write(self, client_fd: int):
        """Gestiona disponibilidad de escritura cuando se drena un buffer pendiente."""
        session = self.honeywall.sessions_by_fd.get(client_fd)
        if not session:
            return

        # Restablecer máscara para escuchar únicamente lecturas
        try:
            self._modify_socket(client_fd, include_write=False)
        except (KeyError, ValueError, OSError):
            pass

    def _handle_client_error(self, client_fd: int):
        """Gestiona errores críticos detectados por epoll (EPOLLERR, EPOLLHUP)."""
        self._unregister_and_close(client_fd, "Evento EPOLLHUP o EPOLLERR detectado")

    def _unregister_and_close(self, client_fd: int, reason: str):
        """Elimina el descriptor del multiplexor y delega la desconexión al Honeywall."""
        self._unregister_socket(client_fd)
        self.honeywall.terminate_session(client_fd, reason)

    def start_background(self) -> threading.Thread:
        """Inicia el motor de red en un hilo separado de forma asíncrona."""
        self.server_thread = threading.Thread(
            target=self.run_event_loop,
            name="HoneyGateEpollThread",
            daemon=True
        )
        self.server_thread.start()
        return self.server_thread

    def stop(self):
        """Detiene el bucle de eventos y libera los descriptores."""
        self.is_running = False
        self._cleanup()

    def _cleanup(self):
        """Cierra sockets de servidor y desmantela el multiplexor (epoll/selector)."""
        for fd, sock in list(self.server_sockets.items()):
            self._unregister_socket(fd)
            try:
                sock.close()
            except OSError:
                pass
        self.server_sockets.clear()
        self._tracked_sockets.clear()

        if self.epoll is not None:
            try:
                self.epoll.close()
            except OSError:
                pass
        if self.selector is not None:
            try:
                self.selector.close()
            except OSError:
                pass
        logger.info("[EPOLL-CLEANUP] Descriptores de sockets y multiplexor liberados.")
