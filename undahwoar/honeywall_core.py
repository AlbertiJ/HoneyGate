"""
================================================================================
UNDAHWOAR HONEYWALL: Core Lógico de Red y Capa de Contención Perimetral
Framework de Decepción y Monitoreo Defensivo en Espacio de Usuario (Non-Root)
Compatible con Kali Linux y entornos WSL2
================================================================================
"""

import os
import sys
import time
import fcntl
import socket
import select
import logging
import threading
from collections import deque
from typing import Dict, Tuple, Optional, List, Any, Callable

# Configuración de Logging Forense
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/honeywall.log", mode="a", encoding="utf-8")
    ]
)
logger = logging.getLogger("UndahwoarCore")


class HoneywallSecurityException(Exception):
    """Excepción generada ante violaciones de contención perimetral."""
    pass


class ConnectionSession:
    """
    Estructura de datos para representar una sesión activa capturada por el Honeywall.
    Trackea descriptores, timestamps, volumen de datos y tramas salientes.
    """
    def __init__(self, fd: int, sock: socket.socket, client_ip: str, client_port: int, mac: str = "UNKNOWN"):
        self.fd: int = fd
        self.sock: socket.socket = sock
        self.client_ip: str = client_ip
        self.client_port: int = client_port
        self.mac: str = mac
        self.connected_at: float = time.time()
        self.last_activity: float = time.time()
        self.bytes_in: int = 0
        self.bytes_out: int = 0
        # Cola de marcas de tiempo de tramas/peticiones salientes para el cálculo de tasa por minuto
        self.outbound_timestamps: deque = deque()
        self.is_isolated: bool = False
        self.violation_reason: Optional[str] = None
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


class UndahwoarHoneywall:
    """
    Controlador de Mitigación Perimetral (Undahwoar Honeywall).
    Supervisa conexiones activas, detecta pivoteo/escaneos, ejecuta rate-limiting estricto
    y acciona desconexiones forzadas mediante llamadas al sistema nativas de Linux.
    """
    MAX_OUTBOUND_PER_MINUTE: int = 10  # Umbral estricto contra pivoteo/escaneo

    def __init__(self, alert_callback: Optional[Callable[[str, str, str], None]] = None):
        self._lock = threading.RLock()
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

    def register_connection(self, fd: int, sock: socket.socket, client_ip: str, client_port: int) -> ConnectionSession:
        """
        Registra una nueva conexión en el Honeywall indexándola por IP y MAC.
        Verifica inmediatamente si la IP de origen se encuentra en la lista de aislamiento.
        """
        with self._lock:
            mac = self.resolve_mac_address(client_ip)
            
            # Si la IP ya estaba aislada por violaciones previas, expulsar de inmediato
            if client_ip in self.isolated_ips:
                logger.warning(
                    f"[UNDAHWOAR-DROP] Intento de conexión desde IP aislada: {client_ip}:{client_port} (MAC: {mac})."
                )
                self._force_disconnect_native(fd, sock, "IP en lista de aislamiento activo")
                raise HoneywallSecurityException(f"IP {client_ip} aislada previamente")

            session = ConnectionSession(fd, sock, client_ip, client_port, mac)
            self.sessions_by_fd[fd] = session

            host_key = (client_ip, mac)
            if host_key not in self.sessions_by_host:
                self.sessions_by_host[host_key] = []
            self.sessions_by_host[host_key].append(fd)

            self.stats["total_connections"] += 1
            self.stats["active_connections"] = len(self.sessions_by_fd)

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
                    f"[CRITICAL] [UNDAHWOAR-CONTAINMENT] IP={session.client_ip} (FD={fd}) -> {violation_msg}"
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
            logger.warning(f"[UNDAHWOAR-ISOLATE] IP {ip_address} agregada a lista de contención. Motivo: {reason}")

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
            if ip_address in self.isolated_ips:
                del self.isolated_ips[ip_address]
                self.stats["isolated_count"] = len(self.isolated_ips)
                logger.info(f"[UNDAHWOAR-UNBLOCK] IP {ip_address} desbloqueada satisfactoriamente.")
                return True
            return False

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
                    "fd": s.fd,
                    "ip": s.client_ip,
                    "port": s.client_port,
                    "mac": s.mac,
                    "connected_at": s.connected_at,
                    "duration_sec": round(time.time() - s.connected_at, 2),
                    "bytes_in": s.bytes_in,
                    "bytes_out": s.bytes_out,
                    "outbound_rate_min": s.get_outbound_rate_per_minute(),
                })
            return {
                "stats": dict(self.stats),
                "active_sessions": active_list,
                "isolated_ips": dict(self.isolated_ips),
                "max_outbound_threshold": self.MAX_OUTBOUND_PER_MINUTE,
            }


class EpollNetworkEngine:
    """
    Motor de E/S Asíncrona de Bajo Nivel basado en select.epoll con Edge-Triggered (EPOLLET).
    Gestiona servidores no bloqueantes en puertos altos (>1024) en espacio de usuario.
    """
    def __init__(self, ports: List[int], honeywall: UndahwoarHoneywall):
        self.ports = ports
        self.honeywall = honeywall
        self.epoll = select.epoll()
        self.server_sockets: Dict[int, socket.socket] = {}
        self.is_running = False
        self.server_thread: Optional[threading.Thread] = None

    @staticmethod
    def set_socket_nonblocking(sock: socket.socket):
        """
        Configura el socket como no bloqueante (O_NONBLOCK) mediante la biblioteca fcntl de Linux.
        Garantiza operaciones asíncronas puras sin colgar el bucle de eventos.
        """
        fd = sock.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def _init_server_sockets(self):
        """Inicializa los sockets de escucha en puertos altos no privilegiados (>1024)."""
        for port in self.ports:
            if port <= 1024:
                raise ValueError(f"El puerto {port} requiere privilegios root. Use puertos altos (>1024).")

            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Reutilización rápida de dirección y puerto a nivel kernel (SO_REUSEADDR)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(("0.0.0.0", port))
            server_sock.listen(128)
            
            # Aplicar O_NONBLOCK con fcntl
            self.set_socket_nonblocking(server_sock)

            server_fd = server_sock.fileno()
            self.server_sockets[server_fd] = server_sock

            # Registrar en epoll con Edge-Triggered (EPOLLET) y EPOLLIN
            self.epoll.register(
                server_fd,
                select.EPOLLIN | select.EPOLLET | select.EPOLLPRI | select.EPOLLERR | select.EPOLLHUP
            )
            logger.info(f"[EPOLL-INIT] Escuchando en 0.0.0.0:{port} (FD={server_fd}) en modo Edge-Triggered.")

    def run_event_loop(self):
        """
        Bucle de eventos principal epoll (Edge-Triggered).
        Procesa eventos I/O asíncronos y atiende descargas de buffers hasta agotar EAGAIN.
        """
        self._init_server_sockets()
        self.is_running = True
        logger.info("[EPOLL-LOOP] Bucle de red asíncrono Edge-Triggered iniciado.")

        try:
            while self.is_running:
                try:
                    events = self.epoll.poll(timeout=0.5)
                except InterruptedError:
                    continue

                for fd, event in events:
                    # 1. Eventos en sockets de escucha del servidor (Nuevas conexiones entrantes)
                    if fd in self.server_sockets:
                        self._handle_server_accept(fd)

                    # 2. Eventos de error o desconexión en clientes (EPOLLHUP / EPOLLERR)
                    elif event & (select.EPOLLHUP | select.EPOLLERR):
                        self._handle_client_error(fd)

                    # 3. Datos listos para lectura (EPOLLIN)
                    elif event & select.EPOLLIN:
                        self._handle_client_read(fd)

                    # 4. Datos listos para escritura (EPOLLOUT)
                    elif event & select.EPOLLOUT:
                        self._handle_client_write(fd)

        except Exception as e:
            logger.exception(f"[EPOLL-FATAL] Excepción imprevista en event loop: {e}")
        finally:
            self._cleanup()

    def _handle_server_accept(self, server_fd: int):
        """
        Acepta todas las conexiones entrantes en el socket servidor hasta vaciar la cola (EAGAIN),
        como exige la semántica Edge-Triggered de epoll.
        """
        server_sock = self.server_sockets[server_fd]
        while True:
            try:
                client_sock, (client_ip, client_port) = server_sock.accept()
            except (BlockingIOError, socket.error) as e:
                # En modo Edge-Triggered, EAGAIN / EWOULDBLOCK indica que no quedan conexiones pendientes
                break

            # Configurar descriptor cliente inmediatamente como no bloqueante mediante fcntl
            self.set_socket_nonblocking(client_sock)
            client_fd = client_sock.fileno()

            try:
                # Registrar sesión en el Honeywall perimetral
                self.honeywall.register_connection(client_fd, client_sock, client_ip, client_port)

                # Registrar en epoll en modo Edge-Triggered
                self.epoll.register(
                    client_fd,
                    select.EPOLLIN | select.EPOLLET | select.EPOLLPRI | select.EPOLLERR | select.EPOLLHUP
                )

                # Enviar banner de bienvenida engañoso (Honeypot Deception Banner)
                banner = f"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2 (Undahwoar Deception Emulated)\r\n"
                try:
                    client_sock.send(banner.encode("utf-8"))
                    # Evaluar tráfico de salida en Honeywall
                    self.honeywall.evaluate_outbound_traffic(client_fd, frame_size=len(banner))
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass

            except HoneywallSecurityException:
                # La IP ya estaba en lista negra; socket ya fue cerrado por Honeywall
                pass

    def _handle_client_read(self, client_fd: int):
        """
        Lee datos del cliente hasta vaciar el buffer (EAGAIN) en modo Edge-Triggered.
        Procesa comandos simulados y alimenta el Honeypot.
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

                # Simular respuesta de servicio de decepción (Interactive Deception Echo)
                response = self._generate_deception_response(session, data)
                if response:
                    # Evaluar si la trama saliente respeta el umbral de contención perimetral
                    if self.honeywall.evaluate_outbound_traffic(client_fd, frame_size=len(response)):
                        try:
                            session.sock.send(response)
                        except (BlockingIOError, socket.error):
                            # Si el socket no está listo para escribir, registrar EPOLLOUT
                            self.epoll.modify(
                                client_fd,
                                select.EPOLLIN | select.EPOLLOUT | select.EPOLLET | select.EPOLLHUP | select.EPOLLERR
                            )
                    else:
                        # Sesión mitigada por exceder límite de peticiones salientes
                        try:
                            self.epoll.unregister(client_fd)
                        except OSError:
                            pass
                        break

            except (BlockingIOError, socket.error):
                # Socket vacío en modo Edge-Triggered (EAGAIN); lectura completa
                break
            except (BrokenPipeError, ConnectionResetError) as e:
                self._unregister_and_close(client_fd, f"Falla de tubería o reseteo remoto: {e}")
                break
            except OSError as e:
                self._unregister_and_close(client_fd, f"Error del sistema operativo: {e}")
                break

    def _handle_client_write(self, client_fd: int):
        """Gestiona el evento EPOLLOUT cuando el socket está disponible para drenar buffers pendientes."""
        session = self.honeywall.sessions_by_fd.get(client_fd)
        if not session:
            return

        # Restablecer máscara para escuchar únicamente lecturas
        try:
            self.epoll.modify(
                client_fd,
                select.EPOLLIN | select.EPOLLET | select.EPOLLPRI | select.EPOLLERR | select.EPOLLHUP
            )
        except OSError:
            pass

    def _handle_client_error(self, client_fd: int):
        """Gestiona errores críticos detectados por epoll (EPOLLERR, EPOLLHUP)."""
        self._unregister_and_close(client_fd, "Evento EPOLLHUP o EPOLLERR detectado")

    def _unregister_and_close(self, client_fd: int, reason: str):
        """Elimina el descriptor de epoll y delega la desconexión al Honeywall."""
        try:
            self.epoll.unregister(client_fd)
        except OSError:
            pass
        self.honeywall.terminate_session(client_fd, reason)

    @staticmethod
    def _generate_deception_response(session: ConnectionSession, raw_data: bytes) -> bytes:
        """Genera respuestas simuladas realistas para interactuar con atacantes o escáneres."""
        text = raw_data.decode("utf-8", errors="ignore").strip()
        logger.debug(f"[DECEPTION-PAYLOAD] IP={session.client_ip}:{session.client_port} -> {text!r}")
        
        # Simulación de respuesta a escaneos o peticiones HTTP/SSH
        if text.startswith("GET ") or text.startswith("POST "):
            return (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: Apache/2.4.57 (Debian)\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 26\r\n\r\n"
                b"Undahwoar Honeypot Active\n"
            )
        elif "id" in text or "whoami" in text:
            return b"uid=1001(guest) gid=1001(guest) groups=1001(guest)\r\n"
        elif "uname" in text:
            return b"Linux kali-lab 6.6.9-amd64 #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\r\n"
        else:
            return b"Access denied. Undahwoar security monitoring in progress.\r\n"

    def start_background(self) -> threading.Thread:
        """Inicia el motor de red en un hilo separado de forma asíncrona."""
        self.server_thread = threading.Thread(
            target=self.run_event_loop,
            name="UndahwoarEpollThread",
            daemon=True
        )
        self.server_thread.start()
        return self.server_thread

    def stop(self):
        """Detiene el bucle epoll y libera los descriptores."""
        self.is_running = False
        self._cleanup()

    def _cleanup(self):
        """Cierra sockets de servidor y desmantela el descriptor de epoll."""
        for fd, sock in list(self.server_sockets.items()):
            try:
                self.epoll.unregister(fd)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        self.server_sockets.clear()

        try:
            self.epoll.close()
        except OSError:
            pass
        logger.info("[EPOLL-CLEANUP] Descriptores de sockets y epoll liberados.")
