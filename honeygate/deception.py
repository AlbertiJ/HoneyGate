"""
================================================================================
HONEYGATE DECEPTION: Servicios Emulados Seguros, Honeytokens y Plantilla CSP
- CERO ejecución de entrada del atacante (sin subprocesos ni evaluación dinámica).
- CERO conexiones salientes y CERO resolución DNS de nombres del atacante.
- Respuestas exclusivamente desde tablas fijas + honeytokens ficticios del operador.
- Límites estrictos por línea, comandos por sesión y duración de sesión.
================================================================================
"""

import os
import re
import json
import struct
from typing import Any, Dict, List, Optional, Tuple

from honeygate.mitre import get_mitre_engine

MAX_LINE_BYTES = 512
MAX_COMMANDS_PER_SESSION = 20
MAX_SESSION_DURATION_SEC = 120.0

# Perfil único unificado del host emulado (Debian 12 / Bookworm)
HOST_PROFILE: Dict[str, str] = {
    "os_name": "Debian GNU/Linux 12 (bookworm)",
    "os_short": "Debian 12",
    "hostname": "srv-app-02",
    "kernel_release": "6.1.0-26-amd64",
    "uname_full": "Linux srv-app-02 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64 GNU/Linux",
    "ssh_banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
    "telnet_banner": "Debian GNU/Linux 12 (bookworm) srv-app-02\r\nlogin: ",
    "http_server": "Apache/2.4.57 (Debian)",
    "mysql_server_version": "8.0.39-0+deb12u1",
}

DEFAULT_PORTAL_TEMPLATE: Dict[str, str] = {
    "title": "HoneyGate — Portal Cautivo",
    "subtitle": "Acceso nominal de red. No se solicitan ni almacenan contraseñas.",
    "footer": "",
}

# Dominios reales conocidos explícitamente prohibidos en honeytokens
REAL_KNOWN_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "google.com",
    "outlook.com",
    "hotmail.com",
    "hotmail.es",
    "live.com",
    "msn.com",
    "microsoft.com",
    "yahoo.com",
    "yahoo.es",
    "yahoo.com.ar",
    "icloud.com",
    "me.com",
    "apple.com",
    "proton.me",
    "protonmail.com",
    "aol.com",
    "zoho.com",
    "yandex.com",
    "gmx.com",
    "mail.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "amazon.com",
    "amazonaws.com",
    "cloudflare.com",
    "meta.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "x.com",
    "twitter.com",
    "linkedin.com",
    "mercadolibre.com",
    "mercadolibre.com.ar",
}

REAL_PUBLIC_DOMAIN_TLDS = (
    ".gov",
    ".gob",
    ".edu",
    ".mil",
    ".gov.ar",
    ".gob.ar",
    ".edu.ar",
    ".mil.ar",
)

# Dominios reservados exclusivamente ficticios permitidos cuando un honeytoken incluye correo/URL
RESERVED_FICTITIOUS_EXACT_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
}
RESERVED_FICTITIOUS_SUFFIXES = (
    ".invalid",
    ".test",
    ".example",
    ".localhost",
    ".local",
    ".internal",
    ".decoy",
)

RE_HONEYTOKEN_NAME = re.compile(r"^[A-Za-z0-9_.\-/]{1,64}$")
RE_EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,24})")
RE_URL_DOMAIN = re.compile(r"https?://([A-Za-z0-9.\-]+)", re.IGNORECASE)
RE_DOTTED_DOMAIN = re.compile(r"\b([A-Za-z0-9\-]+\.(?:com|net|org|io|ar|es|co|ai|app|dev|cloud|info|biz)(?:\.[a-z]{2})?)\b", re.IGNORECASE)

# Patrones rechazados en personalización de plantilla del portal (sin scripts ni recursos externos)
RE_FORBIDDEN_TEMPLATE_PATTERNS = re.compile(
    r"(<\s*/?\s*script\b|<\s*iframe\b|<\s*object\b|<\s*embed\b|<\s*link\b|"
    r"<\s*img\b|<\s*svg\b|<\s*style\b|javascript:|vbscript:|data:|"
    r"https?://|//|@import\b|\burl\s*\(|\bon[a-z]+\s*=|\bsrc\s*=|\bhref\s*=)",
    re.IGNORECASE,
)

# Tabla fija de respuestas de shell emulado (sin ejecución ni reflejo de entrada arbitraria)
FIXED_SHELL_RESPONSES: Dict[str, bytes] = {
    "id": b"uid=1001(guest) gid=1001(guest) groups=1001(guest)\r\n",
    "whoami": b"guest\r\n",
    "pwd": b"/home/guest\r\n",
    "hostname": (HOST_PROFILE["hostname"] + "\r\n").encode("ascii"),
    "uname": b"Linux\r\n",
    "uname -a": (HOST_PROFILE["uname_full"] + "\r\n").encode("ascii"),
    "uname -r": (HOST_PROFILE["kernel_release"] + "\r\n").encode("ascii"),
    "cat /etc/os-release": (
        b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\r\n'
        b'NAME="Debian GNU/Linux"\r\n'
        b'VERSION_ID="12"\r\n'
    ),
    "ls": b"backup_notes.txt  config.decoy  readme.txt\r\n",
    "ls -la": (
        b"total 24\r\n"
        b"drwxr-xr-x 2 guest guest 4096 Nov 14 09:00 .\r\n"
        b"drwxr-xr-x 3 root  root  4096 Nov 14 08:30 ..\r\n"
        b"-rw-r--r-- 1 guest guest  128 Nov 14 09:00 backup_notes.txt\r\n"
        b"-rw------- 1 guest guest  256 Nov 14 09:00 config.decoy\r\n"
        b"-rw-r--r-- 1 guest guest   64 Nov 14 08:45 readme.txt\r\n"
    ),
    "ps": (
        b"  PID TTY          TIME CMD\r\n"
        b"  412 pts/0    00:00:00 bash\r\n"
        b"  589 pts/0    00:00:00 ps\r\n"
    ),
    "ps aux": (
        b"USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
        b"root         1  0.0  0.1  22580  4120 ?        Ss   08:00   0:01 /sbin/init\r\n"
        b"www-data   310  0.0  0.2  54210  8192 ?        S    08:05   0:00 nginx: worker\r\n"
        b"guest      412  0.0  0.1   8412  3412 pts/0    Ss   09:00   0:00 -bash\r\n"
    ),
    "ifconfig": (
        b"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
        b"        inet 127.0.0.1  netmask 255.0.0.0\r\n"
    ),
    "ip addr": (
        b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\r\n"
        b"    inet 127.0.0.1/8 scope host lo\r\n"
    ),
    "cat readme.txt": b"Internal staging host srv-app-02.\r\n",
    "cat backup_notes.txt": b"Maintenance window: Sunday 02:00 UTC.\r\n",
    "help": b"GNU bash, version 5.2.15(1)-release (x86_64-pc-linux-gnu)\r\n",
    "exit": b"logout\r\n",
    "quit": b"logout\r\n",
}

FIXED_HTTP_RESPONSES: Dict[str, Tuple[int, bytes]] = {
    "/": (
        200,
        b"<html><head><title>Staging Node</title></head><body><h1>Staging Node Active</h1></body></html>\n",
    ),
    "/robots.txt": (
        200,
        b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n",
    ),
    "/admin": (
        401,
        b"Unauthorized: Authentication required.\n",
    ),
    "/login": (
        200,
        b"<html><head><title>Sign In</title></head><body><h1>Service Console</h1><p>Access restricted.</p></body></html>\n",
    ),
    "/api/v1/health": (
        200,
        b'{"status":"ok","node":"staging-02"}\n',
    ),
}

# Comandos de exfiltración / resolución / conexión saliente: nunca conectan ni resuelven DNS
FIXED_EGRESS_ERROR_BY_TOOL: Dict[str, bytes] = {
    "curl": b"curl: (7) Failed to connect: Network is unreachable\r\n",
    "wget": b"wget: unable to resolve host address\r\n",
    "nc": b"nc: connect failed: Network is unreachable\r\n",
    "ncat": b"Ncat: Network is unreachable.\r\n",
    "netcat": b"nc: connect failed: Network is unreachable\r\n",
    "ping": b"ping: Temporary failure in name resolution\r\n",
    "dig": b";; connection timed out; no servers could be reached\r\n",
    "nslookup": b";; connection timed out; no servers could be reached\r\n",
    "host": b";; connection timed out; no servers could be reached\r\n",
    "ssh": b"ssh: connect: Network is unreachable\r\n",
    "scp": b"ssh: connect: Network is unreachable\r\n",
    "ftp": b"ftp: connect: Network is unreachable\r\n",
    "telnet": b"telnet: Unable to connect to remote host: Network is unreachable\r\n",
    "python": b"Permission denied.\r\n",
    "python3": b"Permission denied.\r\n",
    "perl": b"Permission denied.\r\n",
    "php": b"Permission denied.\r\n",
    "ruby": b"Permission denied.\r\n",
}

SENSITIVE_HONEYTOKEN_FILENAMES = (
    ".env",
    "config.decoy",
    "credentials.txt",
    "backup_keys.txt",
    "secrets.json",
)


def sanitize_captured_text(raw_bytes: bytes, max_len: int = MAX_LINE_BYTES) -> str:
    """
    Convierte entrada del atacante a texto plano seguro (sin bytes de control ANSI/NUL)
    acotado a `max_len` caracteres para persistencia y visualización escapada.
    """
    decoded = raw_bytes.decode("utf-8", errors="replace")
    cleaned_chars: List[str] = []
    for ch in decoded:
        code = ord(ch)
        if code == 9:
            cleaned_chars.append(" ")
        elif code >= 32 and code != 127:
            cleaned_chars.append(ch)
    return "".join(cleaned_chars).strip()[:max_len]


def _is_fictitious_domain(domain: str) -> bool:
    d = domain.strip().lower().rstrip(".")
    if not d:
        return False
    if d in REAL_KNOWN_DOMAINS or any(d.endswith(tld) for tld in REAL_PUBLIC_DOMAIN_TLDS):
        return False
    if d in RESERVED_FICTITIOUS_EXACT_DOMAINS:
        return True
    return any(d.endswith(sfx) for sfx in RESERVED_FICTITIOUS_SUFFIXES)


def validate_honeytokens_config(raw_tokens: Any) -> Tuple[Optional[List[Dict[str, str]]], Optional[str]]:
    """
    Valida la lista de honeytokens definidos por el operador:
    - Estructura limpia: lista de hasta 20 objetos {name, value, kind?}.
    - Valores ficticios solamente; rechaza dominios reales conocidos y cualquier
      dirección/URL que no pertenezca a dominios ficticios reservados.
    """
    if not isinstance(raw_tokens, list):
        return None, "El campo 'honeytokens' debe ser una lista"
    if len(raw_tokens) > 20:
        return None, "Se permiten como máximo 20 honeytokens configurados"

    cleaned_list: List[Dict[str, str]] = []
    seen_names = set()
    allowed_kinds = {"decoy", "api_key", "credential", "email", "file"}

    for item in raw_tokens:
        if not isinstance(item, dict):
            return None, "Cada honeytoken debe ser un objeto JSON con 'name' y 'value'"
        extra = [k for k in item.keys() if k not in ("name", "value", "kind")]
        if extra:
            return None, f"Campos no permitidos en honeytoken: {', '.join(extra)}"

        name = item.get("name")
        value = item.get("value")
        kind = item.get("kind", "decoy")

        if not isinstance(name, str) or not isinstance(value, str) or not isinstance(kind, str):
            return None, "Los campos 'name', 'value' y 'kind' del honeytoken deben ser texto"

        name_clean = name.strip()
        value_clean = value.strip()
        kind_clean = kind.strip().lower() or "decoy"

        if not RE_HONEYTOKEN_NAME.match(name_clean):
            return None, "El nombre del honeytoken debe tener 1..64 caracteres alfanuméricos (._-/)"
        if name_clean.lower() in seen_names:
            return None, f"Nombre de honeytoken duplicado: '{name_clean}'"
        if not value_clean or len(value_clean) > 256:
            return None, "El valor del honeytoken debe tener entre 1 y 256 caracteres"
        if any(ord(c) < 32 or ord(c) == 127 for c in value_clean):
            return None, "El valor del honeytoken contiene caracteres de control no permitidos"
        if kind_clean not in allowed_kinds:
            return None, f"Tipo de honeytoken inválido '{kind_clean}' (permitidos: {', '.join(sorted(allowed_kinds))})"

        # Validar que no contenga dominios reales ni direcciones reales de personas
        combined = f"{name_clean} {value_clean}"
        for dom in RE_EMAIL_IN_TEXT.findall(combined):
            if not _is_fictitious_domain(dom):
                return None, (
                    f"Dominio no permitido en honeytoken ('{dom}'): "
                    "use exclusivamente dominios ficticios reservados (.invalid, .test, .example o example.com)"
                )
        for dom in RE_URL_DOMAIN.findall(combined):
            if not _is_fictitious_domain(dom):
                return None, (
                    f"URL con dominio real no permitida en honeytoken ('{dom}'): "
                    "use dominios ficticios reservados (.invalid, .test, .example)"
                )
        for dom in RE_DOTTED_DOMAIN.findall(combined):
            if not _is_fictitious_domain(dom):
                return None, (
                    f"Dominio real no permitido en honeytoken ('{dom}'): "
                    "use dominios ficticios reservados (.invalid, .test, .example)"
                )

        seen_names.add(name_clean.lower())
        cleaned_list.append({
            "name": name_clean,
            "value": value_clean,
            "kind": kind_clean,
        })

    return cleaned_list, None


def validate_portal_template_config(raw_tpl: Any) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """
    Valida la personalización de la plantilla estática del portal del cliente.
    Rechaza estrictamente etiquetas HTML peligrosas, scripts, eventos inline o recursos externos.
    """
    if not isinstance(raw_tpl, dict):
        return None, "El campo 'portal_template' debe ser un objeto JSON"

    allowed_keys = set(DEFAULT_PORTAL_TEMPLATE.keys())
    unknown = [k for k in raw_tpl.keys() if k not in allowed_keys]
    if unknown:
        return None, f"Campos no permitidos en 'portal_template': {', '.join(unknown)}"

    merged = dict(DEFAULT_PORTAL_TEMPLATE)
    max_lens = {"title": 100, "subtitle": 200, "footer": 240}

    for key, val in raw_tpl.items():
        if not isinstance(val, str):
            return None, f"El campo 'portal_template.{key}' debe ser texto"
        if any(ord(c) < 32 or ord(c) == 127 for c in val):
            return None, f"El campo 'portal_template.{key}' contiene caracteres de control no permitidos"
        cleaned = val.strip()
        if len(cleaned) > max_lens[key]:
            return None, f"El campo 'portal_template.{key}' supera los {max_lens[key]} caracteres"
        if "<" in cleaned or ">" in cleaned or RE_FORBIDDEN_TEMPLATE_PATTERNS.search(cleaned):
            return None, (
                f"Contenido rechazado en 'portal_template.{key}': "
                "no se permiten etiquetas HTML, scripts ni recursos externos"
            )
        if key == "title" and not cleaned:
            return None, "El campo 'portal_template.title' no puede estar vacío"
        merged[key] = cleaned

    return merged, None


def build_mysql_handshake_v10(connection_id: int = 101) -> bytes:
    """
    Construye un paquete binario real Initial Handshake v10 del protocolo MySQL
    coherente con HOST_PROFILE (Debian 12) para respuestas iniciales emuladas.
    """
    version_bytes = HOST_PROFILE["mysql_server_version"].encode("ascii") + b"\x00"
    scramble = bytes((b % 94) + 33 for b in os.urandom(20))
    auth_part_1 = scramble[:8]
    auth_part_2 = scramble[8:20] + b"\x00"  # 13 bytes (12 + NUL)

    # Capabilities: CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
    cap_lower = 0xF7FF
    cap_upper = 0x81FF  # bit 0x0008 = CLIENT_PLUGIN_AUTH
    charset = 0x21  # utf8_general_ci
    status_flags = 0x0002  # SERVER_STATUS_AUTOCOMMIT
    auth_data_len = len(auth_part_1) + len(auth_part_2)  # 21 bytes

    payload = bytearray()
    payload.append(0x0A)  # protocol_version = 10
    payload.extend(version_bytes)
    payload.extend(struct.pack("<I", connection_id))
    payload.extend(auth_part_1)
    payload.append(0x00)  # filler
    payload.extend(struct.pack("<H", cap_lower))
    payload.append(charset)
    payload.extend(struct.pack("<H", status_flags))
    payload.extend(struct.pack("<H", cap_upper))
    payload.append(auth_data_len)
    payload.extend(b"\x00" * 10)  # reserved
    payload.extend(auth_part_2)
    payload.extend(b"mysql_native_password\x00")

    pkt_header = len(payload).to_bytes(3, "little") + b"\x00"  # sequence_id = 0
    return pkt_header + bytes(payload)


def build_mysql_err_packet(
    error_code: int = 1045,
    sql_state: str = "28000",
    message: str = "Access denied for user",
    sequence_id: int = 2,
) -> bytes:
    """Construye un paquete binario ERR_Packet válido del protocolo MySQL (0xFF)."""
    state_bytes = sql_state.encode("ascii", errors="ignore")[:5].ljust(5, b"0")
    payload = b"\xff" + struct.pack("<H", error_code) + b"#" + state_bytes + message.encode("utf-8")
    pkt_header = len(payload).to_bytes(3, "little") + bytes([sequence_id & 0xFF])
    return pkt_header + payload


def _build_http_response(status_code: int, body: bytes, content_type: str = "text/plain; charset=utf-8") -> bytes:
    reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found"}.get(status_code, "OK")
    headers = (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Server: {HOST_PROFILE['http_server']}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")
    return headers + body


class EmulatedServiceEngine:
    """
    Motor de respuestas estáticas para servicios emulados (SSH, Telnet, HTTP/HTTPS, MySQL).
    Todas las respuestas provienen de tablas fijas y de honeytokens ficticios del operador.
    """

    @staticmethod
    def banner_for_service(service: str) -> bytes:
        svc = (service or "").lower()
        if svc == "ssh":
            return (HOST_PROFILE["ssh_banner"] + "\r\n").encode("ascii")
        if svc == "telnet":
            return HOST_PROFILE["telnet_banner"].encode("ascii")
        if svc == "mysql":
            return build_mysql_handshake_v10()
        return b""

    @staticmethod
    def _match_honeytoken(text: str, honeytokens: List[Dict[str, str]]) -> Optional[Dict[str, str]]:
        lowered = text.lower()
        for ht in honeytokens:
            ht_name = str(ht.get("name", "")).strip()
            if ht_name and ht_name.lower() in lowered:
                return ht
        return None

    @classmethod
    def evaluate_input(
        cls,
        service: str,
        raw_line: bytes,
        honeytokens: Optional[List[Dict[str, str]]] = None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Evalúa una línea recibida (ya acotada a MAX_LINE_BYTES) contra tabla fija.
        Retorna (response_bytes, event_metadata_dict).
        """
        svc = (service or "unknown").lower()
        clean_text = sanitize_captured_text(raw_line, max_len=MAX_LINE_BYTES)
        tokens_cfg = honeytokens or []

        mitre_engine = get_mitre_engine()

        # 1. Servicio HTTP / HTTPS emulado (respuesta desde tabla fija por ruta)
        if svc in ("http", "https"):
            parts = clean_text.split()
            method = parts[0].upper() if parts else "GET"
            raw_path = parts[1] if len(parts) >= 2 else "/"
            path_only = raw_path.split("?", 1)[0]

            if method not in ("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"):
                return _build_http_response(400, b"Bad Request\n"), {
                    "event_type": "DECEPTION_HTTP_PROBE",
                    "severity": "normal",
                    "mitre_technique": mitre_engine.resolve_event("DECEPTION_HTTP_BAD_METHOD"),
                    "captured_text": clean_text,
                    "honeytoken_touched": None,
                }

            # Exposición controlada de honeytokens ficticios en rutas señuelo (/.env, /secrets.json)
            if path_only in ("/.env", "/secrets.json", "/config.decoy") and tokens_cfg:
                first_ht = tokens_cfg[0]
                if path_only == "/secrets.json":
                    body_obj = {ht["name"]: ht["value"] for ht in tokens_cfg}
                    body = (json.dumps(body_obj) + "\n").encode("utf-8")
                    ctype = "application/json; charset=utf-8"
                else:
                    lines = [f"{ht['name']}={ht['value']}" for ht in tokens_cfg]
                    body = ("\n".join(lines) + "\n").encode("utf-8")
                    ctype = "text/plain; charset=utf-8"
                return _build_http_response(200, body, content_type=ctype), {
                    "event_type": "HONEYTOKEN_TOUCHED",
                    "severity": "critical",
                    "mitre_technique": mitre_engine.resolve_command(svc, path_only, "HONEYTOKEN_TOUCHED"),
                    "captured_text": clean_text,
                    "honeytoken_touched": first_ht["name"],
                }

            if path_only in FIXED_HTTP_RESPONSES:
                status_code, body = FIXED_HTTP_RESPONSES[path_only]
                ctype = "application/json; charset=utf-8" if path_only == "/api/v1/health" else "text/html; charset=utf-8"
                if path_only == "/robots.txt" or status_code >= 400:
                    ctype = "text/plain; charset=utf-8"
                return _build_http_response(status_code, body, content_type=ctype), {
                    "event_type": "DECEPTION_HTTP_PROBE",
                    "severity": "normal" if status_code == 200 else "warning",
                    "mitre_technique": mitre_engine.resolve_command(svc, path_only, "DECEPTION_HTTP_PROBE"),
                    "captured_text": clean_text,
                    "honeytoken_touched": None,
                }

            return _build_http_response(404, b"Not Found\n"), {
                "event_type": "DECEPTION_HTTP_PROBE",
                "severity": "normal",
                "mitre_technique": mitre_engine.resolve_command(svc, path_only, "DECEPTION_HTTP_PROBE"),
                "captured_text": clean_text,
                "honeytoken_touched": None,
            }

        # 2. Servicio MySQL emulado (respuesta binaria ERR_Packet 1045)
        if svc == "mysql":
            return build_mysql_err_packet(1045, "28000", "Access denied for user", sequence_id=2), {
                "event_type": "DECEPTION_MYSQL_PROBE",
                "severity": "warning",
                "mitre_technique": mitre_engine.resolve_event("DECEPTION_MYSQL_PROBE"),
                "captured_text": clean_text,
                "honeytoken_touched": None,
            }

        # 3. Servicios SSH / Telnet / Shell emulado
        if not clean_text:
            return b"", {
                "event_type": "DECEPTION_COMMAND_CAPTURED",
                "severity": "info",
                "mitre_technique": "",
                "captured_text": "",
                "honeytoken_touched": None,
            }

        normalized = " ".join(clean_text.split())
        lower_norm = normalized.lower()
        first_token = lower_norm.split(" ", 1)[0]

        # 3a. Detectar intentos de conexión saliente / resolución DNS / ejecución script -> NUNCA abrir red
        if first_token in FIXED_EGRESS_ERROR_BY_TOOL:
            err_resp = FIXED_EGRESS_ERROR_BY_TOOL[first_token]
            return err_resp, {
                "event_type": "DECEPTION_EGRESS_BLOCKED",
                "severity": "critical",
                "mitre_technique": mitre_engine.resolve_command(svc, normalized, "DECEPTION_EGRESS_BLOCKED"),
                "captured_text": clean_text,
                "honeytoken_touched": None,
            }

        # 3b. Comprobar acceso a honeytoken configurado por el operador
        matched_ht = cls._match_honeytoken(normalized, tokens_cfg)
        if matched_ht is not None:
            ht_line = f"{matched_ht['name']}={matched_ht['value']}\r\n".encode("utf-8")
            return ht_line, {
                "event_type": "HONEYTOKEN_TOUCHED",
                "severity": "critical",
                "mitre_technique": mitre_engine.resolve_command(svc, normalized, "HONEYTOKEN_TOUCHED"),
                "captured_text": clean_text,
                "honeytoken_touched": matched_ht["name"],
            }

        # Si consulta `env` o `cat .env` / `cat config.decoy` y existen honeytokens configurados
        if tokens_cfg and (
            lower_norm == "env"
            or any(lower_norm == f"cat {fn}" for fn in SENSITIVE_HONEYTOKEN_FILENAMES)
        ):
            first_ht = tokens_cfg[0]
            lines = "\r\n".join(f"{ht['name']}={ht['value']}" for ht in tokens_cfg) + "\r\n"
            return lines.encode("utf-8"), {
                "event_type": "HONEYTOKEN_TOUCHED",
                "severity": "critical",
                "mitre_technique": mitre_engine.resolve_command(svc, normalized, "HONEYTOKEN_TOUCHED"),
                "captured_text": clean_text,
                "honeytoken_touched": first_ht["name"],
            }

        # 3c. Buscar en tabla fija exacta de comandos
        if lower_norm in FIXED_SHELL_RESPONSES:
            return FIXED_SHELL_RESPONSES[lower_norm], {
                "event_type": "DECEPTION_COMMAND_CAPTURED",
                "severity": "warning",
                "mitre_technique": mitre_engine.resolve_command(svc, normalized, "DECEPTION_COMMAND_CAPTURED"),
                "captured_text": clean_text,
                "honeytoken_touched": None,
            }

        # 3d. Fallback estático seguro: nunca refleja entrada arbitraria ni menciona HoneyGate
        return b"bash: command not found\r\n", {
            "event_type": "DECEPTION_COMMAND_CAPTURED",
            "severity": "normal",
            "mitre_technique": mitre_engine.resolve_command(svc, normalized, "DECEPTION_COMMAND_CAPTURED"),
            "captured_text": clean_text,
            "honeytoken_touched": None,
        }
