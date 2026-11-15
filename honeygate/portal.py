"""
================================================================================
HONEYGATE PORTAL: Portal Cautivo Modo 1 (Puerto Independiente, Sin Token API)
Implementa registro solo por correo + consentimiento Ley 25.326/26.388,
fingerprint compuesto real (device_id), detección Anti-Sybil sin bloqueo
inmediato, entrega de OTP vía SMTP por variables de entorno o modo laboratorio,
y escape estricto contra XSS en portal HTML.
================================================================================
"""

import os
import re
import html
import json
import time
import hashlib
import secrets
import smtplib
import logging
import threading
from email.message import EmailMessage
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from honeygate.honeywall_core import HoneyGateHoneywall
from honeygate.storage import HoneyGateStorage

logger = logging.getLogger("HoneyGatePortal")

MAX_PORTAL_BODY_BYTES = 32768
DEFAULT_LEASE_SEC = 300
OBSERVED_LEASE_SEC = 60
DEFAULT_BANDWIDTH_KBPS = 10240
OBSERVED_BANDWIDTH_KBPS = 256
OTP_TTL_SECONDS = 300

RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,189}\.[A-Za-z]{2,24}$")

DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com",
    "10minutemail.com",
    "10minutemail.net",
    "tempmail.com",
    "temp-mail.org",
    "guerrillamail.com",
    "guerrillamail.org",
    "yopmail.com",
    "throwawaymail.com",
    "trashmail.com",
    "sharklasers.com",
    "getnada.com",
    "dispostable.com",
    "mintemail.com",
    "maildrop.cc",
    "fakeinbox.com",
    "emailondeck.com",
}


def is_lab_mode_enabled() -> bool:
    return os.environ.get("HONEYGATE_PORTAL_LAB_MODE", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def is_otp_required_by_env() -> bool:
    return os.environ.get("HONEYGATE_PORTAL_REQUIRE_OTP", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def _clean_text(value: Any, max_len: int = 254) -> str:
    if value is None:
        return ""
    raw = str(value)
    cleaned = "".join(ch for ch in raw if ord(ch) >= 32 and ch != "\x7f")
    return cleaned.strip()[:max_len]


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _infer_device_type(user_agent: str) -> str:
    ua = user_agent.lower()
    if not ua:
        return "unknown"
    if "android" in ua:
        return "Android"
    if "iphone" in ua or "ipad" in ua or "ios" in ua:
        return "iOS"
    if "windows" in ua:
        return "Windows"
    if "mac os" in ua or "macintosh" in ua:
        return "macOS"
    if "linux" in ua:
        return "Linux"
    return "Other"


def build_visitor_fingerprint(
    client_ip: str,
    headers: Any,
    client_telemetry: Optional[Dict[str, Any]] = None,
    mac_resolver: Optional[Callable[[str], str]] = None,
) -> Dict[str, Any]:
    """
    Construye el fingerprint compuesto (device_id) midiendo únicamente señales reales:
    - MAC desde /proc/net/arp (o mac_resolver); SSID queda vacío (requiere AP/hostapd).
    - Navegador: cabeceras HTTP reales + métricas JS si el navegador las envió (vacías si no).
    - Red: orden real de cabeceras HTTP; JA3/JA4 quedan vacíos (HTTP plano en user-space).
    - DHCP: queda vacío (requiere captura UDP 67/68 o hook de servidor DHCP).
    """
    resolver = mac_resolver or HoneyGateHoneywall.resolve_mac_address
    mac = _clean_text(resolver(client_ip), 64) or "UNKNOWN"
    ssid = ""  # No medible en espacio de usuario sin integración con AP/hostapd

    header_keys: List[str] = []
    if headers is not None and hasattr(headers, "keys"):
        header_keys = [_clean_text(k, 64) for k in headers.keys() if _clean_text(k, 64)]
    http_header_order = ",".join(header_keys)

    user_agent = _clean_text(headers.get("User-Agent", "") if headers else "", 256)
    accept_language = _clean_text(headers.get("Accept-Language", "") if headers else "", 128)
    accept_encoding = _clean_text(headers.get("Accept-Encoding", "") if headers else "", 128)

    telemetry = client_telemetry if isinstance(client_telemetry, dict) else {}
    screen = _clean_text(telemetry.get("screen", ""), 64)
    timezone_str = _clean_text(telemetry.get("timezone", ""), 64)
    js_language = _clean_text(telemetry.get("language", ""), 64)
    canvas_hash = _clean_text(telemetry.get("canvas_hash", ""), 128)
    fonts_hash = _clean_text(telemetry.get("fonts_hash", ""), 128)

    browser_obj = {
        "user_agent": user_agent,
        "accept_language": accept_language,
        "accept_encoding": accept_encoding,
        "screen": screen,
        "timezone": timezone_str,
        "language": js_language,
        "canvas_hash": canvas_hash,
        "fonts_hash": fonts_hash,
    }
    network_obj = {
        "http_header_order": http_header_order,
        "ja3": "",
        "ja4": "",
    }
    dhcp_fp = ""

    has_browser_signal = any(
        bool(v)
        for v in (
            user_agent,
            accept_language,
            screen,
            timezone_str,
            js_language,
            canvas_hash,
            fonts_hash,
            http_header_order,
        )
    )
    browser_hash = (
        _sha256_hex(
            json.dumps(
                {
                    "browser": browser_obj,
                    "http_header_order": http_header_order,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )[:24]
        if has_browser_signal
        else ""
    )

    composite_seed = (
        f"mac={mac}|ssid={ssid}|browser={browser_hash}|"
        f"net_order={http_header_order}|ja3=|ja4=|dhcp={dhcp_fp}"
    )
    device_id = f"hg:{_sha256_hex(composite_seed)[:24]}"

    return {
        "device_id": device_id,
        "mac": mac,
        "ssid": ssid,
        "device_type": _infer_device_type(user_agent),
        "browser_hash": browser_hash,
        "browser_fingerprint": json.dumps(browser_obj, sort_keys=True, separators=(",", ":")),
        "network_fingerprint": json.dumps(network_obj, sort_keys=True, separators=(",", ":")),
        "dhcp_fingerprint": dhcp_fp,
    }


def _send_otp_via_smtp(recipient_email: str, otp_code: str) -> Tuple[bool, str]:
    """
    Envía el OTP usando SMTP configurado exclusivamente mediante variables de entorno.
    La contraseña SMTP nunca se guarda en SQLite ni se escribe en logs.
    """
    smtp_host = os.environ.get("HONEYGATE_SMTP_HOST", "").strip()
    if not smtp_host:
        return False, "SMTP no configurado"

    try:
        smtp_port = int(os.environ.get("HONEYGATE_SMTP_PORT", "587").strip())
    except ValueError:
        return False, "HONEYGATE_SMTP_PORT inválido"

    smtp_user = os.environ.get("HONEYGATE_SMTP_USER", "").strip()
    smtp_pass = (
        os.environ.get("HONEYGATE_SMTP_PASS")
        or os.environ.get("HONEYGATE_SMTP_PASSWORD")
        or ""
    )
    smtp_from = os.environ.get("HONEYGATE_SMTP_FROM", "").strip() or smtp_user or "noreply@honeygate.local"
    use_ssl = os.environ.get("HONEYGATE_SMTP_USE_SSL", "").strip().lower() in ("1", "true", "yes")
    use_tls = os.environ.get("HONEYGATE_SMTP_USE_TLS", "1").strip().lower() not in ("0", "false", "no")

    msg = EmailMessage()
    msg["Subject"] = "HoneyGate — Código de verificación de acceso"
    msg["From"] = smtp_from
    msg["To"] = recipient_email
    msg.set_content(
        "Su código de verificación de un solo uso para el portal HoneyGate es:\n\n"
        f"{otp_code}\n\n"
        f"Expira en {OTP_TTL_SECONDS // 60} minutos.\n"
        "Uso exclusivo en redes autorizadas (Ley 25.326 / Ley 26.388).\n"
    )

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as client:
                if smtp_user and smtp_pass:
                    client.login(smtp_user, smtp_pass)
                client.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as client:
                client.ehlo()
                if use_tls:
                    client.starttls()
                    client.ehlo()
                if smtp_user and smtp_pass:
                    client.login(smtp_user, smtp_pass)
                client.send_message(msg)
        return True, "OK"
    except Exception as exc:
        logger.warning(f"[PORTAL-SMTP] Fallo al enviar OTP vía SMTP ({type(exc).__name__}).")
        return False, "No se pudo entregar el código OTP por correo"


def render_portal_html(
    banner_message: str = "",
    banner_is_error: bool = False,
    last_email: str = "",
    last_result: Optional[Dict[str, Any]] = None,
    challenge_id: str = "",
    otp_available: bool = False,
    otp_required: bool = False,
) -> str:
    """
    Genera el HTML del portal cautivo escapando toda entrada del visitante.
    NUNCA incluye token de API ni llamadas a /api/*.
    """
    safe_email = html.escape(last_email, quote=True)
    safe_banner = html.escape(banner_message, quote=True)
    safe_challenge = html.escape(challenge_id, quote=True)

    banner_block = ""
    if safe_banner:
        cls = "alert error" if banner_is_error else "alert ok"
        banner_block = f'<div class="{cls}" id="portal-banner">{safe_banner}</div>'

    result_block = ""
    if last_result:
        r_status = html.escape(str(last_result.get("status", "")), quote=True)
        r_dev = html.escape(str(last_result.get("device_id", "")), quote=True)
        r_lease = html.escape(str(last_result.get("dhcp_lease_sec", "")), quote=True)
        r_bw = html.escape(str(last_result.get("bandwidth_kbps", "")), quote=True)
        r_reason = html.escape(str(last_result.get("observed_reason", "")), quote=True)
        reason_row = f"<p><strong>Motivo de observación:</strong> {r_reason}</p>" if r_reason else ""
        result_block = (
            '<div class="result-card" id="portal-result">'
            f"<p><strong>Estado de sesión:</strong> {r_status}</p>"
            f"<p><strong>Device ID:</strong> <code>{r_dev}</code></p>"
            f"<p><strong>Lease DHCP:</strong> {r_lease}s | <strong>Ancho de banda:</strong> {r_bw} kbps</p>"
            f"{reason_row}"
            "</div>"
        )

    otp_section = ""
    if safe_challenge:
        otp_section = f"""
        <section class="card" style="margin-top: 16px;">
            <h2>Verificación de Código OTP</h2>
            <form method="POST" action="/portal/otp/verify" id="otp-verify-form">
                <input type="hidden" name="challenge_id" value="{safe_challenge}">
                <input type="hidden" name="email" value="{safe_email}">
                <input type="hidden" name="screen" class="fp-screen" value="">
                <input type="hidden" name="timezone" class="fp-tz" value="">
                <input type="hidden" name="language" class="fp-lang" value="">
                <input type="hidden" name="canvas_hash" class="fp-canvas" value="">
                <input type="hidden" name="fonts_hash" class="fp-fonts" value="">
                <label for="otp_code">Código OTP (6 dígitos)</label>
                <input type="text" id="otp_code" name="otp_code" inputmode="numeric" maxlength="10" required placeholder="000000">
                <label class="consent">
                    <input type="checkbox" name="consent" value="1" required>
                    <span>Acepto el registro de metadatos técnicos (Ley 25.326 AR) y declaro uso autorizado (Ley 26.388).</span>
                </label>
                <button type="submit">Validar OTP y Conectar</button>
            </form>
        </section>
        """

    otp_btn = ""
    if otp_available:
        otp_btn = (
            '<button type="submit" formaction="/portal/otp/request" class="secondary">'
            "Solicitar código OTP por correo"
            "</button>"
        )

    primary_action = "/portal/otp/request" if otp_required else "/portal/register"
    primary_label = "Solicitar código OTP" if otp_required else "Registrar acceso (sin contraseña)"

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HoneyGate — Portal de Acceso de Red</title>
    <style>
        body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f141c; color: #e2e8f0; margin: 0; padding: 24px; }}
        .container {{ max-width: 520px; margin: 24px auto; }}
        .card {{ background: #161e2e; border: 1px solid #263147; border-radius: 12px; padding: 20px; }}
        h1 {{ margin: 0 0 6px; font-size: 20px; color: #10b981; }}
        h2 {{ margin: 0 0 12px; font-size: 16px; color: #06b6d4; }}
        p.sub {{ margin: 0 0 16px; font-size: 13px; color: #94a3b8; }}
        label {{ display: block; font-size: 13px; margin-bottom: 6px; color: #cbd5e1; }}
        input[type=email], input[type=text] {{
            width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px;
            border: 1px solid #334155; background: #0b1017; color: #f8fafc; margin-bottom: 14px; font-size: 14px;
        }}
        .consent {{ display: flex; gap: 10px; align-items: flex-start; font-size: 12px; color: #cbd5e1; margin-bottom: 16px; line-height: 1.4; }}
        button {{
            width: 100%; padding: 11px 14px; border: 0; border-radius: 8px;
            background: #10b981; color: #052e16; font-weight: 700; font-size: 14px; cursor: pointer;
        }}
        button.secondary {{ margin-top: 8px; background: #1e293b; color: #06b6d4; border: 1px solid #06b6d4; }}
        .legal {{ margin-top: 14px; padding: 10px; border-radius: 8px; background: #0f172a; border: 1px solid #1e293b; font-size: 11px; color: #94a3b8; line-height: 1.45; }}
        .alert {{ padding: 10px 12px; border-radius: 8px; margin-bottom: 14px; font-size: 13px; }}
        .alert.ok {{ background: rgba(16,185,129,0.14); border: 1px solid #10b981; color: #a7f3d0; }}
        .alert.error {{ background: rgba(239,68,68,0.14); border: 1px solid #ef4444; color: #fecaca; }}
        .result-card {{ background: #0b1017; border: 1px solid #06b6d4; border-radius: 8px; padding: 12px; margin-bottom: 14px; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>HoneyGate — Portal Cautivo</h1>
            <p class="sub">Acceso nominal de red. No se solicitan ni almacenan contraseñas.</p>
            {banner_block}
            {result_block}
            <form method="POST" action="{primary_action}" id="portal-register-form">
                <input type="hidden" name="screen" class="fp-screen" value="">
                <input type="hidden" name="timezone" class="fp-tz" value="">
                <input type="hidden" name="language" class="fp-lang" value="">
                <input type="hidden" name="canvas_hash" class="fp-canvas" value="">
                <input type="hidden" name="fonts_hash" class="fp-fonts" value="">
                <label for="email">Correo electrónico identificatorio (solo etiqueta, sin clave)</label>
                <input type="email" id="email" name="email" value="{safe_email}" maxlength="254" required placeholder="visitante@organizacion.com">
                <label class="consent">
                    <input type="checkbox" name="consent" value="1" required>
                    <span>Consiento la recopilación exclusiva de metadatos técnicos de sesión conforme a la <strong>Ley 25.326</strong> (Protección de Datos Personales, AR). Nunca se inspecciona contenido de tráfico ni se solicitan contraseñas.</span>
                </label>
                <button type="submit">{primary_label}</button>
                {otp_btn if not otp_required else ""}
            </form>
            <div class="legal">
                <strong>Aviso Legal (Ley 25.326 y Ley 26.388):</strong> El uso de esta red está autorizado exclusivamente para fines operativos legítimos o auditorías autorizadas por el propietario de la infraestructura.
            </div>
        </div>
        {otp_section}
    </div>
    <script>
        (function() {{
            function shaFallback(str) {{
                var h = 2166136261;
                for (var i = 0; i < str.length; i++) {{
                    h ^= str.charCodeAt(i);
                    h = Math.imul(h, 16777619);
                }}
                return ('00000000' + (h >>> 0).toString(16)).slice(-8);
            }}
            var scr = (window.screen ? (screen.width + 'x' + screen.height + 'x' + (screen.colorDepth || 0)) : '');
            var tz = '';
            try {{ tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; }} catch (e) {{}}
            var lang = navigator.language || '';
            var canvasVal = '';
            try {{
                var c = document.createElement('canvas');
                c.width = 180; c.height = 36;
                var ctx = c.getContext('2d');
                if (ctx) {{
                    ctx.textBaseline = 'top';
                    ctx.font = '14px sans-serif';
                    ctx.fillText('HoneyGate-FP', 2, 2);
                    canvasVal = shaFallback(c.toDataURL());
                }}
            }} catch (e) {{}}
            var fontsVal = '';
            try {{
                var probe = ['monospace', 'sans-serif', 'serif', 'Arial', 'Courier New'];
                var c2 = document.createElement('canvas').getContext('2d');
                if (c2) {{
                    fontsVal = shaFallback(probe.map(function(f) {{
                        c2.font = '16px ' + f;
                        return f + ':' + Math.round(c2.measureText('mmmmmmmmmmli').width);
                    }}).join(','));
                }}
            }} catch (e) {{}}
            function setAll(cls, val) {{
                var els = document.getElementsByClassName(cls);
                for (var i = 0; i < els.length; i++) {{ els[i].value = val; }}
            }}
            setAll('fp-screen', scr);
            setAll('fp-tz', tz);
            setAll('fp-lang', lang);
            setAll('fp-canvas', canvasVal);
            setAll('fp-fonts', fontsVal);
        }})();
    </script>
</body>
</html>
"""


class PortalService:
    """
    Lógica de negocio del Portal Cautivo Modo 1:
    - Validación de correo sin contraseña + consentimiento Ley 25.326.
    - Detección Anti-Sybil (dominios desechables, múltiples correos por device_id,
      velocidad elevada desde IP, rotación de MAC con misma huella de navegador).
    - Generación y verificación de OTP por SMTP o modo laboratorio explícito.
    """

    def __init__(
        self,
        storage: HoneyGateStorage,
        alert_callback: Optional[Callable[[str, str, str], None]] = None,
        mac_resolver: Optional[Callable[[str], str]] = None,
    ):
        self.storage = storage
        self.alert_callback = alert_callback
        self.mac_resolver = mac_resolver or HoneyGateHoneywall.resolve_mac_address

    def is_portal_active(self) -> Tuple[bool, str]:
        cfg = self.storage.get_config()
        if not cfg.get("portal_enabled", True):
            return False, "El portal cautivo está deshabilitado en la configuración operativa"
        if int(cfg.get("mode", 1)) not in (1, 3):
            return False, "El portal cautivo solo opera en Modo 1 o Modo 3"
        return True, ""

    @staticmethod
    def _parse_consent(raw_consent: Any) -> bool:
        if isinstance(raw_consent, bool):
            return raw_consent
        if isinstance(raw_consent, (int, float)):
            return raw_consent == 1
        if isinstance(raw_consent, str):
            return raw_consent.strip().lower() in ("1", "true", "yes", "on", "si", "sí")
        return False

    @staticmethod
    def _validate_email(raw_email: Any) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        cleaned = _clean_text(raw_email, 254).lower()
        if not cleaned or not RE_EMAIL.match(cleaned):
            return None, None, "Correo electrónico inválido"
        domain = cleaned.split("@", 1)[1]
        return cleaned, domain, None

    def _evaluate_anti_sybil(
        self,
        email_hash: str,
        email_domain: str,
        fp: Dict[str, Any],
        client_ip: str,
    ) -> Tuple[bool, bool, str, int, int]:
        """
        Evalúa las reglas Anti-Sybil de Modo 1.
        Retorna: (rejected_disposable, in_observation, reason, dhcp_lease_sec, bandwidth_kbps)
        """
        cfg = self.storage.get_config()
        max_emails = int(cfg.get("sybil_max_emails_per_device", 3))
        window_sec = int(cfg.get("sybil_window_seconds", 600))
        since_ts = time.time() - float(window_sec)

        # 1. Dominio de correo desechable/temporal -> rechazar dominio temporal (sin bloquear IP)
        if email_domain in DISPOSABLE_EMAIL_DOMAINS:
            reason = f"Dominio de correo temporal bloqueado ({email_domain})"
            self.storage.record_event(
                event_type="ANTISYBIL_DISPOSABLE_DOMAIN",
                severity="warning",
                mode=int(cfg.get("mode", 1)),
                device_id=fp["device_id"],
                ip=client_ip,
                mitre_technique="T1078",
                description=f"Registro rechazado por dominio temporal en portal ({email_domain})",
                metadata={
                    "domain": email_domain,
                    "mac": fp["mac"],
                    "action": "rejected_disposable",
                },
            )
            if self.alert_callback:
                self.alert_callback(
                    "Anti-Sybil Portal (Dominio Temporal)",
                    f"IP {client_ip} ({fp['device_id']}) intentó usar dominio temporal {email_domain}",
                    "warning",
                )
            return True, True, reason, OBSERVED_LEASE_SEC, OBSERVED_BANDWIDTH_KBPS

        reasons: List[str] = []

        # 2. Múltiples correos distintos desde el mismo device_id en la ventana temporal
        recent_hashes = self.storage.list_recent_email_hashes_for_device(fp["device_id"], since_ts)
        distinct_after = set(recent_hashes)
        distinct_after.add(email_hash)
        if len(distinct_after) > max_emails:
            reasons.append(
                f"Múltiples cuentas desde mismo device_id ({len(distinct_after)}/{max_emails} en {window_sec}s)"
            )

        # 3. Alta velocidad de registros desde la misma IP
        recent_ip_count = self.storage.count_recent_registrations_for_ip(client_ip, since_ts)
        velocity_limit = max(max_emails * 2, 5)
        if recent_ip_count >= velocity_limit:
            reasons.append(
                f"Alta frecuencia de registros desde IP ({recent_ip_count + 1} en {window_sec}s)"
            )

        # 4. Misma huella de navegador con MAC cambiante -> En observación (sin bloquear)
        prev_mac = self.storage.find_mac_rotation(fp["browser_hash"], fp["mac"], since_ts)
        if prev_mac is not None:
            reasons.append(
                f"Rotación de MAC detectada con misma huella de navegador ({prev_mac} -> {fp['mac']})"
            )

        if reasons:
            combined_reason = "; ".join(reasons)
            return False, True, combined_reason, OBSERVED_LEASE_SEC, OBSERVED_BANDWIDTH_KBPS

        return False, False, "", DEFAULT_LEASE_SEC, DEFAULT_BANDWIDTH_KBPS

    def _finalize_registration(
        self,
        email: str,
        email_domain: str,
        client_ip: str,
        fp: Dict[str, Any],
        otp_verified: bool,
    ) -> Tuple[int, Dict[str, Any]]:
        email_hash = _sha256_hex(email)
        cfg = self.storage.get_config()
        mode = int(cfg.get("mode", 1))

        rejected_disp, in_obs, obs_reason, lease_sec, bw_kbps = self._evaluate_anti_sybil(
            email_hash=email_hash,
            email_domain=email_domain,
            fp=fp,
            client_ip=client_ip,
        )
        if rejected_disp:
            return 400, {
                "accepted": False,
                "status": "rejected_disposable",
                "error": obs_reason,
                "device_id": fp["device_id"],
                "dhcp_lease_sec": lease_sec,
                "bandwidth_kbps": bw_kbps,
            }

        session_status = "en_observacion" if in_obs else "active"
        session_id = self.storage.create_session(
            ip=client_ip,
            mac=fp["mac"],
            client_port=0,
            device_id=fp["device_id"],
            device_type=fp["device_type"],
            browser_fingerprint=fp["browser_fingerprint"],
            browser_hash=fp["browser_hash"],
            network_fingerprint=fp["network_fingerprint"],
            dhcp_fingerprint=fp["dhcp_fingerprint"],
            dest_ip="127.0.0.1",
            dest_port=0,
            service="portal-cautivo",
            visitor_label=email,
            mode=mode,
            status=session_status,
            dhcp_lease_sec=lease_sec,
            bandwidth_kbps=bw_kbps,
            observed_reason=obs_reason,
        )

        self.storage.record_portal_registration(
            session_id=session_id,
            device_id=fp["device_id"],
            browser_hash=fp["browser_hash"],
            mac=fp["mac"],
            ip=client_ip,
            email_hash=email_hash,
            email_domain=email_domain,
            consent_accepted=True,
            otp_verified=otp_verified,
            observed=in_obs,
            observed_reason=obs_reason,
            dhcp_lease_sec=lease_sec,
            bandwidth_kbps=bw_kbps,
        )

        # IMPORTANTE: nunca escribir el correo del visitante ni OTP en eventos ni en logs
        if in_obs:
            self.storage.record_event(
                event_type="ANTISYBIL_OBSERVATION",
                severity="warning",
                session_id=session_id,
                mode=mode,
                device_id=fp["device_id"],
                ip=client_ip,
                mitre_technique="T1078",
                description=(
                    f"Sesión #{session_id} marcada en observación (lease={lease_sec}s, bw={bw_kbps}kbps): "
                    f"{obs_reason}"
                ),
                metadata={
                    "mac": fp["mac"],
                    "dhcp_lease_sec": lease_sec,
                    "bandwidth_kbps": bw_kbps,
                    "reason": obs_reason,
                    "email_domain": email_domain,
                },
            )
            logger.warning(
                f"[PORTAL-ANTISYBIL] Sesión #{session_id} en observación "
                f"(device_id={fp['device_id']}, ip={client_ip}, lease={lease_sec}s)."
            )
            if self.alert_callback:
                self.alert_callback(
                    "Anti-Sybil Portal (En Observación)",
                    f"Sesión #{session_id} ({fp['device_id']}) marcada en observación: {obs_reason}",
                    "warning",
                )
        else:
            self.storage.record_event(
                event_type="PORTAL_ACCESS_GRANTED",
                severity="info",
                session_id=session_id,
                mode=mode,
                device_id=fp["device_id"],
                ip=client_ip,
                description=(
                    f"Acceso nominal concedido en portal para sesión #{session_id} "
                    f"(consentimiento Ley 25.326, lease={lease_sec}s)"
                ),
                metadata={
                    "mac": fp["mac"],
                    "dhcp_lease_sec": lease_sec,
                    "bandwidth_kbps": bw_kbps,
                    "otp_verified": otp_verified,
                    "consent_law": "Ley 25.326",
                },
            )
            logger.info(
                f"[PORTAL-ACCESS] Sesión #{session_id} habilitada "
                f"(device_id={fp['device_id']}, ip={client_ip}, lease={lease_sec}s)."
            )

        return 200, {
            "accepted": True,
            "session_id": session_id,
            "device_id": fp["device_id"],
            "status": session_status,
            "observed_reason": obs_reason,
            "dhcp_lease_sec": lease_sec,
            "bandwidth_kbps": bw_kbps,
            "otp_verified": otp_verified,
            "consent_accepted": True,
        }

    def register_direct(
        self,
        payload: Dict[str, Any],
        client_ip: str,
        headers: Any,
    ) -> Tuple[int, Dict[str, Any]]:
        active, reason = self.is_portal_active()
        if not active:
            return 503, {"accepted": False, "error": reason}

        if not self._parse_consent(payload.get("consent")):
            return 400, {
                "accepted": False,
                "error": "Debe aceptar el consentimiento informado de metadatos (Ley 25.326)",
            }

        email, domain, err = self._validate_email(payload.get("email"))
        if err:
            return 400, {"accepted": False, "error": err}

        if is_otp_required_by_env():
            return self.request_otp(payload, client_ip, headers)

        fp = build_visitor_fingerprint(
            client_ip=client_ip,
            headers=headers,
            client_telemetry=payload,
            mac_resolver=self.mac_resolver,
        )
        return self._finalize_registration(
            email=email,
            email_domain=domain,
            client_ip=client_ip,
            fp=fp,
            otp_verified=False,
        )

    def request_otp(
        self,
        payload: Dict[str, Any],
        client_ip: str,
        headers: Any,
    ) -> Tuple[int, Dict[str, Any]]:
        active, reason = self.is_portal_active()
        if not active:
            return 503, {"accepted": False, "error": reason}

        if not self._parse_consent(payload.get("consent")):
            return 400, {
                "accepted": False,
                "error": "Debe aceptar el consentimiento informado de metadatos (Ley 25.326)",
            }

        email, domain, err = self._validate_email(payload.get("email"))
        if err:
            return 400, {"accepted": False, "error": err}

        if domain in DISPOSABLE_EMAIL_DOMAINS:
            fp = build_visitor_fingerprint(
                client_ip=client_ip,
                headers=headers,
                client_telemetry=payload,
                mac_resolver=self.mac_resolver,
            )
            return self._finalize_registration(
                email=email,
                email_domain=domain,
                client_ip=client_ip,
                fp=fp,
                otp_verified=False,
            )

        smtp_host = os.environ.get("HONEYGATE_SMTP_HOST", "").strip()
        lab_mode = is_lab_mode_enabled()
        if not smtp_host and not lab_mode:
            return 503, {
                "accepted": False,
                "error": "Entrega de OTP no disponible: configure HONEYGATE_SMTP_HOST o active modo laboratorio",
            }

        fp = build_visitor_fingerprint(
            client_ip=client_ip,
            headers=headers,
            client_telemetry=payload,
            mac_resolver=self.mac_resolver,
        )

        otp_code = f"{secrets.randbelow(1_000_000):06d}"
        challenge_id = secrets.token_urlsafe(16)
        otp_salt = secrets.token_hex(16)
        otp_hash = _sha256_hex(f"{otp_salt}:{otp_code}")
        email_hash = _sha256_hex(email)

        if smtp_host:
            sent, send_err = _send_otp_via_smtp(email, otp_code)
            if not sent:
                return 502, {"accepted": False, "error": send_err}

        self.storage.create_otp_challenge(
            challenge_id=challenge_id,
            device_id=fp["device_id"],
            ip=client_ip,
            email_hash=email_hash,
            otp_salt=otp_salt,
            otp_hash=otp_hash,
            ttl_sec=OTP_TTL_SECONDS,
        )

        # En modo normal NO se escribe ni el mail ni el OTP en logs.
        # Solo en modo laboratorio explícito se registra el OTP (sin el mail del visitante).
        if lab_mode:
            logger.info(
                f"[PORTAL-LAB] OTP generado para desafio={challenge_id} "
                f"device_id={fp['device_id']}: {otp_code}"
            )
        else:
            logger.info(
                f"[PORTAL-OTP] Desafío OTP emitido desafio={challenge_id} device_id={fp['device_id']}."
            )

        return 202, {
            "accepted": True,
            "otp_required": True,
            "challenge_id": challenge_id,
            "device_id": fp["device_id"],
            "expires_in_sec": OTP_TTL_SECONDS,
            "message": "Código OTP emitido. Ingresá el código para completar el acceso.",
        }

    def verify_otp(
        self,
        payload: Dict[str, Any],
        client_ip: str,
        headers: Any,
    ) -> Tuple[int, Dict[str, Any]]:
        active, reason = self.is_portal_active()
        if not active:
            return 503, {"accepted": False, "error": reason}

        if not self._parse_consent(payload.get("consent")):
            return 400, {
                "accepted": False,
                "error": "Debe aceptar el consentimiento informado de metadatos (Ley 25.326)",
            }

        email, domain, err = self._validate_email(payload.get("email"))
        if err:
            return 400, {"accepted": False, "error": err}

        challenge_id = _clean_text(payload.get("challenge_id"), 128)
        otp_code = _clean_text(payload.get("otp_code"), 16)
        if not challenge_id or not otp_code:
            return 400, {"accepted": False, "error": "Faltan challenge_id u otp_code"}

        ok, verify_msg = self.storage.verify_otp_challenge(
            challenge_id=challenge_id,
            email_hash=_sha256_hex(email),
            otp_code=otp_code,
        )
        if not ok:
            return 401, {"accepted": False, "error": verify_msg}

        fp = build_visitor_fingerprint(
            client_ip=client_ip,
            headers=headers,
            client_telemetry=payload,
            mac_resolver=self.mac_resolver,
        )
        return self._finalize_registration(
            email=email,
            email_domain=domain,
            client_ip=client_ip,
            fp=fp,
            otp_verified=True,
        )


class PortalHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    Manejador HTTP aislado para el Portal Cautivo.
    NUNCA posee el token de la API administrativa y bloquea con 404 cualquier /api/*.
    """
    portal_service: Optional[PortalService] = None

    def log_message(self, format, *args):
        pass

    def _send_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'",
        )
        self.send_header("Cache-Control", "no-store")

    def _send_json(self, data: Any, status_code: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _send_html(self, html_text: str, status_code: int = 200):
        body = html_text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _wants_json(self) -> bool:
        accept = (self.headers.get("Accept") or "").lower()
        ctype = (self.headers.get("Content-Type") or "").lower()
        return "application/json" in accept or "application/json" in ctype

    def _read_payload(self) -> Tuple[bool, Optional[Dict[str, Any]]]:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None or raw_len.strip() == "":
            return False, None
        try:
            length = int(raw_len.strip())
        except ValueError:
            return False, None
        if length <= 0 or length > MAX_PORTAL_BODY_BYTES:
            return False, None

        raw_bytes = self.rfile.read(length)
        ctype = (self.headers.get("Content-Type") or "").lower()
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return False, None

        if "application/json" in ctype:
            try:
                parsed = json.loads(text)
                return (isinstance(parsed, dict), parsed if isinstance(parsed, dict) else None)
            except Exception:
                return False, None

        form = parse_qs(text, keep_blank_values=True)
        flat = {k: (vals[0] if vals else "") for k, vals in form.items()}
        return True, flat

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            self._send_json({"error": "Recurso no disponible en el portal"}, status_code=404)
            return

        if path in ("/", "/portal"):
            svc = self.portal_service
            active, reason = svc.is_portal_active() if svc else (False, "Portal no inicializado")
            otp_avail = bool(os.environ.get("HONEYGATE_SMTP_HOST", "").strip()) or is_lab_mode_enabled()
            if not active:
                html_body = render_portal_html(
                    banner_message=reason,
                    banner_is_error=True,
                    otp_available=False,
                )
                self._send_html(html_body, status_code=503)
                return

            html_body = render_portal_html(
                otp_available=otp_avail,
                otp_required=is_otp_required_by_env(),
            )
            self._send_html(html_body, status_code=200)
            return

        self._send_json({"error": "Ruta no encontrada en el portal"}, status_code=404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            self._send_json({"error": "Recurso no disponible en el portal"}, status_code=404)
            return

        if path not in ("/portal/register", "/portal/otp/request", "/portal/otp/verify"):
            self._send_json({"error": "Ruta no encontrada en el portal"}, status_code=404)
            return

        ok, payload = self._read_payload()
        if not ok or payload is None:
            if self._wants_json():
                self._send_json({"accepted": False, "error": "Payload inválido"}, status_code=400)
            else:
                self._send_html(
                    render_portal_html(banner_message="Solicitud inválida", banner_is_error=True),
                    status_code=400,
                )
            return

        client_ip = self.client_address[0]
        svc = self.portal_service
        if path == "/portal/register":
            status_code, result = svc.register_direct(payload, client_ip, self.headers)
        elif path == "/portal/otp/request":
            status_code, result = svc.request_otp(payload, client_ip, self.headers)
        else:
            status_code, result = svc.verify_otp(payload, client_ip, self.headers)

        if self._wants_json():
            self._send_json(result, status_code=status_code)
            return

        otp_avail = bool(os.environ.get("HONEYGATE_SMTP_HOST", "").strip()) or is_lab_mode_enabled()
        raw_email = _clean_text(payload.get("email", ""), 254)
        if result.get("otp_required"):
            html_body = render_portal_html(
                banner_message=result.get("message", "Código OTP emitido."),
                banner_is_error=False,
                last_email=raw_email,
                challenge_id=result.get("challenge_id", ""),
                otp_available=otp_avail,
                otp_required=is_otp_required_by_env(),
            )
        elif result.get("accepted"):
            banner = (
                "Acceso habilitado en observación (ancho de banda y lease reducidos)."
                if result.get("status") == "en_observacion"
                else "Acceso nominal habilitado."
            )
            html_body = render_portal_html(
                banner_message=banner,
                banner_is_error=False,
                last_email=raw_email,
                last_result=result,
                otp_available=otp_avail,
                otp_required=is_otp_required_by_env(),
            )
        else:
            html_body = render_portal_html(
                banner_message=result.get("error", "No se pudo completar el registro."),
                banner_is_error=True,
                last_email=raw_email,
                challenge_id=_clean_text(payload.get("challenge_id", ""), 128),
                otp_available=otp_avail,
                otp_required=is_otp_required_by_env(),
            )
        self._send_html(html_body, status_code=status_code)

    def do_PUT(self):
        self._send_json({"error": "Método no permitido en el portal"}, status_code=404)


class AsyncPortalServer:
    """Servidor HTTP independiente para el Portal Cautivo Modo 1 (puerto separado del panel)."""

    def __init__(
        self,
        storage: HoneyGateStorage,
        host: str = "127.0.0.1",
        port: int = 8090,
        alert_callback: Optional[Callable[[str, str, str], None]] = None,
        mac_resolver: Optional[Callable[[str], str]] = None,
    ):
        self.host = host
        self.port = port
        self.storage = storage
        self.service = PortalService(
            storage=storage,
            alert_callback=alert_callback,
            mac_resolver=mac_resolver,
        )
        self.httpd: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None

    def start_background(self) -> threading.Thread:
        bound_service = self.service

        class BoundPortalHandler(PortalHTTPRequestHandler):
            portal_service = bound_service

        HTTPServer.allow_reuse_address = True
        self.httpd = HTTPServer((self.host, self.port), BoundPortalHandler)
        logger.info(f"[PORTAL-HTTP] Portal Cautivo activo en http://{self.host}:{self.port}")
        self.server_thread = threading.Thread(
            target=self.httpd.serve_forever,
            name="HoneyGatePortalThread",
            daemon=True,
        )
        self.server_thread.start()
        return self.server_thread

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
