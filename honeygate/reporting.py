"""
================================================================================
HONEYGATE REPORTING: Generación de Informes Forenses y Cumplimiento (Fase 5)
- Formatos: JSON, CSV (protegido contra inyección de fórmulas = + - @) y Markdown
  (con escape estricto anti-HTML y anti-inyección de enlaces).
- Privacidad por defecto: correos de visitantes enmascarados (j***@dominio),
  salvo parámetro explícito `include_full_email=True`.
================================================================================
"""

import csv
import io
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from honeygate.deception import HOST_PROFILE
from honeygate.mitre import get_mitre_engine
from honeygate.storage import HoneyGateStorage

SUPPORTED_REPORT_FORMATS = ("json", "csv", "markdown")

_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_MD_ESCAPE_CHARS = set("\\`*_[]()#!|<>~&{}")
_RE_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_RE_URL_SCHEME = re.compile(r"(?i)\b(https?|ftp|javascript|vbscript|data):")


def mask_email(email: Optional[str]) -> str:
    """Enmascara direcciones de correo (`juan@empresa.com` -> `j***@empresa.com`)."""
    if not email or not isinstance(email, str):
        return ""
    cleaned = email.strip()
    if "@" not in cleaned:
        return (cleaned[0] + "***") if cleaned else ""
    local, domain = cleaned.split("@", 1)
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"


def csv_safe_cell(value: Any) -> str:
    """
    Neutraliza celdas CSV que puedan interpretarse como fórmulas en planillas.
    Si el valor (o su versión sin espacios iniciales) empieza con =, +, -, @, \\t o \\r,
    antepone un apóstrofo ('). También reemplaza saltos de línea por espacios.
    """
    if value is None:
        return ""
    raw = str(value)
    raw = _RE_CONTROL.sub(lambda m: " " if m.group(0) in ("\n", "\r", "\t") else "", raw)
    stripped = raw.lstrip(" ")
    if raw.startswith(_CSV_FORMULA_PREFIXES) or (stripped and stripped[0] in ("=", "+", "-", "@")):
        return "'" + raw
    return raw


def markdown_escape(value: Any) -> str:
    """
    Escapa texto potencialmente hostil (entrada de atacante) para incrustación segura
    en Markdown: neutraliza HTML (<, >, &), sintaxis Markdown ([]()*`!|#...) y
    esquemas de enlaces (http://, https://, javascript:) para evitar links o HTML activo.
    """
    if value is None:
        return ""
    raw = str(value)
    raw = _RE_CONTROL.sub(" ", raw)
    # Desarmar esquemas URL antes de escapar signos de puntuación
    raw = _RE_URL_SCHEME.sub(lambda m: f"{m.group(1)}[colon]", raw)
    out: List[str] = []
    for ch in raw:
        if ch == "<":
            out.append("&lt;")
        elif ch == ">":
            out.append("&gt;")
        elif ch == "&":
            out.append("&amp;")
        elif ch in _MD_ESCAPE_CHARS:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _format_ts(ts: Optional[float]) -> str:
    if not ts:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))


def collect_report_data(
    storage: HoneyGateStorage,
    honeywall: Optional[Any] = None,
    include_full_email: bool = False,
    mode: Optional[int] = None,
    since: Optional[float] = None,
    until: Optional[float] = None,
    limit: int = 500,
) -> Dict[str, Any]:
    """Recopila el estado real del daemon y enmascara correos salvo pedido explícito."""
    cfg = storage.get_config()
    sessions, sessions_total = storage.list_sessions(mode=mode, limit=limit, offset=0)
    events, events_total = storage.list_events(mode=mode, since=since, until=until, limit=limit, offset=0)
    isolated = storage.list_isolated_ips()
    mitre_engine = get_mitre_engine()

    sanitized_sessions: List[Dict[str, Any]] = []
    for s in sessions:
        raw_label = s.get("visitor_label")
        display_label = None
        if raw_label:
            display_label = raw_label if include_full_email else mask_email(raw_label)

        origin = s.get("origin", {})
        target = s.get("target", {})
        sess_info = s.get("session", {})
        sanitized_sessions.append({
            "id": s.get("id"),
            "mode": s.get("mode"),
            "device_id": origin.get("device_id") or s.get("device_id"),
            "ip": origin.get("ip") or s.get("ip"),
            "mac": origin.get("mac") or s.get("mac"),
            "service": target.get("service") or s.get("service"),
            "dest_port": target.get("dest_port") if target.get("dest_port") is not None else s.get("dest_port"),
            "status": sess_info.get("status") or s.get("status"),
            "duration_sec": sess_info.get("duration_sec", 0.0),
            "bytes_in": sess_info.get("bytes_in", 0),
            "bytes_out": sess_info.get("bytes_out", 0),
            "dhcp_lease_sec_suggested": sess_info.get("dhcp_lease_sec"),
            "bandwidth_kbps_suggested": sess_info.get("bandwidth_kbps"),
            "mail_verified": sess_info.get("mail_verified"),
            "honeytoken_touched": target.get("honeytoken_touched"),
            "observed_reason": sess_info.get("observed_reason"),
            "visitor_label": display_label,
        })

    severity_counts = {"critical": 0, "warning": 0, "normal": 0, "info": 0}
    mitre_counts: Dict[str, int] = {}
    sanitized_events: List[Dict[str, Any]] = []

    for ev in events:
        sev = str(ev.get("severity") or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        tech = str(ev.get("mitre_technique") or "").strip()
        if tech:
            mitre_counts[tech] = mitre_counts.get(tech, 0) + 1
        meta = ev.get("metadata") or {}
        sanitized_events.append({
            "id": ev.get("id"),
            "session_id": ev.get("session_id"),
            "timestamp": ev.get("timestamp"),
            "created_at": ev.get("created_at"),
            "mode": ev.get("mode"),
            "device_id": ev.get("device_id"),
            "ip": ev.get("ip"),
            "event_type": ev.get("event_type"),
            "severity": sev,
            "mitre_technique": tech or None,
            "service": meta.get("service"),
            "dest_port": meta.get("dest_port"),
            "honeytoken_touched": meta.get("honeytoken_touched"),
            "captured_command": meta.get("command"),
            "description": ev.get("description"),
        })

    mitre_breakdown = []
    for tid, count in sorted(mitre_counts.items(), key=lambda x: (-x[1], x[0])):
        info = mitre_engine.describe_technique(tid)
        mitre_breakdown.append({
            "technique": tid,
            "name": info["name"],
            "tactic": info["tactic"],
            "count": count,
        })

    hw_stats = dict(honeywall.stats) if honeywall is not None else {}

    return {
        "generated_at": _format_ts(time.time()),
        "host_profile": {
            "os": HOST_PROFILE["os_name"],
            "hostname": HOST_PROFILE["hostname"],
            "kernel": HOST_PROFILE["kernel_release"],
        },
        "privacy": {
            "email_masking_applied": not include_full_email,
            "retention_days": cfg.get("retention_days"),
            "legal_framework": "Ley 25.326 / Ley 26.388 (AR)",
        },
        "config_summary": {
            "mode": cfg.get("mode"),
            "portal_enabled": cfg.get("portal_enabled"),
            "honeypot_enabled": cfg.get("honeypot_enabled"),
            "max_outbound_per_minute": cfg.get("max_outbound_per_minute"),
            "retention_days": cfg.get("retention_days"),
            "honeytokens_count": len(cfg.get("honeytokens") or []),
        },
        "summary": {
            "sessions_total": sessions_total,
            "sessions_included": len(sanitized_sessions),
            "events_total": events_total,
            "events_included": len(sanitized_events),
            "isolated_ips_count": len(isolated),
            "severity_counts": severity_counts,
            "honeywall_stats": hw_stats,
        },
        "mitre_breakdown": mitre_breakdown,
        "isolated_ips": isolated,
        "sessions": sanitized_sessions,
        "events": sanitized_events,
    }


def render_report_csv(report: Dict[str, Any]) -> str:
    """Genera un informe CSV completo con neutralización de fórmulas en TODAS las celdas."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")

    writer.writerow([
        csv_safe_cell(col)
        for col in (
            "record_type",
            "id",
            "timestamp",
            "mode",
            "status_or_severity",
            "ip",
            "mac_or_source",
            "device_id",
            "service",
            "dest_port",
            "visitor_or_event_type",
            "mitre_technique",
            "honeytoken_touched",
            "detail_or_command",
        )
    ])

    for s in report.get("sessions", []):
        row = [
            "session",
            s.get("id"),
            report.get("generated_at"),
            s.get("mode"),
            s.get("status"),
            s.get("ip"),
            s.get("mac"),
            s.get("device_id"),
            s.get("service"),
            s.get("dest_port"),
            s.get("visitor_label") or "",
            "",
            s.get("honeytoken_touched") or "",
            s.get("observed_reason") or "",
        ]
        writer.writerow([csv_safe_cell(v) for v in row])

    for ev in report.get("events", []):
        detail = ev.get("captured_command") or ev.get("description") or ""
        row = [
            "event",
            ev.get("id"),
            ev.get("created_at"),
            ev.get("mode"),
            ev.get("severity"),
            ev.get("ip") or "",
            "",
            ev.get("device_id") or "",
            ev.get("service") or "",
            ev.get("dest_port") or "",
            ev.get("event_type") or "",
            ev.get("mitre_technique") or "",
            ev.get("honeytoken_touched") or "",
            detail,
        ]
        writer.writerow([csv_safe_cell(v) for v in row])

    return buf.getvalue()


def render_report_markdown(report: Dict[str, Any]) -> str:
    """Genera un informe Markdown escapando todo contenido capturado o variable."""
    summary = report.get("summary", {})
    sev = summary.get("severity_counts", {})
    cfg = report.get("config_summary", {})
    privacy = report.get("privacy", {})
    profile = report.get("host_profile", {})

    lines: List[str] = [
        "# HoneyGate — Informe Forense y Operativo",
        "",
        f"- **Fecha de generación:** {markdown_escape(report.get('generated_at'))}",
        f"- **Perfil unificado:** {markdown_escape(profile.get('os'))} (`{markdown_escape(profile.get('hostname'))}`)",
        f"- **Modo operativo:** Modo {markdown_escape(cfg.get('mode'))} (portal={markdown_escape(cfg.get('portal_enabled'))}, honeypot={markdown_escape(cfg.get('honeypot_enabled'))})",
        f"- **Retención configurada:** {markdown_escape(cfg.get('retention_days'))} días | **Enmascaramiento de correo:** {'activo (j***@dominio)' if privacy.get('email_masking_applied') else 'desactivado por operador'}",
        f"- **Marco legal:** {markdown_escape(privacy.get('legal_framework'))}",
        "",
        "## Resumen Cuantitativo",
        "",
        f"- **Sesiones:** {summary.get('sessions_total', 0)} totales ({summary.get('sessions_included', 0)} en informe)",
        f"- **Eventos:** {summary.get('events_total', 0)} totales (critical={sev.get('critical', 0)}, warning={sev.get('warning', 0)}, normal={sev.get('normal', 0)}, info={sev.get('info', 0)})",
        f"- **IPs aisladas:** {summary.get('isolated_ips_count', 0)}",
        "",
        "## Cobertura MITRE ATT&CK",
        "",
    ]

    mitre_rows = report.get("mitre_breakdown", [])
    if not mitre_rows:
        lines.append("_Sin técnicas MITRE ATT&CK registradas en el rango seleccionado._")
    else:
        lines.append("| Técnica | Nombre | Táctica | Eventos |")
        lines.append("| --- | --- | --- | --- |")
        for m in mitre_rows:
            lines.append(
                f"| {markdown_escape(m.get('technique'))} | {markdown_escape(m.get('name'))} | "
                f"{markdown_escape(m.get('tactic'))} | {markdown_escape(m.get('count'))} |"
            )

    lines.extend(["", "## Sesiones Registradas", ""])
    sessions = report.get("sessions", [])
    if not sessions:
        lines.append("_Sin sesiones registradas._")
    else:
        lines.append("| ID | IP | Device ID | Servicio | Estado | Visitante | Honeytoken |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for s in sessions[:50]:
            v_label = s.get("visitor_label")
            if not v_label:
                v_rendered = "—"
            elif privacy.get("email_masking_applied") and "***@" in str(v_label):
                prefix_part, dom_part = str(v_label).split("***@", 1)
                v_rendered = f"{markdown_escape(prefix_part)}***@{markdown_escape(dom_part)}"
            else:
                v_rendered = markdown_escape(v_label)
            lines.append(
                f"| #{markdown_escape(s.get('id'))} | {markdown_escape(s.get('ip'))} | "
                f"{markdown_escape(s.get('device_id'))} | {markdown_escape(s.get('service'))}:{markdown_escape(s.get('dest_port'))} | "
                f"{markdown_escape(s.get('status'))} | {v_rendered} | "
                f"{markdown_escape(s.get('honeytoken_touched') or '—')} |"
            )

    lines.extend(["", "## Eventos Recientes (Contenido Capturado Escapado)", ""])
    events = report.get("events", [])
    if not events:
        lines.append("_Sin eventos registrados._")
    else:
        for ev in events[:50]:
            cmd = ev.get("captured_command")
            cmd_suffix = f" | Entrada: {markdown_escape(cmd)}" if cmd else ""
            mitre_str = f" [{markdown_escape(ev.get('mitre_technique'))}]" if ev.get("mitre_technique") else ""
            lines.append(
                f"- `{markdown_escape(ev.get('created_at'))}` **{markdown_escape(str(ev.get('severity', '')).upper())}** "
                f"`{markdown_escape(ev.get('event_type'))}`{mitre_str} ({markdown_escape(ev.get('ip') or 'sistema')}): "
                f"{markdown_escape(ev.get('description'))}{cmd_suffix}"
            )

    lines.append("")
    return "\n".join(lines)


def build_report_payload(
    storage: HoneyGateStorage,
    honeywall: Optional[Any] = None,
    fmt: str = "json",
    include_full_email: bool = False,
    mode: Optional[int] = None,
    since: Optional[float] = None,
    until: Optional[float] = None,
) -> Tuple[str, bytes]:
    """Construye el informe en `json`, `csv` o `markdown` y retorna `(content_type, body_bytes)`."""
    normalized_fmt = (fmt or "json").strip().lower()
    if normalized_fmt == "md":
        normalized_fmt = "markdown"
    if normalized_fmt not in SUPPORTED_REPORT_FORMATS:
        raise ValueError(f"Formato no soportado '{fmt}'. Use: json, csv o markdown")

    report = collect_report_data(
        storage=storage,
        honeywall=honeywall,
        include_full_email=include_full_email,
        mode=mode,
        since=since,
        until=until,
    )

    if normalized_fmt == "csv":
        return "text/csv; charset=utf-8", render_report_csv(report).encode("utf-8")
    if normalized_fmt == "markdown":
        return "text/markdown; charset=utf-8", render_report_markdown(report).encode("utf-8")
    return "application/json; charset=utf-8", json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
