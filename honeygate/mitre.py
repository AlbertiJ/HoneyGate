"""
================================================================================
HONEYGATE MITRE LOADER: Reglas MITRE ATT&CK Externalizadas (mitre_rules.json)
Carga y valida al arrancar las definiciones de técnicas, reglas por tipo de evento
y reglas por patrón de comando/ruta para ampliar el mapeo sin tocar código.
================================================================================
"""

import os
import re
import json
from typing import Any, Dict, List, Optional

DEFAULT_MITRE_RULES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "mitre_rules.json",
)
RE_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class MitreRulesEngine:
    """Cargador y validador estricto de reglas MITRE ATT&CK desde JSON."""

    def __init__(self, rules_path: Optional[str] = None):
        env_path = os.environ.get("HONEYGATE_MITRE_RULES_PATH", "").strip()
        self.rules_path = rules_path or env_path or DEFAULT_MITRE_RULES_PATH
        self.version: int = 1
        self.techniques: Dict[str, Dict[str, str]] = {}
        self.event_type_rules: Dict[str, str] = {}
        self.command_rules: List[Dict[str, Any]] = []
        self.reload(self.rules_path)

    def reload(self, rules_path: Optional[str] = None) -> None:
        target_path = rules_path or self.rules_path
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Archivo de reglas MITRE no encontrado: {target_path}")

        with open(target_path, "r", encoding="utf-8") as fh:
            try:
                raw = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSON inválido en reglas MITRE ({target_path}): {exc}") from exc

        if not isinstance(raw, dict):
            raise ValueError("La raíz de mitre_rules.json debe ser un objeto JSON")

        version = raw.get("version")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ValueError("El campo 'version' de mitre_rules.json debe ser entero >= 1")

        raw_techs = raw.get("techniques")
        if not isinstance(raw_techs, dict) or not raw_techs:
            raise ValueError("El campo 'techniques' debe ser un objeto JSON no vacío")

        validated_techs: Dict[str, Dict[str, str]] = {}
        for tid, info in raw_techs.items():
            if not isinstance(tid, str) or not RE_TECHNIQUE_ID.match(tid):
                raise ValueError(f"ID de técnica MITRE inválido: {tid!r}")
            if not isinstance(info, dict):
                raise ValueError(f"Definición de técnica MITRE {tid} debe ser un objeto JSON")
            name = str(info.get("name", "")).strip()
            tactic = str(info.get("tactic", "")).strip()
            if not name or not tactic:
                raise ValueError(f"Técnica MITRE {tid} requiere 'name' y 'tactic' no vacíos")
            validated_techs[tid] = {"name": name, "tactic": tactic}

        raw_ev_rules = raw.get("event_type_rules")
        if not isinstance(raw_ev_rules, dict):
            raise ValueError("El campo 'event_type_rules' debe ser un objeto JSON")

        validated_ev_rules: Dict[str, str] = {}
        for ev_key, tech_id in raw_ev_rules.items():
            if not isinstance(ev_key, str) or not ev_key.strip():
                raise ValueError(f"Clave inválida en 'event_type_rules': {ev_key!r}")
            if not isinstance(tech_id, str):
                raise ValueError(f"Valor MITRE inválido para evento {ev_key}: {tech_id!r}")
            if tech_id != "" and tech_id not in validated_techs:
                raise ValueError(
                    f"Evento {ev_key} referencia técnica MITRE no declarada: {tech_id!r}"
                )
            validated_ev_rules[ev_key.strip()] = tech_id

        raw_cmd_rules = raw.get("command_rules", [])
        if not isinstance(raw_cmd_rules, list):
            raise ValueError("El campo 'command_rules' debe ser una lista JSON")

        validated_cmd_rules: List[Dict[str, Any]] = []
        seen_ids = set()
        for idx, rule in enumerate(raw_cmd_rules):
            if not isinstance(rule, dict):
                raise ValueError(f"Regla de comando #{idx} debe ser un objeto JSON")
            rule_id = str(rule.get("id", "")).strip()
            pattern = rule.get("pattern")
            tech_id = rule.get("technique")
            services = rule.get("services")

            if not rule_id or rule_id in seen_ids:
                raise ValueError(f"ID de regla MITRE inválido o duplicado: {rule_id!r}")
            if not isinstance(pattern, str) or not pattern:
                raise ValueError(f"Regla {rule_id} requiere 'pattern' regex no vacío")
            if not isinstance(tech_id, str) or tech_id not in validated_techs:
                raise ValueError(f"Regla {rule_id} referencia técnica MITRE inválida: {tech_id!r}")
            if not isinstance(services, list) or not services or not all(isinstance(s, str) and s.strip() for s in services):
                raise ValueError(f"Regla {rule_id} requiere lista no vacía 'services'")

            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(f"Regex inválido en regla {rule_id}: {exc}") from exc

            seen_ids.add(rule_id)
            validated_cmd_rules.append({
                "id": rule_id,
                "services": {s.strip().lower() for s in services},
                "regex": compiled,
                "technique": tech_id,
            })

        self.rules_path = target_path
        self.version = version
        self.techniques = validated_techs
        self.event_type_rules = validated_ev_rules
        self.command_rules = validated_cmd_rules

    def resolve_event(self, event_type: str, default: str = "") -> str:
        return self.event_type_rules.get(event_type, default)

    def resolve_command(self, service: str, command_text: str, default_event_type: str) -> str:
        svc = (service or "").strip().lower()
        text = (command_text or "").strip()
        if text:
            for rule in self.command_rules:
                if "*" in rule["services"] or svc in rule["services"]:
                    if rule["regex"].search(text):
                        return rule["technique"]
        return self.resolve_event(default_event_type, "")

    def describe_technique(self, tech_id: str) -> Dict[str, str]:
        info = self.techniques.get(tech_id)
        if info:
            return {"technique": tech_id, "name": info["name"], "tactic": info["tactic"]}
        return {"technique": tech_id, "name": "Desconocida", "tactic": "Desconocida"}


_DEFAULT_ENGINE: Optional[MitreRulesEngine] = None


def get_mitre_engine() -> MitreRulesEngine:
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = MitreRulesEngine()
    return _DEFAULT_ENGINE


def validate_and_load_mitre_rules(rules_path: Optional[str] = None) -> MitreRulesEngine:
    return MitreRulesEngine(rules_path=rules_path)


# Validar reglas al importar el módulo durante el arranque del daemon
get_mitre_engine()
