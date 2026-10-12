"""Sanitización de informes: nunca publicar secretos por accidente."""
from __future__ import annotations
import copy
import re

SENSITIVE_KEY = re.compile(r"(pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|hash|credential|credencial)", re.I)
INLINE = [
    re.compile(r"(?i)(bearer\\s+)[A-Za-z0-9._~+/-]+"),
    re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key)\\s*[:=]\\s*)[^\\s,;]+"),
]
IDENTIFIERS = re.compile(r"(?i)(?:\\b(?:[a-z0-9-]+\\.)+[a-z]{2,}\\b|\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b)")

def sanitize(value, include_identifiers=False):
    """Copia redactada. El modo compartible no expone valores de secretos."""
    if isinstance(value, dict):
        return {k: ("[REDACTADO]" if SENSITIVE_KEY.search(str(k))
                    else sanitize(v, include_identifiers)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(v, include_identifiers) for v in value]
    if isinstance(value, str):
        for pat in INLINE:
            value = pat.sub(lambda m: m.group(1) + "[REDACTADO]", value)
        if not include_identifiers:
            value = IDENTIFIERS.sub("[IDENTIFICADOR]", value)
        return value
    return copy.deepcopy(value)

def shared_report(consolidated, sections=None, include_identifiers=False):
    """Proyección compartible; no modifica ni devuelve las evidencias originales."""
    allowed = set(sections or ("findings", "remediation"))
    result = {"profile": "compartible", "sources_count": len(consolidated.get("sources", []))}
    if "findings" in allowed:
        result["unique_observations"] = sanitize(
            consolidated.get("unique_observations", []), include_identifiers)
    if "remediation" in allowed:
        result["remediation_note"] = "Validar cada observación antes de remediar."
    return result
