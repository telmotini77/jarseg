"""Local, defensive threat taxonomy used to enrich CyberSeg alerts.

This is intentionally a classification aid, not an offensive toolkit.  It
maps the wording already emitted by the local IDS to response-oriented threat
families, so alerts remain useful even when the upstream engine has no label.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ThreatFamily:
    """A defensive family and the response focus it implies."""

    identifier: str
    title: str
    response_focus: str
    indicators: tuple[str, ...]


THREAT_FAMILIES: tuple[ThreatFamily, ...] = (
    ThreatFamily("reconnaissance", "Reconocimiento y escaneo", "Revisar exposición, registrar el origen y limitar sondeos repetidos.", ("scan", "escaneo", "recon", "enumeration", "sondeo")),
    ThreatFamily("credential_access", "Acceso a credenciales", "Proteger cuentas afectadas, revisar MFA y conservar evidencias de autenticación.", ("brute force", "fuerza bruta", "credential", "credencial", "password", "login failed", "inicio de sesion fallido", "credential stuffing")),
    ThreatFamily("phishing", "Suplantación y phishing", "Verificar identidad, aislar mensajes sospechosos y revocar sesiones comprometidas.", ("phishing", "suplantacion", "spoofing", "impersonation", "correo malicioso")),
    ThreatFamily("malware", "Malware y ransomware", "Aislar el equipo afectado y activar la respuesta a incidentes con copias verificadas.", ("malware", "ransomware", "trojan", "troyano", "virus", "worm", "gusano")),
    ThreatFamily("web_exploitation", "Explotación de aplicaciones web", "Corregir el componente expuesto, validar registros y aplicar controles de entrada.", ("injection", "inyeccion", "xss", "csrf", "path traversal", "traversal", "rce", "remote code", "web exploit")),
    ThreatFamily("denial_of_service", "Denegación de servicio", "Aplicar límites, mitigación aguas arriba y preservar métricas de disponibilidad.", ("ddos", "dos", "denial of service", "denegacion de servicio", "flood")),
    ThreatFamily("network_interception", "Intercepción de red", "Comprobar cifrado, DNS, certificados y segmentación de la red afectada.", ("man in the middle", "mitm", "arp spoof", "dns spoof", "intercept")),
    ThreatFamily("lateral_movement", "Movimiento lateral", "Aislar el segmento, revisar privilegios y correlacionar accesos entre equipos.", ("lateral movement", "movimiento lateral", "pass the hash", "remote service")),
    ThreatFamily("command_control", "Mando y control", "Bloquear la comunicación confirmada y buscar persistencia en los equipos involucrados.", ("command and control", "c2", "beacon", "callback")),
    ThreatFamily("exfiltration", "Exfiltración de datos", "Restringir la salida, preservar registros y evaluar el alcance de la información.", ("exfiltration", "exfiltracion", "data leak", "fuga de datos", "unusual upload")),
    ThreatFamily("cloud_identity", "Identidad y servicios en la nube", "Revisar tokens, privilegios, registros de auditoría y políticas de acceso.", ("cloud", "oauth", "api key", "access token", "identity")),
    ThreatFamily("supply_chain", "Cadena de suministro", "Validar procedencia, firmas e integridad de componentes y actualizaciones.", ("supply chain", "dependency", "dependencia", "package", "firma invalida", "signature")),
    ThreatFamily("wireless", "Interferencia inalámbrica", "Verificar el enlace físico, espectro, autenticación y equipos autorizados.", ("jamming", "jammer", "interferencia", "wifi deauth", "deauth")),
    ThreatFamily("iot", "Dispositivos IoT", "Aislar el dispositivo, actualizar firmware y rotar sus credenciales de servicio.", ("iot", "esp32", "firmware", "mqtt", "sensor")),
    ThreatFamily("insider", "Riesgo interno", "Aplicar mínimo privilegio y revisar actividad autorizada con el responsable correspondiente.", ("insider", "interno", "privilege abuse", "abuso de privilegios")),
)


def _normalise(value: str) -> str:
    decomposed = unicodedata.normalize("NFD", value.casefold())
    return "".join(char for char in decomposed if unicodedata.category(char) != "Mn")


def classify(text: str) -> tuple[ThreatFamily, ...]:
    """Return every relevant defensive family, in stable priority order."""
    normalised = _normalise(text)
    matches: list[ThreatFamily] = []
    for family in THREAT_FAMILIES:
        if any(re.search(rf"(?<!\w){re.escape(_normalise(indicator))}(?!\w)", normalised) for indicator in family.indicators):
            matches.append(family)
    return tuple(matches)


def coverage_report() -> str:
    """Describe the locally available defensive training coverage."""
    names = ", ".join(family.title.lower() for family in THREAT_FAMILIES)
    return (
        "Cobertura defensiva local de CyberSeg: " + names + ". "
        "Esta base clasifica alertas y sugiere contención; no ejecuta ni genera ataques."
    )


def enrich_alerts(alerts: str) -> str:
    """Append concise response-oriented labels to human-readable IDS rows."""
    enriched: list[str] = []
    for line in alerts.splitlines():
        families = classify(line)
        if families and ("[" in line or "severidad" in _normalise(line)):
            labels = ", ".join(family.title for family in families)
            enriched.append(f"{line} [Clasificación: {labels}]")
        else:
            enriched.append(line)
    return "\n".join(enriched)
