from __future__ import annotations

import re
import unicodedata

from app.commands.base import RouteType


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFD", text.lower())
    without_accents = "".join(char for char in normalized if unicodedata.category(char) != "Mn")
    return re.sub(r"\s+", " ", without_accents).strip(" .,!¿?¡")


class IntentClassifier:
    """Deterministic intent classifier for the supported Windows command grammar."""

    _command_patterns = (
        r"^(?:jarvis[ ,]*)?(?:dime|muestrame|muestra|activa|desactiva|crea|ejecuta|revisa|corrige|busca|abre)\b.*\b(?:agentes?|orquestador|modo asistido|modo solo lectura|modo autonomo|modo autónomo|automatizaciones?|documentacion oficial|documentación oficial|quedo pendiente|quedó pendiente)\b",
        r"^(?:jarvis[ ,]*)?(?:abre|abri|cierra|cerrar|busca|buscar|lista|listar|recuerda|guard[aá]|acuerdate|acuérdate|olvida|elimina|borra|recuerdame|cancela|completa|marca|crea|agrega|anade|añade)\b",
        r"^(?:jarvis[ ,]*)?(?:mira|captura|analiza|cambia|minimiza|maximiza|restaura|vuelve|ve|mueve|haz|clic|click|pulsa|desplazate|escribe|presiona|guarda|copia|pega|selecciona|recarga|resume|lee|envia|enviar|confirma|publica|publicar)\b",
        r"^(?:jarvis[ ,]*)?(?:sube|baja|pon|silencia|activa)\b.*\b(?:volumen|sonido|computador)?",
        r"^(?:jarvis[ ,]*)?(?:dime|muestrame|lista|listar|cual es|cuanto|que|que ventana|donde)\b.*\b(?:cpu|ram|memoria|disco|espacio|estado|pantalla|ventana|ventanas|mouse|recuerdos|recordatorios|pendiente|proyectos|editor|aplicaciones|programas)\b",
        r"^(?:jarvis[ ,]*)?(?:dime|muestrame|que dice|cuales son|hay)\b.*\b(?:pagina|pestanas?|enlaces?|resultados?|requisitos?|tecnologias?|codigo)\b",
        r"^(?:jarvis[ ,]*)?dime los puntos principales$",
        r"^(?:jarvis[ ,]*)?(?:salir|cerrar|detener|detente|cancela|para)$",
        r"^(?:jarvis[ ,]*)?(?:analiza|revisa|corrige|explicame|explica|encuentra|aplica)\b.*\b(?:proyecto|arquitectura|codigo|código|archivo|metodo|método|error|service|login|jwt|prisma|cambios|plan)\b",
        r"^(?:jarvis[ ,]*)?(?:dime|muestrame|muestra|que|que stack|donde)\b.*\b(?:stack|estructura|organizado|dependencias|authservice|login|prismaservice|archivo|archivos modificados|diff)\b",
        r"^(?:jarvis[ ,]*)?(?:crea|agrega|ejecuta|abre)\b.*\b(?:servicio|test|prueba|endpoint|build|lint|vs code|visual studio code|proyecto)\b",
        r"^(?:jarvis[ ,]*)?(?:conecta|desconecta|registra|monitoriza|monitorea|enciende|apaga|pon|activa|desactiva|deten)\b.*\b(?:mqtt|iot|esp32|dispositivo|led|luz|relay|rele|buzzer|servo|automatizacion|regla|sensor)\b",
        r"^(?:jarvis[ ,]*)?(?:dime|muestrame|muestra|cual fue|cuando fue|que)\b.*\b(?:mqtt|iot|esp32|dispositivos?|temperatura|humedad|ldr|telemetria|lecturas?|automatizaciones?|estado del led)\b",
        r"^(?:jarvis[ ,]*)?(?:esta|está)\b.*\b(?:esp32|mqtt|iot)\b.*\b(?:conectado|online)\b",
        r"^(?:jarvis[ ,]*)?(?:avisame|avísame|si)\b.*\b(?:temperatura|humedad|ldr|luz)\b.*\b(?:supera|mayor|baja|menor)\b",
        r"^(?:jarvis[ ,]*)?comprueba\b.*\b(?:arduino|platformio)\b",
        r"^(?:jarvis[ ,]*)?(?:dime|muestrame|muestra)\b.*\b(?:sensor|lecturas?|telemetria)\b",
        r"^(?:jarvis[ ,]*)?(?:dime|muestrame|muestra|inicia|deten|detiene|revisa)\b.*\bcyberseg\b",
    )
    _terminal_patterns = (
        r"^(?:jarvis[ ,]*)?(?:ejecuta|ejecutar|instala|instalar|inicia|iniciar)\b.*\b(?:git|python|py|pip|node|npm|pytest|docker|requirements|dependencias|tests?|build|entorno|backend)\b",
        r"^(?:jarvis[ ,]*)?(?:crea)\b.*\bentorno virtual\b",
        r"^(?:jarvis[ ,]*)?(?:dime|muestrame|que)\b.*\b(?:version de python|version de node|git.*instalado|docker.*instalado|rama|commits|archivos.*modificados|procesos.*node|procesos.*iniciado|scripts.*(?:package|proyecto)|donde estoy|salida.*backend|error completo|que harias)\b",
        r"^(?:jarvis[ ,]*)?(?:entra|ve)\s+(?:a )?(?:documentos|documents)\b",
        r"^(?:jarvis[ ,]*)?(?:cambia al proyecto|establece)\b",
        r"^(?:jarvis[ ,]*)?(?:abre la terminal|abre powershell|deten(?:e)? el backend|diagnostica este error|modo solo lectura|activa modo)\b",
        r"^(?:jarvis[ ,]*)?(?:formatea|format|diskpart|borra todo|elimina todo|remove-item|rmdir|shutdown)\b",
    )

    def classify(self, text: str) -> RouteType:
        normalized = normalize_text(text)
        if any(re.search(pattern, normalized) for pattern in self._terminal_patterns):
            return RouteType.TERMINAL_COMMAND
        if any(re.search(pattern, normalized) for pattern in self._command_patterns):
            return RouteType.COMMAND
        return RouteType.CONVERSATION
