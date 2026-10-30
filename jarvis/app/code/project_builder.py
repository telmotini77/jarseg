from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from app.code.models import FilePatch, PatchApplyResult, PatchChange
from app.code.patcher import PatchEngine
from app.code.security import protected_file, secret_free, validate_project_path


@dataclass(frozen=True, slots=True)
class ProjectBuildPlan:
    id: str
    objective: str
    name: str
    root: Path
    stack: tuple[str, ...]
    summary: str
    patches: tuple[FilePatch, ...]


class ProjectBuilder:
    """Plans small prompt-driven projects and applies only an approved draft."""

    def __init__(
        self,
        root: Path,
        answerer: Callable[[Sequence[dict[str, str]]], str],
        *,
        max_files: int = 20,
        max_file_chars: int = 40_000,
        patcher: PatchEngine | None = None,
    ) -> None:
        self.root = root.expanduser().resolve()
        self.answerer = answerer
        self.max_files = max_files
        self.max_file_chars = max_file_chars
        self.patcher = patcher or PatchEngine()

    def plan(self, objective: str) -> ProjectBuildPlan:
        cleaned = objective.strip()
        if len(cleaned) < 12:
            raise ValueError("Describe el proyecto con más detalle: objetivo, usuarios y tecnología deseada.")
        raw = self.answerer(self._messages(cleaned))
        payload = self._parse_payload(raw)
        name = self._safe_name(payload.get("name"), cleaned)
        target = self.root / name
        files = payload.get("files")
        if not isinstance(files, list) or not files:
            raise ValueError("La IA no propuso archivos para el proyecto. Reformula el prompt con el tipo de aplicación y sus pantallas o API.")
        if len(files) > self.max_files:
            raise ValueError(f"La propuesta supera el máximo seguro de {self.max_files} archivos.")
        patches: list[FilePatch] = []
        seen: set[Path] = set()
        for item in files:
            if not isinstance(item, dict):
                raise ValueError("La propuesta de archivos no tiene un formato válido.")
            relative = self._safe_relative_path(item.get("path"))
            content = item.get("content")
            if not isinstance(content, str) or not content.strip():
                raise ValueError(f"El archivo {relative} no tiene contenido válido.")
            if len(content) > self.max_file_chars:
                raise ValueError(f"El archivo {relative} supera el límite de tamaño permitido.")
            if not secret_free(content):
                raise ValueError(f"El archivo {relative} parece incluir una credencial. Usa variables de entorno documentadas, sin valores reales.")
            destination = target / relative
            if destination in seen:
                raise ValueError(f"La propuesta repite el archivo {relative}.")
            if not validate_project_path(destination, self.root) or protected_file(destination):
                raise ValueError(f"La ruta {relative} no está permitida para un proyecto generado.")
            seen.add(destination)
            patches.append(FilePatch(destination, None, (PatchChange(1, 0, content),), create=True))
        stack = payload.get("stack", [])
        normalized_stack = tuple(str(item).strip() for item in stack[:8] if isinstance(item, str) and item.strip())
        summary = str(payload.get("summary", cleaned)).strip()[:600]
        return ProjectBuildPlan(str(uuid4()), cleaned, name, target, normalized_stack, summary, tuple(patches))

    def preview(self, plan: ProjectBuildPlan) -> str:
        stack = ", ".join(plan.stack) or "por detectar"
        files = "\n".join(f"- {patch.path.relative_to(plan.root)}" for patch in plan.patches)
        diff = self.patcher.preview(plan.patches, self.root)
        return (
            f"Proyecto propuesto: {plan.name}\nRuta: {plan.root}\nStack: {stack}\n"
            f"Resumen: {plan.summary}\n\nArchivos:\n{files}\n\nDiff previsto:\n{diff}"
        )

    def apply(self, plan: ProjectBuildPlan) -> PatchApplyResult:
        if plan.root.exists():
            raise ValueError("Ya existe una carpeta con ese nombre. No sobrescribiré un proyecto existente.")
        return self.patcher.apply(plan.patches, self.root)

    def _safe_relative_path(self, value: object) -> Path:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Cada archivo necesita una ruta relativa válida.")
        path = Path(value.strip().replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts or path.name in {"", "."}:
            raise ValueError("Los archivos generados deben permanecer dentro del proyecto.")
        if path.suffix.casefold() in {".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1", ".sh"}:
            raise ValueError("La generación de ejecutables o scripts de sistema no está permitida.")
        return path

    @staticmethod
    def _safe_name(value: object, objective: str) -> str:
        source = str(value).strip() if isinstance(value, str) else objective
        slug = re.sub(r"[^a-z0-9]+", "-", source.casefold()).strip("-")[:48]
        if not slug:
            raise ValueError("No pude crear un nombre seguro para el proyecto.")
        return slug

    @staticmethod
    def _parse_payload(raw: str) -> dict[str, object]:
        candidate = raw.strip()
        fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", candidate, flags=re.DOTALL | re.IGNORECASE)
        if fenced:
            candidate = fenced.group(1)
        else:
            start, end = candidate.find("{"), candidate.rfind("}")
            if start >= 0 and end > start:
                candidate = candidate[start : end + 1]
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError as error:
            raise ValueError("La IA no devolvió un borrador estructurado. Intenta de nuevo con más detalle.") from error
        if not isinstance(value, dict):
            raise ValueError("La IA no devolvió un proyecto válido.")
        return value

    @staticmethod
    def _messages(objective: str) -> list[dict[str, str]]:
        return [
            {
                "role": "user",
                "content": (
                    "JARVIS_PROJECT_BUILD_SPEC. Diseña un proyecto pequeño y funcional para esta petición. "
                    "Responde ÚNICAMENTE JSON válido, sin Markdown, con esta forma exacta: "
                    '{"name":"nombre-kebab","stack":["tecnología"],"summary":"resumen",'
                    '"files":[{"path":"README.md","content":"..."}]}. '
                    "Incluye como máximo 20 archivos de texto, un README con instrucciones y una prueba mínima si corresponde. "
                    "No incluyas secretos, binarios, comandos de sistema, archivos .env ni instrucciones para evadir seguridad. "
                    f"Petición del usuario: {objective}"
                ),
            }
        ]
