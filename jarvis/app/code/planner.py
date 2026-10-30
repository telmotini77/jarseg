from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from app.code.models import CodeChangePlan, CodeRiskLevel, FilePatch, PatchChange, ProjectContext
from app.code.security import patch_risk


class ChangePlanner:
    def plan(self, objective: str, project: ProjectContext) -> CodeChangePlan:
        lowered = objective.casefold()
        creates: list[Path] = []
        patches: list[FilePatch] = []
        validation = ["Revisar el diff", "Ejecutar las validaciones disponibles"]
        if "servicio" in lowered and "nest" in " ".join(project.frameworks).casefold():
            name = self._entity_name(lowered, "servicio")
            directory = project.root_path / "src" / name
            path = directory / f"{name}.service.ts"
            creates.append(path)
            class_name = "".join(piece.capitalize() for piece in name.replace("-", " ").split()) + "Service"
            content = "import { Injectable } from '@nestjs/common';\n\n@Injectable()\nexport class " + class_name + " {\n}\n"
            patches.append(FilePatch(path, None, (PatchChange(1, 0, content),), create=True))
            validation.insert(0, "Verificar que el módulo NestJS registre el servicio")
        elif "test" in lowered or "prueba" in lowered:
            name = self._entity_name(lowered, "test")
            path = project.root_path / "tests" / f"{name}.test.py"
            creates.append(path)
            content = f"def test_{name.replace('-', '_')}():\n    assert True\n"
            patches.append(FilePatch(path, None, (PatchChange(1, 0, content),), create=True))
            validation.insert(0, "Ejecutar el test creado")
        files = list(creates)
        risk = patch_risk(files) if files else CodeRiskLevel.CONFIRMATION
        return CodeChangePlan(str(uuid4()), objective, [], creates, [], validation, risk, tuple(patches))

    @staticmethod
    def _entity_name(text: str, fallback: str) -> str:
        words = text.replace(".", " ").split()
        for index, word in enumerate(words):
            if word in {"servicio", "test", "prueba"} and index + 1 < len(words):
                return "".join(char for char in words[index + 1] if char.isalnum() or char == "-").casefold() or fallback
        return fallback
