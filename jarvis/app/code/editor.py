from __future__ import annotations

from pathlib import Path

from app.code.models import FilePatch, PatchApplyResult, PatchChange
from app.code.patcher import PatchEngine, content_hash
from app.code.security import protected_file, validate_project_path


class CodeEditor:
    def __init__(self, patcher: PatchEngine | None = None) -> None:
        self.patcher = patcher or PatchEngine()

    def create_file(self, path: Path, content: str, root: Path) -> PatchApplyResult:
        if path.exists():
            raise ValueError("El archivo ya existe; no lo sobrescribiré.")
        return self.patcher.apply((FilePatch(path, None, (PatchChange(1, 0, content),), create=True),), root)

    def replace_block(self, path: Path, start_line: int, end_line: int, replacement: str, root: Path) -> PatchApplyResult:
        before = path.read_text(encoding="utf-8", errors="replace")
        patch = FilePatch(path, content_hash(before), (PatchChange(start_line, end_line, replacement),))
        return self.patcher.apply((patch,), root)

    def rename_file(self, source: Path, target: Path, root: Path) -> Path:
        if not validate_project_path(source, root) or not validate_project_path(target, root) or protected_file(source) or target.exists():
            raise ValueError("El renombrado no es seguro o el destino ya existe.")
        source.rename(target)
        return target

    def delete_file(self, path: Path, root: Path) -> None:
        if not validate_project_path(path, root) or protected_file(path) or not path.is_file():
            raise ValueError("No se puede borrar ese archivo.")
        path.unlink()
