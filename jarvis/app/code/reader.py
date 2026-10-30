from __future__ import annotations

from pathlib import Path

from app.code.models import CodeSymbol
from app.code.security import may_read, validate_project_path


class CodeReader:
    def __init__(self, max_bytes: int = 1_000_000) -> None:
        self.max_bytes = max_bytes

    def read(self, path: Path, root: Path) -> str:
        self._validate(path, root)
        if path.stat().st_size > self.max_bytes:
            raise ValueError("El archivo supera el límite de lectura segura.")
        return path.read_text(encoding="utf-8", errors="replace")

    def read_range(self, path: Path, root: Path, start: int, end: int) -> str:
        if start < 1 or end < start:
            raise ValueError("El rango solicitado no es válido.")
        return "\n".join(self.read(path, root).splitlines()[start - 1:end])

    def read_symbol(self, symbol: CodeSymbol, root: Path, context_lines: int = 20) -> str:
        return self.read_range(symbol.path, root, max(1, symbol.line - 1), symbol.end_line or symbol.line + context_lines)

    @staticmethod
    def _validate(path: Path, root: Path) -> None:
        if not validate_project_path(path, root):
            raise ValueError("La ruta está fuera del proyecto activo.")
        if not may_read(path):
            raise ValueError("Ese archivo contiene datos protegidos y no se leerá automáticamente.")
