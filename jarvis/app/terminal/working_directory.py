from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class WorkingDirectoryManager:
    current_directory: Path
    active_project: str | None = None

    def __post_init__(self) -> None:
        self.current_directory = self._validate(self.current_directory)

    @staticmethod
    def _validate(path: Path) -> Path:
        resolved = path.expanduser().resolve()
        if not resolved.exists() or not resolved.is_dir():
            raise ValueError("La carpeta indicada no existe.")
        return resolved

    def change_to(self, target: str | Path) -> Path:
        candidate = Path(target).expanduser()
        if not candidate.is_absolute():
            if str(target).casefold() in {"documentos", "documents"}:
                candidate = Path.home() / "Documents"
            else:
                candidate = self.current_directory / candidate
        self.current_directory = self._validate(candidate)
        return self.current_directory

    def parent(self) -> Path:
        return self.change_to(self.current_directory.parent)

    def set_project(self, name: str) -> Path:
        normalized = name.casefold().strip()
        # A sibling project (for example Documents/ChatGPT/CyberSeg next to
        # JARVIS) is a normal local workspace, not an arbitrary filesystem scan.
        roots = (self.current_directory, self.current_directory.parent, Path.home() / "Documents")
        for root in roots:
            if not root.exists():
                continue
            for candidate in root.iterdir():
                if candidate.is_dir() and candidate.name.casefold() == normalized:
                    self.current_directory = candidate.resolve()
                    self.active_project = candidate.name
                    return self.current_directory
        raise ValueError("No encontré ese proyecto en la carpeta actual ni en Documentos.")
