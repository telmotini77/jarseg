from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.code.language_detector import detect_language
from app.code.models import ProjectFile
from app.code.security import protected_file


DEFAULT_EXCLUDED = frozenset({"node_modules", ".venv", "venv", "dist", "build", "coverage", ".next", ".git", ".cache", "__pycache__", "vendor"})


@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_files: int = 2_000
    max_file_size: int = 1_000_000
    max_total_bytes: int = 8_000_000
    respect_gitignore: bool = True


class ProjectScanner:
    def __init__(self, limits: ScanLimits | None = None) -> None:
        self.limits = limits or ScanLimits()

    @staticmethod
    def _gitignore_patterns(root: Path) -> list[str]:
        try:
            return [line.strip().rstrip("/") for line in (root / ".gitignore").read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
        except OSError:
            return []

    def scan(self, root: Path) -> list[ProjectFile]:
        root = root.resolve()
        if not root.is_dir():
            raise ValueError("El proyecto no existe o no es una carpeta.")
        patterns = self._gitignore_patterns(root) if self.limits.respect_gitignore else []
        files: list[ProjectFile] = []
        total = 0
        for current, directories, names in os.walk(root):
            current_path = Path(current)
            directories[:] = [name for name in directories if name not in DEFAULT_EXCLUDED]
            for name in names:
                path = current_path / name
                relative = path.relative_to(root).as_posix()
                if protected_file(path) or any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(name, pattern) for pattern in patterns):
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                if stat.st_size > self.limits.max_file_size or total + stat.st_size > self.limits.max_total_bytes:
                    continue
                files.append(ProjectFile(path, detect_language(path), stat.st_size, datetime.fromtimestamp(stat.st_mtime, timezone.utc)))
                total += stat.st_size
                if len(files) >= self.limits.max_files:
                    return files
        return files
