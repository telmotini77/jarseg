"""Índice local de proyectos. Solo inspecciona nombres/metadatos no sensibles."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from app.memory.models import ProjectMemory
from app.memory.repository import MemoryRepository


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return slug or "proyecto"


class ProjectMemoryService:
    def __init__(self, repository: MemoryRepository) -> None:
        self.repository = repository

    def index(self, root: str | Path, name: str | None = None) -> ProjectMemory:
        path = Path(root).resolve()
        project_name = name or path.name
        technologies: set[str] = set()
        metadata: dict[str, object] = {"files": []}
        evidence = metadata["files"]
        for filename, technology in {
            "pyproject.toml": "Python",
            "requirements.txt": "Python",
            "package.json": "Node.js",
            "docker-compose.yml": "Docker",
            "docker-compose.yaml": "Docker",
            "Dockerfile": "Docker",
            "Cargo.toml": "Rust",
            "go.mod": "Go",
            "pom.xml": "Java",
        }.items():
            candidate = path / filename
            if candidate.is_file():
                technologies.add(technology)
                evidence.append(filename)
        package = path / "package.json"
        if package.is_file():
            try:
                data = json.loads(package.read_text(encoding="utf-8"))
                dependencies = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for dependency, technology in {"react": "React", "vite": "Vite", "electron": "Electron"}.items():
                    if dependency in dependencies:
                        technologies.add(technology)
            except (OSError, ValueError):
                pass
        now = datetime.now(timezone.utc)
        project = ProjectMemory(
            id=slugify(project_name), name=project_name, root_path=str(path), technologies=tuple(sorted(technologies)),
            metadata=metadata, created_at=now, updated_at=now,
        )
        return self.repository.upsert_project(project)
