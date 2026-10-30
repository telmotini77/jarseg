from __future__ import annotations

import json
from pathlib import Path

from app.code.models import ProjectContext, ProjectFile
from app.code.scanner import ProjectScanner


class ProjectInspector:
    def __init__(self, scanner: ProjectScanner | None = None) -> None:
        self.scanner = scanner or ProjectScanner()

    def inspect(self, root: Path) -> ProjectContext:
        root = root.resolve()
        files = self.scanner.scan(root)
        names = {item.path.relative_to(root).as_posix() for item in files}
        languages = sorted({item.language for item in files if item.language})
        frameworks: set[str] = set()
        managers: set[str] = set()
        if "package.json" in names:
            managers.add("npm")
            package = self._package(root)
            dependencies = {**package.get("dependencies", {}), **package.get("devDependencies", {})} if isinstance(package, dict) else {}
            for dependency, framework in {
                "@nestjs/core": "NestJS", "react": "React", "next": "Next.js", "@angular/core": "Angular",
                "fastapi": "FastAPI", "django": "Django", "@prisma/client": "Prisma",
            }.items():
                if dependency in dependencies:
                    frameworks.add(framework)
        if "nest-cli.json" in names:
            frameworks.add("NestJS")
        if "angular.json" in names:
            frameworks.add("Angular")
        if any(name.startswith("vite.config.") for name in names):
            frameworks.add("Vite")
        if any(name.startswith("next.config.") for name in names):
            frameworks.add("Next.js")
        if "requirements.txt" in names or "pyproject.toml" in names:
            managers.add("pip" if "requirements.txt" in names else "pyproject")
            content = self._read_text(root / "requirements.txt") + self._read_text(root / "pyproject.toml")
            if "fastapi" in content.casefold():
                frameworks.add("FastAPI")
            if "django" in content.casefold():
                frameworks.add("Django")
        if "Cargo.toml" in names:
            managers.add("cargo")
        if "go.mod" in names:
            managers.add("go")
        if "pom.xml" in names or "build.gradle" in names:
            managers.add("maven" if "pom.xml" in names else "gradle")
        entries = [item.path for item in files if item.path.relative_to(root).as_posix() in {"src/main.ts", "src/main.py", "main.py", "app.py", "manage.py", "index.ts", "index.js"}]
        return ProjectContext(
            name=root.name, root_path=root, languages=languages, frameworks=sorted(frameworks),
            package_managers=sorted(managers), git_branch=self._git_branch(root),
            has_tests=any(self._is_test(item, root) for item in files), entry_points=entries, files=files,
        )

    @staticmethod
    def _read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    @staticmethod
    def _package(root: Path) -> dict[str, object]:
        try:
            data = json.loads((root / "package.json").read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    @staticmethod
    def _git_branch(root: Path) -> str | None:
        try:
            head = (root / ".git" / "HEAD").read_text(encoding="utf-8").strip()
            return head.rsplit("/", 1)[-1] if head.startswith("ref: ") else None
        except OSError:
            return None

    @staticmethod
    def _is_test(item: ProjectFile, root: Path) -> bool:
        name = item.path.name.casefold()
        suffixes = (".test.ts", ".test.tsx", ".test.js", ".test.jsx", ".spec.ts", ".spec.tsx", ".spec.js", ".spec.jsx", "_test.py")
        relative_parts = {part.casefold() for part in item.path.relative_to(root).parts}
        return name.startswith("test_") or name.endswith(suffixes) or "tests" in relative_parts
