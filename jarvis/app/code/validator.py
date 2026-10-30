from __future__ import annotations

import json
from pathlib import Path

from app.code.models import ProjectContext, ValidationPlan


class CodeValidator:
    def available(self, project: ProjectContext) -> ValidationPlan:
        commands: list[tuple[str, ...]] = []
        labels: list[str] = []
        package = self._package_scripts(project.root_path)
        for script, label in (("lint", "lint"), ("typecheck", "typecheck"), ("test", "tests"), ("build", "build")):
            if script in package:
                commands.append(("npm", "run", script) if script != "test" else ("npm", "test"))
                labels.append(label)
        if (project.root_path / "pytest.ini").is_file() or any(item.language == "Python" for item in project.files):
            if "tests" not in labels:
                commands.append(("pytest",))
                labels.append("tests")
        if (project.root_path / "pyproject.toml").is_file():
            content = (project.root_path / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
            if "ruff" in content:
                commands.append(("python", "-m", "ruff", "check", "."))
                labels.append("lint")
        return ValidationPlan(tuple(commands), tuple(labels))

    @staticmethod
    def _package_scripts(root: Path) -> dict[str, str]:
        try:
            data = json.loads((root / "package.json").read_text(encoding="utf-8"))
            scripts = data.get("scripts", {})
            return {str(key): str(value) for key, value in scripts.items()} if isinstance(scripts, dict) else {}
        except (OSError, ValueError):
            return {}
