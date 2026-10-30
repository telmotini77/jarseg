from __future__ import annotations

import json
import re
from pathlib import Path


def dependencies_for_project(root: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    package = root / "package.json"
    if package.is_file():
        try:
            data = json.loads(package.read_text(encoding="utf-8"))
            result["npm"] = sorted({*data.get("dependencies", {}), *data.get("devDependencies", {})})
        except (OSError, ValueError, TypeError):
            result["npm"] = []
    requirements = root / "requirements.txt"
    if requirements.is_file():
        try:
            result["pip"] = [re.split(r"[<>=!~\[]", line.strip(), maxsplit=1)[0] for line in requirements.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
        except OSError:
            result["pip"] = []
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            content = pyproject.read_text(encoding="utf-8")
            result["pyproject"] = re.findall(r"['\"]([A-Za-z0-9_.-]+)(?:[<>=!~][^'\"]*)?['\"]", content)
        except OSError:
            result["pyproject"] = []
    return result


def has_dependency(root: Path, name: str) -> bool:
    target = name.casefold()
    return any(target == dependency.casefold() for dependencies in dependencies_for_project(root).values() for dependency in dependencies)
