from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.code.project_builder import ProjectBuilder


def _answerer(_messages):
    return json.dumps({
        "name": "inventario-local",
        "stack": ["Python", "FastAPI"],
        "summary": "API local para registrar productos.",
        "files": [
            {"path": "README.md", "content": "# Inventario local\n\nEjecuta `py main.py`.\n"},
            {"path": "main.py", "content": "def health() -> str:\n    return 'ok'\n"},
            {"path": "tests/test_main.py", "content": "from main import health\n\ndef test_health():\n    assert health() == 'ok'\n"},
        ],
    })


def test_project_builder_previews_then_creates_only_approved_files(tmp_path: Path) -> None:
    builder = ProjectBuilder(tmp_path / "generated", _answerer)
    plan = builder.plan("Crea un proyecto para administrar inventario local de una tienda")
    assert plan.name == "inventario-local"
    assert not plan.root.exists()
    preview = builder.preview(plan)
    assert "main.py" in preview and "Proyecto propuesto" in preview
    result = builder.apply(plan)
    assert result.changed_files
    assert (plan.root / "main.py").read_text(encoding="utf-8").startswith("def health")


def test_project_builder_blocks_paths_and_secrets_from_model_output(tmp_path: Path) -> None:
    def unsafe_answerer(_messages):
        return json.dumps({
            "name": "unsafe",
            "files": [{"path": "../outside.py", "content": "print('no')"}],
        })

    with pytest.raises(ValueError, match="dentro del proyecto"):
        ProjectBuilder(tmp_path, unsafe_answerer).plan("Crea un proyecto de demostración seguro")

    def secret_answerer(_messages):
        return json.dumps({
            "name": "secret-project",
            "files": [{"path": "main.py", "content": "API_KEY='secret-value'"}],
        })

    with pytest.raises(ValueError, match="credencial"):
        ProjectBuilder(tmp_path, secret_answerer).plan("Crea un proyecto de demostración seguro")
