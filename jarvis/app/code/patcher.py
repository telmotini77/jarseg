from __future__ import annotations

import hashlib
from pathlib import Path

from app.code.diff import unified_diff
from app.code.models import FilePatch, PatchApplyResult
from app.code.security import protected_file, secret_free, validate_project_path


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class PatchEngine:
    def render(self, patch: FilePatch, root: Path) -> tuple[str, str]:
        if not validate_project_path(patch.path, root):
            raise ValueError("El parche intenta salir del proyecto activo.")
        if protected_file(patch.path):
            raise ValueError("No se modifica un archivo protegido.")
        before = "" if patch.create else patch.path.read_text(encoding="utf-8", errors="replace")
        if not patch.create and patch.original_hash != content_hash(before):
            raise ValueError("El archivo cambió desde que fue analizado. No aplicaré el parche automáticamente.")
        lines = before.splitlines(keepends=True)
        offset = 0
        for change in sorted(patch.changes, key=lambda item: item.start_line):
            if change.start_line < 1 or change.end_line < change.start_line - 1:
                raise ValueError("El cambio de parche no tiene un rango válido.")
            replacement = change.replacement
            if not secret_free(replacement):
                raise ValueError("El parche contiene un secreto o credencial y fue bloqueado.")
            start = change.start_line - 1 + offset
            end = change.end_line + offset
            replacement_lines = replacement.splitlines(keepends=True)
            if replacement and not replacement.endswith("\n"):
                replacement_lines[-1:] = [replacement_lines[-1] + "\n"]
            lines[start:end] = replacement_lines
            offset += len(replacement_lines) - (end - start)
        return before, "".join(lines)

    def preview(self, patches: tuple[FilePatch, ...], root: Path) -> str:
        return "\n".join(unified_diff(patch.path, *self.render(patch, root), root=root) for patch in patches)

    def apply(self, patches: tuple[FilePatch, ...], root: Path) -> PatchApplyResult:
        rendered = [(patch, *self.render(patch, root)) for patch in patches]
        originals: dict[Path, str | None] = {}
        changed: list[Path] = []
        try:
            for patch, before, after in rendered:
                patch.path.parent.mkdir(parents=True, exist_ok=True)
                originals[patch.path] = None if patch.create else before
                patch.path.write_text(after, encoding="utf-8", newline="\n")
                changed.append(patch.path)
        except OSError as error:
            for path, original in originals.items():
                try:
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        path.write_text(original, encoding="utf-8", newline="\n")
                except OSError:
                    continue
            raise ValueError(f"No se pudo aplicar el parche; restauré los cambios propios: {error}") from error
        diff = "\n".join(unified_diff(patch.path, before, after, root=root) for patch, before, after in rendered)
        return PatchApplyResult(tuple(changed), diff, f"Apliqué cambios en {len(changed)} archivo(s).")
