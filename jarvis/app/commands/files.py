from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

from app.commands.base import CommandResult
from app.commands.classifier import normalize_text

MAX_FILES = 20

FOLDER_ALIASES: dict[str, str] = {
    "escritorio": "desktop", "desktop": "desktop",
    "documentos": "documents", "documents": "documents",
    "descargas": "downloads", "downloads": "downloads",
    "imagenes": "pictures", "fotos": "pictures", "pictures": "pictures",
    "videos": "videos", "video": "videos",
    "musica": "music", "music": "music",
}

FOLDER_NAMES: dict[str, str] = {
    "desktop": "Escritorio", "documents": "Documentos", "downloads": "Descargas",
    "pictures": "Imágenes", "videos": "Videos", "music": "Música",
}


def resolve_folder(target: str | None, home: Path | None = None) -> Path | None:
    if not target:
        return None
    key = FOLDER_ALIASES.get(normalize_text(target))
    if key is None:
        return None
    root = home or Path.home()
    return {
        "desktop": root / "Desktop", "documents": root / "Documents", "downloads": root / "Downloads",
        "pictures": root / "Pictures", "videos": root / "Videos", "music": root / "Music",
    }[key]


class FileService:
    def open_folder(self, target: str | None) -> CommandResult:
        path = resolve_folder(target)
        if path is None:
            return CommandResult(False, "Esa carpeta no está en la lista de carpetas conocidas.")
        if not path.exists():
            return CommandResult(False, "No encontré esa carpeta.")
        try:
            if platform.system() == "Windows":
                os.startfile(str(path))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(path)], shell=False)
        except OSError:
            return CommandResult(False, "No pude abrir esa carpeta.")
        return CommandResult(True, f"Abriendo {self._display_name(target)}.")

    def list_files(self, target: str | None) -> CommandResult:
        path = resolve_folder(target)
        if path is None:
            return CommandResult(False, "Esa carpeta no está en la lista de carpetas conocidas.")
        if not path.exists():
            return CommandResult(False, "No encontré esa carpeta.")
        try:
            entries = sorted(path.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))
        except OSError:
            return CommandResult(False, "No pude leer esa carpeta.")
        folder_name = self._display_name(target)
        if not entries:
            return CommandResult(True, f"La carpeta {folder_name} está vacía.")
        shown = entries[:MAX_FILES]
        lines = [f"Encontré {len(entries)} elementos en {folder_name}."]
        if len(entries) > MAX_FILES:
            lines.append(f"Mostraré los primeros {MAX_FILES}.")
        lines.extend(f"{index}. {entry.name}" for index, entry in enumerate(shown, start=1))
        return CommandResult(True, "\n".join(lines))

    def search_files(self, target: str | None, query: str) -> CommandResult:
        """Search file names only inside an allow-listed user folder.

        No arbitrary path, file content, or network location is accepted here.
        """
        path = resolve_folder(target)
        term = query.strip()
        if path is None:
            return CommandResult(False, "Indica una carpeta local conocida, como Documentos o Descargas.")
        if not term:
            return CommandResult(False, "Indica el nombre del archivo que quieres buscar.")
        if not path.exists():
            return CommandResult(False, "No encontré esa carpeta.")
        matches: list[str] = []
        try:
            for entry in path.rglob("*"):
                if term.casefold() in entry.name.casefold():
                    matches.append(str(entry.relative_to(path)))
                    if len(matches) >= MAX_FILES:
                        break
        except OSError:
            return CommandResult(False, "No pude buscar en esa carpeta local.")
        if not matches:
            return CommandResult(True, f"No encontré archivos locales con '{term}' en {self._display_name(target)}.")
        return CommandResult(True, f"Archivos locales encontrados en {self._display_name(target)}:\n" + "\n".join(
            f"{index}. {item}" for index, item in enumerate(matches, 1)
        ))

    @staticmethod
    def _display_name(target: str | None) -> str:
        key = FOLDER_ALIASES.get(normalize_text(target or ""), "")
        return FOLDER_NAMES.get(key, "esa carpeta")
