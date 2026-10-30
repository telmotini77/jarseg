from __future__ import annotations

from pathlib import Path


_EXTENSIONS = {
    ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript", ".jsx": "JavaScript",
    ".py": "Python", ".cs": "C#", ".java": "Java", ".c": "C/C++", ".h": "C/C++",
    ".cpp": "C/C++", ".cc": "C/C++", ".hpp": "C/C++", ".ino": "Arduino/C++", ".html": "HTML", ".htm": "HTML",
    ".css": "CSS", ".scss": "CSS", ".sql": "SQL", ".json": "JSON", ".yaml": "YAML",
    ".yml": "YAML", ".md": "Markdown", ".rs": "Rust", ".go": "Go", ".php": "PHP",
    ".rb": "Ruby", ".kt": "Kotlin", ".swift": "Swift", ".vue": "Vue",
}


def detect_language(path: Path) -> str | None:
    if path.name == "Dockerfile":
        return "Dockerfile"
    return _EXTENSIONS.get(path.suffix.casefold())
