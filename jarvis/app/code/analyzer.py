from __future__ import annotations

from app.code.dependencies import dependencies_for_project
from app.code.models import CodeReviewFinding, ProjectContext
from app.code.reader import CodeReader
from app.code.symbols import extract_symbols


class CodeAnalyzer:
    def __init__(self, reader: CodeReader | None = None) -> None:
        self.reader = reader or CodeReader()

    def architecture(self, project: ProjectContext) -> str:
        stack = ", ".join([*project.frameworks, *project.languages]) or "no detectado"
        top = sorted({item.path.relative_to(project.root_path).parts[0] for item in project.files if len(item.path.relative_to(project.root_path).parts) > 1})[:15]
        return f"Proyecto {project.name}. Stack: {stack}. Gestores: {', '.join(project.package_managers) or 'no detectados'}. Estructura principal: {', '.join(top) or 'sin carpetas relevantes'}."

    def explain_file(self, path, project: ProjectContext) -> str:
        content = self.reader.read(path, project.root_path)
        symbols = extract_symbols(path, content)
        labels = ", ".join(f"{symbol.kind} {symbol.name}" for symbol in symbols[:12]) or "sin símbolos estáticos detectados"
        return f"{path.relative_to(project.root_path)} tiene {len(content.splitlines())} líneas. Símbolos: {labels}."

    def dependencies(self, project: ProjectContext) -> str:
        dependencies = dependencies_for_project(project.root_path)
        if not dependencies:
            return "No encontré manifiestos de dependencias compatibles."
        return "\n".join(f"{manager}: {', '.join(items[:25]) or 'sin dependencias detectadas'}" for manager, items in dependencies.items())

    def review(self, project: ProjectContext) -> list[CodeReviewFinding]:
        findings: list[CodeReviewFinding] = []
        markers = {"eval(": "Uso de eval; valida que no procese entrada no confiable.", "SELECT ": "Consulta SQL detectada; revisa que use parámetros.", "password=": "Posible credencial hardcodeada; se omitió su valor."}
        for item in project.files:
            try:
                content = self.reader.read(item.path, project.root_path)
            except (OSError, ValueError):
                continue
            for number, line in enumerate(content.splitlines(), 1):
                for marker, message in markers.items():
                    if marker.casefold() in line.casefold():
                        findings.append(CodeReviewFinding("warning", message, item.path, number))
        return findings[:20]
