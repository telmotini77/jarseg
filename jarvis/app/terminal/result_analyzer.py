from __future__ import annotations

import re

from app.terminal.models import TerminalCommand, TerminalCommandResult
from app.terminal.security import display_command, redact_text


def summarize_result(command: TerminalCommand, result: TerminalCommandResult) -> str:
    if result.timed_out:
        return "El comando superó el tiempo máximo permitido y fue detenido de forma controlada."
    if result.success:
        pytest_match = re.search(r"(\d+) passed(?:, (\d+) failed)?", result.stdout, re.IGNORECASE)
        if pytest_match:
            passed, failed = pytest_match.groups(default="0")
            return f"Los tests finalizaron: {passed} correctos y {failed} fallidos."
        git_lines = [line for line in result.stdout.splitlines() if line.strip()]
        if command.executable.casefold() == "git" and command.args and command.args[0] == "status":
            changed = sum(1 for line in git_lines if not line.startswith("##"))
            branch = next((line[3:].split("...", 1)[0] for line in git_lines if line.startswith("##")), None)
            return f"Estás en la rama {branch or 'actual'}. Tienes {changed} archivos con cambios o sin seguimiento."
        preview = redact_text("\n".join(git_lines[:6]))
        return f"El comando finalizó correctamente en {result.duration:.2f} s." + (f"\n{preview}" if preview else "")
    detail = redact_text((result.stderr or result.stdout).strip())
    first = detail.splitlines()[0] if detail else "sin salida de error"
    return f"El comando falló (código {result.exit_code}). {first}"


def diagnostic_context(command: TerminalCommand | None, result: TerminalCommandResult | None) -> str:
    if command is None or result is None:
        return "No hay un comando reciente para diagnosticar."
    output = redact_text((result.stderr or result.stdout)[-4_000:])
    return (
        "Analiza este resultado de terminal en español. Propón pasos de corrección, pero no ejecutes comandos ni asumas permisos.\n"
        f"COMMAND: {display_command(command)}\nEXIT_CODE: {result.exit_code}\nOUTPUT_UNTRUSTED:\n{output}"
    )
