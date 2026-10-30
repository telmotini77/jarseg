from __future__ import annotations

import subprocess
import time
from pathlib import Path
from uuid import uuid4

from app.terminal.models import TerminalCommandResult
from app.terminal.provider import TerminalProvider
from app.terminal.security import redact_text


def _bounded_output(value: str | bytes | None, maximum: int) -> str:
    text = value.decode(errors="replace") if isinstance(value, bytes) else value or ""
    text = redact_text(text)
    if len(text) <= maximum:
        return text
    return f"[Salida recortada a {maximum} caracteres]\n{text[-maximum:]}"


class SubprocessTerminalProvider(TerminalProvider):
    """Windows-compatible subprocess provider; it always uses shell=False."""

    def __init__(self, max_output: int = 12_000) -> None:
        self.max_output = max_output

    def execute(
        self,
        command: list[str],
        cwd: Path | None = None,
        timeout: float | None = None,
    ) -> TerminalCommandResult:
        started = time.perf_counter()
        command_id = uuid4().hex
        try:
            completed = subprocess.run(
                command,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,
                check=False,
            )
            duration = time.perf_counter() - started
            stdout = _bounded_output(completed.stdout, self.max_output)
            stderr = _bounded_output(completed.stderr, self.max_output)
            return TerminalCommandResult(command_id, completed.returncode, stdout, stderr, duration, False, completed.returncode == 0)
        except subprocess.TimeoutExpired as error:
            duration = time.perf_counter() - started
            return TerminalCommandResult(
                command_id,
                None,
                _bounded_output(error.stdout, self.max_output),
                _bounded_output(error.stderr, self.max_output),
                duration,
                True,
                False,
            )
        except FileNotFoundError:
            duration = time.perf_counter() - started
            return TerminalCommandResult(command_id, None, "", "No encontré el ejecutable en PATH.", duration, False, False)
        except OSError as error:
            duration = time.perf_counter() - started
            return TerminalCommandResult(command_id, None, "", redact_text(str(error)), duration, False, False)
