from __future__ import annotations

import subprocess
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.terminal.models import ManagedProcess, TerminalCommand
from app.terminal.security import redact_text


class ProcessManager:
    """Owns only processes launched by JARVIS; it never searches or kills arbitrary PIDs."""

    def __init__(self, output_limit: int = 200) -> None:
        self.output_limit = output_limit
        self._processes: dict[str, tuple[ManagedProcess, subprocess.Popen[str]]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def is_long_running(command: TerminalCommand) -> bool:
        joined = " ".join((command.executable, *command.args)).casefold()
        return any(marker in joined for marker in ("npm run start", "npm run start:dev", "nest start --watch", "vite", "ng serve", "docker compose up", "python servidor.py", "python server.py"))

    def start_process(self, command: TerminalCommand, name: str | None = None) -> ManagedProcess:
        process = subprocess.Popen(
            command.argv,
            cwd=str(command.cwd) if command.cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
        managed = ManagedProcess(uuid4().hex[:8], name or " ".join(command.argv[:3]), process.pid, command, datetime.now(timezone.utc))
        with self._lock:
            self._processes[managed.id] = (managed, process)
        threading.Thread(target=self._capture_output, args=(managed.id,), daemon=True).start()
        return managed

    def _capture_output(self, process_id: str) -> None:
        with self._lock:
            item = self._processes.get(process_id)
        if item is None:
            return
        managed, process = item
        if process.stdout is not None:
            for line in process.stdout:
                managed.output.append(redact_text(line.rstrip()))
                del managed.output[:-self.output_limit]
        process.wait()
        managed.status = "stopped" if managed.status == "stopping" else "exited"

    def list_managed_processes(self) -> list[ManagedProcess]:
        with self._lock:
            items = list(self._processes.values())
        for managed, process in items:
            if process.poll() is not None and managed.status == "running":
                managed.status = "exited"
        return [item[0] for item in items]

    def stop_process(self, identifier: str) -> ManagedProcess | None:
        needle = identifier.casefold().strip()
        matches = [
            item for item in self.list_managed_processes()
            if item.id == identifier or needle == item.name.casefold() or needle in item.name.casefold()
        ]
        if len(matches) != 1:
            return None
        managed = matches[0]
        with self._lock:
            process = self._processes[managed.id][1]
        if process.poll() is None:
            managed.status = "stopping"
            process.terminate()
        return managed

    def get_process_output(self, identifier: str) -> list[str]:
        matches = [item for item in self.list_managed_processes() if item.id == identifier or item.name.casefold() == identifier.casefold()]
        return list(matches[0].output) if len(matches) == 1 else []
