from __future__ import annotations

from os import environ
from pathlib import Path

import psutil

from app.commands.base import CommandResult


def _gigabytes(value: int | float) -> str:
    return f"{value / (1024 ** 3):.1f} GB"


class SystemInfoService:
    def info(self, metric: str = "status") -> CommandResult:
        try:
            cpu = psutil.cpu_percent(interval=0.2)
            memory = psutil.virtual_memory()
            disk_root = Path(environ.get("SystemDrive", "C:")) / "\\"
            disk = psutil.disk_usage(str(disk_root))
            battery = psutil.sensors_battery()
        except Exception:
            return CommandResult(False, "No pude obtener la información del sistema.")

        if metric == "cpu":
            return CommandResult(True, f"El uso actual de CPU es {cpu:.0f} %.")
        if metric == "memory":
            return CommandResult(True, f"RAM: {_gigabytes(memory.used)} / {_gigabytes(memory.total)} ({memory.percent:.0f} %).")
        if metric == "disk":
            return CommandResult(True, f"Disco C: {_gigabytes(disk.free)} libres de {_gigabytes(disk.total)}.")
        lines = [
            f"CPU: {cpu:.0f} %.",
            f"RAM: {_gigabytes(memory.used)} / {_gigabytes(memory.total)} ({memory.percent:.0f} %).",
            f"Disco C: {_gigabytes(disk.free)} libres.",
        ]
        if battery is not None:
            lines.append(f"Batería: {battery.percent:.0f} %.")
        return CommandResult(True, " ".join(lines))
