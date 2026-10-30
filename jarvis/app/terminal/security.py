from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from app.security.permissions import SecurityLevel
from app.terminal.models import CommandSource, TerminalCommand
from app.terminal.registry import canonical_executable, is_registered_tool


_META_CHARACTERS = ("&&", "||", ";", "|", ">", "<", "`", "$()")
_SECRET_VALUE = re.compile(
    r"(?i)(--?(?:password|pass|token|secret|api[-_]?key|key|credential|auth)(?:=|\s+))(\S+)"
)
_SECRET_ENV = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|API_KEY|KEY|DATABASE_URL|AUTH|CREDENTIAL)[A-Z0-9_]*)=(\S+)"
)
_BLOCKED_EXECUTABLES = frozenset({"format", "diskpart", "cipher", "bcdedit", "reg", "shutdown"})
_RESTRICTED_EXECUTABLES = frozenset({"del", "erase", "rmdir", "rd", "remove-item", "move-item", "rename-item", "taskkill", "icacls"})
_BLOCKED_ARGUMENTS = frozenset({"reset --hard", "clean -fd", "clean -f", "branch -d", "push --force", "push -f"})


def redact_text(value: str) -> str:
    value = _SECRET_VALUE.sub(r"\1[REDACTED]", value)
    return _SECRET_ENV.sub(r"\1=[REDACTED]", value)


def redact_args(args: tuple[str, ...]) -> tuple[str, ...]:
    redacted: list[str] = []
    mask_next = False
    for argument in args:
        if mask_next:
            redacted.append("[REDACTED]")
            mask_next = False
            continue
        lowered = argument.casefold()
        if lowered in {"--password", "--pass", "--token", "--secret", "--api-key", "--key", "--credential", "--auth"}:
            redacted.append(argument)
            mask_next = True
        else:
            redacted.append(redact_text(argument))
    return tuple(redacted)


def display_command(command: TerminalCommand) -> str:
    return " ".join((command.executable, *redact_args(command.args)))


def contains_shell_syntax(command: TerminalCommand) -> bool:
    return any(marker in value for value in (command.executable, *command.args) for marker in _META_CHARACTERS)


def _targets_system_root(command: TerminalCommand) -> bool:
    values = " ".join(command.args).casefold().replace("/", "\\")
    return any(target in values for target in ("c:\\", "c:\\windows", "system32", "\\\\.\\physicaldrive"))


def classify_command(command: TerminalCommand) -> SecurityLevel:
    executable = canonical_executable(command.executable)
    joined = " ".join(command.args).casefold()
    if command.source in {CommandSource.WEB_CONTENT, CommandSource.MODEL}:
        return SecurityLevel.BLOCKED
    if contains_shell_syntax(command):
        return SecurityLevel.BLOCKED
    if executable in _BLOCKED_EXECUTABLES:
        return SecurityLevel.BLOCKED
    if executable in _RESTRICTED_EXECUTABLES:
        return SecurityLevel.BLOCKED if _targets_system_root(command) else SecurityLevel.RESTRICTED
    if any(pattern in joined for pattern in _BLOCKED_ARGUMENTS):
        return SecurityLevel.BLOCKED
    if not is_registered_tool(executable):
        return SecurityLevel.RESTRICTED
    if executable == "git":
        if command.args and command.args[0].casefold() in {"merge", "rebase", "cherry-pick", "reset", "stash"}:
            return SecurityLevel.SENSITIVE
        if any(item in joined for item in ("branch -d", "push --force", "push -f")):
            return SecurityLevel.SENSITIVE
        if any(item in joined for item in ("add", "commit", "checkout", "switch", "fetch", "pull")):
            return SecurityLevel.CONFIRMATION
        return SecurityLevel.SAFE
    if executable == "pytest":
        return SecurityLevel.CONFIRMATION
    if executable == "code":
        return SecurityLevel.CONFIRMATION
    if executable in {"npm", "npx"}:
        if command.args in {("--version",), ("-v",), ("list",)}:
            return SecurityLevel.SAFE
        return SecurityLevel.CONFIRMATION
    if executable == "pip":
        if command.args in {("--version",), ("list",)}:
            return SecurityLevel.SAFE
        return SecurityLevel.CONFIRMATION
    if executable in {"python", "py"}:
        if command.args[:2] in {("-m", "venv"), ("-m", "pip")} or any(arg.endswith(".py") for arg in command.args):
            return SecurityLevel.CONFIRMATION
        return SecurityLevel.SAFE
    if executable == "mkdir":
        return SecurityLevel.CONFIRMATION
    if executable in {"docker", "docker-compose"}:
        lowered_args = tuple(argument.casefold() for argument in command.args)
        if lowered_args[:2] in {("compose", "up"), ("compose", "down"), ("image", "rm")} or lowered_args[:1] in {("stop",), ("rm",)}:
            return SecurityLevel.SENSITIVE
        return SecurityLevel.SAFE
    return SecurityLevel.SAFE


def classified(command: TerminalCommand) -> TerminalCommand:
    level = classify_command(command)
    return replace(command, risk_level=level, requires_confirmation=level in {SecurityLevel.CONFIRMATION, SecurityLevel.SENSITIVE})


def safe_cwd(cwd: Path | None) -> Path | None:
    if cwd is None:
        return None
    resolved = cwd.resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise ValueError("El directorio de trabajo no existe o no es una carpeta.")
    return resolved
