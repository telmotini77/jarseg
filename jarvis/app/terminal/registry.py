from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RegisteredTool:
    name: str
    aliases: tuple[str, ...] = ()


COMMAND_REGISTRY: dict[str, RegisteredTool] = {
    "python": RegisteredTool("Python", ("python.exe", "py", "py.exe")),
    "pip": RegisteredTool("Pip", ("pip.exe",)),
    "git": RegisteredTool("Git", ("git.exe",)),
    "node": RegisteredTool("Node.js", ("node.exe",)),
    "npm": RegisteredTool("NPM", ("npm.cmd", "npm.exe")),
    "npx": RegisteredTool("NPX", ("npx.cmd", "npx.exe")),
    "pytest": RegisteredTool("Pytest", ("pytest.exe",)),
    "docker": RegisteredTool("Docker", ("docker.exe",)),
    "docker-compose": RegisteredTool("Docker Compose", ("docker-compose.exe",)),
    "where": RegisteredTool("Where", ("where.exe",)),
    "whoami": RegisteredTool("Whoami", ("whoami.exe",)),
    "dir": RegisteredTool("Dir"),
    "mkdir": RegisteredTool("Mkdir", ("md",)),
    "tasklist": RegisteredTool("Tasklist", ("tasklist.exe",)),
    "code": RegisteredTool("Visual Studio Code", ("code.cmd", "code.exe")),
    "arduino-cli": RegisteredTool("Arduino CLI", ("arduino-cli.exe",)),
    "platformio": RegisteredTool("PlatformIO", ("platformio.exe", "pio", "pio.exe")),
}


def canonical_executable(executable: str) -> str:
    candidate = executable.strip().replace("\\", "/").rsplit("/", 1)[-1].casefold()
    for key, tool in COMMAND_REGISTRY.items():
        if candidate == key or candidate in tool.aliases:
            return key
    return candidate.removesuffix(".exe").removesuffix(".cmd")


def is_registered_tool(executable: str) -> bool:
    return canonical_executable(executable) in COMMAND_REGISTRY
