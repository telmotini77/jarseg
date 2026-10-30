from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.commands.apps import InstalledApplication, last_used_chrome_profile, resolve_application, resolve_chrome_launch_command, resolve_discovered_application, resolve_launch_command
from app.commands.base import Command, CommandResult, RouteType
from app.commands.classifier import IntentClassifier
from app.commands.files import resolve_folder
from app.commands.router import CommandRouter
from app.system.audio_control import VolumeValidationError, validate_volume


@dataclass
class FakeApps:
    opened: str | None = None
    closed: str | None = None

    def open(self, target: str | None) -> CommandResult:
        self.opened = target
        return CommandResult(True, "aplicación abierta")

    def close(self, target: str | None) -> CommandResult:
        self.closed = target
        return CommandResult(True, "aplicación cerrada")

    def list_available(self, target: str | None = None) -> CommandResult:
        return CommandResult(True, f"aplicaciones {target or ''}")


@dataclass
class FakeBrowser:
    query: str | None = None
    opened_url: str | None = None

    def open_url(self, url: str) -> CommandResult:
        self.opened_url = url
        return CommandResult(True, f"url {url}")

    def open_site(self, target: str) -> CommandResult:
        return CommandResult(True, f"sitio {target}")

    def search(self, query: str) -> CommandResult:
        self.query = query
        return CommandResult(True, f"búsqueda {query}")


@dataclass
class FakeFiles:
    folder: str | None = None

    def open_folder(self, target: str | None) -> CommandResult:
        self.folder = target
        return CommandResult(True, "carpeta abierta")

    def list_files(self, target: str | None) -> CommandResult:
        self.folder = target
        return CommandResult(True, "archivos listados")


class FakeSystem:
    def info(self, metric: str) -> CommandResult:
        return CommandResult(True, f"sistema {metric}")


class FakeAudio:
    def set_volume(self, level: int) -> CommandResult:
        return CommandResult(True, f"volumen {level}")

    def volume_up(self) -> CommandResult:
        return CommandResult(True, "subido")

    def volume_down(self) -> CommandResult:
        return CommandResult(True, "bajado")

    def set_mute(self, muted: bool) -> CommandResult:
        return CommandResult(True, f"mute {muted}")


def make_router() -> tuple[CommandRouter, FakeApps, FakeBrowser, FakeFiles]:
    apps = FakeApps()
    browser = FakeBrowser()
    files = FakeFiles()
    return CommandRouter(applications=apps, browser=browser, files=files, system_info=FakeSystem(), audio=FakeAudio()), apps, browser, files


@pytest.mark.parametrize("text", ["¿Qué es Docker?", "¿Para qué sirve Visual Studio Code?"])
def test_classifier_keeps_questions_as_conversations(text: str) -> None:
    assert IntentClassifier().classify(text) is RouteType.CONVERSATION


@pytest.mark.parametrize(
    ("text", "action", "target"),
    [
        ("Jarvis abre Visual Studio Code", "open_application", "visual studio code"),
        ("Jarvis abre Documentos", "open_folder", "documentos"),
        ("Jarvis lista los archivos de Descargas", "list_files", "descargas"),
        ("Jarvis cierra Spotify", "close_application", "spotify"),
        ("Jarvis busca MQTT ESP32", "web_search", None),
    ],
)
def test_router_parses_safe_commands(text: str, action: str, target: str | None) -> None:
    router, _, _, _ = make_router()
    route = router.route(text)
    assert route.type is RouteType.COMMAND
    assert route.parsed_command is not None
    assert route.parsed_command.action == action
    assert route.parsed_command.target == target


def test_router_parses_volume_and_rejects_out_of_range_in_controller() -> None:
    router, _, _, _ = make_router()
    command = router.parse("Jarvis pon el volumen al 150 por ciento")
    assert command == Command("set_volume", arguments={"level": 150})
    with pytest.raises(VolumeValidationError):
        validate_volume(150)


def test_router_dispatches_to_injected_handlers() -> None:
    router, apps, browser, files = make_router()
    assert router.execute(Command("open_application", target="vscode")).success
    assert apps.opened == "vscode"
    assert router.execute(Command("web_search", arguments={"query": "mqtt esp32"})).success
    assert browser.query == "mqtt esp32"
    assert router.execute(Command("list_files", target="descargas")).success
    assert files.folder == "descargas"


def test_router_keeps_local_and_internet_searches_on_their_respective_routes() -> None:
    router, _, _, _ = make_router()
    local = router.parse("Jarvis busca presupuesto en Documentos")
    web = router.parse("Jarvis busca en internet presupuesto familiar")
    assert local == Command("search_local_files", target="documentos", arguments={"query": "presupuesto"})
    assert web == Command("web_search", arguments={"query": "presupuesto familiar"})


def test_google_login_uses_the_regular_chrome_profile_not_the_automation_browser() -> None:
    router, _, browser, _ = make_router()
    command = router.parse("Jarvis inicia sesión en Google")
    assert command == Command("browser_trusted_login")
    assert router.execute(command).success
    assert browser.opened_url == "https://accounts.google.com/"


def test_unknown_actions_are_never_dispatched() -> None:
    router, _, _, _ = make_router()
    result = router.execute(Command("run_powershell", arguments={"code": "danger"}))
    assert not result.success
    assert "permitida" in result.message


def test_application_aliases_are_canonical() -> None:
    assert resolve_application("Visual Studio Code").key == "vscode"
    assert resolve_application("arduino ide").key == "arduino"
    assert resolve_application("algo desconocido") is None


def test_discovered_application_matching_is_local_and_unambiguous(tmp_path) -> None:
    firefox = InstalledApplication("Mozilla Firefox", tmp_path / "firefox.exe", "executable")
    assert resolve_discovered_application("Firefox", [firefox]) == firefox
    chrome = InstalledApplication("Google Chrome", tmp_path / "chrome.exe", "executable")
    chromium = InstalledApplication("Chromium", tmp_path / "chromium.exe", "executable")
    assert resolve_discovered_application("chrom", [chrome, chromium]) is None


def test_router_lists_discovered_applications() -> None:
    router, _, _, _ = make_router()
    command = router.parse("Jarvis muestra aplicaciones disponibles")
    assert command == Command("list_applications")
    assert router.execute(command).success


@pytest.mark.parametrize(
    "text",
    [
        "Jarvis abre YouTube en Chrome",
        "Jarvis abre una pestaña de YouTube en Chrome",
        "Jarvis abre YouTube en una pestaña de Chrome",
        "Jarvis abre youtube.com en Chrome",
        "Jarvis abre YouTube en Crhome",
        "Jarvis abre una pestaña de YouTube en Crome",
    ],
)
def test_router_opens_explicit_sites_in_personal_chrome(text: str) -> None:
    router, _, browser, _ = make_router()
    command = router.parse(text)
    assert command is not None and command.action == "open_url"
    assert router.execute(command).success
    assert browser.opened_url is not None and "youtube" in browser.opened_url


def test_launch_command_uses_registry_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.commands.apps.which", lambda _executable: None)
    monkeypatch.setattr("app.commands.apps._registered_windows_app", lambda _executable: r"C:\Apps\chrome.exe")
    monkeypatch.setattr("app.commands.apps._standard_windows_app", lambda _executable: None)
    assert resolve_launch_command(("chrome.exe",)) == (r"C:\Apps\chrome.exe",)


def test_last_used_chrome_profile_is_read_from_local_state(tmp_path) -> None:
    (tmp_path / "Local State").write_text('{"profile": {"last_used": "Profile 1"}}', encoding="utf-8")
    assert last_used_chrome_profile(tmp_path) == "Profile 1"


def test_chrome_command_uses_selected_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.commands.apps.resolve_launch_command", lambda _command: (r"C:\Apps\chrome.exe",))
    assert resolve_chrome_launch_command("Profile 1", "https://example.com") == (
        r"C:\Apps\chrome.exe",
        "--profile-directory=Profile 1",
        "https://example.com",
    )


def test_folder_resolver_uses_provided_home(tmp_path) -> None:
    assert resolve_folder("documentos", tmp_path) == tmp_path / "Documents"
    assert resolve_folder("descargas", tmp_path) == tmp_path / "Downloads"
    assert resolve_folder("C:/Windows", tmp_path) is None


@pytest.mark.parametrize("level", [0, 40, 100])
def test_volume_validation_accepts_safe_bounds(level: int) -> None:
    assert validate_volume(level) == level
