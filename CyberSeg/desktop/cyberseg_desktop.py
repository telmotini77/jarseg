"""CyberSeg para Windows: conecta este PC con el servidor CyberSeg de tu red.

Guarda la IP del servidor, instala (con tu confirmación) el certificado de su
autoridad local y abre el panel en su propia ventana, sin barra de navegador.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

VERSION = "1.0.0"
APP_DIR = Path(os.getenv("APPDATA", str(Path.home()))) / "CyberSeg"
CONFIG = APP_DIR / "config.json"
BROWSER_PROFILE = Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / "CyberSeg" / "navegador"
_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", re.S)


class ConnectionProblem(RuntimeError):
    pass


def normalise_server(value: str) -> str:
    """Accept '192.168.1.50', 'https://192.168.1.50/' or '192.168.1.50:8443'."""
    text = value.strip()
    text = re.sub(r"^[a-zA-Z]+://", "", text).split("/", 1)[0]
    host, _, port = text.partition(":")
    try:
        ipaddress.IPv4Address(host)
    except ValueError as error:
        raise ConnectionProblem("Escribe la IP del servidor, por ejemplo 192.168.1.50.") from error
    if port and (not port.isdigit() or not 0 < int(port) < 65536):
        raise ConnectionProblem("El puerto no es válido.")
    return f"{host}:{port}" if port and port != "443" else host


def host_only(server: str) -> str:
    return server.split(":", 1)[0]


def pem_to_der(pem: bytes) -> bytes:
    match = _PEM.search(pem)
    if match is None:
        raise ConnectionProblem("El servidor no devolvió un certificado válido.")
    return base64.b64decode(b"".join(match.group(1).split()))


def fingerprint(pem: bytes, algorithm: str = "sha256") -> str:
    """Same format as `openssl x509 -fingerprint -sha256`: AA:BB:CC..."""
    digest = hashlib.new(algorithm, pem_to_der(pem)).hexdigest().upper()
    return ":".join(digest[index:index + 2] for index in range(0, len(digest), 2))


def download_ca(server: str, timeout: float = 5.0) -> bytes:
    # Plain HTTP on purpose: the certificate is what makes HTTPS trustworthy.
    # The user verifies its fingerprint before installing it.
    url = f"http://{host_only(server)}/cyberseg-ca.crt"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = response.read(64_000)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ConnectionProblem(f"No se pudo contactar con {host_only(server)}. ¿Está encendido el servidor y en tu misma red?") from error
    pem_to_der(data)
    return data


def check_https(server: str, ca_pem: bytes, timeout: float = 5.0) -> None:
    """Verify the dashboard's certificate against this exact CA (not the Windows store)."""
    with tempfile.NamedTemporaryFile("wb", suffix=".crt", delete=False) as handle:
        handle.write(ca_pem)
        ca_file = handle.name
    try:
        context = ssl.create_default_context(cafile=ca_file)
        request = urllib.request.Request(f"https://{server}/api/auth/me")
        try:
            urllib.request.urlopen(request, timeout=timeout, context=context).close()
        except urllib.error.HTTPError as error:
            if error.code != 401:  # 401 = reachable, waiting for login
                raise ConnectionProblem(f"El panel respondió con el error {error.code}.") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            reason = getattr(error, "reason", error)
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise ConnectionProblem("El certificado HTTPS del servidor no coincide con su autoridad. No continúes.") from error
            raise ConnectionProblem(f"No se pudo abrir https://{server}/ ({reason}).") from error
    finally:
        os.unlink(ca_file)


def ca_installed(ca_pem: bytes) -> bool:
    if os.name != "nt":
        return False
    thumbprint = fingerprint(ca_pem, "sha1").replace(":", "").lower()
    result = subprocess.run(["certutil", "-user", "-store", "Root"], capture_output=True, text=True, check=False,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return thumbprint in result.stdout.replace(" ", "").lower()


def install_ca(ca_pem: bytes) -> bool:
    """Add the CA to the current user's trusted roots; Windows asks for confirmation."""
    with tempfile.NamedTemporaryFile("wb", suffix=".crt", delete=False) as handle:
        handle.write(ca_pem)
        path = handle.name
    try:
        result = subprocess.run(["certutil", "-user", "-addstore", "Root", path], capture_output=True, text=True, check=False,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return result.returncode == 0
    finally:
        os.unlink(path)


def find_browser(candidates: list[str] | None = None) -> str | None:
    if candidates is None:
        roots = [os.getenv("ProgramFiles(x86)", ""), os.getenv("ProgramFiles", ""), os.getenv("LOCALAPPDATA", "")]
        candidates = [os.path.join(root, *relative) for root in roots if root for relative in (
            ("Microsoft", "Edge", "Application", "msedge.exe"), ("Google", "Chrome", "Application", "chrome.exe"),
        )]
    return next((path for path in candidates if os.path.isfile(path)), None)


def open_window(server: str, path: str = "/") -> None:
    url = f"https://{server}{path}"
    browser = find_browser()
    if browser is None:
        webbrowser.open(url)
        return
    BROWSER_PROFILE.mkdir(parents=True, exist_ok=True)
    subprocess.Popen([browser, f"--app={url}", f"--user-data-dir={BROWSER_PROFILE}", "--no-first-run", "--no-default-browser-check"])


def load_config() -> dict:
    try:
        return json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(data: dict) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps(data, indent=2), encoding="utf-8")


def resource(name: str) -> str:
    return os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), name)


class App:
    def __init__(self) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.root = tk.Tk()
        self.root.title("CyberSeg")
        self.root.geometry("560x420")
        self.root.minsize(480, 380)
        self.root.configure(bg="#06101e")
        try:
            self.root.iconbitmap(resource("cyberseg.ico"))
        except tk.TclError:
            pass
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TButton", padding=8, font=("Segoe UI", 10))
        style.configure("Primary.TButton", background="#51cfff", foreground="#06101e")

        self.config = load_config()
        self.server = tk.StringVar(value=self.config.get("server", ""))
        self.status = tk.StringVar(value="Escribe la IP del servidor CyberSeg y pulsa Conectar.")

        frame = tk.Frame(self.root, bg="#06101e", padx=24, pady=20)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text="CYBERSEG", fg="#51cfff", bg="#06101e", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(frame, text="Conexión con el servidor", fg="#dcecff", bg="#06101e", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(2, 14))
        tk.Label(frame, text="IP del servidor (por ejemplo 192.168.1.50)", fg="#86a8ca", bg="#06101e", font=("Segoe UI", 10)).pack(anchor="w")
        entry = ttk.Entry(frame, textvariable=self.server, font=("Segoe UI", 12))
        entry.pack(fill="x", pady=(4, 12))
        entry.bind("<Return>", lambda _event: self.connect())

        buttons = tk.Frame(frame, bg="#06101e")
        buttons.pack(fill="x")
        self.connect_button = ttk.Button(buttons, text="Conectar y abrir el panel", style="Primary.TButton", command=self.connect)
        self.connect_button.pack(side="left")
        ttk.Button(buttons, text="Informe PDF (7 días)", command=lambda: self.open("/api/export/report.pdf?days=7")).pack(side="left", padx=8)

        tk.Label(frame, textvariable=self.status, fg="#dcecff", bg="#091a2d", justify="left", anchor="nw", wraplength=480,
                 font=("Segoe UI", 10), padx=12, pady=10, relief="flat").pack(fill="both", expand=True, pady=(16, 8))
        tk.Label(frame, text=f"CyberSeg para Windows {VERSION} · solo para tu red local", fg="#5a7a9a", bg="#06101e",
                 font=("Segoe UI", 8)).pack(anchor="w")
        if self.config.get("server"):
            self.status.set(f"Último servidor: {self.config['server']}. Pulsa Conectar para abrir el panel.")

    def run(self) -> None:
        self.root.mainloop()

    def say(self, text: str) -> None:
        self.root.after(0, self.status.set, text)

    def open(self, path: str) -> None:
        try:
            server = normalise_server(self.server.get())
        except ConnectionProblem as problem:
            self.status.set(str(problem))
            return
        open_window(server, path)

    def connect(self) -> None:
        self.connect_button.state(["disabled"])
        threading.Thread(target=self._connect, daemon=True).start()

    def _connect(self) -> None:
        from tkinter import messagebox

        try:
            server = normalise_server(self.server.get())
            self.say(f"Contactando con {server}…")
            ca = download_ca(server)
            ca_print = fingerprint(ca)
            if not ca_installed(ca):
                question = (
                    "Para usar HTTPS sin dominio, este PC debe confiar en el certificado del servidor.\n\n"
                    f"Huella SHA-256:\n{ca_print}\n\n"
                    "Compárala con la que mostró el servidor al instalarse (deploy/install.sh) o con la de "
                    f"http://{host_only(server)}/certificado. ¿Coinciden y quieres instalarlo?"
                )
                if not self._ask(messagebox.askyesno, "Instalar certificado de CyberSeg", question):
                    self.say("Instalación cancelada. Sin el certificado el navegador mostrará advertencias de seguridad.")
                    return
                self.say("Windows te pedirá confirmar la instalación del certificado…")
                if not install_ca(ca):
                    self.say("No se instaló el certificado (cancelado o sin permisos).")
                    return
            self.say("Comprobando la conexión cifrada…")
            check_https(server, ca)
            save_config({"server": server, "fingerprint": ca_print})
            self.say(f"Conectado a {server} con HTTPS verificado.\nHuella de la autoridad: {ca_print[:47]}…\nAbriendo el panel…")
            open_window(server)
        except ConnectionProblem as problem:
            self.say(str(problem))
        finally:
            self.root.after(0, lambda: self.connect_button.state(["!disabled"]))

    def _ask(self, dialog, title: str, text: str) -> bool:
        answer: list[bool] = []
        done = threading.Event()

        def ask() -> None:
            answer.append(bool(dialog(title, text, parent=self.root)))
            done.set()

        self.root.after(0, ask)
        done.wait()
        return answer[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="CyberSeg", description="Conecta este PC con el servidor CyberSeg de tu red.")
    parser.add_argument("--version", action="version", version=f"CyberSeg para Windows {VERSION}")
    parser.add_argument("--check", metavar="IP", help="Comprueba el servidor sin abrir ventanas y muestra la huella del certificado.")
    arguments = parser.parse_args(argv)
    if arguments.check:
        try:
            server = normalise_server(arguments.check)
            ca = download_ca(server)
            print(f"Certificado de la autoridad: SHA-256 {fingerprint(ca)}")
            check_https(server, ca)
            print(f"HTTPS verificado: https://{server}/ responde y su certificado es válido.")
            return 0
        except ConnectionProblem as problem:
            print(problem, file=sys.stderr)
            return 1
    App().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
