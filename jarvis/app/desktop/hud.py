from __future__ import annotations

import logging
import math
import threading
import tkinter as tk
from datetime import datetime
from queue import Empty, Queue
from tkinter import scrolledtext
from typing import Any

try:  # The desktop view remains usable on minimal Python installations.
    import psutil
except ImportError:  # pragma: no cover - psutil is an application dependency.
    psutil = None  # type: ignore[assignment]

from app.core.jarvis import Jarvis, ProcessResult
from app.experience.states import JarvisVisualState
from app.voice.microphone import MicrophoneError
from app.voice.speech_to_text import SpeechToTextError
from app.voice.text_to_speech import TextToSpeechError
from app.voice.wake_word import extract_wake_command


class JarvisDesktopApp:
    """A native Tk desktop HUD backed directly by the local JARVIS core.

    No browser, HTTP polling, or embedded web view is used here.  Expensive
    work (voice recognition, AI and speech) runs on background threads, while
    Tk owns all rendering work on its main thread.
    """

    _STATE_COLORS = {
        JarvisVisualState.IDLE: "#37c9ff",
        JarvisVisualState.LISTENING: "#34e8a1",
        JarvisVisualState.PROCESSING: "#b583ff",
        JarvisVisualState.EXECUTING: "#ffbe55",
        JarvisVisualState.SPEAKING: "#78a8ff",
        JarvisVisualState.ALERT: "#ff9a62",
        JarvisVisualState.ERROR: "#ff647c",
    }
    _STATE_NAMES = {
        JarvisVisualState.IDLE: "EN ESPERA",
        JarvisVisualState.LISTENING: "ESCUCHANDO",
        JarvisVisualState.PROCESSING: "ANALIZANDO",
        JarvisVisualState.EXECUTING: "EJECUTANDO",
        JarvisVisualState.SPEAKING: "RESPONDIENDO",
        JarvisVisualState.ALERT: "ALERTA",
        JarvisVisualState.ERROR: "ATENCIÓN",
    }

    def __init__(
        self,
        *,
        jarvis: Jarvis,
        agents: Any,
        experience: Any,
        users: Any | None,
        microphone: Any | None,
        stt: Any | None,
        tts: Any,
        logger: logging.Logger,
        listen_timeout: int,
        phrase_time_limit: int,
        tts_enabled: bool,
        wake_word: Any | None = None,
        scheduler: Any | None = None,
        cyberseg: Any | None = None,
        particles_enabled: bool = True,
        target_fps: int = 60,
    ) -> None:
        self._jarvis = jarvis
        self._agents = agents
        self._experience = experience
        self._users = users
        self._microphone = microphone
        self._stt = stt
        self._tts = tts
        self._logger = logger
        self._listen_timeout = listen_timeout
        self._phrase_time_limit = phrase_time_limit
        self._tts_enabled = tts_enabled
        self._wake_word = wake_word
        self._scheduler = scheduler
        self._cyberseg = cyberseg
        self._particles_enabled = particles_enabled
        self._frame_delay = max(16, int(1_000 / max(20, min(target_fps, 60))))
        self._events: Queue[tuple[str, Any]] = Queue()
        self._stop = threading.Event()
        self._processing_lock = threading.Lock()
        self._closed = False
        self._busy = False
        self._phase = 0.0
        self._state_override: JarvisVisualState | None = None

        self._root = tk.Tk()
        self._root.title("JARVIS v1.4 — Aplicación de escritorio")
        self._root.geometry("1280x820")
        self._root.minsize(920, 620)
        self._root.configure(bg="#030b17")
        self._root.protocol("WM_DELETE_WINDOW", self._close)
        self._root.bind("<Escape>", lambda _event: self._close())
        self._root.bind("<Control-space>", self._focus_command)
        self._root.bind("<F11>", self._toggle_fullscreen)

        self._status = tk.StringVar(value="SISTEMA OPERATIVO")
        self._detail = tk.StringVar(value="Listo para recibir una orden")
        self._time = tk.StringVar()
        self._metrics = tk.StringVar(value="CPU --%   RAM --%")
        self._profile = tk.StringVar(value="PERFIL LOCAL")
        self._command = tk.StringVar()
        self._agent_summary = tk.StringVar(value="AGENTES  -- / --")
        self._cyberseg_summary = tk.StringVar(value="CYBERSEG  VERIFICANDO" if cyberseg is not None else "CYBERSEG  DESACTIVADO")
        self._build()

    def run(self) -> None:
        """Start the native event loop and local services required by the HUD."""
        self._root.after(20, self._draw_frame)
        self._root.after(40, self._drain_events)
        self._root.after(250, self._refresh_system_data)
        self._append("JARVIS", "JARVIS Desktop está listo. Escribe una orden o di “Jarvis”.", "jarvis")
        if self._scheduler is not None:
            self._scheduler.set_reminder_callback(self._queue_reminder)
            self._scheduler.start()
        if self._microphone is not None and self._stt is not None:
            threading.Thread(target=self._voice_loop, daemon=True, name="jarvis-desktop-voice").start()
        self._root.mainloop()

    def _build(self) -> None:
        root = self._root
        header = tk.Frame(root, bg="#061325", highlightbackground="#153455", highlightthickness=1, padx=26, pady=15)
        header.pack(fill="x", padx=18, pady=(18, 10))
        tk.Label(header, text="JARVIS", font=("Segoe UI", 25, "bold"), fg="#63d3ff", bg="#061325").pack(side="left")
        tk.Label(header, text="DESKTOP COMMAND CENTER  •  v1.4", font=("Segoe UI", 10, "bold"), fg="#8aa4c4", bg="#061325").pack(side="left", padx=18, pady=(8, 0))
        tk.Label(header, textvariable=self._time, font=("Consolas", 11), fg="#d6e8ff", bg="#061325").pack(side="right", pady=(7, 0))
        tk.Label(header, text="● LOCAL", font=("Segoe UI", 10, "bold"), fg="#39e5a5", bg="#061325").pack(side="right", padx=22, pady=(7, 0))

        content = tk.Frame(root, bg="#030b17")
        content.pack(fill="both", expand=True, padx=18, pady=0)
        content.grid_columnconfigure(0, weight=3, minsize=520)
        content.grid_columnconfigure(1, weight=2, minsize=330)
        content.grid_rowconfigure(0, weight=3)
        content.grid_rowconfigure(1, weight=2)

        hud_card = tk.Frame(content, bg="#061325", highlightbackground="#164365", highlightthickness=1)
        hud_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(0, 10))
        self._canvas = tk.Canvas(hud_card, bg="#061325", highlightthickness=0)
        self._canvas.pack(fill="both", expand=True, padx=2, pady=2)

        info = tk.Frame(content, bg="#061325", highlightbackground="#164365", highlightthickness=1, padx=21, pady=19)
        info.grid(row=0, column=1, sticky="nsew", pady=(0, 10))
        tk.Label(info, text="ESTADO DEL SISTEMA", font=("Segoe UI", 10, "bold"), fg="#6d9dc8", bg="#061325").pack(anchor="w")
        tk.Label(info, textvariable=self._status, font=("Segoe UI", 21, "bold"), fg="#cce9ff", bg="#061325").pack(anchor="w", pady=(8, 1))
        tk.Label(info, textvariable=self._detail, font=("Segoe UI", 10), fg="#98b5d2", bg="#061325", justify="left", wraplength=310).pack(anchor="w")

        self._separator(info, 18)
        tk.Label(info, text="TELEMETRÍA LOCAL", font=("Segoe UI", 10, "bold"), fg="#6d9dc8", bg="#061325").pack(anchor="w")
        tk.Label(info, textvariable=self._metrics, font=("Consolas", 12, "bold"), fg="#54d7ff", bg="#061325").pack(anchor="w", pady=(7, 0))
        self._separator(info, 18)
        tk.Label(info, text="CYBERSEG IDS", font=("Segoe UI", 10, "bold"), fg="#6d9dc8", bg="#061325").pack(anchor="w")
        tk.Label(info, textvariable=self._cyberseg_summary, font=("Consolas", 10, "bold"), fg="#4ce2a5", bg="#061325").pack(anchor="w", pady=(7, 0))
        self._separator(info, 18)
        tk.Label(info, text="IDENTIDAD ACTIVA", font=("Segoe UI", 10, "bold"), fg="#6d9dc8", bg="#061325").pack(anchor="w")
        tk.Label(info, textvariable=self._profile, font=("Segoe UI", 12, "bold"), fg="#e2f0ff", bg="#061325", justify="left", wraplength=310).pack(anchor="w", pady=(7, 0))
        self._separator(info, 18)
        tk.Label(info, textvariable=self._agent_summary, font=("Segoe UI", 10, "bold"), fg="#4ce2a5", bg="#061325").pack(anchor="w")
        self._agent_list = tk.Label(info, text="", font=("Consolas", 9), fg="#97b6d6", bg="#061325", justify="left", anchor="nw")
        self._agent_list.pack(fill="both", expand=True, anchor="w", pady=(8, 0))

        conversation_card = tk.Frame(content, bg="#061325", highlightbackground="#164365", highlightthickness=1)
        conversation_card.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(0, 12))
        tk.Label(conversation_card, text="CANAL DE CONVERSACIÓN", font=("Segoe UI", 9, "bold"), fg="#6d9dc8", bg="#061325").pack(anchor="w", padx=17, pady=(12, 3))
        self._conversation = scrolledtext.ScrolledText(
            conversation_card,
            height=7,
            wrap="word",
            state="disabled",
            bg="#061325",
            fg="#dcecff",
            insertbackground="#dcecff",
            relief="flat",
            padx=15,
            pady=7,
            font=("Segoe UI", 10),
        )
        self._conversation.pack(fill="both", expand=True, padx=7, pady=(0, 8))
        self._conversation.tag_configure("user", foreground="#77ccff", font=("Segoe UI", 10, "bold"))
        self._conversation.tag_configure("jarvis", foreground="#4ce2a5", font=("Segoe UI", 10, "bold"))
        self._conversation.tag_configure("notice", foreground="#ffc669", font=("Segoe UI", 10, "bold"))

        command_bar = tk.Frame(root, bg="#061325", highlightbackground="#215985", highlightthickness=1, padx=18, pady=13)
        command_bar.pack(fill="x", padx=18, pady=(0, 18))
        tk.Label(command_bar, text="⌘", font=("Segoe UI Symbol", 18), fg="#62d3ff", bg="#061325").pack(side="left", padx=(2, 10))
        self._entry = tk.Entry(
            command_bar,
            textvariable=self._command,
            bg="#071a30",
            fg="#edf7ff",
            insertbackground="#edf7ff",
            relief="flat",
            font=("Segoe UI", 12),
        )
        self._entry.pack(side="left", fill="x", expand=True, ipady=9)
        self._entry.bind("<Return>", lambda _event: self._send_text())
        tk.Button(
            command_bar,
            text="ENVIAR  ↵",
            command=self._send_text,
            bg="#1676a8",
            fg="white",
            activebackground="#259bd0",
            activeforeground="white",
            relief="flat",
            padx=18,
            pady=9,
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left", padx=(12, 0))
        self._entry.focus_set()

    @staticmethod
    def _separator(parent: tk.Misc, top: int) -> None:
        tk.Frame(parent, bg="#173450", height=1).pack(fill="x", pady=(top, 12))

    def _draw_frame(self) -> None:
        if self._closed:
            return
        self._phase += 0.075
        self._render_core()
        self._root.after(self._frame_delay, self._draw_frame)

    def _render_core(self) -> None:
        canvas = self._canvas
        width, height = max(1, canvas.winfo_width()), max(1, canvas.winfo_height())
        cx, cy = width / 2, height / 2
        snapshot = self._experience.public_snapshot() if self._experience is not None else {}
        raw_state = snapshot.get("visual_state", "idle") if isinstance(snapshot, dict) else "idle"
        try:
            state = self._state_override or JarvisVisualState(str(raw_state))
        except ValueError:
            state = JarvisVisualState.IDLE
        color = self._STATE_COLORS[state]
        level = float(snapshot.get("level", 0.12)) if isinstance(snapshot, dict) else 0.12
        pulse = 1 + math.sin(self._phase * 2.1) * (0.05 + level * 0.075)
        base = min(width, height) * 0.17 * pulse
        canvas.delete("hud")

        # Fine grid makes the native canvas feel like an operational display.
        for x in range(0, width, 40):
            canvas.create_line(x, 0, x, height, fill="#0b223a", width=1, tags="hud")
        for y in range(0, height, 40):
            canvas.create_line(0, y, width, y, fill="#0b223a", width=1, tags="hud")

        for index, multiplier in enumerate((2.6, 2.05, 1.48)):
            radius = base * multiplier + math.sin(self._phase * (1.7 + index)) * 8
            canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius, outline=color, width=1 if index else 2, tags="hud")
        canvas.create_oval(cx - base, cy - base, cx + base, cy + base, fill="#071d35", outline=color, width=3, tags="hud")
        canvas.create_oval(cx - base * 0.56, cy - base * 0.56, cx + base * 0.56, cy + base * 0.56, fill=color, outline="", tags="hud")
        canvas.create_oval(cx - base * 0.29, cy - base * 0.29, cx + base * 0.29, cy + base * 0.29, fill="#d7f5ff", outline="", tags="hud")

        if self._particles_enabled:
            for index in range(18):
                angle = self._phase * (0.8 + index % 4 * 0.13) + index * math.tau / 18
                radius = base * (1.5 + (index % 3) * 0.42)
                px, py = cx + math.cos(angle) * radius, cy + math.sin(angle) * radius
                size = 2 + index % 3
                canvas.create_oval(px - size, py - size, px + size, py + size, fill=color, outline="", tags="hud")

        label = self._STATE_NAMES[state]
        canvas.create_text(cx, 29, text=f"●  {label}", fill=color, font=("Segoe UI", 11, "bold"), tags="hud")
        action = snapshot.get("action") if isinstance(snapshot, dict) else None
        canvas.create_text(cx, height - 30, text=str(action or "NÚCLEO NEURAL ACTIVO").upper(), fill="#9dc6e9", font=("Consolas", 9), tags="hud")
        self._status.set(label)
        self._detail.set(self._status_detail(snapshot, state))

    def _status_detail(self, snapshot: dict[str, Any], state: JarvisVisualState) -> str:
        if state is JarvisVisualState.LISTENING:
            return "Micrófono activo. Di tu orden después de “Jarvis”."
        if state in {JarvisVisualState.PROCESSING, JarvisVisualState.EXECUTING}:
            return str(snapshot.get("action") or "Validando la orden y coordinando agentes.")[:120]
        if state is JarvisVisualState.ERROR:
            return str(snapshot.get("response") or "Revisa el canal de conversación.")[:120]
        if state is JarvisVisualState.SPEAKING:
            return "Respuesta lista en el canal de conversación."
        return "Aplicación local nativa; sin navegador ni servidor público."

    def _refresh_system_data(self) -> None:
        if self._closed:
            return
        now = datetime.now().strftime("%H:%M:%S  •  %d/%m/%Y")
        self._time.set(now)
        if psutil is not None:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            self._metrics.set(f"CPU {cpu:>5.1f}%   RAM {ram:>5.1f}%")
        else:
            self._metrics.set("CPU N/D   RAM N/D")
        if self._users is not None and self._users.active_user() is not None:
            user = self._users.active_user()
            self._profile.set(f"{user.display_name}\n{user.role.value.upper()}  •  {user.language.upper()}")
        else:
            self._profile.set("Sin perfil activo")
        statuses = self._agents.status() if self._agents is not None else {}
        online = sum(1 for status in statuses.values() if status in {"ready", "healthy", "online"})
        self._agent_summary.set(f"AGENTES  {online} / {len(statuses)} OPERATIVOS")
        items = [f"● {name.upper():<16} {status.upper()}" for name, status in sorted(statuses.items())]
        self._agent_list.configure(text="\n".join(items) or "Sin agentes registrados")
        if self._cyberseg is not None:
            cyberseg_state = str(statuses.get("cyberseg", "ready")).upper()
            self._cyberseg_summary.set(f"CYBERSEG  {cyberseg_state}  •  LOCAL")
        self._root.after(1_000, self._refresh_system_data)

    def _send_text(self) -> None:
        if self._busy:
            return
        text = self._command.get().strip()
        if not text:
            return
        self._command.set("")
        self._set_busy(True)
        self._state_override = JarvisVisualState.PROCESSING
        self._events.put(("user", text))
        threading.Thread(target=self._process_request, args=(text,), daemon=True, name="jarvis-desktop-command").start()

    def _voice_loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self._wake_word is not None:
                    text = self._wake_word.wait_for_command(lambda: self._busy)
                else:
                    audio = self._microphone.listen(self._listen_timeout, self._phrase_time_limit)
                    text = extract_wake_command(self._stt.transcribe(audio)) if audio is not None else None
                if not text:
                    continue
                if not self._processing_lock.acquire(blocking=False):
                    continue
                self._state_override = JarvisVisualState.LISTENING
                self._events.put(("notice", "🎤 Orden de voz detectada"))
                try:
                    self._process_request(text, lock_held=True)
                finally:
                    self._processing_lock.release()
            except (MicrophoneError, SpeechToTextError) as error:
                if not self._stop.is_set():
                    self._logger.warning("Desktop voice input error: %s", error)
                    self._events.put(("notice", f"Entrada de voz no disponible: {error}"))
            except Exception:
                if not self._stop.is_set():
                    self._logger.exception("Unexpected desktop voice error")

    def _process_request(self, text: str, *, lock_held: bool = False) -> None:
        try:
            if not lock_held:
                with self._processing_lock:
                    result = self._jarvis.process(text)
            else:
                result = self._jarvis.process(text)
        except Exception:
            self._logger.exception("Unexpected desktop command error")
            result = ProcessResult("Ocurrió un error inesperado al procesar la solicitud.")
        self._events.put(("complete", result))

    def _drain_events(self) -> None:
        if self._closed:
            return
        try:
            while True:
                kind, payload = self._events.get_nowait()
                if kind == "user":
                    self._append("TÚ", str(payload), "user")
                elif kind == "notice":
                    self._append("SISTEMA", str(payload), "notice")
                elif kind == "complete":
                    self._complete(payload)
                elif kind == "reminder":
                    self._append("RECORDATORIO", str(payload), "notice")
                    self._speak_async(str(payload))
        except Empty:
            pass
        self._root.after(40, self._drain_events)

    def _complete(self, result: ProcessResult) -> None:
        self._append("JARVIS", result.response, "jarvis")
        self._set_busy(False)
        self._state_override = JarvisVisualState.SPEAKING
        self._speak_async(result.response)
        self._root.after(1_600, self._return_to_idle)
        if result.should_exit:
            self._root.after(600, self._close)

    def _return_to_idle(self) -> None:
        if self._closed or self._busy:
            return
        self._state_override = None
        if self._experience is not None:
            self._experience.set_state(JarvisVisualState.IDLE)

    def _speak_async(self, text: str) -> None:
        if not self._tts_enabled:
            return
        threading.Thread(target=self._speak, args=(text,), daemon=True, name="jarvis-desktop-tts").start()

    def _speak(self, text: str) -> None:
        try:
            if self._wake_word is not None:
                self._wake_word.suspend()
            self._tts.speak(text)
        except TextToSpeechError as error:
            self._logger.warning("Desktop TTS error: %s", error)
        finally:
            if self._wake_word is not None:
                self._wake_word.resume()

    def _queue_reminder(self, reminder: Any) -> None:
        title = getattr(reminder, "title", "tu tarea pendiente")
        self._events.put(("reminder", f"Es hora de {title}."))

    def _append(self, speaker: str, text: str, tag: str) -> None:
        if self._closed:
            return
        self._conversation.configure(state="normal")
        self._conversation.insert(tk.END, f"{speaker}\n", tag)
        self._conversation.insert(tk.END, f"{text}\n\n")
        self._conversation.configure(state="disabled")
        self._conversation.see(tk.END)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self._entry.configure(state="disabled" if busy else "normal")

    def _focus_command(self, _event: tk.Event[Any] | None = None) -> str:
        self._entry.focus_set()
        return "break"

    def _toggle_fullscreen(self, _event: tk.Event[Any] | None = None) -> str:
        self._root.attributes("-fullscreen", not bool(self._root.attributes("-fullscreen")))
        return "break"

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._scheduler is not None:
            self._scheduler.stop()
        self._root.destroy()
