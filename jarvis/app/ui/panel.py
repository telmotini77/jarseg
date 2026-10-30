from __future__ import annotations

import logging
import threading
import tkinter as tk
from queue import Empty, Queue
from tkinter import scrolledtext

from app.core.jarvis import Jarvis, ProcessResult
from app.core.state import AssistantState
from app.tasks.scheduler import LocalScheduler
from app.voice.microphone import Microphone, MicrophoneError
from app.voice.speech_to_text import SpeechToTextError, SpeechToTextProvider
from app.voice.text_to_speech import TextToSpeechError, TextToSpeechProvider
from app.voice.wake_word import extract_wake_command
from app.wakeword.detector import WakeWordDetector


READY_STATUS = 'En espera — di "Jarvis"'


class JarvisPanel:
    """A responsive native panel; audio capture and AI work stay off the UI thread."""

    def __init__(
        self,
        jarvis: Jarvis,
        microphone: Microphone,
        stt: SpeechToTextProvider,
        tts: TextToSpeechProvider,
        logger: logging.Logger,
        listen_timeout: int,
        phrase_time_limit: int,
        tts_enabled: bool = True,
        wake_word: WakeWordDetector | None = None,
        scheduler: LocalScheduler | None = None,
    ) -> None:
        self._jarvis = jarvis
        self._microphone = microphone
        self._stt = stt
        self._tts = tts
        self._logger = logger
        self._listen_timeout = listen_timeout
        self._phrase_time_limit = phrase_time_limit
        self._tts_enabled = tts_enabled
        self._wake_word = wake_word
        self._scheduler = scheduler
        self._state = AssistantState.IDLE
        self._busy = False
        self._closed = False
        self._stop_listening = threading.Event()
        self._processing_lock = threading.Lock()
        self._events: Queue[tuple[str, object]] = Queue()
        self._root = tk.Tk()
        self._status = tk.StringVar(value=READY_STATUS)
        self._entry = tk.Entry()
        self._conversation = scrolledtext.ScrolledText(self._root)
        self._build()

    def run(self) -> None:
        self._root.after(300, lambda: self._deliver("JARVIS listo. Dime Jarvis y tu pregunta."))
        self._root.after(50, self._drain_events)
        if self._scheduler is not None:
            self._scheduler.set_reminder_callback(self._queue_reminder)
            self._scheduler.start()
        threading.Thread(target=self._background_listen_loop, daemon=True).start()
        self._root.mainloop()

    def _build(self) -> None:
        root = self._root
        root.title("JARVIS v1.1")
        root.geometry("760x620")
        root.minsize(620, 480)
        root.configure(bg="#0b1020")
        root.protocol("WM_DELETE_WINDOW", self._close)

        header = tk.Frame(root, bg="#111a33", padx=24, pady=18)
        header.pack(fill="x")
        tk.Label(header, text="JARVIS", font=("Segoe UI", 22, "bold"), fg="#7dd3fc", bg="#111a33").pack(anchor="w")
        tk.Label(
            header,
            text="Asistente local · Voz, Visual Control Center y agentes seguros",
            font=("Segoe UI", 10),
            fg="#cbd5e1",
            bg="#111a33",
        ).pack(anchor="w", pady=(3, 0))

        status_row = tk.Frame(root, bg="#0b1020", padx=24, pady=12)
        status_row.pack(fill="x")
        tk.Label(status_row, text="●", font=("Segoe UI", 14), fg="#34d399", bg="#0b1020").pack(side="left")
        tk.Label(status_row, textvariable=self._status, font=("Segoe UI", 10), fg="#e2e8f0", bg="#0b1020").pack(side="left", padx=(6, 0))
        tk.Label(
            status_row,
            text='Di “Jarvis” y luego tu comando',
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#0b1020",
        ).pack(side="right")

        self._conversation = scrolledtext.ScrolledText(
            root,
            wrap="word",
            state="disabled",
            bg="#111827",
            fg="#e5e7eb",
            insertbackground="white",
            relief="flat",
            padx=16,
            pady=14,
            font=("Segoe UI", 11),
        )
        self._conversation.pack(fill="both", expand=True, padx=24, pady=(0, 14))
        self._conversation.tag_configure("user", foreground="#93c5fd", font=("Segoe UI", 11, "bold"))
        self._conversation.tag_configure("jarvis", foreground="#86efac", font=("Segoe UI", 11, "bold"))
        self._conversation.tag_configure("body", foreground="#e5e7eb")

        input_row = tk.Frame(root, bg="#0b1020", padx=24, pady=0)
        input_row.pack(fill="x", pady=(0, 22))
        self._entry = tk.Entry(
            input_row,
            bg="#1f2937",
            fg="#f8fafc",
            insertbackground="white",
            relief="flat",
            font=("Segoe UI", 11),
        )
        self._entry.pack(side="left", fill="x", expand=True, ipady=9)
        self._entry.bind("<Return>", lambda _event: self._send_text())
        tk.Button(
            input_row,
            text="Enviar",
            command=self._send_text,
            bg="#334155",
            fg="white",
            activebackground="#475569",
            activeforeground="white",
            relief="flat",
            padx=18,
            pady=8,
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left", padx=(10, 0))
        self._entry.focus_set()

    def _background_listen_loop(self) -> None:
        """Remain idle until the wake-word provider yields a complete command."""
        while not self._stop_listening.is_set():
            try:
                if self._wake_word is not None:
                    command = self._wake_word.wait_for_command(lambda: self._state is AssistantState.SPEAKING)
                else:
                    audio = self._microphone.listen(self._listen_timeout, self._phrase_time_limit)
                    if audio is None:
                        continue
                    command = extract_wake_command(self._stt.transcribe(audio))
                if command is None:
                    continue
                self._state = AssistantState.LISTENING
                self._events.put(("ready", "🎤 Te escucho..."))
                if not self._processing_lock.acquire(blocking=False):
                    self._logger.debug("Ignored wake-word command while another request is processing.")
                    continue
                try:
                    self._process_request(command)
                finally:
                    self._processing_lock.release()
            except (MicrophoneError, SpeechToTextError) as error:
                if self._stop_listening.is_set():
                    return
                self._logger.warning("Voice panel input error: %s", error)
                self._events.put(("notice", str(error)))

    def _send_text(self) -> None:
        if self._busy:
            return
        text = self._entry.get().strip()
        if not text:
            return
        self._entry.delete(0, tk.END)
        self._set_busy(True, "Procesando...")
        threading.Thread(target=self._typed_request_worker, args=(text,), daemon=True).start()

    def _typed_request_worker(self, text: str) -> None:
        with self._processing_lock:
            self._process_request(text)

    def _process_request(self, text: str) -> None:
        self._state = AssistantState.PROCESSING
        self._events.put(("user", text))
        self._events.put(("status", "👁 Analizando pantalla..." if self._is_visual_request(text) else "Procesando..."))
        self._events.put(("acknowledge", None))
        try:
            result = self._jarvis.process(text)
        except Exception:
            self._logger.exception("Unexpected panel processing error")
            result = ProcessResult("Ocurrió un error inesperado al procesar la solicitud.")
        self._events.put(("complete", result))

    @staticmethod
    def _is_visual_request(text: str) -> bool:
        normalized = text.casefold()
        return any(phrase in normalized for phrase in ("pantalla", "ventana", "captura", "analiza", "mira mi error"))

    def _complete(self, result: ProcessResult) -> None:
        self._state = AssistantState.SPEAKING
        self._set_busy(True, "Hablando...")
        self._root.update_idletasks()
        self._deliver(result.response)
        self._state = AssistantState.IDLE
        self._set_busy(False, READY_STATUS)
        if result.should_exit:
            self._root.after(500, self._close)

    def _deliver(self, text: str) -> None:
        self._append("JARVIS", text, "jarvis")
        if not self._tts_enabled:
            self._logger.warning("Text response delivered while TTS is disabled.")
            return
        try:
            if self._wake_word is not None:
                self._wake_word.suspend()
            self._tts.speak(text)
            self._logger.info("Voice response completed")
        except TextToSpeechError as error:
            self._logger.error("Panel TTS error: %s", error)
        finally:
            if self._wake_word is not None:
                self._wake_word.resume()

    def _drain_events(self) -> None:
        if self._closed:
            return
        try:
            while True:
                event, payload = self._events.get_nowait()
                if event == "user":
                    self._append("Usuario", str(payload), "user")
                elif event == "complete":
                    self._complete(payload)  # type: ignore[arg-type]
                elif event == "status":
                    self._set_busy(True, str(payload))
                elif event == "acknowledge":
                    self._acknowledge_request()
                elif event == "notice":
                    self._logger.debug("Voice listener notice: %s", payload)
                    self._set_busy(False, READY_STATUS)
                elif event == "ready":
                    self._status.set(str(payload))
                elif event == "reminder":
                    self._append("🔔 RECORDATORIO", str(payload), "jarvis")
                    self._deliver(str(payload))
        except Empty:
            pass
        self._root.after(50, self._drain_events)

    def _acknowledge_request(self) -> None:
        if not self._tts_enabled:
            return
        try:
            if self._wake_word is not None:
                self._wake_word.suspend()
            self._tts.speak("Un momento.")
            self._logger.info("Voice acknowledgement completed")
        except TextToSpeechError as error:
            self._logger.error("Panel acknowledgement error: %s", error)
        finally:
            if self._wake_word is not None:
                self._wake_word.resume()

    def _queue_reminder(self, reminder: object) -> None:
        title = getattr(reminder, "title", "tu tarea pendiente")
        self._events.put(("reminder", f"Es hora de {title}."))

    def _append(self, speaker: str, text: str, tag: str) -> None:
        if self._closed:
            return
        self._conversation.configure(state="normal")
        self._conversation.insert(tk.END, f"{speaker}\n", tag)
        self._conversation.insert(tk.END, f"{text}\n\n", "body")
        self._conversation.configure(state="disabled")
        self._conversation.see(tk.END)

    def _set_busy(self, busy: bool, status: str) -> None:
        self._busy = busy
        self._status.set(status)
        self._entry.configure(state="disabled" if busy else "normal")

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop_listening.set()
        if self._scheduler is not None:
            self._scheduler.stop()
        self._tts.close()
        self._root.destroy()
