from __future__ import annotations

from dataclasses import dataclass
from queue import Empty, Queue
from time import monotonic

import numpy as np
import sounddevice as sd
import speech_recognition as sr


class MicrophoneError(RuntimeError):
    """The microphone is unavailable or failed while recording."""


@dataclass(slots=True)
class Microphone:
    device_index: int | None
    ambient_noise_duration: float

    def validate(self) -> None:
        try:
            devices = sd.query_devices()
            inputs = [device for device in devices if device["max_input_channels"] > 0]
            if not inputs:
                raise MicrophoneError("No se detectó ningún micrófono.")
            if self.device_index is not None:
                device = devices[self.device_index]
                if device["max_input_channels"] <= 0:
                    raise MicrophoneError("MICROPHONE_INDEX no corresponde a un dispositivo de entrada.")
        except (sd.PortAudioError, ValueError) as error:
            raise MicrophoneError("No fue posible acceder a los dispositivos de audio.") from error

    def listen(self, timeout: int, phrase_time_limit: int) -> sr.AudioData | None:
        """Record a phrase after speech is detected, returning None on silence timeout."""
        audio_blocks: Queue[np.ndarray] = Queue()
        stream_errors: Queue[str] = Queue()

        def callback(indata: np.ndarray, _frames: int, _time: object, status: sd.CallbackFlags) -> None:
            if status:
                stream_errors.put(str(status))
                return
            audio_blocks.put(indata.copy())

        try:
            device_info = sd.query_devices(self.device_index, "input")
            sample_rate = int(device_info["default_samplerate"])
            with sd.InputStream(
                device=self.device_index,
                channels=1,
                samplerate=sample_rate,
                dtype="int16",
                callback=callback,
            ):
                noise_samples: list[np.ndarray] = []
                calibration_deadline = monotonic() + self.ambient_noise_duration
                while monotonic() < calibration_deadline:
                    try:
                        noise_samples.append(audio_blocks.get(timeout=0.1))
                    except Empty:
                        pass
                if not stream_errors.empty():
                    raise MicrophoneError(f"Error de audio: {stream_errors.get_nowait()}")
                baseline = float(np.mean(np.abs(np.concatenate(noise_samples)))) if noise_samples else 50.0
                threshold = max(200.0, baseline * 3.0)
                wait_deadline = monotonic() + timeout
                phrase: list[np.ndarray] = []
                while monotonic() < wait_deadline:
                    try:
                        block = audio_blocks.get(timeout=0.2)
                    except Empty:
                        continue
                    if float(np.mean(np.abs(block))) >= threshold:
                        phrase.append(block)
                        break
                if not phrase:
                    return None
                phrase_deadline = monotonic() + phrase_time_limit
                silence_blocks = 0
                while monotonic() < phrase_deadline:
                    try:
                        block = audio_blocks.get(timeout=0.2)
                    except Empty:
                        silence_blocks += 1
                        if silence_blocks >= 8:
                            break
                        continue
                    phrase.append(block)
                    silence_blocks = silence_blocks + 1 if float(np.mean(np.abs(block))) < threshold else 0
                    if silence_blocks >= 8:
                        break
                samples = np.concatenate(phrase).tobytes()
                return sr.AudioData(samples, sample_rate, 2)
        except (sd.PortAudioError, OSError, ValueError) as error:
            raise MicrophoneError("El micrófono se desconectó o no está disponible.") from error
