#!/usr/bin/env python3
"""
test_mic.py - check that the USB microphone works (no sudo needed).

  python3 test_mic.py      # records 5 seconds - talk while it records
  aplay test_mic.wav       # listen to the result
"""
import array
import math
import subprocess
import sys
import wave

import settings

SECONDS = 5


def main():
    print(f"Recording {SECONDS} seconds from '{settings.AUDIO_DEVICE}' at {settings.SAMPLE_RATE} Hz ... speak now!")
    command = ["arecord", "-q", "-D", settings.AUDIO_DEVICE, "-f", "S16_LE", "-c", str(settings.CHANNELS),
               "-r", str(settings.SAMPLE_RATE), "-t", "raw", "-d", str(SECONDS)]
    result = subprocess.run(command, capture_output=True)
    if result.returncode != 0 or not result.stdout:
        print("\nFAILED:", result.stderr.decode(errors="replace").strip())
        print("Hints:\n  * list microphones:  arecord -l"
              "\n  * 'No such file or directory' -> fix AUDIO_DEVICE in settings.py (card name after 'card N:')"
              "\n  * 'Device or resource busy'   -> close Zoom/Teams/browser tabs/Sound Settings using the mic")
        sys.exit(1)

    pcm = result.stdout
    with wave.open("test_mic.wav", "wb") as wav:
        wav.setnchannels(settings.CHANNELS)
        wav.setsampwidth(2)
        wav.setframerate(settings.SAMPLE_RATE)
        wav.writeframes(pcm)

    samples = array.array("h", pcm[:len(pcm) // 2 * 2])
    per_second = settings.SAMPLE_RATE * settings.CHANNELS
    print()
    for start in range(0, len(samples), per_second):
        part = samples[start:start + per_second]
        rms = math.sqrt(sum(s * s for s in part) / len(part))
        level = 20 * math.log10(max(rms, 1.0) / 32768)
        print(f"  second {start // per_second + 1}: {level:6.1f} dBFS  {'#' * int(max(0.0, level + 70) / 2)}")

    peak = max(abs(s) for s in samples)
    print(f"\nSaved test_mic.wav ({len(pcm) // 1024} KB). Peak level {peak} of 32767.")
    if peak < 300:
        print("WARNING: almost silent. Is the mic muted, unplugged, or is AUDIO_DEVICE the wrong card?")
    else:
        print("OK: the microphone is picking up sound. Play it back with:  aplay test_mic.wav")


if __name__ == "__main__":
    main()
