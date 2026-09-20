#!/usr/bin/env python3
"""
edge_device.py - runs on the laptop with the USB microphone ("Edge Device" + "PQC SSD 1").

  sudo python3 edge_device.py register            # ONCE: create the device key in the SSD, register at server
  sudo python3 edge_device.py record              # every meeting: handshake, then record -> sign -> send
                                                  # press Ctrl+C to end the meeting
Options:
  --duration 60     stop automatically after 60 seconds (handy for testing)
  --email a@b.com   default email stored at registration
  --new-key         register: replace the identity key (then register again at the server)
  --mock-pqc        no SSD, fake signatures (testing only, no sudo needed)
"""
import argparse
import array
import io
import json
import math
import os
import queue
import signal
import subprocess
import sys
import threading
import time
import uuid
import wave

import settings
from common import (TOPIC_REGISTER, TOPIC_SESSION_START, b64e, connect, device_id_for, get_mac_address,
                    log, make_client, pack_frame, publish, sha256_hex, topic_audio, topic_disconnect,
                    topic_status)
from pqc_sdk import KAZ_PUBLIC_KEY_LENGTH, PQCError, open_pqc

BYTES_PER_SECOND = settings.SAMPLE_RATE * settings.CHANNELS * 2   # 16-bit samples = 2 bytes


def make_wav(pcm):
    """Wrap raw 16-bit PCM samples in a WAV header (the 'encodeWAV' step)."""
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav:
        wav.setnchannels(settings.CHANNELS)
        wav.setsampwidth(2)
        wav.setframerate(settings.SAMPLE_RATE)
        wav.writeframes(pcm)
    return buffer.getvalue()


def loudness_dbfs(pcm):
    """Rough loudness of a chunk: about -20 dBFS = normal speech, below -60 = silence/muted mic."""
    samples = array.array("h", pcm[:len(pcm) // 2 * 2])[::8]
    if not samples:
        return -99.0
    rms = math.sqrt(sum(s * s for s in samples) / len(samples))
    return 20 * math.log10(max(rms, 1.0) / 32768)


class EdgeDevice:
    def __init__(self, mock):
        self.pqc = open_pqc(mock)
        self.interface, self.mac = get_mac_address()
        self.device_id = device_id_for(self.mac)
        self.client = None
        self.replies = queue.Queue()        # answers from the server (except chunk acks)
        self.chunk_rejected = threading.Event()

    # ------------------------------------------------------------------ helpers
    def check_ssd(self):
        log("ssd", f"Phison SDK {self.pqc.version()}, drive {settings.PQC_DEVICE}")
        firmware = self.pqc.check_device()
        log("ssd", f"PQC SSD detected, firmware {firmware}", "ok")

    def on_message(self, client, userdata, msg):
        try:
            reply = json.loads(msg.payload)
        except ValueError:
            return
        if reply.get("type") == "chunk_ack":
            if reply.get("ok"):
                log("server", f"chunk #{reply.get('seq')} verified by server SSD "
                              f"({reply.get('verify_ms')} ms) and stored", "ok")
            else:
                log("server", f"chunk #{reply.get('seq')} REJECTED: {reply.get('reason')}", "err")
                self.chunk_rejected.set()
        else:
            self.replies.put(reply)

    def wait_reply(self, expected_type, timeout):
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            try:
                reply = self.replies.get(timeout=remaining)
            except queue.Empty:
                return None
            if reply.get("type") == expected_type:
                return reply

    def mqtt_connect(self, will=None):
        self.client = make_client(f"edge-recorder-{self.device_id}",
                                  settings.EDGE_MQTT_USER, settings.EDGE_MQTT_PASSWORD, will)
        self.client.on_message = self.on_message
        status_topic = topic_status(self.device_id)
        # UserProperty mac_address, as in the sequence diagram (step 2.2)
        connect(self.client, {"mac_address": self.mac, "device_id": self.device_id},
                on_connected=lambda c: c.subscribe(status_topic, qos=1))

    def mqtt_disconnect(self):
        if self.client:
            self.client.disconnect()
            self.client.loop_stop()

    def fail(self, reason):
        log("FAILURE", reason, "err")
        print("\x1b[31m" + "=" * 70 + "\n  FAILED - recording stopped (fail closed)\n" + "=" * 70 + "\x1b[0m")
        self.mqtt_disconnect()
        return 2

    # ------------------------------------------------------------------ 1. registration (once)
    def existing_key(self, slot):
        try:
            public_key = self.pqc.get_public_key(slot)
        except PQCError:
            return None
        return public_key if len(public_key) == KAZ_PUBLIC_KEY_LENGTH else None

    def register(self, email, new_key):
        self.check_ssd()
        log("register", f"MAC {self.mac} ({self.interface}) -> device id {self.device_id}")
        slot = settings.EDGE_IDENTITY_SLOT
        # Re-use the existing key: a rejected registration must never destroy a working identity
        public_key = None if new_key else self.existing_key(slot)
        if public_key:
            log("ssd", f"re-using the identity key already in slot 0x{slot:02X} (add --new-key to replace it)")
        else:
            log("ssd", f"generating identity key pair INSIDE the SSD (slot 0x{slot:02X}) ...")
            public_key = self.pqc.generate_key_pair(slot)
        log("ssd", f"identity public key: {len(public_key)} bytes (private key stays in the SSD)", "ok")

        header = {"type": "register", "alg": self.pqc.name, "device_id": self.device_id, "mac": self.mac,
                  "email": email, "identity_pubkey": b64e(public_key), "ts": int(time.time())}
        frame = pack_frame(header, b"", lambda data: self.pqc.sign(data, settings.EDGE_IDENTITY_SLOT))
        log("ssd", "registration request signed with KAZ-SIGN (354-byte signature)", "ok")

        self.mqtt_connect()
        publish(self.client, TOPIC_REGISTER, frame)
        log("register", "sent to server, waiting for verification ...")
        reply = self.wait_reply("register_result", 30)
        if reply is None:
            return self.fail("no answer from server - is 'sudo python3 server.py --allow-register' running?")
        if not reply.get("ok"):
            return self.fail(f"server rejected registration: {reply.get('reason')}")
        log("register", "server verified the signature and stored this device. Registration done!", "ok")
        self.mqtt_disconnect()
        return 0

    # ------------------------------------------------------------------ 2-4. one meeting
    def record(self, duration):
        self.check_ssd()
        self.pqc.get_public_key(settings.EDGE_IDENTITY_SLOT)   # fails early if never registered
        room, session_id = settings.ROOM_ID, uuid.uuid4().hex
        log("session", f"device {self.device_id} (MAC {self.mac}) room {room} session {session_id[:8]}")

        # 2a. brand-new key pair for this meeting, endorsed by the long-term identity key
        log("ssd", f"generating NEW session key pair in the SSD (slot 0x{settings.EDGE_SESSION_SLOT:02X}) ...")
        session_pubkey = self.pqc.generate_key_pair(settings.EDGE_SESSION_SLOT)

        def sign_identity(data):
            return self.pqc.sign(data, settings.EDGE_IDENTITY_SLOT)

        def sign_session(data):
            return self.pqc.sign(data, settings.EDGE_SESSION_SLOT)

        base = {"alg": self.pqc.name, "device_id": self.device_id, "session_id": session_id}
        audio_format = {"format": "wav", "sample_rate": settings.SAMPLE_RATE, "channels": settings.CHANNELS,
                        "bits": 16, "chunk_seconds": settings.CHUNK_SECONDS}
        start_frame = pack_frame(dict(base, type="session_start", mac=self.mac, room=room, audio=audio_format,
                                      session_pubkey=b64e(session_pubkey), ts=int(time.time())),
                                 b"", sign_identity)
        # Pre-signed "OFF" that the broker sends for us if the laptop crashes or loses network
        will_frame = pack_frame(dict(base, type="session_end", reason="aborted", ts=int(time.time())),
                                b"OFF", sign_session)
        log("ssd", "session key signed by identity key (KAZ-SIGN)", "ok")

        # 2b. handshake: server checks registration + signature, answers pass/fail
        self.mqtt_connect(will=(topic_disconnect(room), will_frame))
        publish(self.client, TOPIC_SESSION_START, start_frame)
        log("handshake", "waiting for the server to verify this device ...")
        reply = self.wait_reply("session_result", 30)
        if reply is None:
            return self.fail("no answer from server - is 'sudo python3 server.py' running?")
        if not reply.get("ok"):
            return self.fail(f"server rejected this device: {reply.get('reason')}")
        log("handshake", "PASS - device identity verified by server, recording starts", "ok")

        # 3. voice ingestion loop
        try:
            chunks, end_reason = self.stream_audio(room, base, duration, sign_session)
        except PQCError as e:
            log("ssd", f"signing failed: {e}", "err")
            publish(self.client, topic_disconnect(room), will_frame)
            return self.fail("could not sign audio with the PQC SSD")

        # 4. terminate session: signed "OFF"
        end_frame = pack_frame(dict(base, type="session_end", reason=end_reason, chunks=chunks,
                                    ts=int(time.time())), b"OFF", sign_session)
        publish(self.client, topic_disconnect(room), end_frame)
        log("session", f"sent OFF after {chunks} chunk(s), waiting for server to close the session ...")
        closed = self.wait_reply("session_closed", 60)
        if end_reason in ("chunk_rejected", "recorder_failed"):
            return self.fail(f"session ended: {end_reason}")
        self.mqtt_disconnect()
        if closed and closed.get("ok"):
            log("server", f"meeting saved: {closed.get('merged_file')} "
                          f"({closed.get('verified_chunks')} verified chunk(s))", "ok")
        else:
            log("server", "no confirmation from the server (check server.py output)", "warn")
        return 0

    def stream_audio(self, room, base, duration, sign_session):
        chunk_bytes = BYTES_PER_SECOND * settings.CHUNK_SECONDS
        recorder = self.start_recorder()
        pcm_queue = queue.Queue()
        threading.Thread(target=self.read_audio, args=(recorder, pcm_queue, chunk_bytes), daemon=True).start()

        stop_requested = threading.Event()
        signal.signal(signal.SIGINT, lambda *_: stop_requested.set())
        signal.signal(signal.SIGTERM, lambda *_: stop_requested.set())
        log("audio", f"recording {settings.AUDIO_DEVICE} in {settings.CHUNK_SECONDS}s chunks "
                     f"- press Ctrl+C to end the meeting", "info")

        seq, samples_sent, end_reason, started = 0, 0, None, time.time()
        try:
            while True:
                if end_reason is None:
                    if stop_requested.is_set():
                        end_reason = "user_stopped"
                    elif duration and time.time() - started >= duration:
                        end_reason = "duration_reached"
                    elif self.chunk_rejected.is_set() and settings.STOP_ON_REJECTED_CHUNK:
                        end_reason = "chunk_rejected"
                    if end_reason:
                        log("audio", f"stopping ({end_reason}), sending the last part ...")
                        recorder.terminate()
                try:
                    pcm = pcm_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                if pcm is None:                      # recorder has finished
                    break
                if len(pcm) < BYTES_PER_SECOND // 5:  # ignore leftovers shorter than 0.2 s
                    continue
                seq += 1
                self.send_chunk(room, base, seq, pcm, samples_sent, sign_session)
                samples_sent += len(pcm) // (2 * settings.CHANNELS)
        finally:
            if recorder.poll() is None:
                recorder.terminate()
            signal.signal(signal.SIGINT, signal.default_int_handler)

        if end_reason is None:
            log("audio", "the recorder stopped unexpectedly (see arecord messages above)", "err")
            end_reason = "recorder_failed"
        return seq, end_reason

    def send_chunk(self, room, base, seq, pcm, samples_before, sign_session):
        wav = make_wav(pcm)
        header = dict(base, type="audio_chunk", seq=seq, format="wav",
                      start_ms=samples_before * 1000 // settings.SAMPLE_RATE,
                      duration_ms=len(pcm) * 1000 // BYTES_PER_SECOND,
                      sha256=sha256_hex(wav), ts=round(time.time(), 3))
        t0 = time.perf_counter()
        frame = pack_frame(header, wav, sign_session)          # KAZ signature from the SSD
        sign_ms = (time.perf_counter() - t0) * 1000
        sent = publish(self.client, topic_audio(room), frame)
        level = loudness_dbfs(pcm)
        log("chunk", f"#{seq}: {len(pcm) / BYTES_PER_SECOND:.1f}s audio, {len(wav) // 1024} KB, "
                     f"level {level:.0f} dBFS, KAZ-signed in {sign_ms:.0f} ms, "
                     f"{'published' if sent else 'NOT confirmed by broker yet'}", "info" if sent else "warn")
        if level < -60:
            log("audio", "very quiet - is the microphone muted or unplugged?", "warn")

    @staticmethod
    def start_recorder():
        command = ["arecord", "-q", "-D", settings.AUDIO_DEVICE, "-f", "S16_LE",
                   "-c", str(settings.CHANNELS), "-r", str(settings.SAMPLE_RATE), "-t", "raw"]
        try:
            # own session: Ctrl+C goes to Python only, so we can finish the last chunk cleanly
            recorder = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=True)
        except FileNotFoundError:
            raise SystemExit("arecord not found - install it with: sudo apt install alsa-utils")

        def show_errors():
            for line in recorder.stderr:
                log("arecord", line.decode(errors="replace").strip(), "warn")
        threading.Thread(target=show_errors, daemon=True).start()
        return recorder

    @staticmethod
    def read_audio(recorder, pcm_queue, chunk_bytes):
        """Background thread: keeps draining the microphone so no audio is lost while we sign/send."""
        buffer = bytearray()
        fd = recorder.stdout.fileno()
        while True:
            data = os.read(fd, 65536)
            if not data:
                break
            buffer += data
            while len(buffer) >= chunk_bytes:
                pcm_queue.put(bytes(buffer[:chunk_bytes]))
                del buffer[:chunk_bytes]
        pcm_queue.put(bytes(buffer))   # last partial chunk
        pcm_queue.put(None)


def main():
    parser = argparse.ArgumentParser(description="Edge device: record meeting audio, sign with PQC SSD, send via MQTT/TLS")
    parser.add_argument("command", nargs="?", default="record", choices=["register", "record"])
    parser.add_argument("--email", default="", help="default email stored at registration")
    parser.add_argument("--new-key", action="store_true", help="register: replace the identity key in the SSD")
    parser.add_argument("--duration", type=float, default=0, help="stop after N seconds (0 = until Ctrl+C)")
    parser.add_argument("--mock-pqc", action="store_true", help="testing only: no SSD, fake signatures")
    args = parser.parse_args()

    edge = EdgeDevice(args.mock_pqc)
    try:
        code = edge.register(args.email, args.new_key) if args.command == "register" else edge.record(args.duration)
    except PQCError as e:
        log("ssd", str(e), "err")
        code = 1
    sys.exit(code)


if __name__ == "__main__":
    main()
