#!/usr/bin/env python3
"""
server.py - the verifier ("Server" + "PQC SSD 2" + "Database" in the sequence diagram).

  sudo python3 server.py --allow-register    # while registering a new edge device
  sudo python3 server.py                     # normal operation (registration closed)
Options:
  --mock-pqc   testing only: no SSD, fake signatures

For every incoming message:
  1. split it into header + KAZ signature + body
  2. verify the signature INSIDE this machine's PQC SSD (verify_signature_with_key)
  3. valid   -> store (SQLite + WAV file) and answer "ok" on the device's status topic
     invalid -> store NOTHING, log a security event, answer "rejected"
"""
import argparse
import json
import re
import signal
import sqlite3
import threading
import time
import traceback
import wave
from datetime import datetime

import settings
from common import (SERVER_SUBSCRIPTIONS, TOPIC_REGISTER, TOPIC_SESSION_START, b64d, connect, device_id_for,
                    give_back_to_user, log, make_client, sha256_hex, topic_audio, topic_disconnect,
                    topic_status, unpack_frame)
from pqc_sdk import KAZ_PUBLIC_KEY_LENGTH, KAZ_SIGNATURE_LENGTH, PQCError, open_pqc

DEVICE_ID_RE = re.compile(r"[0-9a-f]{16}")
SESSION_ID_RE = re.compile(r"[0-9a-f]{32}")
ROOM_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
SESSIONS_DIR = settings.DATA_DIR / "sessions"

# The reply type edge_device.py waits for, for each incoming message type
REPLY_TYPES = {"register": "register_result", "session_start": "session_result",
               "audio_chunk": "chunk_ack", "session_end": "session_closed"}


def reply_extra(header):
    """Chunk answers also carry the chunk number, so the edge can say which chunk failed."""
    return {"seq": header.get("seq")} if header.get("type") == "audio_chunk" else {}

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY, mac_hash TEXT NOT NULL, email TEXT,
    identity_pubkey BLOB NOT NULL, alg TEXT NOT NULL, registered_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY, device_id TEXT NOT NULL, room TEXT NOT NULL, session_pubkey BLOB NOT NULL,
    audio TEXT, started_at TEXT NOT NULL, ended_at TEXT, end_reason TEXT, status TEXT NOT NULL, merged_file TEXT);
CREATE TABLE IF NOT EXISTS chunks (
    session_id TEXT NOT NULL, seq INTEGER NOT NULL, received_at TEXT NOT NULL, start_ms INTEGER,
    duration_ms INTEGER, size_bytes INTEGER, sha256 TEXT, verify_ms REAL, path TEXT,
    PRIMARY KEY (session_id, seq));
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, topic TEXT, device_id TEXT, detail TEXT);
"""


class Rejected(Exception):
    """Raised by a handler when a message must not be trusted."""
    def __init__(self, reply_type, reason, **extra):
        super().__init__(reason)
        self.reply_type, self.reason, self.extra = reply_type, reason, extra


def now():
    return datetime.now().isoformat(timespec="seconds")


class Server:
    def __init__(self, mock, allow_register):
        self.pqc = open_pqc(mock)
        self.allow_register = allow_register
        self.client = None
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        give_back_to_user(settings.DATA_DIR)
        give_back_to_user(SESSIONS_DIR)
        # used only from the MQTT network thread after start-up
        self.db = sqlite3.connect(str(settings.DB_PATH), check_same_thread=False)
        self.db.executescript(SCHEMA)
        give_back_to_user(settings.DB_PATH)

    # ------------------------------------------------------------------ plumbing
    def verify(self, signed, signature, public_key):
        """KAZ verification inside the server SSD. Returns (valid, milliseconds)."""
        if len(signature) != KAZ_SIGNATURE_LENGTH or len(public_key) != KAZ_PUBLIC_KEY_LENGTH:
            return False, 0.0
        t0 = time.perf_counter()
        valid = self.pqc.verify_with_key(signed, signature, public_key, settings.SERVER_VERIFY_SLOT)
        return valid, round((time.perf_counter() - t0) * 1000, 1)

    def reply(self, device_id, message):
        if DEVICE_ID_RE.fullmatch(str(device_id)):
            # no waiting here: we are inside the MQTT network thread
            self.client.publish(topic_status(device_id), json.dumps(message), qos=1)

    def security_event(self, topic, device_id, detail):
        self.db.execute("INSERT INTO security_events (at, topic, device_id, detail) VALUES (?,?,?,?)",
                        (now(), topic, str(device_id), detail))
        self.db.commit()
        log("SECURITY", f"REJECTED on {topic} (device {device_id}): {detail}", "err")

    def on_message(self, client, userdata, msg):
        header, device_id = {}, None
        try:
            header, signed, signature, body = unpack_frame(msg.payload)
            device_id = header.get("device_id")
            handlers = {"register": self.handle_register, "session_start": self.handle_session_start,
                        "audio_chunk": self.handle_chunk, "session_end": self.handle_session_end}
            handler = handlers.get(header.get("type"))
            if handler is None:
                raise Rejected("error", f"unknown message type {header.get('type')!r}")
            if header.get("alg") != self.pqc.name:
                raise Rejected(REPLY_TYPES[header["type"]], f"algorithm {header.get('alg')!r} not accepted "
                                                             f"(server runs {self.pqc.name})", **reply_extra(header))
            if not DEVICE_ID_RE.fullmatch(str(device_id)):
                raise Rejected("error", "invalid device id")
            handler(msg.topic, header, signed, signature, body)
        except Rejected as e:
            self.security_event(msg.topic, device_id, e.reason)
            self.reply(device_id, dict({"type": e.reply_type, "ok": False, "reason": e.reason}, **e.extra))
        except PQCError as e:
            # Not an attack: this machine's SSD could not do the check (e.g. the known -13 verify issue).
            # Answer with the reply type the edge is waiting for, so it shows the reason immediately.
            log("ssd", f"server SSD error: {e}", "err")
            self.reply(device_id, dict({"type": REPLY_TYPES.get(header.get("type"), "error"), "ok": False,
                                        "reason": f"server SSD could not verify: {e}"}, **reply_extra(header)))
        except (ValueError, KeyError, TypeError) as e:
            self.security_event(msg.topic, device_id, f"malformed message: {e}")
        except Exception:
            traceback.print_exc()   # never let one bad message kill the server

    # ------------------------------------------------------------------ 1. registration
    def handle_register(self, topic, h, signed, signature, body):
        device_id, mac = h["device_id"], str(h["mac"])
        if topic != TOPIC_REGISTER:
            raise Rejected("register_result", "register message on wrong topic")
        if not self.allow_register:
            raise Rejected("register_result", "registration is closed (start server.py with --allow-register)")
        if device_id_for(mac) != device_id:
            raise Rejected("register_result", "device id does not match the MAC address")
        public_key = b64d(h["identity_pubkey"])
        valid, ms = self.verify(signed, signature, public_key)
        if not valid:
            raise Rejected("register_result", "invalid KAZ signature")
        self.db.execute("INSERT OR REPLACE INTO devices VALUES (?,?,?,?,?,?)",
                        (device_id, sha256_hex(mac.encode()), h.get("email", ""), public_key, h["alg"], now()))
        self.db.commit()
        log("register", f"device {device_id} registered - signature VALID ({ms} ms in SSD), "
                        f"stored hashed MAC + identity public key", "ok")
        self.reply(device_id, {"type": "register_result", "ok": True})

    # ------------------------------------------------------------------ 2. handshake
    def handle_session_start(self, topic, h, signed, signature, body):
        device_id, session_id, room = h["device_id"], str(h["session_id"]), str(h["room"])
        if topic != TOPIC_SESSION_START:
            raise Rejected("session_result", "session start on wrong topic")
        if not SESSION_ID_RE.fullmatch(session_id) or not ROOM_RE.fullmatch(room):
            raise Rejected("session_result", "invalid session id or room name")
        device = self.db.execute("SELECT mac_hash, identity_pubkey FROM devices WHERE device_id=?",
                                 (device_id,)).fetchone()
        if device is None:
            raise Rejected("session_result", "unregistered device - possible attack")
        if sha256_hex(str(h["mac"]).encode()) != device[0]:
            raise Rejected("session_result", "MAC address does not match the registration")
        if abs(time.time() - float(h["ts"])) > settings.MAX_CLOCK_SKEW_SECONDS:
            raise Rejected("session_result", "request timestamp too old/new (replay?) - check both clocks")
        valid, ms = self.verify(signed, signature, device[1])
        if not valid:
            raise Rejected("session_result", "invalid identity signature - possible attack")
        if self.db.execute("SELECT 1 FROM sessions WHERE session_id=?", (session_id,)).fetchone():
            raise Rejected("session_result", "session id already used (replay?)")
        session_pubkey = b64d(h["session_pubkey"])
        if len(session_pubkey) != KAZ_PUBLIC_KEY_LENGTH:
            raise Rejected("session_result", "invalid session public key")

        self.db.execute("INSERT INTO sessions (session_id, device_id, room, session_pubkey, audio, started_at, "
                        "status) VALUES (?,?,?,?,?,?,?)",
                        (session_id, device_id, room, session_pubkey, json.dumps(h.get("audio", {})), now(),
                         "recording"))
        self.db.commit()
        session_dir = SESSIONS_DIR / session_id
        session_dir.mkdir(exist_ok=True)
        give_back_to_user(session_dir)
        log("handshake", f"device {device_id} PASS - registered + identity signature VALID ({ms} ms). "
                         f"Session {session_id[:8]} started in {room}", "ok")
        self.reply(device_id, {"type": "session_result", "ok": True, "session_id": session_id})

    # ------------------------------------------------------------------ 3. audio chunks
    def load_session(self, h, reply_type, **extra):
        session_id = str(h["session_id"])
        row = self.db.execute("SELECT device_id, session_pubkey, status, room, audio FROM sessions "
                              "WHERE session_id=?", (session_id,)).fetchone()
        if row is None or row[0] != h["device_id"]:
            raise Rejected(reply_type, "unknown session for this device", **extra)
        return session_id, row

    def handle_chunk(self, topic, h, signed, signature, body):
        seq = int(h["seq"])
        session_id, (device_id, session_pubkey, status, room, _) = self.load_session(h, "chunk_ack", seq=seq)
        if status != "recording":
            raise Rejected("chunk_ack", "session is already closed", seq=seq)
        if topic != topic_audio(room) or seq < 1:
            raise Rejected("chunk_ack", "wrong topic or sequence number", seq=seq)
        valid, ms = self.verify(signed, signature, session_pubkey)
        if not valid:
            raise Rejected("chunk_ack", "invalid KAZ signature - chunk discarded (tampered?)", seq=seq)
        if sha256_hex(body) != h["sha256"]:
            raise Rejected("chunk_ack", "audio hash mismatch", seq=seq)
        if self.db.execute("SELECT 1 FROM chunks WHERE session_id=? AND seq=?", (session_id, seq)).fetchone():
            raise Rejected("chunk_ack", "duplicate chunk (replay?)", seq=seq)

        path = SESSIONS_DIR / session_id / f"chunk_{seq:05d}.wav"
        path.write_bytes(body)
        give_back_to_user(path)
        self.db.execute("INSERT INTO chunks VALUES (?,?,?,?,?,?,?,?,?)",
                        (session_id, seq, now(), h.get("start_ms"), h.get("duration_ms"), len(body),
                         h["sha256"], ms, str(path)))
        self.db.commit()
        log("verify", f"session {session_id[:8]} chunk #{seq}: KAZ signature VALID ({ms} ms in SSD) "
                      f"-> stored {path.name} ({len(body) // 1024} KB)", "ok")
        self.reply(device_id, {"type": "chunk_ack", "ok": True, "seq": seq, "verify_ms": ms})

    # ------------------------------------------------------------------ 4. end of meeting
    def handle_session_end(self, topic, h, signed, signature, body):
        session_id, (device_id, session_pubkey, status, room, audio) = self.load_session(h, "session_closed")
        if topic != topic_disconnect(room) or body != b"OFF":
            raise Rejected("session_closed", "invalid OFF message")
        valid, ms = self.verify(signed, signature, session_pubkey)
        if not valid:
            raise Rejected("session_closed", "invalid KAZ signature on OFF message")
        if status != "recording":
            log("session", f"session {session_id[:8]} already closed - ignoring extra OFF")
            return

        merged_file, chunk_count, missing = self.merge_session(session_id, json.loads(audio or "{}"))
        reason = str(h.get("reason", ""))
        self.db.execute("UPDATE sessions SET status='closed', ended_at=?, end_reason=?, merged_file=? "
                        "WHERE session_id=?", (now(), reason, merged_file, session_id))
        self.db.commit()
        log("session", f"session {session_id[:8]} closed ({reason}): {chunk_count} verified chunk(s)"
                       f"{', missing ' + str(missing) if missing else ''} -> {merged_file}", "ok")
        self.reply(device_id, {"type": "session_closed", "ok": True, "merged_file": merged_file,
                               "verified_chunks": chunk_count, "missing_chunks": missing})

    def merge_session(self, session_id, audio):
        """Join all verified chunks into one WAV (ready for transcription). Gaps become silence."""
        rows = self.db.execute("SELECT seq, path FROM chunks WHERE session_id=? ORDER BY seq",
                               (session_id,)).fetchall()
        if not rows:
            return None, 0, []
        chunk_seconds = min(max(int(audio.get("chunk_seconds", settings.CHUNK_SECONDS)), 1), 600)
        merged_path = SESSIONS_DIR / session_id / "meeting_full.wav"
        missing, expected = [], 1
        with wave.open(str(merged_path), "wb") as merged:
            for index, (seq, path) in enumerate(rows):
                with wave.open(path, "rb") as chunk:
                    if index == 0:
                        merged.setparams(chunk.getparams())
                    frame_bytes = chunk.getsampwidth() * chunk.getnchannels()
                    while expected < seq:
                        missing.append(expected)
                        merged.writeframes(b"\x00" * (chunk.getframerate() * chunk_seconds * frame_bytes))
                        expected += 1
                    merged.writeframes(chunk.readframes(chunk.getnframes()))
                expected = seq + 1
        give_back_to_user(merged_path)
        return str(merged_path), len(rows), missing

    # ------------------------------------------------------------------ main loop
    def run(self):
        log("ssd", f"Phison SDK {self.pqc.version()}, drive {settings.PQC_DEVICE}")
        log("ssd", f"PQC SSD detected, firmware {self.pqc.check_device()}", "ok")
        self.client = make_client("pqc-server", settings.SERVER_MQTT_USER, settings.SERVER_MQTT_PASSWORD)
        self.client.on_message = self.on_message

        def subscribe(client):
            for topic in SERVER_SUBSCRIPTIONS:
                client.subscribe(topic, qos=1)
            log("mqtt", "subscribed to " + ", ".join(SERVER_SUBSCRIPTIONS))

        connect(self.client, on_connected=subscribe)
        log("server", f"registration is {'OPEN' if self.allow_register else 'closed'}; "
                      f"data in {settings.DATA_DIR}. Waiting for edge devices (Ctrl+C to stop) ...", "info")
        stop = threading.Event()
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        while not stop.wait(1):
            pass
        log("server", "shutting down")
        self.client.disconnect()
        self.client.loop_stop()


def main():
    parser = argparse.ArgumentParser(description="PQC server: verify KAZ-signed audio chunks and store them")
    parser.add_argument("--allow-register", action="store_true", help="accept new device registrations")
    parser.add_argument("--mock-pqc", action="store_true", help="testing only: no SSD, fake signatures")
    args = parser.parse_args()
    Server(args.mock_pqc, args.allow_register).run()


if __name__ == "__main__":
    main()
