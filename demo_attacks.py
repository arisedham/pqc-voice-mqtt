#!/usr/bin/env python3
"""
demo_attacks.py - show that the server rejects forged, tampered and replayed data.

  sudo python3 demo_attacks.py

Needs: server.py running and this device already registered.
Do NOT run it while a real recording is in progress (it replaces the session key in the SSD).
Every attack must end as REJECTED / BLOCKED - watch server.py print SECURITY events.
"""
import json
import os
import queue
import sys
import time
import uuid

import settings
from common import (TOPIC_SESSION_START, b64e, connect, device_id_for, get_mac_address, log, make_client,
                    pack_frame, publish, sha256_hex, topic_audio, topic_disconnect, topic_status)
from edge_device import make_wav
from pqc_sdk import KAZ_PUBLIC_KEY_LENGTH, KAZ_SIGNATURE_LENGTH, open_pqc

replies = queue.Queue()
results = []


def on_message(client, userdata, msg):
    try:
        replies.put(json.loads(msg.payload))
    except ValueError:
        pass


def wait_for(reply_type, seq=None, timeout=20):
    deadline = time.time() + timeout
    while (remaining := deadline - time.time()) > 0:
        try:
            reply = replies.get(timeout=remaining)
        except queue.Empty:
            break
        if reply.get("type") == reply_type and (seq is None or reply.get("seq") == seq):
            return reply
    return None


def check(name, reply, should_be_accepted):
    if reply is None:
        outcome, passed = "no answer from server", False
    elif reply.get("ok"):
        outcome, passed = "accepted", should_be_accepted
    else:
        outcome, passed = f"REJECTED: {reply.get('reason')}", not should_be_accepted
    results.append((name, outcome, passed))
    log("demo", f"{name} -> {outcome}", "ok" if passed else "err")


def main():
    pqc = open_pqc(mock="--mock-pqc" in sys.argv)
    _, mac = get_mac_address()
    device_id = device_id_for(mac)
    fake_mac = "02:00:DE:AD:BE:EF"
    fake_id = device_id_for(fake_mac)
    room = settings.ROOM_ID

    def sign_identity(data):
        return pqc.sign(data, settings.EDGE_IDENTITY_SLOT)

    def sign_session(data):
        return pqc.sign(data, settings.EDGE_SESSION_SLOT)

    def subscribe(client):
        client.subscribe(topic_status(device_id), qos=1)
        client.subscribe(topic_status(fake_id), qos=1)

    client = make_client(f"edge-recorder-{device_id}-demo", settings.EDGE_MQTT_USER, settings.EDGE_MQTT_PASSWORD)
    client.on_message = on_message
    connect(client, {"mac_address": mac}, on_connected=subscribe)

    # Attack 1: a device that was never registered tries to start a session
    fake_start = {"type": "session_start", "alg": pqc.name, "device_id": fake_id, "mac": fake_mac,
                  "session_id": uuid.uuid4().hex, "room": room, "audio": {}, "ts": int(time.time()),
                  "session_pubkey": b64e(os.urandom(KAZ_PUBLIC_KEY_LENGTH))}
    publish(client, TOPIC_SESSION_START, pack_frame(fake_start, b"", sign_identity))
    check("1. unregistered device starts a session", wait_for("session_result"), False)

    # Genuine session, needed for the next attacks
    session_id = uuid.uuid4().hex
    session_pubkey = pqc.generate_key_pair(settings.EDGE_SESSION_SLOT)
    base = {"alg": pqc.name, "device_id": device_id, "session_id": session_id}
    start = dict(base, type="session_start", mac=mac, room=room, audio={"chunk_seconds": 1},
                 session_pubkey=b64e(session_pubkey), ts=int(time.time()))
    publish(client, TOPIC_SESSION_START, pack_frame(start, b"", sign_identity))
    check("   genuine device starts a session", wait_for("session_result"), True)

    wav = make_wav(bytes(settings.SAMPLE_RATE * settings.CHANNELS * 2))  # 1 second of silence

    def chunk(seq):
        header = dict(base, type="audio_chunk", seq=seq, format="wav", start_ms=(seq - 1) * 1000,
                      duration_ms=1000, sha256=sha256_hex(wav), ts=time.time())
        return pack_frame(header, wav, sign_session)

    genuine = chunk(1)
    publish(client, topic_audio(room), genuine)
    check("   genuine signed chunk #1", wait_for("chunk_ack", seq=1), True)

    # Attack 2: change ONE audio byte after the SSD signed it (man-in-the-middle)
    tampered = bytearray(chunk(2))
    tampered[-1] ^= 0x01
    publish(client, topic_audio(room), bytes(tampered))
    check("2. tampered audio (1 byte changed)", wait_for("chunk_ack", seq=2), False)

    # Attack 3: send the accepted chunk #1 again (replay)
    publish(client, topic_audio(room), genuine)
    check("3. replay of an already accepted chunk", wait_for("chunk_ack", seq=1), False)

    # Attack 4: replace the KAZ signature with random bytes (forgery)
    forged = bytearray(chunk(3))
    signature_start = 10 + int.from_bytes(forged[4:8], "big")
    forged[signature_start:signature_start + KAZ_SIGNATURE_LENGTH] = os.urandom(KAZ_SIGNATURE_LENGTH)
    publish(client, topic_audio(room), bytes(forged))
    check("4. forged signature (random bytes)", wait_for("chunk_ack", seq=3), False)

    end = dict(base, type="session_end", reason="demo_finished", ts=int(time.time()))
    publish(client, topic_disconnect(room), pack_frame(end, b"OFF", sign_session))
    wait_for("session_closed")
    client.disconnect()
    client.loop_stop()

    # Attack 5: log in to the broker with a wrong password
    intruder = make_client("intruder", settings.EDGE_MQTT_USER, "wrong-password")
    try:
        connect(intruder, timeout=10)
        intruder.disconnect()
        intruder.loop_stop()
        outcome, passed = "accepted", False
    except SystemExit:
        outcome, passed = "BLOCKED by broker", True
    results.append(("5. MQTT login with wrong password", outcome, passed))
    log("demo", f"5. MQTT login with wrong password -> {outcome}", "ok" if passed else "err")

    print("\n  Result  Test")
    for name, outcome, passed in results:
        print(f"  {'PASS' if passed else 'FAIL':<6}  {name:<42} {outcome}")
    sys.exit(0 if all(passed for _, _, passed in results) else 1)


if __name__ == "__main__":
    main()
