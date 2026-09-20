"""
common.py - helpers shared by edge_device.py and server.py

  * topic names
  * message format: header + KAZ signature + body
  * MQTT client over TLS (works with paho-mqtt 1.6 from apt and paho-mqtt 2.x from pip)
  * MAC address / device id, logging
"""
import base64
import hashlib
import json
import os
import ssl
import struct
import threading
import time
from pathlib import Path

import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties

import settings

# --------------------------------------------------------------------------- topics
P = settings.TOPIC_PREFIX
TOPIC_REGISTER = f"{P}/register"                    # edge -> server (once)
TOPIC_SESSION_START = f"{P}/session/start"          # edge -> server (every meeting)
SERVER_SUBSCRIPTIONS = [TOPIC_REGISTER, TOPIC_SESSION_START, f"{P}/+/audio", f"{P}/+/audio/disconnect"]


def topic_audio(room):             # edge -> server, one message per signed chunk
    return f"{P}/{room}/audio"


def topic_disconnect(room):        # edge -> server, payload "OFF" = end of meeting
    return f"{P}/{room}/audio/disconnect"


def topic_status(device_id):       # server -> edge, pass/fail answers
    return f"{P}/device/{device_id}/status"


# --------------------------------------------------------------------------- message format
#
#  +--------+------------+---------+---------------+----------------+---------------+
#  | "PQC1" | header len | sig len | header (JSON) | KAZ signature  | body (WAV...) |
#  | 4 B    | 4 B        | 2 B     |               | 354 B          |               |
#  +--------+------------+---------+---------------+----------------+---------------+
#
#  The SSD signs exactly: header bytes + body bytes.
#  So nobody can change the audio OR its metadata (session, sequence number, time)
#  without the signature check failing on the server.
MAGIC = b"PQC1"
_PREFIX = struct.Struct(">4sIH")


def pack_frame(header, body, sign):
    """sign(bytes) -> signature bytes (e.g. lambda data: pqc.sign(data, slot))."""
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    signature = sign(header_bytes + body)
    return _PREFIX.pack(MAGIC, len(header_bytes), len(signature)) + header_bytes + signature + body


def unpack_frame(payload):
    """Returns (header, signed_bytes, signature, body). Raises ValueError if malformed."""
    if len(payload) < _PREFIX.size:
        raise ValueError("payload too short")
    magic, header_len, sig_len = _PREFIX.unpack_from(payload)
    if magic != MAGIC:
        raise ValueError("not a PQC1 message")
    start = _PREFIX.size
    header_bytes = payload[start:start + header_len]
    signature = payload[start + header_len:start + header_len + sig_len]
    body = payload[start + header_len + sig_len:]
    if len(header_bytes) != header_len or len(signature) != sig_len:
        raise ValueError("truncated message")
    header = json.loads(header_bytes)
    if not isinstance(header, dict):
        raise ValueError("header is not a JSON object")
    return header, header_bytes + body, signature, body


def b64e(data):
    return base64.b64encode(data).decode()


def b64d(text):
    return base64.b64decode(text, validate=True)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- device identity
def get_mac_address():
    """Returns (interface, MAC). 'auto' = first physical network card, sorted by name."""
    net = Path("/sys/class/net")
    if settings.MAC_INTERFACE == "auto":
        names = sorted(p.name for p in net.iterdir() if (p / "device").exists())
    else:
        names = [settings.MAC_INTERFACE]
    for name in names:
        try:
            mac = (net / name / "address").read_text().strip().upper()
        except OSError:
            continue
        if mac and mac != "00:00:00:00:00:00":
            return name, mac
    raise SystemExit(f"No usable network card found (MAC_INTERFACE={settings.MAC_INTERFACE!r} in settings.py)")


def device_id_for(mac):
    """Short id derived from the hashed MAC address (used in topics and client id)."""
    return sha256_hex(mac.encode())[:16]


# --------------------------------------------------------------------------- MQTT over TLS
def _is_failure(reason_code):
    value = getattr(reason_code, "value", reason_code)
    return value >= 0x80 if isinstance(value, int) else bool(value)


def make_client(client_id, username, password, will=None):
    """MQTT v5 client that only talks TLS and checks the broker certificate against our CA."""
    kwargs = dict(client_id=client_id, protocol=mqtt.MQTTv5)
    if hasattr(mqtt, "CallbackAPIVersion"):   # paho-mqtt 2.x
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, **kwargs)
    else:                                     # paho-mqtt 1.6 (Ubuntu apt package)
        client = mqtt.Client(**kwargs)
    client.username_pw_set(username, password)

    if not Path(settings.CA_CERT).exists():
        raise SystemExit(f"CA certificate not found: {settings.CA_CERT}\n"
                         "Create it first:  bash broker/make_certs.sh")
    context = ssl.create_default_context(cafile=str(settings.CA_CERT))  # verifies cert + hostname
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    client.tls_set_context(context)

    if will:
        topic, payload = will
        client.will_set(topic, payload, qos=1)   # broker publishes this if we vanish
    return client


def connect(client, user_properties=None, on_connected=None, timeout=15):
    """Connect + start the background network thread. Returns once connected.
    on_connected(client) is called after every (re)connect - use it to subscribe."""
    connected = threading.Event()
    outcome = {}

    def on_connect(client, userdata, flags, reason_code, properties=None):
        outcome["reason"] = reason_code
        if not _is_failure(reason_code) and on_connected:
            on_connected(client)
        connected.set()

    client.on_connect = on_connect
    properties = Properties(PacketTypes.CONNECT)
    for key, value in (user_properties or {}).items():
        properties.UserProperty = (key, value)

    host, port = settings.BROKER_HOST, settings.BROKER_PORT
    try:
        client.connect(host, port, keepalive=30, properties=properties)
    except ssl.SSLCertVerificationError as e:
        raise SystemExit(f"TLS certificate problem talking to {host}:{port}: {e.verify_message}\n"
                         "-> is BROKER_HOST in the certificate? Re-run broker/make_certs.sh with that "
                         "name/IP, reinstall the broker config, and copy the new ca.crt to the edge.")
    except OSError as e:
        raise SystemExit(f"Cannot reach MQTT broker at {host}:{port}: {e}\n"
                         "-> is Mosquitto running?  sudo systemctl status mosquitto")
    client.loop_start()

    if not connected.wait(timeout):
        client.loop_stop()
        raise SystemExit(f"No answer from broker {host}:{port} within {timeout}s")
    if _is_failure(outcome["reason"]):
        client.loop_stop()
        raise SystemExit(f"Broker refused the connection: {outcome['reason']}\n"
                         "-> check the MQTT username/password in settings.py and broker/install_broker.sh")
    tls = client.socket().version() if hasattr(client.socket(), "version") else "?"
    log("mqtt", f"connected to {host}:{port} over {tls} as '{client._username.decode()}'", "ok")


def publish(client, topic, payload, timeout=30):
    """Publish with QoS 1 and wait until the broker confirms. Returns True/False."""
    info = client.publish(topic, payload, qos=1)
    try:
        info.wait_for_publish(timeout)
    except (RuntimeError, ValueError):
        return False
    return info.is_published()


# --------------------------------------------------------------------------- misc
COLORS = {"ok": "\x1b[32m", "err": "\x1b[31m", "warn": "\x1b[33m", "info": "\x1b[36m"}


def log(tag, message, level=None):
    line = f"[{time.strftime('%H:%M:%S')}] [{tag}] {message}"
    print(f"{COLORS[level]}{line}\x1b[0m" if level in COLORS else line, flush=True)


def give_back_to_user(path):
    """Files created under sudo belong to root; hand them back to the normal user."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() == 0 and uid and gid:
        try:
            os.chown(path, int(uid), int(gid))
        except OSError:
            pass
