"""
settings.py - the ONLY file you normally need to edit.

Both edge_device.py (laptop + USB mic) and server.py (verifier) read this file.
If the server later runs on another machine, copy this whole folder there and
change BROKER_HOST (on the edge) and PQC_DEVICE (on the server).
"""
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# MQTT broker (Mosquitto) - MQTT over TLS
# --------------------------------------------------------------------------
BROKER_HOST = "100.88.77.71"      # edge on another machine? use the server IP, e.g. "10.176.68.49"
BROKER_PORT = 8883             # 8883 = standard port for MQTT over TLS
CA_CERT = PROJECT_DIR / "broker" / "certs" / "ca.crt"   # made by broker/make_certs.sh

# Must match the users created by broker/install_broker.sh
EDGE_MQTT_USER = "pqc-edge"
EDGE_MQTT_PASSWORD = "edge123"
SERVER_MQTT_USER = "pqc-server"
SERVER_MQTT_PASSWORD = "server123"

TOPIC_PREFIX = "maistorage/pqc"
ROOM_ID = "room-04"            # audio goes to maistorage/pqc/room-04/audio

# --------------------------------------------------------------------------
# Phison PQC SSD (E31T) + SDK
# --------------------------------------------------------------------------
# Phison PQC library V3 (the "PQC-LIBR V3" folder). The V3 library reports its own
# version number as 1.1.0, so "Phison SDK 1.1.0" in the output means V3 is in use.
SDK_LIB = Path("/home/phison/pqc_linux_so/demo_project/lib/libphison_agent.so.1.1.0")

# On this laptop: nvme1n1 = E31T PQC SSD, nvme0n1 = your OS disk. Do NOT use nvme0n1.
PQC_DEVICE = "/dev/nvme1n1"

# SSD password. Factory default is the 32 bytes 0x00..0x1F (same as Phison demo_app).
# If you changed it with demo_app option 4, put it here, e.g. b"my-new-password"
PQC_PASSWORD = bytes(range(32))

# KAZ key slots (valid 0x02-0x07). 0x02/0x03 are left free for Phison's demo_app.
EDGE_IDENTITY_SLOT = 0x04      # long-term device key, created once by "register"
EDGE_SESSION_SLOT = 0x05       # brand-new key pair for every meeting
SERVER_VERIFY_SLOT = 0x06      # server injects the edge's public key here to verify
SELFTEST_SLOT = 0x07           # used only by test_pqc.py

# --------------------------------------------------------------------------
# Audio capture (edge device)
# --------------------------------------------------------------------------
AUDIO_DEVICE = "plughw:CARD=Device,DEV=0"   # "USB PnP Sound Device" (check with: arecord -l)
SAMPLE_RATE = 16000            # 16 kHz mono = what speech-to-text models (e.g. Whisper) use
CHANNELS = 1
CHUNK_SECONDS = 10             # length of each signed chunk (your diagram says 20-60 s; any value works)

MAC_INTERFACE = "auto"         # "auto" = first physical network card, or set e.g. "wlo1"

# Fail closed: stop recording if the server rejects a chunk.
STOP_ON_REJECTED_CHUNK = True

# --------------------------------------------------------------------------
# Server storage ("Database" in the sequence diagram)
# --------------------------------------------------------------------------
DATA_DIR = PROJECT_DIR / "server_data"
DB_PATH = DATA_DIR / "pqc_poc.db"
MAX_CLOCK_SKEW_SECONDS = 300   # reject session requests older/newer than 5 minutes (replay protection)

# Used only with --mock-pqc (software stand-in, no SSD, NOT secure)
MOCK_KEYSTORE = PROJECT_DIR / "mock_ssd_keys.json"
