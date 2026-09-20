# PQC-Signed Meeting Audio over MQTT/TLS: Step-by-Step Guide

POC goal: the **EDGE laptop** records meeting audio and **signs every chunk inside its Phison PQC SSD (KAZ-SIGN)**.
It sends the chunks with **MQTT over TLS** to the **SERVER**, which **verifies every chunk inside its own PQC SSD**
before storing it.

```
EDGE = your laptop                                     SERVER = 100.88.77.71
USB mic ─► edge_device.py                              Mosquitto broker (TLS 1.3, port 8883)
           PQC SSD 1: KAZ sign ─── MQTT over TLS ───►    └─► server.py ─► PQC SSD 2: KAZ verify
                                                                      └─► SQLite + WAV files
```

> ⚠️ **Known issue (15 Sept):** signature **verification** fails with error `-13` on the laptop's SSD
> (firmware `EVFM00.0-0002`), even in Phison's own `demo_app`. Signing works. The server's SSD must be able to verify,
> so test it in step **A4**. See [Known issue](#known-issue-verification-fails-with--13) and `PHISON_VERIFY_ISSUE.md`.

---

## Which machine does what

| | **EDGE** (your laptop) | **SERVER** (`100.88.77.71`) |
|---|---|---|
| Hardware | USB mic + PQC SSD 1 (`/dev/nvme1n1`) | PQC SSD 2 |
| The PQC SSD... | creates keys and **signs** | **verifies** |
| Install | `python3-paho-mqtt`, `alsa-utils`, `mosquitto-clients` | `mosquitto`, `mosquitto-clients`, `python3-paho-mqtt` |
| Runs | `test_mic.py`, `test_pqc.py`, `edge_device.py`, `demo_attacks.py` | `test_pqc.py`, `broker/make_certs.sh`, `broker/install_broker.sh`, `server.py` |
| Keeps | only `broker/certs/ca.crt` | all certificates and keys, `server_data/` (recordings + database) |

**Order:** set up the SERVER first (Part A), then the EDGE (Part B), then record (Part C).

Both machines use **the same project folder and the same `settings.py`**. Only `PQC_DEVICE` and `SDK_LIB` may be
different on the server.

> **Terminal tip:** in VS Code use *Terminal → New Terminal*. To type commands on the server from your laptop,
> open a terminal and run `ssh <server-user>@100.88.77.71` (`<server-user>` = your login name on the server).
> Unless a step says otherwise, run commands inside the project folder: `cd ~/pqc-voice-mqtt`
>
> `~/pqc-voice-poc` on the laptop holds a **different, earlier implementation**. Don't mix files between the two folders.

---

## Part A: SERVER setup

### A1. Copy the project and the Phison SDK to the server
**Run on: EDGE** (the files are on your laptop)
```bash
scp -r ~/pqc-voice-mqtt <server-user>@100.88.77.71:~/
scp "/home/phison/PQC/PQC-LIBR V3/pqc_linux_so.tar.gz" <server-user>@100.88.77.71:~/
```
No SSH on the server? Copy the `pqc-voice-mqtt` folder and `pqc_linux_so.tar.gz` into the server user's home folder
with a USB stick.

### A2. Install the software and unpack the SDK
**Run on: SERVER**
```bash
sudo apt update
sudo apt install -y mosquitto mosquitto-clients python3-paho-mqtt
mkdir -p ~/pqc_linux_so && tar -xzf ~/pqc_linux_so.tar.gz -C ~/pqc_linux_so
```

### A3. Point `settings.py` at the server's SSD and SDK
**Run on: SERVER**

Find the PQC SSD. It is the line with `vendor=0x1987 device=0x5031` (Phison E31T):
```bash
for d in /sys/class/nvme/nvme*; do echo "/dev/$(basename $d)n1  vendor=$(cat $d/device/vendor) device=$(cat $d/device/device) firmware=$(cat $d/firmware_rev)"; done
```

Open the settings with `nano ~/pqc-voice-mqtt/settings.py` and change only these two lines
(save: Ctrl+O then Enter, exit: Ctrl+X):
```python
PQC_DEVICE = "/dev/nvme1n1"   # use the E31T line from the command above
SDK_LIB = Path("/home/<server-user>/pqc_linux_so/demo_project/lib/libphison_agent.so.1.1.0")
```
Leave `BROKER_HOST = "100.88.77.71"` and the MQTT users and passwords exactly as they are on the laptop.

### A4. Test the server SSD
**Run on: SERVER**
```bash
cd ~/pqc-voice-mqtt
sudo python3 test_pqc.py
```
The last lines tell you what this SSD can do:
```
  EDGE functions   (key pair + signing):         PASS
  SERVER functions (verify_signature_with_key):  PASS
```
**On the server, the SERVER line must say PASS.** If it says FAIL with `-13`, this SSD has the known verification issue.
Run `sudo python3 diag_verify.py` and send its output to Phison together with `PHISON_VERIFY_ISSUE.md`
(write the server's firmware version in the report too). You can finish the setup, but registration and recording
will be rejected until verification works.

### A5. Create the TLS certificates and start the broker
**Run on: SERVER**
```bash
bash broker/make_certs.sh 100.88.77.71
sudo bash broker/install_broker.sh
```
Expected: `Certificate is valid for: ... IP:100.88.77.71` and `OK: Mosquitto is running with TLS 1.3 on port 8883`.
If the script says the firewall is active, also run `sudo ufw allow 8883/tcp`.

`install_broker.sh` creates the MQTT users `pqc-edge` and `pqc-server` with the passwords from `settings.py`.
If you change a password later, change it in `settings.py` on **both** machines and run `install_broker.sh` again here.

### A6. Start the server
**Run on: SERVER** (keep this terminal open)
```bash
sudo python3 server.py --allow-register
```
Wait for: `registration is OPEN ... Waiting for edge devices`

---

## Part B: EDGE setup

### B1. Install the software
**Run on: EDGE**
```bash
sudo apt update
sudo apt install -y python3-paho-mqtt alsa-utils mosquitto-clients
```
The laptop doesn't need the Mosquitto broker itself, only the client tools.

### B2. Copy the server's CA certificate to the laptop
**Run on: EDGE**
```bash
mkdir -p ~/pqc-voice-mqtt/broker/certs
scp <server-user>@100.88.77.71:~/pqc-voice-mqtt/broker/certs/ca.crt ~/pqc-voice-mqtt/broker/certs/
```
Copy **only** `ca.crt`. `ca.key` and `server.key` must stay on the server.
Whenever you run `make_certs.sh` again on the server, copy the new `ca.crt` again.

### B3. Check `settings.py`
**Run on: EDGE.** Open `~/pqc-voice-mqtt/settings.py` and check:
* `BROKER_HOST = "100.88.77.71"`
* `EDGE_MQTT_USER`, `EDGE_MQTT_PASSWORD`, `SERVER_MQTT_USER` and `SERVER_MQTT_PASSWORD` are the same as on the server
* `PQC_DEVICE = "/dev/nvme1n1"` (the laptop's E31T; `nvme0n1` is your system disk)

### B4. Test the microphone
**Run on: EDGE**
```bash
cd ~/pqc-voice-mqtt
python3 test_mic.py        # talk for 5 seconds
aplay test_mic.wav         # listen
```
Expected: a level bar for every second and `OK: the microphone is picking up sound`.
* Too quiet? Run `alsamixer -c 1`, press **F4**, and raise the capture level.
* `Device or resource busy`? Close Zoom, Teams, browser tabs or Sound Settings that use the mic.

### B5. Test the laptop SSD
**Run on: EDGE**
```bash
sudo python3 test_pqc.py
```
**On the laptop, the EDGE line must say PASS.** Because of the known issue, the SERVER line says FAIL on this laptop.
That's fine: the edge only creates keys and signs.

### B6. Test the connection to the server's broker
**Run on: EDGE**
```bash
mosquitto_sub -d -h 100.88.77.71 -p 8883 --cafile broker/certs/ca.crt \
  -u pqc-edge -P edge123 -t 'maistorage/pqc/device/+/status' -W 5
```
(If you changed the edge password in `settings.py`, use that instead of `edge123`.)

It works when you see `received CONNACK (0)` and `Subscribed`, then `Timed out` after 5 seconds. The timeout is normal.

| Instead you see | Fix |
|---|---|
| `Connection Refused: not authorised` | Username or password differ: make both `settings.py` files the same, then run `sudo bash broker/install_broker.sh` on the server |
| `host name verification failed` | The certificate doesn't include `100.88.77.71`: repeat A5, then B2 |
| `Error: Connection refused` | Mosquitto isn't running: on the server run `sudo systemctl status mosquitto` |
| Nothing happens for a long time, then a timeout error | Network or firewall: `ping 100.88.77.71`, and on the server `sudo ufw allow 8883/tcp` |

---

## Part C: Record a meeting

### C1. Register the laptop (once)
**Run on: EDGE** (while the server runs with `--allow-register`)
```bash
sudo python3 edge_device.py register --email you@company.com
```
* EDGE shows: `server verified the signature and stored this device. Registration done!`
* SERVER shows: `device ... registered - signature VALID`

Then close registration. **Run on: SERVER:** press Ctrl+C, then start the server normally:
```bash
sudo python3 server.py
```

### C2. Record
**Run on: EDGE**
```bash
sudo python3 edge_device.py record
```
Talk, then press **Ctrl+C** to end the meeting. The EDGE shows something like:
```
[handshake] PASS - device identity verified by server, recording starts
[chunk] #1: 10.0s audio, 312 KB, level -28 dBFS, KAZ-signed in 180 ms, published
[server] chunk #1 verified by server SSD (25 ms) and stored
...
[server] meeting saved: .../server_data/sessions/<session-id>/meeting_full.wav
```
The SERVER prints a green `KAZ signature VALID` line for every chunk.
For a test that stops by itself: `sudo python3 edge_device.py record --duration 30`

### C3. Listen to the recording
The recording is saved **on the SERVER** in `~/pqc-voice-mqtt/server_data/sessions/<session-id>/meeting_full.wav`.

**Run on: SERVER** to show the path of the newest recording:
```bash
ls -t ~/pqc-voice-mqtt/server_data/sessions/*/meeting_full.wav | head -1
```
**Run on: EDGE** to copy it to the laptop and play it (paste the path from the server):
```bash
scp <server-user>@100.88.77.71:<path from the server> ~/meeting.wav
aplay ~/meeting.wav
```

### C4. Show that attacks are rejected
**Run on: EDGE** (with the server running, and not while recording)
```bash
sudo python3 demo_attacks.py
```
All lines must say PASS. The SERVER prints red `SECURITY` lines and saves them in the `security_events` table.

---

## Demo-day checklist (30 Sept)

**The day before**
* SERVER: A4 (`sudo python3 test_pqc.py`)
* EDGE: B4, B5, B6 and C4

**On the day**
1. **SERVER:** `sudo systemctl status mosquitto` shows *active (running)*, and `timedatectl` shows `System clock synchronized: yes`.
2. **EDGE:** plug in the USB mic **before** you start, and check `timedatectl` too.
3. Open three terminals on the laptop:
   * **T1 (SERVER, via ssh):** `cd ~/pqc-voice-mqtt && sudo python3 server.py`
   * **T2 (SERVER, via ssh), traffic watcher:**
     `cd ~/pqc-voice-mqtt && mosquitto_sub -h localhost -p 8883 --cafile broker/certs/ca.crt -u pqc-server -P server123 -t 'maistorage/pqc/#' -F '%t  (%l bytes)'`
   * **T3 (EDGE):** `cd ~/pqc-voice-mqtt` for the edge commands
4. Demo flow: T3 `sudo python3 test_pqc.py` → T3 `sudo python3 edge_device.py record` (talk for 1 minute, then Ctrl+C)
   → play the recording (C3) → T3 `sudo python3 demo_attacks.py`

---

## Trying everything on one laptop (optional)

To rehearse without the server, run both roles on the laptop:
1. In `settings.py`, set `BROKER_HOST = "localhost"`.
2. `sudo apt install -y mosquitto mosquitto-clients python3-paho-mqtt alsa-utils`
3. `bash broker/make_certs.sh`, then `sudo bash broker/install_broker.sh`
4. Terminal 1: `sudo python3 server.py --allow-register`. Terminal 2: steps B4, B5, C1 and C2.

Both roles then share the laptop's SSD, using different key slots. Because of the known issue, the server part
rejects registration on this laptop until verification works.

---

## Known issue: verification fails with -13

* **What:** `verify_signature` and `verify_signature_with_key` return `-13 (P_ERR_SEND_VERIFY_DATA_FAIL)`. Creating keys and signing work.
* **Where:** the laptop's E31T (firmware `EVFM00.0-0002`) with SDK V3 (1.1.0). Phison's own `demo_app` fails the same way,
  and data size doesn't matter (tested from 32 bytes to 1 MB).
* **Effect:** the SERVER needs verification. On an SSD with this issue, the server rejects registration and recording
  with `server SSD could not verify ... -13`.
* **What to do:** fill in the contact line in `PHISON_VERIFY_ISSUE.md` and send it to Phison/MaiStorage with the output
  of `sudo python3 diag_verify.py`. Test the server's SSD with A4.

---

## Troubleshooting

| You see | On | Fix |
|---|---|---|
| `The PQC SSD needs root` | both | Put `sudo` in front of the command |
| `-9 (P_ERR_COMMAND_FAIL) ... could not open the drive` | both | Use `sudo`, and check `PQC_DEVICE` is the E31T |
| `-5 (P_ERR_SESSION_FAIL)` | both | Wrong SSD password (`PQC_PASSWORD`). Don't keep guessing: some secure drives lock after several wrong attempts |
| `-13 (P_ERR_SEND_VERIFY_DATA_FAIL)` or `server SSD could not verify` | SERVER | [Known issue](#known-issue-verification-fails-with--13) |
| `SDK library not found` | SERVER | Fix `SDK_LIB` (A2, A3) |
| `CA certificate not found` | EDGE | Copy `ca.crt` from the server (B2) |
| `Cannot reach MQTT broker` | EDGE | See the table in B6 |
| `TLS certificate problem` | EDGE | The certificate doesn't include `BROKER_HOST`: repeat A5, then B2 |
| `Broker refused the connection` | both | MQTT username or password differ: same `settings.py` on both machines, then `install_broker.sh` on the server |
| `no answer from server` | EDGE | `server.py` isn't running on the server |
| `registration is closed` | EDGE | Start the server with `--allow-register` (A6) |
| `unregistered device` | EDGE | Register first (C1) |
| `invalid identity signature` | EDGE | The laptop's identity key (slot 0x04) was replaced: register again (C1) |
| `request timestamp too old/new` | EDGE | The clocks differ: check `timedatectl` on both machines |
| `arecord: ... Device or resource busy` | EDGE | Close other apps that use the mic |
| `arecord: ... No such file or directory` | EDGE | Run `arecord -l` and update `AUDIO_DEVICE` |
| `very quiet - is the microphone muted?` | EDGE | `alsamixer -c 1`, press F4, raise the capture level |

---

## Reference

### Files

| File | Runs on | What it is |
|---|---|---|
| `settings.py` | both | **The only file you edit** |
| `test_pqc.py` | both | PQC SSD check with an EDGE and a SERVER result line |
| `diag_verify.py` | both | Detailed verification test (for Phison support) |
| `test_mic.py` | EDGE | Microphone check |
| `edge_device.py` | EDGE | Records, signs and sends the audio |
| `demo_attacks.py` | EDGE | Shows that forged, tampered and replayed data is rejected |
| `broker/make_certs.sh` | SERVER | Creates the TLS certificates |
| `broker/install_broker.sh` | SERVER | Configures Mosquitto (TLS, users, topic permissions) |
| `server.py` | SERVER | Verifies and stores the chunks |
| `pqc_sdk.py`, `common.py` | both | Helper code (SDK wrapper, MQTT/TLS, message format) |
| `PHISON_VERIFY_ISSUE.md` | - | Bug report for Phison/MaiStorage |

### How your sequence diagram maps to the code

| Diagram phase | What happens | Where |
|---|---|---|
| **1. Registration** (once) | EDGE SSD creates the **identity key** (slot 0x04) and signs the MAC address. SERVER SSD verifies it; the server stores the hashed MAC and public key | EDGE `edge_device.py register` → SERVER `handle_register` |
| **2. Handshake** (every meeting) | EDGE SSD creates a **new session key** (slot 0x05), signed by the identity key. The broker checks username/password. The server checks the registration and signature, then answers PASS or FAIL | EDGE `record()` → SERVER `handle_session_start` |
| **3. Voice ingestion** (loop) | Record 10 s → WAV → **sign in EDGE SSD** → publish to `maistorage/pqc/room-04/audio` → **verify in SERVER SSD** → store → acknowledge | EDGE `stream_audio()` → SERVER `handle_chunk` |
| **4. Terminate** | Ctrl+C → last chunk → signed `"OFF"` on `.../audio/disconnect` → the server merges the chunks into `meeting_full.wav`. If the laptop crashes, the broker sends a **pre-signed** OFF (MQTT Last Will) | EDGE `record()` → SERVER `handle_session_end` |

### Three fixes to your diagram
1. **The private key is never sent** (steps 1.5 and 3.7 say "Public & Private Key"). It cannot leave the SSD.
   Only the **public key (118 bytes)** and the **signature (354 bytes)** travel.
2. **No new key for every chunk** (step 3.5). One new key pair per meeting signs every chunk.
3. **Step 2.3 (the broker queries the database):** Mosquitto cannot do that without a custom plugin. The broker checks
   the password, then `server.py` checks the registration and answers PASS or FAIL. The result is the same.

### Keys (all created inside an SSD; private keys never leave it)
* **Identity key**, EDGE slot 0x04: created once at registration. The server stores its public key and the hashed MAC.
* **Session key**, EDGE slot 0x05: new for every meeting and signed by the identity key.
* **Verify slot**, SERVER slot 0x06: the server loads the edge's public key here (`verify_signature_with_key`).

### One MQTT message = one chunk
```
"PQC1" | header length | signature length | header (JSON) | KAZ signature (354 B) | WAV audio
```
The EDGE SSD signs **header + audio** together, so changing the audio, the sequence number, the session or the time
breaks the signature. The server also rejects duplicates (replays), unknown sessions and old handshakes.

### POC limits (be honest about them in the demo)
* TLS protects the connection with classical crypto. The post-quantum protection is the **KAZ signature on the data itself**.
* The server's PASS/FAIL replies are protected by TLS and topic permissions, but not signed.
* Passwords live in `settings.py`, and `edge123` / `server123` are only suitable for a POC.
* MAC addresses can be copied. The real proof of device identity is the key inside the SSD.

**Next steps after the POC:** compress the audio with Opus, run the scripts as systemd services, sign the server's
replies, and feed `meeting_full.wav` to the transcription model (for example Whisper) on the AI server.
