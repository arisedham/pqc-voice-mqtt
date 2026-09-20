#!/usr/bin/env bash
# Creates a private Certificate Authority (CA) and a TLS certificate for the MQTT broker.
#
# Usage (run on the machine that runs Mosquitto):
#   bash broker/make_certs.sh                 # localhost + this machine's hostname and IPs
#   bash broker/make_certs.sh 192.168.1.50    # also add an extra IP or hostname
#
# Output in broker/certs/:
#   ca.crt      -> copy to every edge device (clients use it to trust the broker)
#   ca.key      -> keep secret (only needed to create new certificates)
#   server.crt  -> broker certificate
#   server.key  -> broker private key (keep secret)
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs
cd certs

HOST="$(hostname)"
SAN="DNS:localhost,IP:127.0.0.1,DNS:${HOST}"
for ip in $(hostname -I 2>/dev/null); do
  [[ "$ip" == *:* ]] && continue            # skip IPv6 addresses
  SAN="${SAN},IP:${ip}"
done
for extra in "$@"; do
  if [[ "$extra" =~ ^[0-9.]+$ ]]; then SAN="${SAN},IP:${extra}"; else SAN="${SAN},DNS:${extra}"; fi
done

cat > ca.ext <<EOF
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF

cat > server.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=${SAN}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

echo "[1/3] Creating the CA (ca.key, ca.crt)"
openssl req -new -newkey rsa:3072 -sha256 -nodes -keyout ca.key -out ca.csr \
  -subj "/CN=PQC-POC-Local-CA" 2>/dev/null
openssl x509 -req -in ca.csr -signkey ca.key -out ca.crt -days 825 -sha256 \
  -extfile ca.ext 2>/dev/null

echo "[2/3] Creating the broker key and certificate request"
openssl req -new -newkey rsa:3072 -sha256 -nodes -keyout server.key -out server.csr \
  -subj "/CN=${HOST}" 2>/dev/null

echo "[3/3] Signing the broker certificate with the CA"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extfile server.ext 2>/dev/null

rm -f ca.csr server.csr ca.ext server.ext ca.srl
chmod 600 ca.key server.key
chmod 644 ca.crt server.crt

echo
echo "Certificate is valid for: ${SAN}"
openssl verify -CAfile ca.crt server.crt
