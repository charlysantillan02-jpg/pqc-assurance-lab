#!/usr/bin/env bash
# Setup del PQC Assurance Lab en Kali Linux (VMware).
set -e

echo "[*] PQC Assurance Lab - setup Kali"
echo "[*] Python: $(python3 --version)"

# --- Tier 1: dependencias minimas (el lab corre con esto) ------------------
echo "[*] Instalando dependencias Python (Tier 1)..."
pip3 install --break-system-packages -r "$(dirname "$0")/../requirements.txt" || \
pip3 install -r "$(dirname "$0")/../requirements.txt"

# --- Tier 2: criptografia real (opcional) ----------------------------------
# Para ML-KEM real y captura de handshakes:
#   - OpenSSL 3.5+  (ML-KEM nativo)  o  liboqs + oqs-provider
#   - wireshark / tshark             (ver el key_share en loopback)
echo
echo "[*] (Opcional, Tier 2) para criptografia real:"
echo "    sudo apt update && sudo apt install -y wireshark tshark"
echo "    # liboqs:"
echo "    sudo apt install -y cmake ninja-build gcc libssl-dev git"
echo "    git clone https://github.com/open-quantum-safe/liboqs"
echo "    # oqs-provider: https://github.com/open-quantum-safe/oqs-provider"

echo
echo "[*] Verificando backend disponible:"
python3 "$(dirname "$0")/../lab/pqc_common.py" || true

echo
echo "[+] Listo. Probá:  make all"
