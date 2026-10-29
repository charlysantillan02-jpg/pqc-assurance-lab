"""
pqc_common.py — utilidades compartidas del laboratorio PQC Assurance.

Provee claves ML-KEM-768 y X25519 en sus tres representaciones (raw / DER / PEM)
y la tabla de tamaños de FIPS 203.

Modo REAL  : si 'cryptography' trae ML-KEM (>=46) se generan claves reales.
Modo SIM   : si no, se simulan con bytes aleatorios del tamaño EXACTO del
             estandar y un SubjectPublicKeyInfo (SPKI) construido a mano.
En ambos modos los TAMAÑOS son identicos a los de FIPS 203, que es lo que
importa para los ejercicios de assurance.
"""
from __future__ import annotations
import os, base64, textwrap

# ---------------------------------------------------------------------------
# Tabla de tamaños FIPS 203 (bytes, representacion raw)
# ek = 384*k + 32 | dk = 768*k + 96 | ct = 32*(du*k + dv) | K = 32
# ---------------------------------------------------------------------------
MLKEM_PARAMS = {
    "ML-KEM-512":  dict(k=2, du=10, dv=4),
    "ML-KEM-768":  dict(k=3, du=10, dv=4),
    "ML-KEM-1024": dict(k=4, du=11, dv=5),
}

def mlkem_sizes(name: str) -> dict:
    p = MLKEM_PARAMS[name]; k, du, dv = p["k"], p["du"], p["dv"]
    return {"ek": 384*k + 32, "dk": 768*k + 96,
            "ct": 32*(du*k + dv), "ss": 32}

X25519_RAW = 32

# OIDs NIST para ML-KEM (usados al construir el SPKI en modo SIM)
MLKEM_OID = {
    "ML-KEM-512":  "2.16.840.1.101.3.4.4.1",
    "ML-KEM-768":  "2.16.840.1.101.3.4.4.2",
    "ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
}

# ---------------------------------------------------------------------------
# Deteccion del backend real
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization as _ser
    _REAL = True
except Exception:
    _REAL = False


def backend() -> str:
    return "REAL (cryptography/ML-KEM)" if _REAL else "SIM (simulado, tamaños FIPS 203)"


# ---------------------------------------------------------------------------
# Codificacion ASN.1/DER minima para el modo SIM
# ---------------------------------------------------------------------------
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF); n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)

def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value

def _oid_to_der(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    first = 40 * parts[0] + parts[1]
    body = [first]
    for p in parts[2:]:
        if p < 0x80:
            body.append(p)
        else:
            stack = []
            while p:
                stack.insert(0, p & 0x7F); p >>= 7
            for i in range(len(stack) - 1):
                stack[i] |= 0x80
            body.extend(stack)
    return _der_tlv(0x06, bytes(body))

def build_spki(raw_key: bytes, oid: str) -> bytes:
    """Arma un SubjectPublicKeyInfo DER a partir de una clave raw."""
    alg = _der_tlv(0x30, _oid_to_der(oid))          # AlgorithmIdentifier
    bitstr = _der_tlv(0x03, b"\x00" + raw_key)       # BIT STRING (0 bits sin usar)
    return _der_tlv(0x30, alg + bitstr)              # SEQUENCE externa

def der_to_pem(der: bytes, label: str = "PUBLIC KEY") -> bytes:
    b64 = base64.encodebytes(der).decode().replace("\n", "")
    body = "\n".join(textwrap.wrap(b64, 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n".encode()


# ---------------------------------------------------------------------------
# Generacion de claves publicas en las tres representaciones
# ---------------------------------------------------------------------------
class PubKey:
    def __init__(self, alg, raw, der, pem):
        self.alg, self.raw, self.der, self.pem = alg, raw, der, pem
    def sizes(self):
        return {"raw": len(self.raw), "der": len(self.der), "pem": len(self.pem)}


def gen_mlkem768() -> PubKey:
    if _REAL:
        dk = MLKEM768PrivateKey.generate(); ek = dk.public_key()
        raw = ek.public_bytes_raw()
        der = ek.public_bytes(_ser.Encoding.DER, _ser.PublicFormat.SubjectPublicKeyInfo)
        pem = ek.public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo)
        return PubKey("ML-KEM-768", raw, der, pem)
    raw = os.urandom(mlkem_sizes("ML-KEM-768")["ek"])        # 1184 B
    der = build_spki(raw, MLKEM_OID["ML-KEM-768"])
    return PubKey("ML-KEM-768", raw, der, der_to_pem(der))


def gen_x25519() -> PubKey:
    if _REAL:
        sk = X25519PrivateKey.generate(); pk = sk.public_key()
        raw = pk.public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
        der = pk.public_bytes(_ser.Encoding.DER, _ser.PublicFormat.SubjectPublicKeyInfo)
        pem = pk.public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo)
        return PubKey("X25519", raw, der, pem)
    raw = os.urandom(X25519_RAW)                              # 32 B
    der = build_spki(raw, "1.3.101.110")                      # id-X25519
    return PubKey("X25519", raw, der, der_to_pem(der))


if __name__ == "__main__":
    print("backend:", backend())
    for g in (gen_x25519, gen_mlkem768):
        kobj = g()
        print(f"{kobj.alg:12} {kobj.sizes()}")
