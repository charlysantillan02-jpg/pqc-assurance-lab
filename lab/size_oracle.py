"""
size_oracle.py — referencia de tamaños FIPS 203 y validadores.

Contiene:
  - STANDARD_RAW : tabla de tamaños raw de referencia (ground truth).
  - normalize_to_raw(blob) : detecta representacion y devuelve la clave raw.
  - compare_safe(a, b)     : comparacion CORRECTA (normaliza antes de medir).
  - compare_buggy(a, b)    : comparacion VULNERABLE (mezcla representaciones),
                             reproduce el bug del reto E01.
"""
from __future__ import annotations
import base64
from pqc_common import mlkem_sizes, X25519_RAW

STANDARD_RAW = {
    "X25519":      X25519_RAW,
    "ML-KEM-512":  mlkem_sizes("ML-KEM-512")["ek"],
    "ML-KEM-768":  mlkem_sizes("ML-KEM-768")["ek"],
    "ML-KEM-1024": mlkem_sizes("ML-KEM-1024")["ek"],
}


def detect_representation(blob: bytes) -> str:
    """raw | der | pem a partir de la forma del blob."""
    if b"-----BEGIN" in blob:
        return "pem"
    if blob[:1] == b"\x30":          # SEQUENCE ASN.1
        return "der"
    return "raw"


def _read_tlv(buf: bytes, i: int):
    """Lee un TLV DER desde la posicion i. Devuelve (tag, value, next_i)."""
    tag = buf[i]; i += 1
    ln = buf[i]; i += 1
    if ln & 0x80:                      # longitud larga
        nbytes = ln & 0x7F
        ln = int.from_bytes(buf[i:i+nbytes], "big"); i += nbytes
    return tag, buf[i:i+ln], i + ln


def normalize_to_raw(blob: bytes) -> bytes:
    """Extrae la clave raw sin importar la representacion de entrada.
    Recorre el SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }."""
    rep = detect_representation(blob)
    if rep == "pem":
        b64 = b"".join(l for l in blob.splitlines() if not l.startswith(b"-----"))
        blob = base64.b64decode(b64); rep = "der"
    if rep == "der":
        _, seq, _ = _read_tlv(blob, 0)          # SEQUENCE externa -> contenido
        _, _, j = _read_tlv(seq, 0)             # saltar AlgorithmIdentifier
        tag, bitstr, _ = _read_tlv(seq, j)      # BIT STRING
        if tag == 0x03:
            return bitstr[1:]                   # saltar byte de bits no usados
        return bitstr
    return blob


def classify_by_raw_size(raw: bytes) -> str:
    n = len(raw)
    for alg, size in STANDARD_RAW.items():
        if n == size:
            return alg
    return f"DESCONOCIDO({n}B)"


# --- comparacion CORRECTA -------------------------------------------------
def compare_safe(blob_a: bytes, blob_b: bytes) -> dict:
    ra, rb = normalize_to_raw(blob_a), normalize_to_raw(blob_b)
    return {
        "representation_error": False,
        "a": {"alg": classify_by_raw_size(ra), "raw": len(ra)},
        "b": {"alg": classify_by_raw_size(rb), "raw": len(rb)},
        "ratio": round(len(rb) / len(ra), 2),
    }


# --- comparacion VULNERABLE (bug E01) -------------------------------------
def compare_buggy(blob_a: bytes, blob_b: bytes) -> dict:
    """Mide cada blob 'tal como vino' sin normalizar: mezcla raw/DER/PEM."""
    na, nb = len(blob_a), len(blob_b)
    return {
        "representation_error": detect_representation(blob_a) != detect_representation(blob_b),
        "a": {"repr": detect_representation(blob_a), "size": na},
        "b": {"repr": detect_representation(blob_b), "size": nb},
        "ratio": round(nb / na, 2),
    }


if __name__ == "__main__":
    import json
    print("STANDARD_RAW:", json.dumps(STANDARD_RAW))
