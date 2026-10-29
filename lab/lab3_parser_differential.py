#!/usr/bin/env python3
r"""
LAB 3 — Parser differential en formatos compuestos (X.509 / COSE-CBOR)
=======================================================================

ESCENARIO (todo sobre blobs PROPIOS del lab)
--------------------------------------------
Una clave publica ML-KEM-768 no viaja sola: va ANIDADA dentro de estructuras
compuestas (un SubjectPublicKeyInfo en un certificado X.509, un COSE_Key en
CBOR, etc.). Dos componentes de un sistema suelen parsear el mismo blob con
librerias/criterios distintos:

    VALIDADOR  (ej. motor de politica / allowlist de fingerprints)
    CONSUMIDOR (ej. el stack que realmente usa la clave)

VULNERABILIDAD — "parser differential"
--------------------------------------
Si el validador y el consumidor extraen claves DISTINTAS del mismo blob, un
atacante arma un blob que:
    - al validador le muestra K1  (clave aprobada / allowlisted)  -> PASA
    - al consumidor le entrega K2 (clave del atacante)            -> SE USA
=> sustitucion de clave sin romper ninguna firma. Clase de bug clasica en
   X.509 (datos finales / length confusion) y en CBOR/COSE (claves de mapa
   duplicadas, donde los decoders difieren en 'first-wins' vs 'last-wins').

Correr:  python3 lab/lab3_parser_differential.py
"""
import os, sys, hashlib
sys.path.insert(0, os.path.dirname(__file__))
from pqc_common import gen_mlkem768, build_spki, backend, MLKEM_OID
from size_oracle import _read_tlv

OID = MLKEM_OID["ML-KEM-768"]
def fp(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()[:16]
def banner(t): print("\n" + "=" * 68 + f"\n{t}\n" + "=" * 68)


# ===========================================================================
# 3a) X.509 / DER — trailing data (length confusion)
# ===========================================================================
# El blob malicioso = SPKI(K1) || SPKI(K2).
#   - parser ESTRICTO lee UN TLV por su longitud declarada -> K1 (y, si es
#     correcto, deberia RECHAZAR por datos finales no consumidos).
#   - parser LAXO que "toma el ultimo bloque de clave" -> K2.

def der_extract_raw_first(blob: bytes) -> bytes:
    """Lee el primer SubjectPublicKeyInfo por longitud declarada."""
    _, seq, nxt = _read_tlv(blob, 0)          # SEQUENCE externa
    _, _, j = _read_tlv(seq, 0)               # AlgorithmIdentifier
    tag, bitstr, _ = _read_tlv(seq, j)        # BIT STRING
    raw = bitstr[1:] if tag == 0x03 else bitstr
    return raw, nxt                            # nxt = bytes consumidos

def der_extract_raw_last(blob: bytes) -> bytes:
    """Parser LAXO: escanea y se queda con el ULTIMO SPKI del blob."""
    i, last = 0, None
    n = len(blob)
    while i < n:
        try:
            _, seq, nxt = _read_tlv(blob, i)
            _, _, j = _read_tlv(seq, 0)
            tag, bitstr, _ = _read_tlv(seq, j)
            last = bitstr[1:] if tag == 0x03 else bitstr
            i = nxt
        except Exception:
            break
    return last

def strict_validator(blob: bytes) -> dict:
    """Parser correcto: lee el primer SPKI y EXIGE que no haya datos finales."""
    raw, consumed = der_extract_raw_first(blob)
    trailing = len(blob) - consumed
    if trailing != 0:
        return {"ok": False, "reason": f"datos finales no consumidos: {trailing} B -> RECHAZO"}
    return {"ok": True, "key_fp": fp(raw)}

def lenient_validator(blob: bytes) -> dict:
    """Parser VULNERABLE: lee solo el primer SPKI, ignora datos finales."""
    raw, _ = der_extract_raw_first(blob)
    return {"ok": True, "key_fp": fp(raw)}      # no chequea trailing

def buggy_consumer(blob: bytes) -> dict:
    """Consumidor VULNERABLE: usa el ULTIMO bloque de clave del blob."""
    raw = der_extract_raw_last(blob)
    return {"key_fp": fp(raw)}


def demo_x509():
    banner("3a) X.509 / DER — trailing data (validador vs consumidor)")
    k1 = gen_mlkem768()     # clave APROBADA (allowlisted)
    k2 = gen_mlkem768()     # clave del ATACANTE
    print(f"    K1 (aprobada) fp={fp(k1.raw)}")
    print(f"    K2 (atacante) fp={fp(k2.raw)}")

    spki1 = build_spki(k1.raw, OID)
    spki2 = build_spki(k2.raw, OID)
    malicious = spki1 + spki2                   # trailing data
    print(f"    blob malicioso = SPKI(K1) || SPKI(K2) = {len(malicious)} B")

    print("\n    [parser ESTRICTO correcto]")
    print("      ", strict_validator(malicious))

    v = lenient_validator(malicious)
    c = buggy_consumer(malicious)
    print("\n    [sistema VULNERABLE]")
    print(f"      validador laxo ve  : {v['key_fp']}  "
          f"({'K1' if v['key_fp']==fp(k1.raw) else 'K2'})  -> aprueba")
    print(f"      consumidor usa     : {c['key_fp']}  "
          f"({'K1' if c['key_fp']==fp(k1.raw) else 'K2'})")
    if v["key_fp"] != c["key_fp"]:
        print("\n    [!] EXPLOTADO: el validador aprobo K1 pero el consumidor usa K2.")
        print("        Sustitucion de clave por parser differential (trailing data).")


# ===========================================================================
# 3b) COSE_Key / CBOR — clave de mapa DUPLICADA (first-wins vs last-wins)
# ===========================================================================
# Un COSE_Key es un mapa CBOR. El parametro de la clave publica (label -1 en
# este ejemplo didactico) se incluye DOS veces. RFC 8949: los mapas con claves
# duplicadas son invalidos, pero los decoders difieren: unos toman la primera
# ocurrencia, otros la ultima. Mismo efecto que 3a: K1 al validador, K2 al uso.

def _cbor_uint(mt: int, n: int) -> bytes:
    if n < 24:      return bytes([(mt << 5) | n])
    if n < 256:     return bytes([(mt << 5) | 24, n])
    if n < 65536:   return bytes([(mt << 5) | 25]) + n.to_bytes(2, "big")
    return bytes([(mt << 5) | 26]) + n.to_bytes(4, "big")

def cbor_int(n: int) -> bytes:
    return _cbor_uint(0, n) if n >= 0 else _cbor_uint(1, -1 - n)

def cbor_bstr(b: bytes) -> bytes:
    return _cbor_uint(2, len(b)) + b

def build_cose_key_dup(k1: bytes, k2: bytes) -> bytes:
    """Mapa CBOR con el label -1 duplicado (x = K1, luego x = K2)."""
    entries  = cbor_int(1) + cbor_int(4)        # 1: kty  (didactico)
    entries += cbor_int(-1) + cbor_bstr(k1)     # -1: x = K1
    entries += cbor_int(-1) + cbor_bstr(k2)     # -1: x = K2 (duplicado)
    n_pairs = 3
    return _cbor_uint(5, n_pairs) + entries      # major type 5 = map

def _cbor_read(buf, i):
    ib = buf[i]; mt, ai = ib >> 5, ib & 0x1F; i += 1
    if ai < 24: val = ai
    elif ai == 24: val = buf[i]; i += 1
    elif ai == 25: val = int.from_bytes(buf[i:i+2], "big"); i += 2
    elif ai == 26: val = int.from_bytes(buf[i:i+4], "big"); i += 4
    else: raise ValueError("ai no soportado")
    if mt == 0: return ("int", val, i)
    if mt == 1: return ("int", -1 - val, i)
    if mt == 2: return ("bytes", buf[i:i+val], i + val)
    if mt == 5: return ("map", val, i)
    raise ValueError(f"mt {mt} no soportado")

def cose_extract_x(blob: bytes, strategy: str) -> bytes:
    """strategy = 'first' | 'last' sobre el label -1 duplicado."""
    t, npairs, i = _cbor_read(blob, 0)
    assert t == "map"
    found = None
    for _ in range(npairs):
        tk, key, i = _cbor_read(blob, i)
        tv, val, i = _cbor_read(blob, i)
        if key == -1:
            if strategy == "first" and found is None:
                found = val
            elif strategy == "last":
                found = val
    return found


def demo_cose():
    banner("3b) COSE_Key / CBOR — clave de mapa duplicada (first vs last)")
    k1 = gen_mlkem768(); k2 = gen_mlkem768()
    print(f"    K1 (aprobada) fp={fp(k1.raw)}")
    print(f"    K2 (atacante) fp={fp(k2.raw)}")
    blob = build_cose_key_dup(k1.raw, k2.raw)
    print(f"    COSE_Key con label -1 duplicado = {len(blob)} B")

    first = cose_extract_x(blob, "first")
    last  = cose_extract_x(blob, "last")
    print(f"\n    decoder first-wins (validador): {fp(first)}  "
          f"({'K1' if first==k1.raw else 'K2'})  -> aprueba")
    print(f"    decoder last-wins  (consumidor): {fp(last)}  "
          f"({'K1' if last==k1.raw else 'K2'})")
    if fp(first) != fp(last):
        print("\n    [!] EXPLOTADO: decoders discrepan en la clave duplicada.")
        print("        Un RFC 8949 estricto RECHAZA mapas con claves duplicadas.")


def main():
    print(f"[*] backend: {backend()}")
    demo_x509()
    demo_cose()
    banner("MITIGACION")
    print("    - Rechazar datos finales no consumidos (no 'leer el primer objeto').")
    print("    - Parseo canonico y estricto; rechazar claves de mapa duplicadas (RFC 8949).")
    print("    - Validador y consumidor deben usar el MISMO parser sobre los MISMOS bytes.")
    print("    - Fingerprint de la clave EXACTA que se usa, no la que se valido.")


if __name__ == "__main__":
    main()
