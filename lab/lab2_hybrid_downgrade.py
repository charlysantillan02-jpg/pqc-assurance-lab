#!/usr/bin/env python3
r"""
LAB 2 — Downgrade de un KEM hibrido X25519MLKEM768
===================================================

ESCENARIO (handshake MOCK sobre servicios PROPIOS del lab)
----------------------------------------------------------
Cliente y servidor negocian un secreto con el grupo hibrido
X25519MLKEM768 (el que usan TLS 1.3 y OpenSSH modernos). El keyshare del
cliente es la concatenacion:

    keyshare = X25519_pub (32 B)  ||  ML-KEM-768_ek (1184 B)   = 1216 B

El componente clasico (X25519) protege contra atacantes de hoy; el
componente PQC protege contra "cosechar ahora, descifrar despues" con una
futura computadora cuantica. La seguridad del hibrido depende de que AMBOS
se usen.

VULNERABILIDAD
--------------
El servidor parsea de forma permisiva:

    tomar los primeros 32 bytes como X25519;
    si quedan >= 1184 bytes extra, usar ML-KEM; si no, seguir SOLO con X25519.

No hay binding de la longitud total ni autenticacion del keyshare antes de
decidir la suite. Un MITM activo RECORTA los bytes del componente PQC; el
servidor no ve error y completa un handshake CLASICO. La proteccion
post-cuantica se pierde de forma SILENCIOSA (classical downgrade / rollback).

Esto reproduce la clase de bug que motiva el "downgrade protection" del
RFC 8446 (TLS 1.3) y las defensas de los hibridos PQC.

Correr:  python3 lab/lab2_hybrid_downgrade.py
"""
import os, sys, hashlib
sys.path.insert(0, os.path.dirname(__file__))
from pqc_common import gen_x25519, gen_mlkem768, backend, X25519_RAW, mlkem_sizes

EK = mlkem_sizes("ML-KEM-768")["ek"]          # 1184
HYBRID_LEN = X25519_RAW + EK                   # 1216


def client_keyshare() -> bytes:
    x = gen_x25519(); m = gen_mlkem768()
    return x.raw + m.raw                        # X25519 || ML-KEM-768


def server_parse(keyshare: bytes) -> dict:
    """Servidor VULNERABLE: parser permisivo sin binding de longitud."""
    if len(keyshare) < X25519_RAW:
        return {"ok": False, "suite": None, "reason": "keyshare demasiado corto"}
    classical = keyshare[:X25519_RAW]
    rest = keyshare[X25519_RAW:]
    if len(rest) >= EK:                          # hay componente PQC
        pqc = rest[:EK]
        suite = "X25519MLKEM768"
        material = classical + pqc
    else:                                        # <-- fallback silencioso
        suite = "X25519 (clasico)"
        material = classical
    return {"ok": True, "suite": suite,
            "secret_tag": hashlib.sha256(material).hexdigest()[:16]}


def server_parse_fixed(keyshare: bytes) -> dict:
    """Servidor CORREGIDO: exige la longitud exacta del grupo negociado."""
    if len(keyshare) != HYBRID_LEN:
        return {"ok": False, "suite": None,
                "reason": f"longitud invalida para X25519MLKEM768: "
                          f"{len(keyshare)}B (esperado {HYBRID_LEN}B) -> ABORT"}
    classical, pqc = keyshare[:X25519_RAW], keyshare[X25519_RAW:]
    return {"ok": True, "suite": "X25519MLKEM768",
            "secret_tag": hashlib.sha256(classical + pqc).hexdigest()[:16]}


def mitm_strip_pqc(keyshare: bytes) -> bytes:
    """Atacante activo: descarta el componente ML-KEM, deja solo X25519."""
    return keyshare[:X25519_RAW]


def banner(t): print("\n" + "=" * 68 + f"\n{t}\n" + "=" * 68)


def main():
    print(f"[*] backend: {backend()}")
    print(f"[*] keyshare hibrido esperado: {HYBRID_LEN} B (32 + {EK})")

    ks = client_keyshare()

    banner("1) Handshake LIMPIO (sin atacante)")
    r = server_parse(ks)
    print(f"    cliente envia {len(ks)}B -> servidor negocia: {r['suite']}")
    print(f"    secreto={r['secret_tag']}  [PQC activo]")

    banner("2) ATAQUE MITM: strip del componente PQC")
    tampered = mitm_strip_pqc(ks)
    r2 = server_parse(tampered)
    print(f"    MITM recorta {len(ks)}B -> {len(tampered)}B")
    print(f"    servidor VULNERABLE negocia: {r2['suite']}")
    print(f"    secreto={r2['secret_tag']}")
    if r2["suite"] != "X25519MLKEM768":
        print("\n    [!] EXPLOTADO: downgrade a clasico SIN error.")
        print("        'Harvest now, decrypt later' vuelve a ser viable.")

    banner("3) MISMO ataque contra el servidor CORREGIDO")
    r3 = server_parse_fixed(tampered)
    print(f"    servidor corregido: ok={r3['ok']}")
    print(f"    {r3.get('reason','')}")
    print("    [+] Mitigado: el recorte se detecta y el handshake aborta.")

    banner("RESUMEN")
    print(f"    limpio            -> {r['suite']}")
    print(f"    vulnerable + MITM -> {r2['suite']}   <- downgrade")
    print(f"    corregido  + MITM -> ABORT")


if __name__ == "__main__":
    main()
