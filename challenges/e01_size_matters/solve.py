#!/usr/bin/env python3
"""
solve.py — resuelve el reto E01 'Size Matters'.

Detecta la mezcla de representaciones (raw vs PEM) y entrega el tamaño raw
estandarizado de ML-KEM-768 segun FIPS 203: ek = 384*k + 32, k=3 => 1184.

Uso: python3 solve.py  (lee instance.json en la misma carpeta)
"""
import json, os

here = os.path.dirname(__file__)
inst = json.load(open(os.path.join(here, "instance.json")))

k = 3                       # ML-KEM-768
mlkem_raw = 384 * k + 32    # FIPS 203 -> 1184

submission = {
    "representation_error": inst["mlkem768_pub_pem_size"] != mlkem_raw,
    "mlkem_raw_size": mlkem_raw,
}

print("[*] instancia:", inst["instance"])
print("[*] x25519 raw :", inst["x25519_pub_raw_size"], "B")
print("[*] mlkem  pem :", inst["mlkem768_pub_pem_size"], "B  <- PEM, no es el tamaño de la clave")
print("[*] mlkem  raw :", mlkem_raw, "B  <- FIPS 203 (384*k+32, k=3)")
print("\n[SUBMIT]")
print(json.dumps(submission))

# Campos de evidencia (EVIDENCE_SCHEMA del challenge)
print("\n[EVIDENCIA]")
print(json.dumps({
    "size-table": f"x25519_raw=32 | mlkem768_pem={inst['mlkem768_pub_pem_size']} | mlkem768_raw={mlkem_raw}",
    "compared-formats": ["raw", "pem"],
    "source-standard": "FIPS 203",
}, ensure_ascii=False))
