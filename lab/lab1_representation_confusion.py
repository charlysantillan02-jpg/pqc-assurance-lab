#!/usr/bin/env python3
r"""
LAB 1 — Confusion de representacion en un pipeline de assurance
================================================================

ESCENARIO (todo sobre servicios PROPIOS del lab)
------------------------------------------------
Una organizacion corre un "Auditor de migracion PQC" que recibe DOS claves
publicas (una clasica, una post-cuantica) y emite un veredicto GO/NO-GO para
habilitar la migracion. La politica interna es:

    "Aprobar la migracion solo si la clave PQC no es mas de 40x el tamaño
     de la clave clasica (control de ancho de banda / MTU)."

VULNERABILIDAD (la misma del reto E01)
--------------------------------------
El auditor mide cada clave 'tal como llega', sin normalizar la representacion:
la clasica suele llegar raw (32 B) y la PQC puede llegar en PEM (1686 B).
Quien CONTROLA EL FORMATO de las claves que entran al pipeline controla el
veredicto, porque:

    ratio_buggy = 1686 / 32 = 52.7x  -> NO-GO (falso: bloquea migracion segura)
    ratio_real  = 1184 / 32 = 37.0x  ->   GO  (correcto)

Impacto: integridad del proceso de assurance. Un atacante que entrega la
clave PQC en PEM fuerza un NO-GO (DoS de la aprobacion); uno que la entrega
en raw recortada puede forzar un GO indebido. El veredicto depende del
ENVOLTORIO, no de la criptografia.

Correr:  python3 lab/lab1_representation_confusion.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from pqc_common import gen_x25519, gen_mlkem768, backend
from size_oracle import compare_buggy, compare_safe

RATIO_POLICY = 40.0


def auditor_vulnerable(classical_blob: bytes, pqc_blob: bytes) -> dict:
    """Mide sin normalizar (BUG)."""
    r = compare_buggy(classical_blob, pqc_blob)
    verdict = "GO" if r["ratio"] <= RATIO_POLICY else "NO-GO"
    return {**r, "verdict": verdict}


def auditor_fixed(classical_blob: bytes, pqc_blob: bytes) -> dict:
    """Normaliza a raw antes de medir (FIX)."""
    r = compare_safe(classical_blob, pqc_blob)
    verdict = "GO" if r["ratio"] <= RATIO_POLICY else "NO-GO"
    return {**r, "verdict": verdict}


def banner(t): print("\n" + "=" * 68 + f"\n{t}\n" + "=" * 68)


def main():
    print(f"[*] backend: {backend()}")
    x = gen_x25519()
    m = gen_mlkem768()

    banner("1) Trafico LEGITIMO: ambas claves en raw")
    legit = auditor_vulnerable(x.raw, m.raw)
    print(f"    clasica={legit['a']['size']}B ({legit['a']['repr']})  "
          f"pqc={legit['b']['size']}B ({legit['b']['repr']})  "
          f"ratio={legit['ratio']}x  -> {legit['verdict']}")

    banner("2) ATAQUE: el atacante entrega la clave PQC en PEM")
    atk = auditor_vulnerable(x.raw, m.pem)
    print(f"    clasica={atk['a']['size']}B ({atk['a']['repr']})  "
          f"pqc={atk['b']['size']}B ({atk['b']['repr']})  "
          f"ratio={atk['ratio']}x  -> {atk['verdict']}")
    print(f"    representation_error detectado por el blob: {atk['representation_error']}")
    if legit["verdict"] != atk["verdict"]:
        print(f"\n    [!] EXPLOTADO: el veredicto cambio de {legit['verdict']} "
              f"a {atk['verdict']} solo cambiando el ENVOLTORIO de la misma clave.")

    banner("3) MISMO input contra el auditor CORREGIDO (normaliza a raw)")
    fix = auditor_fixed(x.raw, m.pem)
    print(f"    alg_a={fix['a']['alg']} raw={fix['a']['raw']}B  "
          f"alg_b={fix['b']['alg']} raw={fix['b']['raw']}B  "
          f"ratio={fix['ratio']}x  -> {fix['verdict']}")
    print("    [+] Mitigado: el envoltorio ya no cambia el veredicto.")

    banner("RESUMEN")
    print(f"    politica: PQC <= {RATIO_POLICY}x clasica")
    print(f"    vulnerable  (raw vs raw) : {legit['verdict']}")
    print(f"    vulnerable  (raw vs pem) : {atk['verdict']}   <- forzado por el atacante")
    print(f"    corregido   (normalizado): {fix['verdict']}")


if __name__ == "__main__":
    main()
