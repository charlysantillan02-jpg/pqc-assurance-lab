#!/usr/bin/env python3
"""
keygen.py — genera un par de claves de muestra y las vuelca en samples/
en las tres representaciones, imprimiendo la tabla de tamaños FIPS 203.

Uso:
    python3 lab/keygen.py [--out samples]
"""
import argparse, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from pqc_common import gen_x25519, gen_mlkem768, backend, mlkem_sizes


def dump(kobj, outdir, stem):
    for rep in ("raw", "der", "pem"):
        ext = rep if rep != "pem" else "pem"
        with open(os.path.join(outdir, f"{stem}.{ext}"), "wb") as f:
            f.write(getattr(kobj, rep))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="samples")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    print(f"[*] backend: {backend()}\n")

    x = gen_x25519(); m = gen_mlkem768()
    dump(x, a.out, "x25519_pub")
    dump(m, a.out, "mlkem768_pub")

    print(f"{'clave':14}{'raw':>8}{'der':>8}{'pem':>8}")
    print("-" * 38)
    for k in (x, m):
        s = k.sizes()
        print(f"{k.alg:14}{s['raw']:>8}{s['der']:>8}{s['pem']:>8}")

    print("\nTabla ML-KEM (raw, FIPS 203):")
    print(f"{'conjunto':14}{'ek':>6}{'dk':>7}{'ct':>7}{'ss':>5}")
    for name in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        s = mlkem_sizes(name)
        print(f"{name:14}{s['ek']:>6}{s['dk']:>7}{s['ct']:>7}{s['ss']:>5}")
    print(f"\n[+] claves escritas en {a.out}/")


if __name__ == "__main__":
    main()
