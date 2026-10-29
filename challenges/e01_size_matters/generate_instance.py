#!/usr/bin/env python3
"""
generate_instance.py — reproduce LOCALMENTE una instancia del reto E01 de
qlab.i-314.com, generando claves reales y un bundle equivalente al del Target.

Salida: instance.json (bundle publico, sin ground truth).
"""
import json, os, sys, hashlib, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lab"))
from pqc_common import gen_x25519, gen_mlkem768

x = gen_x25519()
m = gen_mlkem768()

inst_id = hashlib.sha1(str(time.time()).encode()).hexdigest()[:16]
bundle = {
    "instance": inst_id,
    "x25519_pub_raw_size": len(x.raw),
    "mlkem768_pub_pem_size": len(m.pem),
    "buggy_report": f"compara x25519_raw ({len(x.raw)}) con "
                    f"mlkem_pem ({len(m.pem)}): mezcla raw y PEM",
    "task": "entregá {'representation_error': true, 'mlkem_raw_size': <tamaño raw estándar>}",
}

here = os.path.dirname(__file__)
with open(os.path.join(here, "instance.json"), "w") as f:
    json.dump(bundle, f, indent=2, ensure_ascii=False)
# guardamos tambien las claves de muestra
with open(os.path.join(here, "mlkem768_pub.pem"), "wb") as f:
    f.write(m.pem)
with open(os.path.join(here, "x25519_pub.raw"), "wb") as f:
    f.write(x.raw)

print(f"[+] instancia {inst_id} generada")
print(json.dumps(bundle, indent=2, ensure_ascii=False))
