# PQC Assurance Lab

Laboratorio de entrenamiento **red team** sobre criptografía post-cuántica
(ML-KEM / FIPS 203) y errores de *assurance* en su despliegue real.

Nace del reto **E01 · Size Matters** de [qlab.i-314.com](https://qlab.i-314.com/)
y lo lleva de un ejercicio de medición a dos escenarios **explotables** sobre
servicios propios del lab:

| Lab | Escenario | Clase de bug | Impacto |
|-----|-----------|--------------|---------|
| **E01** | Reproducción del reto | Mezcla de representaciones raw/PEM | Medición incorrecta |
| **Lab 1** | Auditor de migración PQC | Confusión de representación | Integridad del veredicto GO/NO-GO |
| **Lab 2** | Handshake híbrido X25519MLKEM768 | Parsing differential sin binding de longitud | **Downgrade** a criptografía clásica |
| **Lab 3** | Formatos compuestos (X.509 / COSE-CBOR) | Parser differential validador vs consumidor | **Sustitución de clave** (K1 aprobada, K2 usada) |

> ⚠️ **Alcance y ética.** Todo el lab corre contra servicios *mock* incluidos
> en este repo, en tu propia máquina (Kali en VMware). No ataca sistemas de
> terceros. Está pensado para formación defensiva/ofensiva en entorno
> controlado y autorizado.

## Dónde aparece esto en la vida real

ML-KEM ya está en producción; el tamaño y el formato de sus claves importan:

- **TLS 1.3** — grupo híbrido `X25519MLKEM768` (code point `0x11EC`), activo en
  Chrome, Firefox, Cloudflare, Google, AWS. El keyshare híbrido son **1216 B**
  (32 de X25519 + 1184 de ML-KEM) en la extensión `key_share`.
- **OpenSSH 9.x+** — KEX `mlkem768x25519-sha256` por defecto.
- **IKEv2 / IPsec** — KEMs adicionales (RFC 9370) para VPNs post-cuánticas.
- **Benchmarks y papers de migración** — donde nace el bug del E01: medir el
  `.pem` del disco en vez de los bytes que viajan en el cable.

El ángulo ofensivo real no es romper ML-KEM, sino las **costuras**: confusión
de formato, downgrade de híbrido a clásico y parsers permisivos.

## Estructura

```
pqc-assurance-lab/
├── lab/
│   ├── pqc_common.py                 # claves raw/DER/PEM + tabla FIPS 203
│   ├── size_oracle.py                # normalizador y comparadores safe/buggy
│   ├── keygen.py                     # genera claves de muestra
│   ├── lab1_representation_confusion.py
│   ├── lab2_hybrid_downgrade.py
│   └── lab3_parser_differential.py
├── challenges/e01_size_matters/
│   ├── generate_instance.py          # reproduce una instancia del reto
│   └── solve.py                      # solver + evidencia
├── reports/REPORT_TEMPLATE.md        # plantilla de reporte por reto
├── docs/lab_guide.md                 # guía paso a paso
├── setup/kali-setup.sh               # dependencias en Kali
├── samples/                          # claves generadas (gitignored)
├── Makefile
└── requirements.txt
```

## Quickstart (Kali)

```bash
git clone <TU_REPO>.git && cd pqc-assurance-lab
bash setup/kali-setup.sh         # instala deps
make all                         # corre keygen + E01 + lab1 + lab2
```

O uno por uno:

```bash
make keygen      # genera claves y muestra la tabla de tamaños
make e01         # reproduce y resuelve el reto E01
make lab1        # confusión de representación (bypass del auditor)
make lab2        # downgrade del híbrido (MITM strip del componente PQC)
make lab3        # parser differential (sustitución de clave K1->K2)
```

## Backend real vs simulado

- **REAL** — si `cryptography >= 46` trae ML-KEM, se generan claves reales.
- **SIM** — si no, se simulan con bytes aleatorios del **tamaño exacto** del
  estándar y un SPKI construido a mano. Los ejercicios de assurance son
  idénticos porque dependen de los tamaños, no del material criptográfico.

Verificá cuál estás usando: `python3 lab/pqc_common.py`

## Tier 2 — criptografía real con OpenSSL 3.5+ / liboqs

Para trabajar con claves y handshakes reales, ver `docs/lab_guide.md`:
generación con `openssl genpkey -algorithm ML-KEM-768`, captura del
`key_share` híbrido en Wireshark sobre loopback, y `open-quantum-safe/oqs-provider`.

## Licencia

MIT (uso educativo). Ver `LICENSE`.
