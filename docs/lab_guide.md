# Guía del laboratorio

Guía paso a paso para correr y entender el PQC Assurance Lab en Kali/VMware.

## 0. Preparación

```bash
bash setup/kali-setup.sh
python3 lab/pqc_common.py      # ¿REAL o SIM?
```

## 1. Fundamento — tamaños (reto E01)

FIPS 203 fija los tamaños raw de ML-KEM (no se miden, se calculan):

```
ek = 384*k + 32        dk = 768*k + 96        ct = 32*(du*k + dv)
ML-KEM-768 (k=3):  ek=1184  dk=2400  ct=1088  ss=32
```

Las tres representaciones de una clave pública:

| Repr | Qué es | ML-KEM-768 |
|------|--------|------------|
| raw  | bytes del estándar | 1184 B |
| DER  | SubjectPublicKeyInfo (OID + BIT STRING) | 1206 B |
| PEM  | DER en Base64 + headers BEGIN/END | 1686 B |

Solo **raw** mide el algoritmo. Comparar raw contra PEM es el bug del E01.

```bash
make e01        # genera instancia local y la resuelve
```

## 2. Lab 1 — Confusión de representación

Un "Auditor de migración PQC" decide GO/NO-GO con la política
`PQC <= 40x clásica`, pero mide sin normalizar.

```bash
make lab1
```

- raw vs raw → 37x → **GO** (correcto)
- raw vs PEM → 52.7x → **NO-GO** (forzado por el atacante)

El atacante controla el **envoltorio**, no la clave, y cambia el veredicto.
El auditor corregido normaliza a raw con `size_oracle.normalize_to_raw()` y el
envoltorio deja de importar.

**Variante para practicar:** hacé que la política sea un *allow* (`GO` si el
ratio es *bajo*) y forzá un falso GO entregando la clave PQC recortada.

## 3. Lab 2 — Downgrade del híbrido

Handshake mock `X25519MLKEM768`: keyshare = 32 + 1184 = **1216 B**.
El servidor vulnerable parsea permisivo (si faltan los bytes PQC, sigue
clásico). Un MITM recorta el componente PQC.

```bash
make lab2
```

- limpio → `X25519MLKEM768`
- MITM strip → `X25519 (clásico)` **sin error** → downgrade
- servidor corregido → **ABORT** (exige longitud exacta)

Esta es la razón del *downgrade protection* de TLS 1.3 (RFC 8446) y del
binding de longitud en los híbridos PQC.

## 4. Tier 2 — criptografía real

### Generar y diseccionar claves (OpenSSL 3.5+)

```bash
openssl genpkey -algorithm ML-KEM-768 -out dk.pem
openssl pkey -in dk.pem -pubout -out ek.pem
wc -c ek.pem                                    # PEM
openssl pkey -pubin -in ek.pem -outform DER | wc -c   # DER = 1206
openssl asn1parse -in ek.pem                    # ver OID + BIT STRING
```

### Capturar el keyshare híbrido en TLS 1.3

```bash
# servidor y cliente locales con grupo híbrido
openssl s_server -groups X25519MLKEM768 -cert c.pem -key k.pem -www &
openssl s_client -groups X25519MLKEM768 -connect localhost:4433
# Wireshark en loopback -> filtro:  tls.handshake.extensions_key_share
```

Vas a ver los 1216 B reales que viajan, confirmando que el PEM (~1686) no
tiene relación con lo que va en el cable.

### liboqs / oqs-provider

```bash
git clone https://github.com/open-quantum-safe/liboqs
# build con cmake + ninja; luego oqs-provider para OpenSSL
```

## 5. Documentar

Copiá `reports/REPORT_TEMPLATE.md` por cada reto/lab y completalo. Subí los
reportes al repo para compartir resultados.

```bash
cp reports/REPORT_TEMPLATE.md reports/lab2_downgrade.filled.md
```
