# Reporte — <RETO / LAB>

| Campo | Valor |
|-------|-------|
| Reto / Lab | |
| Fecha | |
| Operador | Carlos |
| Instancia / entorno | |
| Backend (REAL/SIM) | |
| Estado | |

## 1. Resumen
<2-3 líneas: qué se explotó y con qué impacto.>

## 2. Hallazgo / Causa raíz
<Qué está mal y por qué. Ser específico: representaciones, tamaños, parser.>

## 3. Reproducción
```bash
# comandos exactos
make lab1
```
<Pegá la salida relevante.>

## 4. Explotación
<Paso a paso del ataque. Qué controla el atacante, qué logra.>

| Escenario | Resultado |
|-----------|-----------|
| Legítimo | |
| Con ataque | |

## 5. Impacto
- Confidencialidad / Integridad / Disponibilidad:
- Contexto real donde aplica (TLS 1.3, SSH, IKEv2, pipeline de assurance):

## 6. Mitigación
<Fix concreto. Normalización, binding de longitud, validación contra FIPS 203,
tests automáticos.>

```python
# fragmento del fix
```

## 7. Referencias
- NIST FIPS 203 (ML-KEM)
- RFC 7748 (X25519), RFC 8446 (TLS 1.3, downgrade protection)
- RFC 9370 (IKEv2 multiple key exchanges)
- draft-ietf-tls-hybrid-design (X25519MLKEM768)

## Anexo — evidencia
<capturas, hashes, salidas completas>
