# Diapositivas – Cifrado en reposo (pasos 6 y 7)

**Responsable:** Daniel Cárdenas Ortiz
**Para:** Sebastián (integración en el PDF final)
**Código:** `internal/crypto/crypto.go`, `internal/pipeline/encrypt.go`, `internal/cli/encrypt.go`

Cada sección es una diapositiva. Lo que está en *Notas* es para decirlo en el video, no para ponerlo en la lámina.

---

## Diapositiva 1 — Paso 6: qué se cifra y cómo

- Entrada: los **bytes exactos** de `log_plain.json` (no se vuelve a serializar el log).
- Antes de cifrar se comprueba que esos bytes sigan teniendo el hash guardado en `log_plain.sha256`. Si no coinciden, **no se cifra** (sería proteger un log ya alterado).
- Algoritmo: **AES-256-GCM** con la librería estándar de Go: `crypto/aes`, `crypto/cipher`, `crypto/rand`.
- Salida: tres artefactos separados del log original → `log_encrypted.bin`, `key.bin`, `nonce.bin`.

*Notas:* el taller pide que el resultado se guarde aparte del original junto con "los insumos requeridos para la operación"; esos insumos son la clave y el nonce.

---

## Diapositiva 2 — Por qué AES-256-GCM

| Modo | Confidencialidad | Detecta alteración | Comentario |
|---|---|---|---|
| AES-CBC | Sí | No | Necesita relleno y un MAC aparte |
| AES-CTR | Sí | No | Un bit cambiado en el cifrado cambia el mismo bit en claro sin aviso |
| **AES-GCM** | **Sí** | **Sí** | Cifrado autenticado (AEAD): agrega una etiqueta de 16 bytes |

- GCM cubre en una sola operación los dos objetivos del taller: **lectura no autorizada** (confidencialidad) y **alteración detectable** (integridad + autenticidad).
- AES-256: clave de 256 bits, estándar (FIPS 197, NIST SP 800-38D para GCM), con aceleración por hardware (AES-NI) en Go.
- Si alguien cambia **un solo bit** del cifrado o del nonce, o usa otra clave, `Decrypt` devuelve `ErrAuthFailed` y **no entrega nada** del texto en claro.

*Notas:* mostrar en la demo que el log de 9 113 bytes queda en 9 129: exactamente +16, la etiqueta GCM. No hay relleno.

---

## Diapositiva 3 — Clave y nonce

- **Clave:** 32 bytes aleatorios (AES-256). **Nonce:** 12 bytes aleatorios (tamaño recomendado para GCM).
- Ambos salen de `crypto/rand` (generador criptográficamente seguro del sistema operativo). Nunca de `math/rand`, que es predecible.
- **Regla de oro de GCM:** nunca repetir un nonce con la misma clave; si se repite, se pueden recuperar datos y falsificar mensajes.
- Nuestra decisión: **cada cifrado genera clave y nonce nuevos.** Por eso cifrar dos veces el mismo log da dos `log_encrypted.bin` distintos (y dos hashes distintos), pero ambos se descifran al mismo log.

*Notas:* las pruebas generan 1 000 cifrados seguidos y verifican que ningún nonce se repite.

---

## Diapositiva 4 — Artefactos y gestión de la clave

| Archivo | Contenido | Protección |
|---|---|---|
| `log_encrypted.bin` | cifrado ‖ etiqueta GCM | ilegible sin la clave |
| `key.bin` | clave AES-256 (32 B) | permisos **0600** (solo el dueño) |
| `nonce.bin` | nonce (12 B) | no es secreto, pero sí obligatorio para descifrar |
| `log_encrypted.sha256` | SHA-256 del cifrado | formato `sha256sum` |

- Los permisos 0600 se fuerzan también si `key.bin` ya existía con otros permisos.
- **Limitación reconocida:** aquí la clave queda en la misma carpeta que el log solo para poder demostrar el flujo. En un sistema real iría en un **gestor de claves (KMS/HSM)** o se derivaría de una contraseña con `crypto/pbkdf2`; quien tenga `key.bin` puede leer el log.
- `output/` está en `.gitignore`: ninguna clave llega al repositorio.

---

## Diapositiva 5 — Paso 7: hash del log cifrado

- Se calcula **SHA-256** (`crypto/sha256`, mediante `hashing.SHA256Hex`) sobre los mismos bytes guardados en `log_encrypted.bin` y se guarda en `log_encrypted.sha256`.
- ¿Para qué, si GCM ya detecta alteraciones?
  - Permite comprobar el archivo **antes de descifrar y sin tener la clave** (por ejemplo, con `sha256sum -c log_encrypted.sha256`).
  - Distingue "el archivo se dañó en reposo" de "la clave o el nonce son incorrectos".
- Por qué SHA-256: está en la librería estándar, no tiene colisiones prácticas conocidas y su salida de 256 bits basta para verificar integridad. MD5 y SHA-1 están descartados por colisiones.
- **Matiz:** el hash no usa clave; quien pueda reescribir el cifrado puede reescribir también su hash. La protección fuerte contra un atacante es la **etiqueta GCM**, que sí depende de la clave. Las dos capas se complementan.

---

## Diapositiva 6 — Pruebas del módulo de cifrado

`go test ./internal/crypto/ ./internal/pipeline/` (20 pruebas, todas pasan):

- Ida y vuelta: el texto descifrado es idéntico byte a byte al original.
- Clave incorrecta → falla con `ErrAuthFailed`.
- Un bit alterado (al inicio, en medio y en la etiqueta) → falla.
- Nonce alterado o cifrado truncado → falla.
- Dos cifrados del mismo log → clave, nonce y cifrado distintos; 1 000 nonces sin repetición.
- El cifrado no deja ver texto del log (`GRADE_`, `student_uid`, …).
- `key.bin` queda en 0600; un log en claro alterado no se cifra.

*Notas:* en la demo, después de cifrar, abrir `log_encrypted.bin` para mostrar que no es legible.
