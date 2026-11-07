# Reporte técnico
## Protección de logs estructurados en reposo

**Proyecto:** LOGSECURE
**Lenguaje:** Go
**Curso:** Criptografía – Taller Dos
**Universidad:** Universidad del Valle

**Integrantes (orden alfabético por apellido):**

- Sebastián Arango Belalcazar
- Daniel Cárdenas Ortiz
- Howard Duvan Sánchez Garcia
- Jacobo Woodcock Ortiz

---

## 1. Introducción

El registro y la modificación de notas son operaciones sensibles de un sistema de gestión académica: si alguien lee, altera o borra estos eventos sin dejar rastro, se pierde la confianza en la información académica. LOGSECURE es una herramienta de línea de comandos en Go que genera un log estructurado simulado de estas operaciones y lo protege mientras está almacenado (datos en reposo).

La herramienta demuestra tres propiedades:

1. **Confidencialidad:** el log cifrado no puede leerse sin la clave.
2. **Integridad:** cualquier alteración del contenido se detecta, tanto por evento como en el log completo.
3. **Preservación:** cifrar y luego descifrar devuelve exactamente la información original.

## 2. Objetivo

Diseñar e implementar una aplicación CLI en Go que genere eventos académicos de registro y modificación de notas, los consolide en un log JSON y aplique hashing y cifrado con bibliotecas estándar de Go, para proteger su integridad, confidencialidad y verificabilidad durante el almacenamiento y la recuperación.

## 3. La operación sensible y sus atributos de seguridad

| Atributo | Amenaza que se quiere evitar | Cómo lo atiende el diseño |
|---|---|---|
| Confidencialidad | Leer notas y datos de estudiantes sin autorización | Cifrado del log completo con AES-256-GCM |
| Integridad | Cambiar una nota o borrar un evento sin que se note | `payload_hash` por evento, SHA-256 del log completo, `event_count` y etiqueta de autenticación GCM |
| Trazabilidad | No poder reconstruir qué pasó, cuándo y sobre qué | `event_id`, `event_type`, `timestamp`, `course_uid` |
| No repudio | Que un actor niegue haber ejecutado la operación | `actor_uid` en cada evento |
| Auditabilidad | No poder comprobar qué valor se reemplazó | `grade_prev` y `grade_new` en las modificaciones |
| Privacidad | Exponer datos personales en el log | Solo identificadores pseudónimos (UID), nunca nombres reales |

## 4. Arquitectura

El proyecto se divide en paquetes con una sola responsabilidad. Los diagramas de estructura y de comportamiento están en `docs/diagramas/`.

| Paquete | Responsabilidad |
|---|---|
| `cmd/logsecure` | Punto de entrada |
| `internal/cli` | Menú interactivo (PromptUI) y conexión con los pasos |
| `internal/model` | Estructuras `Event`, `Log` y `PipelineResult` |
| `internal/generator` | Validación de la cantidad y generación aleatoria de eventos |
| `internal/hashing` | SHA-256 y hash del payload de cada evento |
| `internal/logbuilder` | Armado y serialización estable del log JSON |
| `internal/storage` | Lectura y escritura de artefactos en `output/` |
| `internal/pipeline` | Encadena los pasos 2 a 7 |
| `internal/crypto` | Cifrado y descifrado AES-256-GCM |
| `internal/verify` | Descifrado, comparación de hashes y verificación por evento |
| `internal/report` | Presentación de resultados (fatih/color) |

`model` no depende de nadie y sirve de contrato entre los demás paquetes.

## 5. Diseño del evento

Cada evento es un objeto JSON con estos campos:

| Campo | Ejemplo | Atributo que respalda |
|---|---|---|
| `event_id` | `evt-000042` | Trazabilidad: identifica de forma única la operación |
| `event_type` | `GRADE_REGISTERED` / `GRADE_MODIFIED` | Trazabilidad: distingue registro de modificación |
| `timestamp` | `2026-11-04T15:00:00Z` | Trazabilidad y no repudio: cuándo ocurrió (RFC 3339, UTC) |
| `actor_uid` | `doc-0007` | No repudio: quién ejecutó la operación |
| `student_uid` | `est-0013` | Privacidad: a quién afecta, sin datos personales |
| `course_uid` | `cur-005` | Trazabilidad: recurso afectado |
| `grade_prev` | `3.2` o `null` | Auditabilidad: valor anterior; `null` en un registro |
| `grade_new` | `4.1` | Auditabilidad: valor resultante |
| `payload_hash` | 64 caracteres hexadecimales | Integridad por registro |

**Datos simulados.** Los identificadores son UIDs legibles (`doc-`, `est-`, `cur-`, `evt-`) tomados de conjuntos pequeños (10 docentes, 50 estudiantes, 15 cursos), de modo que una misma persona o curso aparece en varios eventos, como pasaría en un sistema real.

**Notas.** Se generan con distribución uniforme sobre 0.0, 0.1, …, 5.0 (51 valores equiprobables, con un decimal).

**Coherencia de las modificaciones.** Una modificación solo recae sobre una nota ya registrada: su `grade_prev` es la nota vigente de ese estudiante en ese curso y su `grade_new` es siempre distinta. Así el log cuenta una historia verificable y no eventos sueltos.

## 6. Diseño del payload y hash de cada operación (paso 3)

**Qué es el payload.** Todos los campos del evento **excepto** `payload_hash`:

`event_id`, `event_type`, `timestamp`, `actor_uid`, `student_uid`, `course_uid`, `grade_prev`, `grade_new`.

**Por qué se excluye `payload_hash`.** El hash es una función del payload. Si el propio hash formara parte de lo que se hashea, su valor dependería de sí mismo y no existiría un valor que satisficiera esa relación: la operación sería circular. Por eso el cálculo se hace sobre una estructura aparte (`eventPayload`) que no tiene ese campo, y una prueba automática garantiza que esa estructura siempre tenga exactamente los mismos campos que `Event` menos `payload_hash`.

**Cómo se calcula.**

1. Se serializa el payload a JSON compacto, con los campos siempre en el mismo orden (el que fija la estructura en Go).
2. Se calcula SHA-256 sobre esos bytes y se escribe en hexadecimal.
3. El resultado se guarda en el campo `payload_hash` del mismo evento, dentro del log.

**Por qué importa la serialización estable.** Un hash depende de los bytes exactos. Con orden de campos, formato de números y fecha fijos, el mismo evento produce siempre el mismo hash; si cambiara el formato entre generar y verificar, un evento íntegro parecería alterado.

**Qué detecta.** Cambiar cualquier campo del payload (la nota, el estudiante, el actor, el curso, el tipo, la fecha o el identificador) cambia el hash. Las pruebas comprueban cada uno. Como cada evento tiene su propio hash, es posible **localizar qué registro fue alterado**.

## 7. Diseño del log completo (paso 4)

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-11-04T15:00:00Z",
  "event_count": 3,
  "events": [ { "...": "evento con payload_hash" } ]
}
```

| Campo | Por qué está |
|---|---|
| `schema_version` | Permite evolucionar el esquema sin ambigüedad al verificar logs antiguos |
| `generated_at` | Trazabilidad del archivo completo |
| `event_count` | Detecta eventos eliminados o insertados: si el conteo declarado no coincide con los eventos presentes, hay manipulación |
| `events` | Lista ordenada por tiempo de los eventos |

El log se serializa con sangría de 2 espacios y un salto de línea final. **Esos bytes son los que se guardan, se hashean y se cifran**: ninguna etapa posterior vuelve a serializar el log. Una prueba verifica que serializar, leer y volver a serializar produce exactamente los mismos bytes.

## 8. Hash del log completo en claro (paso 5)

Antes de cifrar, se calcula SHA-256 sobre los bytes exactos de `log_plain.json` y se guarda **por separado** en `log_plain.sha256`, con el formato de la herramienta `sha256sum` (`<hash>  <archivo>`). Así también puede comprobarse desde la terminal con `sha256sum -c`.

Este hash es la referencia contra la que se compara el log descifrado en el paso 9.

## 9. Cifrado en reposo (paso 6)

**Algoritmo:** AES-256-GCM, usando solo la librería estándar de Go (`crypto/aes`, `crypto/cipher` y `crypto/rand`).

**Por qué AES-GCM.**

| Modo | Confidencialidad | Detecta alteración |
|---|---|---|
| AES-CBC | Sí | No (requiere un MAC aparte) |
| AES-CTR | Sí | No |
| **AES-GCM** | **Sí** | **Sí** (cifrado autenticado, AEAD) |

GCM cubre en una sola operación los dos primeros objetivos del taller: impide la lectura no autorizada y hace detectable cualquier alteración. Agrega una etiqueta de autenticación de 16 bytes al final del cifrado; si cambia un solo bit del texto cifrado o del nonce, o si se usa otra clave, el descifrado falla y no entrega ningún byte en claro.

**Clave y nonce.**

- Clave de 32 bytes (AES-256) y nonce de 12 bytes (tamaño recomendado para GCM), ambos de `crypto/rand`, nunca de `math/rand`.
- Se generan nuevos en cada cifrado. Con GCM nunca debe repetirse un nonce con la misma clave; generarlos de nuevo cada vez lo garantiza.

**Qué se cifra.** Los bytes exactos de `log_plain.json`. Antes de cifrar se comprueba que sigan coincidiendo con `log_plain.sha256`; si no, no se cifra, porque se estaría protegiendo un log que ya no es el original.

**Artefactos separados del log original** (en `output/`):

| Archivo | Contenido | Protección |
|---|---|---|
| `log_encrypted.bin` | Texto cifrado más etiqueta GCM | Ilegible sin la clave |
| `key.bin` | Clave AES-256 | Permisos 0600 (solo el dueño) |
| `nonce.bin` | Nonce | No es secreto, pero es necesario para descifrar |

## 10. Hash del log cifrado (paso 7)

Se calcula SHA-256 sobre los bytes de `log_encrypted.bin` y se guarda en `log_encrypted.sha256`.

Sirve para comprobar el archivo **antes de descifrar y sin necesidad de la clave**, y para distinguir un archivo dañado en reposo de una clave o nonce incorrectos. Este hash no usa clave: quien pueda reescribir el cifrado podría reescribir también su hash. La protección fuerte frente a un atacante es la etiqueta GCM, que sí depende de la clave. Las dos capas se complementan.

## 11. Descifrado y verificación (pasos 8 y 9)

El descifrado sigue este orden:

1. Se borran los resultados de un descifrado anterior, para que un intento fallido no deje hashes viejos que aparenten éxito.
2. Se verifica el hash del archivo cifrado contra el del paso 7. Si no coincide, se informa **ALTERACIÓN DETECTADA** y no se descifra.
3. Se descifra con AES-GCM. Si falla la autenticación, también se informa alteración detectada.
4. Se guarda `log_decrypted.json` y su SHA-256 en `log_decrypted.sha256`.
5. Se compara el hash del log descifrado con el del log original en claro. Si son iguales, la información se preservó.

La comparación de hashes se hace en tiempo constante (`crypto/subtle`).

La opción **Verificar integridad** añade una comprobación por evento: recalcula el `payload_hash` de cada evento del log descifrado, informa cuántos son válidos y lista los identificadores de los alterados, además de comparar `event_count` con los eventos presentes.

## 12. Presentación de resultados (paso 10)

La pantalla de resultados muestra la cantidad de eventos, la cantidad por tipo, los tres hashes SHA-256 (log en claro, cifrado y descifrado) y la comparación entre el original y el descifrado, con un veredicto inequívoco:

- **[OK] Información preservada**, si los hashes coinciden.
- **[X] ALTERACIÓN DETECTADA**, si difieren.

## 13. Decisiones de diseño y justificación

| Decisión | Justificación |
|---|---|
| Identificadores pseudónimos (UID) | Reducen la exposición de datos personales y siguen el enfoque del enunciado |
| SHA-256 | Está en la librería estándar, no tiene ataques de colisión prácticos conocidos y su salida de 256 bits basta para verificar integridad. MD5 y SHA-1 se descartaron por colisiones |
| Excluir `payload_hash` del payload | Evita la dependencia circular |
| Hashear los bytes guardados, no una reserialización | Garantiza que el hash descifrado sea comparable byte a byte con el original |
| Guardar los hashes en archivos aparte | Una referencia de integridad guardada dentro del mismo archivo que protege podría alterarse junto con él |
| Hash por evento y hash global | El primero localiza qué registro cambió; el segundo confirma que el archivo completo es el mismo |
| AES-256-GCM | Un solo mecanismo da confidencialidad y detección de alteración |
| Clave y nonce nuevos en cada cifrado | Nunca se repite un par (clave, nonce) |
| Verificar el log en claro antes de cifrar | No se protege un contenido ya alterado |
| Solo librería estándar para hashing y cifrado | Cumple la restricción del taller y evita dependencias en la parte criptográfica |
| Librerías de terceros solo para la terminal | PromptUI (menú) y fatih/color (resultados), como pide el taller |

## 14. Pruebas

Se ejecutan con `go test ./...`. Cubren:

- **Hashing:** vector conocido de SHA-256, determinismo, exclusión de `payload_hash` y detección del cambio de cada campo.
- **Generador:** cantidad válida e inválida, identificadores únicos, notas entre 0.0 y 5.0 con un decimal, coherencia de las modificaciones y hashes de payload válidos.
- **Log y almacenamiento:** serialización estable, hash guardado igual al del archivo y permisos restrictivos de la clave.
- **Cifrado:** ida y vuelta exacta, texto cifrado ilegible, clave incorrecta, un bit alterado, nonce alterado, cifrado truncado y nonces sin repetición en 1 000 cifrados.
- **Verificación:** preservación de la información y detección de un byte alterado en el cifrado, una nota alterada en el log, una clave incorrecta y un evento eliminado.

## 15. Limitaciones y mejoras

- **Gestión de la clave:** `key.bin` queda junto al log solo para poder demostrar el flujo; quien tenga ese archivo puede leer el log. En un sistema real la clave iría en un gestor de claves (KMS o HSM) o se derivaría de una contraseña.
- **Autenticidad del hash:** un hash simple no demuestra quién lo generó. Un HMAC o una firma digital lo reforzarían.
- **Encadenamiento:** enlazar cada evento con el hash del anterior permitiría detectar también el reordenamiento o la eliminación de eventos intermedios.
- **Datos simulados:** los eventos son aleatorios y no provienen de un sistema académico real.

## 16. Estructura de carpetas

```
cmd/logsecure/       punto de entrada
internal/cli/        menú interactivo
internal/model/      Event, Log, PipelineResult
internal/generator/  eventos aleatorios
internal/hashing/    SHA-256 y hash del payload
internal/logbuilder/ arma el log JSON
internal/storage/    lectura y escritura en output/
internal/pipeline/   pasos 2 a 7 encadenados
internal/crypto/     AES-256-GCM (Encrypt / Decrypt)
internal/verify/     descifrado, comparación y verificación
internal/report/     presentación de resultados
docs/diagramas/      diagramas de estructura y de comportamiento
docs/diapositivas/   presentación
output/              artefactos generados (ignorado por Git)
```

## 17. Conclusiones

LOGSECURE demuestra el ciclo completo de protección de un log en reposo. El diseño del evento justifica cada campo con un atributo de seguridad; el hash por evento permite localizar alteraciones y el hash del log completo confirma que el archivo es el mismo. El cifrado AES-256-GCM protege la confidencialidad y, además, hace fallar el descifrado ante cualquier manipulación. La comparación final entre el hash del log original y el del descifrado permite concluir si la información se preservó, y las pruebas de alteración muestran que el sistema no declara éxito cuando algo cambió.

La principal limitación es la gestión de la clave, que en este taller es solo demostrativa.
