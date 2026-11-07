# Taller Dos – Protección de logs estructurados en reposo

Herramienta CLI en Go que genera logs JSON de registro y modificación de notas,
calcula su hash (SHA-256), los cifra en reposo (AES-256-GCM), los descifra y
verifica que la información se preservó. Cualquier alteración se detecta.

## Flujo (10 pasos)

1. Solicitar la cantidad de eventos
2. Generar eventos aleatorios (`GRADE_REGISTERED` / `GRADE_MODIFIED`)
3. Calcular el hash del payload de cada evento
4. Armar el log JSON (`log_plain.json`)
5. Hash SHA-256 del log en claro
6. Cifrar con AES-256-GCM (`log_encrypted.bin`, `key.bin`, `nonce.bin`)
7. Hash SHA-256 del log cifrado
8. Descifrar (`log_decrypted.json`)
9. Hash SHA-256 del log descifrado y comparación con el original
10. Mostrar resultados: **Información preservada** o **ALTERACIÓN DETECTADA**

## Requisitos

- Go 1.24 o superior (`go version`)
- Conexión a internet la primera vez, para descargar las dependencias

Dependencias externas (solo para la terminal; el hashing y el cifrado usan
únicamente la librería estándar de Go):

- `github.com/manifoldco/promptui` – menú interactivo
- `github.com/fatih/color` – colores en la salida de resultados

## Compilar y ejecutar

```bash
go mod tidy
go build ./...
go run ./cmd/logsecure
```

## Pruebas

```bash
go test ./...
```

Nota: en Windows, `TestClaveConPermisosRestrictivos` (paquete `storage`) puede
fallar porque Windows no maneja permisos Unix (0600). No afecta el
funcionamiento del programa.

## Opciones del menú

| Opción | Qué hace |
|---|---|
| Generar eventos y log en claro | Pide N, genera el log y su hash (pasos 1 a 5) |
| Cifrar log | Cifra con AES-256-GCM y guarda cifrado, clave, nonce y hash (pasos 6 y 7) |
| Descifrar log | Verifica el hash del cifrado, descifra y calcula el hash (pasos 8 y 9) |
| Verificar integridad | Compara hashes y valida el `payload_hash` de cada evento |
| Ver resultados | Muestra la tabla de resultados (paso 10) |
| Ejecutar flujo completo | Encadena los pasos 1 a 10 para la demostración |
| Salir | Termina el programa |

## Archivos generados en `output/` (ignorado por Git)

| Archivo | Paso |
|---|---|
| `log_plain.json`, `log_plain.sha256` | 4 y 5 |
| `log_encrypted.bin`, `key.bin`, `nonce.bin` | 6 |
| `log_encrypted.sha256` | 7 |
| `log_decrypted.json`, `log_decrypted.sha256` | 8 y 9 |

## Estructura del proyecto

```
cmd/logsecure/       punto de entrada
internal/cli/        menú interactivo
internal/model/      Event, Log, PipelineResult
internal/generator/  eventos aleatorios
internal/hashing/    SHA-256 y hash del payload
internal/logbuilder/ arma el log JSON
internal/storage/    lectura y escritura en output/
internal/pipeline/   pasos 1 a 7 encadenados
internal/crypto/     AES-256-GCM (Encrypt / Decrypt)
internal/verify/     descifrado, comparación y verificación
internal/report/     presentación de resultados
docs/diagramas/      diagramas de estructura y de comportamiento
docs/diapositivas/   PDF de la presentación
```

## Integridad en dos niveles

- **Por evento:** cada evento lleva su `payload_hash`, lo que permite localizar
  qué registro cambió.
- **Por log completo:** un SHA-256 global sobre los bytes del archivo confirma
  que el log completo es el mismo. El `event_count` del encabezado detecta
  eventos eliminados o insertados.

## Aviso de seguridad

`key.bin` se guarda junto al log solo con fines académicos. En un sistema real
la clave iría en un gestor de claves (KMS/HSM), separada de los datos.
