
# Reporte técnico
## Protección de logs estructurados en reposo

**Proyecto:** LOGSECURE  
**Lenguaje:** Go  
**Curso:** Criptografía  
**Integrantes:** [Nombres del equipo]

---

## 1. Introducción

El proyecto LOGSECURE consiste en una herramienta de línea de comandos desarrollada en Go para generar y proteger logs estructurados que representan operaciones académicas sensibles, como el registro y la modificación de notas.

La solución busca demostrar mecanismos de integridad, confidencialidad y trazabilidad mediante hashing y operaciones criptográficas.

## 2. Objetivo

Diseñar e implementar una aplicación CLI que genere eventos académicos simulados, los almacene en un log JSON y aplique mecanismos de protección criptográfica.

## 3. Arquitectura del proyecto

El proyecto se organiza en módulos independientes para separar responsabilidades:

- model: define las estructuras de datos.
- generator: genera eventos académicos aleatorios.
- hashing: calcula y verifica hashes SHA-256.
- logbuilder: construye y serializa el log JSON.
- storage: administra la lectura y escritura de archivos.
- pipeline: coordina los pasos de generación y almacenamiento.
- cli: permite la interacción con el usuario.
- crypto: contiene las operaciones de cifrado y descifrado.
- verify: permite comparar los resultados de integridad.
- report: reúne la presentación de resultados.

## 4. Diseño del evento

Cada evento representa una operación académica de registro o modificación de nota.

Los campos utilizados son:

- event_id: identificador único del evento.
- event_type: tipo de operación.
- timestamp: fecha y hora de la operación.
- actor_uid: identificador pseudónimo del actor.
- student_uid: identificador pseudónimo del estudiante.
- course_uid: identificador de la asignatura.
- grade_prev: nota anterior, cuando se trata de una modificación.
- grade_new: nueva nota.
- payload_hash: hash del contenido del evento.

## 5. Diseño del payload y hashing

El payload está compuesto por los campos que describen la operación, excluyendo payload_hash.

Esta exclusión evita una dependencia circular, porque el hash no puede calcularse incluyéndose a sí mismo.

Se utiliza SHA-256 para obtener una huella digital del contenido de cada evento. Esto permite detectar modificaciones en los datos.

## 6. Diseño del log JSON

Los eventos se agrupan en un documento JSON que contiene:

- schema_version: versión del esquema.
- generated_at: fecha y hora de generación.
- event_count: cantidad total de eventos.
- events: lista de eventos generados.

La serialización utiliza un formato consistente para conservar los mismos bytes al almacenar y calcular el hash.

## 7. Hash del log completo

Después de serializar el log, se calcula SHA-256 sobre los bytes exactos que se escriben en log_plain.json.

El resultado se almacena por separado en log_plain.sha256.

## 8. Decisiones de diseño

Explicar aquí:
- Por qué se utilizan identificadores pseudónimos.
- Por qué se utiliza SHA-256.
- Por qué payload_hash no se incluye en el payload.
- Por qué se conserva el mismo contenido serializado.
- Por qué el hash del archivo se almacena por separado.

## 9. Estructura de carpetas

Incluir una descripción de las carpetas principales del proyecto.

## 10. Conclusiones

La solución permite representar operaciones académicas sensibles mediante logs estructurados y aplicar mecanismos de hashing para verificar la integridad de los datos.

Las etapas de cifrado, descifrado y comparación se documentarán conforme se integren al flujo completo.
