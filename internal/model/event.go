// Package model define las estructuras de datos compartidas por todos los
// módulos del proyecto. Es el "contrato": cualquier cambio aquí afecta a todos.
package model

// Tipos de evento admitidos en el log.
const (
	EventGradeRegistered = "GRADE_REGISTERED" // registro de nota
	EventGradeModified   = "GRADE_MODIFIED"   // modificación de nota
)

// Rango válido de una nota.
const (
	GradeMin = 0.0
	GradeMax = 5.0
)

// Event representa una operación académica sensible.
//
// Todos los identificadores son UIDs o pseudónimos; nunca nombres reales.
//
// Atributo de seguridad que respalda cada campo:
//   - EventID     -> trazabilidad (identifica de forma única la operación)
//   - EventType   -> trazabilidad (distingue registro de modificación)
//   - Timestamp   -> trazabilidad / no repudio (cuándo ocurrió)
//   - ActorUID    -> no repudio (quién ejecutó la operación)
//   - StudentUID  -> pseudonimización (a quién afecta, sin datos personales)
//   - CourseUID   -> trazabilidad (recurso afectado)
//   - GradePrev   -> auditabilidad (valor anterior; nil en un registro)
//   - GradeNew    -> auditabilidad (valor resultante)
//   - PayloadHash -> integridad por registro (SHA-256 del payload, ver hashing)
type Event struct {
	EventID     string   `json:"event_id"`
	EventType   string   `json:"event_type"`
	Timestamp   string   `json:"timestamp"` // RFC 3339, UTC
	ActorUID    string   `json:"actor_uid"`
	StudentUID  string   `json:"student_uid"`
	CourseUID   string   `json:"course_uid"`
	GradePrev   *float64 `json:"grade_prev"` // nil (null) en GRADE_REGISTERED
	GradeNew    float64  `json:"grade_new"`
	PayloadHash string   `json:"payload_hash"` // SHA-256 en hexadecimal
}
