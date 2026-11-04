// Package hashing concentra todas las operaciones de hash del proyecto.
//
// Algoritmo: SHA-256 (crypto/sha256, librería estándar de Go).
package hashing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"criptografia_go/internal/model"
)

// SHA256Hex devuelve el SHA-256 de data en hexadecimal (64 caracteres).
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// eventPayload es el conjunto de campos que se hashean en cada evento.
//
// Contiene TODOS los campos de model.Event EXCEPTO PayloadHash: si el hash
// formara parte de lo que se hashea, su valor dependería de sí mismo y la
// operación sería circular (no habría un valor que lo satisficiera).
//
// El orden de los campos aquí define el orden de serialización, y por tanto
// los bytes que se hashean. No reordenar ni renombrar sin cambiar
// model.SchemaVersion.
type eventPayload struct {
	EventID    string   `json:"event_id"`
	EventType  string   `json:"event_type"`
	Timestamp  string   `json:"timestamp"`
	ActorUID   string   `json:"actor_uid"`
	StudentUID string   `json:"student_uid"`
	CourseUID  string   `json:"course_uid"`
	GradePrev  *float64 `json:"grade_prev"`
	GradeNew   float64  `json:"grade_new"`
}

// PayloadBytes devuelve la serialización estable (JSON compacto, campos en
// orden fijo) del payload del evento, sin incluir PayloadHash.
func PayloadBytes(e model.Event) ([]byte, error) {
	p := eventPayload{
		EventID:    e.EventID,
		EventType:  e.EventType,
		Timestamp:  e.Timestamp,
		ActorUID:   e.ActorUID,
		StudentUID: e.StudentUID,
		CourseUID:  e.CourseUID,
		GradePrev:  e.GradePrev,
		GradeNew:   e.GradeNew,
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("hashing: serializar payload: %w", err)
	}
	return b, nil
}

// PayloadHash calcula el SHA-256 (hex) del payload del evento. El resultado
// se guarda en Event.PayloadHash.
func PayloadHash(e model.Event) (string, error) {
	b, err := PayloadBytes(e)
	if err != nil {
		return "", err
	}
	return SHA256Hex(b), nil
}

// VerifyPayloadHash recalcula el hash del evento y lo compara con el que
// trae almacenado. Devuelve false si el evento fue alterado.
func VerifyPayloadHash(e model.Event) (bool, error) {
	h, err := PayloadHash(e)
	if err != nil {
		return false, err
	}
	return h == e.PayloadHash, nil
}
