package model

// PipelineResult resume una ejecución completa del flujo (pasos 1 a 9) y es
// lo que internal/report muestra en el paso 10.
type PipelineResult struct {
	EventCount  int            // total de eventos generados
	CountByType map[string]int // eventos por tipo (EventGradeRegistered, ...)

	HashPlain     string // paso 5: SHA-256 del log en claro
	HashEncrypted string // paso 7: SHA-256 del log cifrado
	HashDecrypted string // paso 9: SHA-256 del log descifrado

	Preserved bool // true si HashPlain == HashDecrypted
}
