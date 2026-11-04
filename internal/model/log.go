package model

// SchemaVersion identifica la versión del esquema del log. Si se cambia la
// estructura de Event o Log, se debe incrementar.
const SchemaVersion = "1.0"

// Log es el documento JSON completo que se hashea, se cifra y se recupera.
//
// Se guarda un encabezado (versión, fecha y conteo) junto con la lista de
// eventos: el conteo permite detectar eliminación o inserción de eventos
// además de la alteración de su contenido.
type Log struct {
	SchemaVersion string  `json:"schema_version"`
	GeneratedAt   string  `json:"generated_at"` // RFC 3339, UTC
	EventCount    int     `json:"event_count"`
	Events        []Event `json:"events"`
}
