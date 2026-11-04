// Package logbuilder consolida los eventos en el log JSON completo (paso 4).
package logbuilder

import (
	"encoding/json"
	"fmt"
	"time"

	"criptografia_go/internal/model"
)

// Build arma el log con su encabezado (versión del esquema, fecha de
// generación y cantidad de eventos) y la lista de eventos.
func Build(events []model.Event, generatedAt time.Time) model.Log {
	return model.Log{
		SchemaVersion: model.SchemaVersion,
		GeneratedAt:   generatedAt.UTC().Format(time.RFC3339),
		EventCount:    len(events),
		Events:        events,
	}
}

// Marshal serializa el log a JSON con sangría de 2 espacios y un salto de
// línea final.
//
// Estos bytes son los que se guardan en log_plain.json, se hashean (paso 5)
// y se cifran (paso 6). Ninguna etapa posterior debe reserializar el log:
// todas trabajan sobre estos mismos bytes.
func Marshal(l model.Log) ([]byte, error) {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("logbuilder: serializar log: %w", err)
	}
	return append(b, '\n'), nil
}

// Unmarshal lee un log desde sus bytes JSON y comprueba que el conteo del
// encabezado coincida con la cantidad de eventos.
func Unmarshal(data []byte) (model.Log, error) {
	var l model.Log
	if err := json.Unmarshal(data, &l); err != nil {
		return model.Log{}, fmt.Errorf("logbuilder: leer log: %w", err)
	}
	if l.EventCount != len(l.Events) {
		return model.Log{}, fmt.Errorf("logbuilder: event_count=%d pero hay %d eventos",
			l.EventCount, len(l.Events))
	}
	return l, nil
}
