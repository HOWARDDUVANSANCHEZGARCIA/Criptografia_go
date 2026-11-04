// Package pipeline encadena los pasos del flujo. El menú CLI y la opción
// "flujo completo" se apoyan en él.
package pipeline

import (
	"fmt"
	"math/rand/v2"
	"time"

	"criptografia_go/internal/generator"
	"criptografia_go/internal/hashing"
	"criptografia_go/internal/logbuilder"
	"criptografia_go/internal/model"
	"criptografia_go/internal/storage"
)

// PlainResult es lo que producen los pasos 1 a 5.
type PlainResult struct {
	Log         model.Log
	CountByType map[string]int
	HashPlain   string // SHA-256 de los bytes guardados en log_plain.json
}

// GeneratePlain ejecuta los pasos 2 a 5 para n eventos (el paso 1, pedir
// la cantidad, lo hace la CLI):
//
//  2. genera eventos aleatorios        3. cada uno con su payload_hash
//  4. consolida el log JSON y lo guarda en dir/log_plain.json
//  5. calcula el SHA-256 de esos bytes y lo guarda en dir/log_plain.sha256
func GeneratePlain(n int, dir string, rng *rand.Rand, now time.Time) (PlainResult, error) {
	events, err := generator.Generate(n, rng, now.Add(-time.Duration(n)*5*time.Minute))
	if err != nil {
		return PlainResult{}, err
	}

	l := logbuilder.Build(events, now)
	data, err := logbuilder.Marshal(l)
	if err != nil {
		return PlainResult{}, err
	}
	if err := storage.Write(dir, storage.LogPlain, data); err != nil {
		return PlainResult{}, err
	}

	h := hashing.SHA256Hex(data)
	if err := storage.WriteHash(dir, storage.HashPlain, h, storage.LogPlain); err != nil {
		return PlainResult{}, fmt.Errorf("pipeline: guardar hash del log en claro: %w", err)
	}

	return PlainResult{
		Log:         l,
		CountByType: generator.CountByType(events),
		HashPlain:   h,
	}, nil
}
