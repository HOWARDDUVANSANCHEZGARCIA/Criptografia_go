package pipeline

import (
	"math/rand/v2"
	"testing"
	"time"

	"criptografia_go/internal/hashing"
	"criptografia_go/internal/logbuilder"
	"criptografia_go/internal/model"
	"criptografia_go/internal/storage"
)

var now = time.Date(2026, 11, 4, 15, 0, 0, 0, time.UTC)

func rng(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, seed+1)) }

func TestGeneratePlainEscribeLogYHash(t *testing.T) {
	dir := t.TempDir()
	res, err := GeneratePlain(120, dir, rng(1), now)
	if err != nil {
		t.Fatal(err)
	}

	data, err := storage.Read(dir, storage.LogPlain)
	if err != nil {
		t.Fatal(err)
	}

	// El hash guardado es el SHA-256 de los bytes del archivo.
	stored, err := storage.ReadHash(dir, storage.HashPlain)
	if err != nil {
		t.Fatal(err)
	}
	if got := hashing.SHA256Hex(data); got != stored || got != res.HashPlain {
		t.Fatalf("hash inconsistente: archivo=%s guardado=%s resultado=%s", got, stored, res.HashPlain)
	}

	// El archivo es un log válido y completo.
	l, err := logbuilder.Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if l.EventCount != 120 || len(l.Events) != 120 {
		t.Fatalf("esperaba 120 eventos, hubo %d / %d", l.EventCount, len(l.Events))
	}
	if res.CountByType[model.EventGradeRegistered]+res.CountByType[model.EventGradeModified] != 120 {
		t.Fatalf("los conteos por tipo no suman 120: %v", res.CountByType)
	}
}

func TestGeneratePlainRechazaCantidadInvalida(t *testing.T) {
	if _, err := GeneratePlain(0, t.TempDir(), rng(1), now); err == nil {
		t.Fatal("debería rechazar 0 eventos")
	}
}

func TestLogSerializadoEsEstable(t *testing.T) {
	// Serializar, leer y volver a serializar debe dar exactamente los mismos
	// bytes: es lo que garantiza que el hash del log descifrado coincida.
	res, err := GeneratePlain(80, t.TempDir(), rng(2), now)
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := logbuilder.Marshal(res.Log)
	l2, err := logbuilder.Unmarshal(b1)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := logbuilder.Marshal(l2)
	if string(b1) != string(b2) {
		t.Fatal("la serialización no es estable tras un viaje de ida y vuelta")
	}
}

func TestPayloadHashDeCadaEventoSobreviveAlArchivo(t *testing.T) {
	dir := t.TempDir()
	if _, err := GeneratePlain(60, dir, rng(3), now); err != nil {
		t.Fatal(err)
	}
	data, _ := storage.Read(dir, storage.LogPlain)
	l, err := logbuilder.Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range l.Events {
		ok, err := hashing.VerifyPayloadHash(e)
		if err != nil || !ok {
			t.Fatalf("%s: payload_hash no verifica tras leer del archivo", e.EventID)
		}
	}
}

func TestAlterarUnaNotaCambiaElHashDelLogYElDelEvento(t *testing.T) {
	dir := t.TempDir()
	res, err := GeneratePlain(40, dir, rng(4), now)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := storage.Read(dir, storage.LogPlain)
	l, _ := logbuilder.Unmarshal(data)

	l.Events[10].GradeNew = 5.0 - l.Events[10].GradeNew // alteración
	tampered, _ := logbuilder.Marshal(l)

	if hashing.SHA256Hex(tampered) == res.HashPlain {
		t.Fatal("el hash del log debe cambiar al alterar una nota")
	}
	if ok, _ := hashing.VerifyPayloadHash(l.Events[10]); ok && l.Events[10].GradeNew != res.Log.Events[10].GradeNew {
		t.Fatal("el payload_hash del evento alterado no debe verificar")
	}
}
