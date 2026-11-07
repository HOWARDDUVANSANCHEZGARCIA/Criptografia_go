package verify

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"criptografia_go/internal/crypto"
	"criptografia_go/internal/hashing"
	"criptografia_go/internal/model"
	"criptografia_go/internal/storage"
)

// setup deja en un directorio temporal los artefactos de los pasos 4 a 7.
func setup(t *testing.T) (dir string, plain []byte) {
	t.Helper()
	dir = t.TempDir()

	events := make([]model.Event, 3)
	for i := range events {
		e := model.Event{
			EventID: fmt.Sprintf("id-%d", i), EventType: model.EventGradeRegistered,
			Timestamp: "2026-11-04T10:00:00Z", ActorUID: "doc-1",
			StudentUID: "est-1", CourseUID: "cur-1", GradeNew: 3.5,
		}
		h, err := hashing.PayloadHash(e)
		if err != nil {
			t.Fatal(err)
		}
		e.PayloadHash = h
		events[i] = e
	}
	l := model.Log{
		SchemaVersion: model.SchemaVersion, GeneratedAt: "2026-11-04T10:00:00Z",
		EventCount: len(events), Events: events,
	}
	plain, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(storage.Write(dir, storage.LogPlain, plain))
	must(storage.WriteHash(dir, storage.HashPlain, hashing.SHA256Hex(plain), storage.LogPlain))

	ct, key, nonce, err := crypto.Encrypt(plain)
	must(err)
	must(storage.Write(dir, storage.LogEncrypted, ct))
	must(storage.Write(dir, storage.KeyFile, key))
	must(storage.Write(dir, storage.NonceFile, nonce))
	must(storage.WriteHash(dir, storage.HashEncrypted, hashing.SHA256Hex(ct), storage.LogEncrypted))
	return dir, plain
}

func TestRoundTripPreservesInformation(t *testing.T) {
	dir, _ := setup(t)
	if _, err := DecryptLog(dir); err != nil {
		t.Fatalf("DecryptLog: %v", err)
	}
	_, _, ok, err := Compare(dir)
	if err != nil || !ok {
		t.Fatalf("los hashes debían coincidir (ok=%v, err=%v)", ok, err)
	}
	dec, _ := storage.Read(dir, storage.LogDecrypted)
	rep, err := VerifyPayloads(dec)
	if err != nil || rep.Valid != 3 || !rep.OK() {
		t.Fatalf("payloads: %+v err=%v", rep, err)
	}
	r, err := BuildResult(dir)
	if err != nil || !r.Preserved || r.EventCount != 3 || r.CountByType[model.EventGradeRegistered] != 3 {
		t.Fatalf("BuildResult: %+v err=%v", r, err)
	}
}

// (a) Cambiar un byte del archivo cifrado.
func TestAlteredCipherByteIsDetected(t *testing.T) {
	dir, _ := setup(t)
	ct, _ := storage.Read(dir, storage.LogEncrypted)
	ct[len(ct)/2] ^= 0x01
	storage.Write(dir, storage.LogEncrypted, ct)

	// Sin actualizar el .sha256: lo atrapa el hash del cifrado.
	if _, err := DecryptLog(dir); !errors.Is(err, ErrEncryptedTampered) {
		t.Fatalf("esperaba ErrEncryptedTampered, obtuve %v", err)
	}

	// Si el atacante también recalcula el .sha256: lo atrapa GCM.
	storage.WriteHash(dir, storage.HashEncrypted, hashing.SHA256Hex(ct), storage.LogEncrypted)
	if _, err := DecryptLog(dir); !errors.Is(err, crypto.ErrAuthFailed) {
		t.Fatalf("esperaba crypto.ErrAuthFailed, obtuve %v", err)
	}
}

// (b) Cambiar una nota en el JSON en claro.
func TestAlteredPlainGradeIsDetected(t *testing.T) {
	dir, plain := setup(t)
	mod := bytes.Replace(plain, []byte(`"grade_new": 3.5`), []byte(`"grade_new": 4.9`), 1)
	if bytes.Equal(mod, plain) {
		t.Fatal("la alteración no cambió nada; ajusta el texto buscado")
	}
	stored, _ := storage.ReadHash(dir, storage.HashPlain)

	// Nivel log completo: el hash global cambia.
	if SameHash(hashing.SHA256Hex(mod), stored) {
		t.Fatal("el hash global no detectó el cambio")
	}
	// Nivel evento: se localiza el registro alterado.
	rep, err := VerifyPayloads(mod)
	if err != nil || len(rep.Invalid) != 1 || rep.OK() {
		t.Fatalf("esperaba 1 evento inválido, obtuve %+v err=%v", rep, err)
	}
}

// (c) Usar una clave incorrecta.
func TestWrongKeyIsDetected(t *testing.T) {
	dir, _ := setup(t)
	bad := make([]byte, 32)
	if _, err := rand.Read(bad); err != nil {
		t.Fatal(err)
	}
	storage.Write(dir, storage.KeyFile, bad)

	if _, err := DecryptLog(dir); !errors.Is(err, crypto.ErrAuthFailed) {
		t.Fatalf("esperaba crypto.ErrAuthFailed, obtuve %v", err)
	}
	// No debe declararse éxito: no existe log descifrado.
	if _, err := storage.Read(dir, storage.LogDecrypted); err == nil {
		t.Fatal("no debía generarse log_decrypted.json")
	}
}

// Un evento eliminado debe detectarse por el conteo del encabezado.
func TestDeletedEventIsDetected(t *testing.T) {
	_, plain := setup(t)
	var l model.Log
	if err := json.Unmarshal(plain, &l); err != nil {
		t.Fatal(err)
	}
	l.Events = l.Events[:2] // event_count sigue diciendo 3
	b, _ := json.Marshal(l)
	rep, err := VerifyPayloads(b)
	if err != nil || rep.OK() {
		t.Fatalf("debía detectarse la eliminación: %+v err=%v", rep, err)
	}
}

func TestSameHash(t *testing.T) {
	if !SameHash("abc", "abc") || SameHash("abc", "abd") || SameHash("abc", "abcd") {
		t.Fatal("SameHash incorrecto")
	}
}
