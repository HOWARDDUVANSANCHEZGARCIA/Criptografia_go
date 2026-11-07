// Package verify compara hashes y comprueba la integridad del log.
//
// RESPONSABLE: Jacobo (pasos 8 y 9).
package verify

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"

	"criptografia_go/internal/crypto"
	"criptografia_go/internal/hashing"
	"criptografia_go/internal/model"
	"criptografia_go/internal/storage"
)

// ErrEncryptedTampered indica que el hash del archivo cifrado ya no coincide
// con el registrado en el paso 7 (manipulación del archivo en reposo).
var ErrEncryptedTampered = errors.New("ALTERACIÓN DETECTADA: el hash del log cifrado no coincide con el registrado")

// SameHash indica si dos hashes hexadecimales son iguales, con comparación
// en tiempo constante (crypto/subtle).
func SameHash(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// DecryptLog ejecuta el paso 8 y calcula el hash del paso 9:
//  1. verifica el hash del archivo cifrado (paso 7) ANTES de descifrar;
//  2. descifra con crypto.Decrypt;
//  3. guarda log_decrypted.json y log_decrypted.sha256.
//
// Devuelve el SHA-256 del log descifrado. Si el cifrado fue alterado o la
// clave es incorrecta, el error cumple errors.Is(err, crypto.ErrAuthFailed)
// o errors.Is(err, ErrEncryptedTampered), y no se escribe ningún archivo.
func DecryptLog(dir string) (string, error) {
	ct, err := storage.Read(dir, storage.LogEncrypted)
	if err != nil {
		return "", err
	}
	key, err := storage.Read(dir, storage.KeyFile)
	if err != nil {
		return "", err
	}
	nonce, err := storage.Read(dir, storage.NonceFile)
	if err != nil {
		return "", err
	}
	expected, err := storage.ReadHash(dir, storage.HashEncrypted)
	if err != nil {
		return "", err
	}
	if !SameHash(hashing.SHA256Hex(ct), expected) {
		return "", ErrEncryptedTampered
	}

	pt, err := crypto.Decrypt(ct, key, nonce)
	if err != nil {
		if errors.Is(err, crypto.ErrAuthFailed) {
			return "", fmt.Errorf("ALTERACIÓN DETECTADA (falló la autenticación AES-GCM): %w", err)
		}
		return "", fmt.Errorf("no se pudo descifrar: %w", err)
	}

	if err := storage.Write(dir, storage.LogDecrypted, pt); err != nil {
		return "", err
	}
	h := hashing.SHA256Hex(pt)
	if err := storage.WriteHash(dir, storage.HashDecrypted, h, storage.LogDecrypted); err != nil {
		return "", err
	}
	return h, nil
}

// Compare lee los hashes guardados del log en claro (paso 5) y del descifrado
// (paso 9) y devuelve si coinciden, es decir, si la información se preservó.
func Compare(dir string) (plain, decrypted string, preserved bool, err error) {
	plain, err = storage.ReadHash(dir, storage.HashPlain)
	if err != nil {
		return "", "", false, err
	}
	decrypted, err = storage.ReadHash(dir, storage.HashDecrypted)
	if err != nil {
		return "", "", false, err
	}
	return plain, decrypted, SameHash(plain, decrypted), nil
}

// PayloadReport resume la verificación evento por evento.
type PayloadReport struct {
	Total    int      // eventos presentes en el log
	Declared int      // event_count declarado en el encabezado
	Valid    int      // eventos cuyo payload_hash coincide
	Invalid  []string // event_id de los eventos alterados
}

// OK es true si todos los eventos son válidos y el conteo del encabezado
// coincide con los eventos presentes (detecta eliminación o inserción).
func (r PayloadReport) OK() bool {
	return len(r.Invalid) == 0 && r.Total == r.Declared
}

// VerifyPayloads recalcula el payload_hash de cada evento con
// hashing.VerifyPayloadHash. Sirve para LOCALIZAR qué registro cambió.
func VerifyPayloads(logBytes []byte) (PayloadReport, error) {
	var l model.Log
	if err := json.Unmarshal(logBytes, &l); err != nil {
		return PayloadReport{}, fmt.Errorf("JSON inválido: %w", err)
	}
	rep := PayloadReport{Total: len(l.Events), Declared: l.EventCount}
	for _, e := range l.Events {
		ok, err := hashing.VerifyPayloadHash(e)
		if err != nil {
			return rep, err
		}
		if ok {
			rep.Valid++
		} else {
			rep.Invalid = append(rep.Invalid, e.EventID)
		}
	}
	return rep, nil
}

// BuildResult arma el PipelineResult que muestra report.Print (paso 10),
// leyendo los artefactos ya generados en dir.
func BuildResult(dir string) (model.PipelineResult, error) {
	var r model.PipelineResult

	plain, dec, preserved, err := Compare(dir)
	if err != nil {
		return r, err
	}
	enc, err := storage.ReadHash(dir, storage.HashEncrypted)
	if err != nil {
		return r, err
	}
	r.HashPlain, r.HashEncrypted, r.HashDecrypted, r.Preserved = plain, enc, dec, preserved

	b, err := storage.Read(dir, storage.LogPlain)
	if err != nil {
		return r, err
	}
	var l model.Log
	if err := json.Unmarshal(b, &l); err != nil {
		return r, fmt.Errorf("JSON inválido en %s: %w", storage.LogPlain, err)
	}
	r.EventCount = len(l.Events)
	r.CountByType = map[string]int{}
	for _, e := range l.Events {
		r.CountByType[e.EventType]++
	}
	return r, nil
}
