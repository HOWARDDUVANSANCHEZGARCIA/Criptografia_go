package pipeline

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"criptografia_go/internal/crypto"
	"criptografia_go/internal/hashing"
	"criptografia_go/internal/storage"
)

// ErrPlainLogTampered indica que log_plain.json ya no coincide con el hash
// guardado en el paso 5: el log en claro se alteró antes de cifrarlo, así
// que no se cifra (se estaría protegiendo un contenido que no es el original).
var ErrPlainLogTampered = errors.New("pipeline: log_plain.json no coincide con log_plain.sha256; no se cifra un log alterado")

// EncryptResult es lo que producen los pasos 6 y 7.
type EncryptResult struct {
	HashPlain     string // hash del log en claro que se cifró (paso 5)
	HashEncrypted string // SHA-256 de los bytes de log_encrypted.bin (paso 7)
	PlainSize     int    // bytes del log en claro
	EncryptedSize int    // bytes del log cifrado (PlainSize + etiqueta GCM)
}

// EncryptStored ejecuta los pasos 6 y 7 sobre el log que ya está en dir:
//
//  6. lee los bytes EXACTOS de dir/log_plain.json (sin reserializar), verifica
//     que sigan coincidiendo con dir/log_plain.sha256, los cifra con
//     AES-256-GCM y guarda como artefactos separados:
//     log_encrypted.bin, key.bin (permisos 0600) y nonce.bin.
//  7. calcula el SHA-256 de los bytes cifrados y lo guarda en
//     dir/log_encrypted.sha256.
//
// Cada ejecución usa clave y nonce nuevos, por lo que volver a cifrar el
// mismo log produce un log_encrypted.bin (y un hash) distinto.
func EncryptStored(dir string) (EncryptResult, error) {
	plain, err := storage.Read(dir, storage.LogPlain)
	if err != nil {
		return EncryptResult{}, fmt.Errorf("pipeline: primero genere el log en claro: %w", err)
	}
	stored, err := storage.ReadHash(dir, storage.HashPlain)
	if err != nil {
		return EncryptResult{}, fmt.Errorf("pipeline: falta el hash del log en claro: %w", err)
	}
	hashPlain := hashing.SHA256Hex(plain)
	if subtle.ConstantTimeCompare([]byte(hashPlain), []byte(stored)) != 1 {
		return EncryptResult{}, ErrPlainLogTampered
	}

	// Paso 6: cifrado en reposo.
	ciphertext, key, nonce, err := crypto.Encrypt(plain)
	if err != nil {
		return EncryptResult{}, err
	}
	artefactos := []struct {
		name string
		data []byte
	}{
		{storage.LogEncrypted, ciphertext},
		{storage.NonceFile, nonce},
		{storage.KeyFile, key}, // storage.Write le aplica permisos 0600
	}
	for _, a := range artefactos {
		if err := storage.Write(dir, a.name, a.data); err != nil {
			return EncryptResult{}, err
		}
	}

	// Paso 7: hash del log cifrado, sobre los mismos bytes que se guardaron.
	hashEnc := hashing.SHA256Hex(ciphertext)
	if err := storage.WriteHash(dir, storage.HashEncrypted, hashEnc, storage.LogEncrypted); err != nil {
		return EncryptResult{}, fmt.Errorf("pipeline: guardar hash del log cifrado: %w", err)
	}

	return EncryptResult{
		HashPlain:     hashPlain,
		HashEncrypted: hashEnc,
		PlainSize:     len(plain),
		EncryptedSize: len(ciphertext),
	}, nil
}
