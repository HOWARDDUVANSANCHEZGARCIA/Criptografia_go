// Package crypto cifra y descifra el log en reposo.
//
// RESPONSABLE: Daniel (pasos 6 y 7). Jacobo consume Decrypt (paso 8).
// Debe usar únicamente la librería estándar de Go (crypto/aes, crypto/cipher,
// crypto/rand). Recomendado: AES-256-GCM, clave de 32 bytes, nonce de 12 bytes.
package crypto

import "errors"

// ErrNotImplemented se devuelve mientras el módulo no esté implementado.
var ErrNotImplemented = errors.New("crypto: no implementado todavía")

// Encrypt cifra plaintext y devuelve el texto cifrado, la clave y el nonce
// generados, para que el llamador los guarde como artefactos separados.
//
// TODO(Daniel): implementar con AES-256-GCM.
func Encrypt(plaintext []byte) (ciphertext, key, nonce []byte, err error) {
	return nil, nil, nil, ErrNotImplemented
}

// Decrypt descifra ciphertext con la clave y el nonce dados. Si el texto
// cifrado fue alterado o la clave es incorrecta, debe devolver un error.
//
// TODO(Daniel): implementar con AES-256-GCM.
func Decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}
