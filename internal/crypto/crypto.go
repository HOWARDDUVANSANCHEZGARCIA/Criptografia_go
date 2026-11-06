// Package crypto cifra y descifra el log en reposo (paso 6; el paso 8 lo
// consume Jacobo a través de Decrypt).
//
// RESPONSABLE: Daniel.
//
// Algoritmo: AES-256-GCM, implementado solo con la librería estándar de Go:
//
//   - crypto/aes    -> cifrador de bloque AES (clave de 32 bytes = AES-256)
//   - crypto/cipher -> modo GCM (cifrado autenticado, AEAD)
//   - crypto/rand   -> clave y nonce con un generador criptográficamente seguro
//
// Por qué GCM y no CBC o CTR: GCM es un modo AEAD. Además de cifrar
// (confidencialidad) agrega una etiqueta de autenticación de 16 bytes al
// final del texto cifrado. Si cambia un solo bit del texto cifrado, del nonce
// o si se usa otra clave, Decrypt falla en lugar de devolver basura. CBC o CTR
// solos cifran, pero no detectan manipulación.
//
// Formato del texto cifrado que devuelve Encrypt: el que produce
// cipher.AEAD.Seal, es decir  cifrado(plaintext) || etiqueta(16 bytes).
// La clave y el nonce se devuelven aparte para guardarse como artefactos
// separados (key.bin y nonce.bin).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Tamaños usados por el módulo.
const (
	KeySize   = 32 // bytes -> AES-256
	NonceSize = 12 // bytes -> tamaño estándar recomendado para GCM (96 bits)
	TagSize   = 16 // bytes -> etiqueta de autenticación que GCM agrega al final
)

// Errores que el resto de módulos puede distinguir con errors.Is.
var (
	// ErrAuthFailed indica que GCM no pudo autenticar el texto cifrado: el
	// archivo cifrado o el nonce fueron alterados, o la clave no es la
	// correcta. Debe informarse como "alteración detectada", no como un
	// fallo genérico.
	ErrAuthFailed = errors.New("crypto: autenticación fallida (texto cifrado alterado o clave/nonce incorrectos)")

	// ErrInvalidKey indica que la clave no mide KeySize bytes.
	ErrInvalidKey = errors.New("crypto: la clave debe medir 32 bytes (AES-256)")

	// ErrInvalidNonce indica que el nonce no mide NonceSize bytes.
	ErrInvalidNonce = errors.New("crypto: el nonce debe medir 12 bytes")

	// ErrCiphertextTooShort indica que el texto cifrado ni siquiera alcanza
	// a contener la etiqueta de autenticación.
	ErrCiphertextTooShort = errors.New("crypto: el texto cifrado es demasiado corto")
)

// Encrypt cifra plaintext con AES-256-GCM y devuelve el texto cifrado, la
// clave y el nonce generados, para que el llamador los guarde como
// artefactos separados.
//
// En cada llamada se generan una clave y un nonce nuevos con crypto/rand
// (nunca con math/rand). Así se garantiza que nunca se reutiliza un par
// (clave, nonce), que es la condición de seguridad de GCM.
func Encrypt(plaintext []byte) (ciphertext, key, nonce []byte, err error) {
	key, err = randomBytes(KeySize)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("crypto: generar clave: %w", err)
	}
	nonce, err = randomBytes(NonceSize)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("crypto: generar nonce: %w", err)
	}

	aead, err := newGCM(key)
	if err != nil {
		return nil, nil, nil, err
	}

	// Seal(dst=nil, ...) devuelve cifrado || etiqueta en un slice nuevo.
	// No se usa dato adicional autenticado (AAD): el contrato no lo incluye
	// y todo el log viaja dentro del texto cifrado.
	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, key, nonce, nil
}

// Decrypt descifra ciphertext con la clave y el nonce dados.
//
// Si el texto cifrado o el nonce fueron alterados, o la clave es incorrecta,
// devuelve un error que cumple errors.Is(err, ErrAuthFailed) y no entrega
// ningún byte del texto en claro.
func Decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("%w (recibido: %d bytes)", ErrInvalidNonce, len(nonce))
	}
	if len(ciphertext) < TagSize {
		return nil, fmt.Errorf("%w (recibido: %d bytes)", ErrCiphertextTooShort, len(ciphertext))
	}

	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// cipher.AEAD.Open solo devuelve un error genérico a propósito (no
		// dice qué falló, para no dar pistas a un atacante); lo traducimos
		// a ErrAuthFailed para que verify pueda reconocerlo.
		return nil, ErrAuthFailed
	}
	return plaintext, nil
}

// newGCM construye el cifrador AES-GCM para una clave de 32 bytes.
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w (recibido: %d bytes)", ErrInvalidKey, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: crear cifrador AES: %w", err)
	}
	aead, err := cipher.NewGCM(block) // nonce de 12 bytes, etiqueta de 16
	if err != nil {
		return nil, fmt.Errorf("crypto: crear modo GCM: %w", err)
	}
	return aead, nil
}

// randomBytes devuelve n bytes de crypto/rand.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
