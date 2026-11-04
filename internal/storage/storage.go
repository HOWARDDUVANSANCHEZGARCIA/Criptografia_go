// Package storage lee y escribe los artefactos del flujo en el directorio de
// salida (por defecto, output/).
package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultDir es el directorio donde se guardan los artefactos.
const DefaultDir = "output"

// Nombres de los artefactos. Son parte del contrato: todos los módulos los
// usan en lugar de escribir las cadenas a mano.
const (
	LogPlain        = "log_plain.json"       // paso 4
	HashPlain       = "log_plain.sha256"     // paso 5
	LogEncrypted    = "log_encrypted.bin"    // paso 6
	KeyFile         = "key.bin"              // paso 6
	NonceFile       = "nonce.bin"            // paso 6
	HashEncrypted   = "log_encrypted.sha256" // paso 7
	LogDecrypted    = "log_decrypted.json"   // paso 8
	HashDecrypted   = "log_decrypted.sha256" // paso 9
	filePerm        = 0o644
	secretFilePerm  = 0o600
	directoryPerm   = 0o755
	hashFileLineFmt = "%s  %s\n" // mismo formato que `sha256sum`
)

// Write guarda data en dir/name, creando dir si no existe. Los archivos de
// clave se guardan con permisos restrictivos.
func Write(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, directoryPerm); err != nil {
		return fmt.Errorf("storage: crear directorio %s: %w", dir, err)
	}
	perm := os.FileMode(filePerm)
	if name == KeyFile {
		perm = secretFilePerm
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, perm); err != nil {
		return fmt.Errorf("storage: escribir %s: %w", name, err)
	}
	return nil
}

// Read lee dir/name.
func Read(dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, fmt.Errorf("storage: leer %s: %w", name, err)
	}
	return b, nil
}

// WriteHash guarda un hash en dir/hashName con el formato de sha256sum
// ("<hash>  <archivo>"), de modo que también puede comprobarse desde la
// terminal con `sha256sum -c`.
func WriteHash(dir, hashName, hash, hashedFile string) error {
	return Write(dir, hashName, []byte(fmt.Sprintf(hashFileLineFmt, hash, hashedFile)))
}

// ReadHash lee el hash guardado por WriteHash.
func ReadHash(dir, hashName string) (string, error) {
	b, err := Read(dir, hashName)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return "", fmt.Errorf("storage: %s está vacío", hashName)
	}
	return fields[0], nil
}
