package cli

import (
	"errors"
	"fmt"

	"criptografia_go/internal/pipeline"
	"criptografia_go/internal/storage"
)

// cifrarLog conecta los pasos 6 y 7 al menú (opción "Cifrar log").
func cifrarLog() {
	res, err := pipeline.EncryptStored(storage.DefaultDir)
	if err != nil {
		if errors.Is(err, pipeline.ErrPlainLogTampered) {
			fmt.Println("ALTERACIÓN DETECTADA en el log en claro: no coincide con su hash del paso 5.")
			fmt.Println("Genere el log de nuevo antes de cifrarlo.")
			return
		}
		fmt.Println("Error al cifrar el log:", err)
		return
	}

	dir := storage.DefaultDir + "/"
	fmt.Println("\nLog cifrado correctamente con AES-256-GCM.")
	fmt.Printf("Tamaño en claro:   %d bytes\n", res.PlainSize)
	fmt.Printf("Tamaño cifrado:    %d bytes (incluye etiqueta GCM de 16 bytes)\n", res.EncryptedSize)
	fmt.Println("Hash del log en claro: ", res.HashPlain)
	fmt.Println("Hash del log cifrado:  ", res.HashEncrypted)
	fmt.Println("Artefactos generados:")
	fmt.Println("  " + dir + storage.LogEncrypted + "    (log cifrado)")
	fmt.Println("  " + dir + storage.KeyFile + "              (clave AES-256, permisos 0600)")
	fmt.Println("  " + dir + storage.NonceFile + "            (nonce de 12 bytes)")
	fmt.Println("  " + dir + storage.HashEncrypted + " (hash del log cifrado)")
}
