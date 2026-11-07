package cli

import (
	"fmt"

	"criptografia_go/internal/report"
	"criptografia_go/internal/storage"
	"criptografia_go/internal/verify"
)

// descifrarLog conecta la opción "Descifrar log" (pasos 8 y 9).
func descifrarLog() {
	h, err := verify.DecryptLog(storage.DefaultDir)
	if err != nil {
		fmt.Println("\n[X]", err)
		return
	}
	fmt.Println("\nLog descifrado correctamente.")
	fmt.Println("Hash del log descifrado:", h)
	fmt.Println("Archivo generado: output/log_decrypted.json")
	fmt.Println("Hash guardado en: output/log_decrypted.sha256")
}

// verificarIntegridad compara los hashes y revisa cada evento.
func verificarIntegridad() {
	plain, dec, ok, err := verify.Compare(storage.DefaultDir)
	if err != nil {
		fmt.Println("\nPrimero genera, cifra y descifra el log:", err)
		return
	}
	fmt.Println("\nHash log en claro:  ", plain)
	fmt.Println("Hash log descifrado:", dec)

	b, err := storage.Read(storage.DefaultDir, storage.LogDecrypted)
	if err != nil {
		fmt.Println(err)
		return
	}
	rep, err := verify.VerifyPayloads(b)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Eventos válidos: %d/%d (encabezado declara %d)\n", rep.Valid, rep.Total, rep.Declared)
	if len(rep.Invalid) > 0 {
		fmt.Println("Eventos alterados:", rep.Invalid)
	}
	if ok && rep.OK() {
		fmt.Println("[OK] Información preservada")
	} else {
		fmt.Println("[X] ALTERACIÓN DETECTADA")
	}
}

// verResultados conecta la opción "Ver resultados" (paso 10).
func verResultados() {
	r, err := verify.BuildResult(storage.DefaultDir)
	if err != nil {
		fmt.Println("\nPrimero genera, cifra y descifra el log:", err)
		return
	}
	report.Print(r)
}

// flujoCompleto encadena los pasos 1 a 10 para la demostración.
func flujoCompleto() {
	generarLog()
	cifrarLog()
	descifrarLog()
	verResultados()
}
