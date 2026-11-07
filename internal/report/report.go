// Package report muestra al usuario los resultados del flujo (paso 10).
//
// RESPONSABLE: Sebastián.
// Usa github.com/fatih/color como librería de terceros para la terminal.
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"

	"criptografia_go/internal/model"
)

var (
	title = color.New(color.Bold, color.FgCyan)
	label = color.New(color.Bold)
	okC   = color.New(color.Bold, color.FgGreen)
	badC  = color.New(color.Bold, color.FgWhite, color.BgRed)
)

func line() { fmt.Println(strings.Repeat("─", 78)) }

func row(name, value string) {
	label.Printf("  %-26s", name)
	fmt.Println(value)
}

// Print muestra: cantidad de eventos, cantidad por tipo, hash de cada etapa
// y el veredicto de la comparación entre log original y descifrado.
func Print(r model.PipelineResult) {
	fmt.Println()
	line()
	title.Println("  RESULTADOS - PROTECCIÓN DE LOGS ESTRUCTURADOS EN REPOSO")
	line()

	row("Cantidad de eventos:", fmt.Sprint(r.EventCount))

	types := make([]string, 0, len(r.CountByType))
	for t := range r.CountByType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		row("  - "+t+":", fmt.Sprint(r.CountByType[t]))
	}

	line()
	title.Println("  Hashes SHA-256")
	row("Log en claro:", r.HashPlain)
	row("Log cifrado:", r.HashEncrypted)
	row("Log descifrado:", r.HashDecrypted)
	line()

	if r.Preserved {
		row("Claro == Descifrado:", "SÍ (los hashes coinciden)")
		fmt.Println()
		okC.Println("  [OK] Información preservada")
	} else {
		row("Claro == Descifrado:", "NO (los hashes difieren)")
		fmt.Println()
		badC.Println("  [X] ALTERACIÓN DETECTADA ")
	}
	fmt.Println()
	line()
}
