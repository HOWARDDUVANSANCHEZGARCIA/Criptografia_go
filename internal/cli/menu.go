package cli

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"time"

	"github.com/manifoldco/promptui"

	"criptografia_go/internal/generator"
	"criptografia_go/internal/pipeline"
)

func Run() {
	opciones := []string{
		"Generar eventos y log en claro",
		"Cifrar log",
		"Descifrar log",
		"Verificar integridad",
		"Ver resultados",
		"Ejecutar flujo completo",
		"Salir",
	}

	for {
		menu := promptui.Select{
			Label: "LOGSECURE - Protección de logs académicos",
			Items: opciones,
			Size:  len(opciones),
		}

		_, seleccion, err := menu.Run()
		if err != nil {
			fmt.Println("No se pudo mostrar el menú:", err)
			return
		}

		switch seleccion {
		case opciones[0]:
			generarLog()
		case opciones[1]:
			cifrarLog()
		case opciones[2]:
			descifrarLog()
		case opciones[3]:
			verificarIntegridad()
		case opciones[4]:
			verResultados()
		case opciones[5]:
			flujoCompleto()
		case opciones[6]:
			fmt.Println("Cerrando LOGSECURE...")
			return
		}

		fmt.Println()
	}
}

func generarLog() {
	prompt := promptui.Prompt{
		Label: "¿Cuántos eventos desea generar?",
		Validate: func(input string) error {
			n, err := strconv.Atoi(input)
			if err != nil {
				return fmt.Errorf("ingrese un número entero")
			}

			return generator.ValidateCount(n)
		},
	}

	entrada, err := prompt.Run()
	if err != nil {
		fmt.Println("No se pudo leer la cantidad:", err)
		return
	}

	cantidad, _ := strconv.Atoi(entrada)

	semilla := uint64(time.Now().UnixNano())
	rng := rand.New(rand.NewPCG(semilla, semilla+1))

	resultado, err := pipeline.GeneratePlain(
		cantidad,
		"output",
		rng,
		time.Now(),
	)

	if err != nil {
		fmt.Println("Error al generar el log:", err)
		return
	}

	fmt.Println("\nLog generado correctamente.")
	fmt.Println("Cantidad de eventos:", resultado.Log.EventCount)
	fmt.Println("Hash del log:", resultado.HashPlain)
	fmt.Println("Archivo generado: output/log_plain.json")
	fmt.Println("Hash guardado en: output/log_plain.sha256")
}
