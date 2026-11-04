// Package generator produce eventos académicos aleatorios (paso 2) y les
// asigna su hash de payload (paso 3).
//
// Los datos son simulados: los identificadores son UIDs legibles y
// pseudónimos, nunca nombres reales.
package generator

import (
	"fmt"
	"math/rand/v2"
	"time"

	"criptografia_go/internal/hashing"
	"criptografia_go/internal/model"
)

// Límites de la cantidad de eventos que acepta el programa.
const (
	MinEvents = 1
	MaxEvents = 100000
)

// Tamaño de los conjuntos de identificadores simulados.
const (
	numTeachers = 10 // doc-0001 ... doc-0010
	numStudents = 50 // est-0001 ... est-0050
	numCourses  = 15 // cur-001  ... cur-015
)

// Las notas tienen un decimal: 0.0, 0.1, ..., 5.0 (51 valores equiprobables).
const gradeSteps = 51

// ValidateCount comprueba que n esté dentro del rango admitido.
func ValidateCount(n int) error {
	if n < MinEvents || n > MaxEvents {
		return fmt.Errorf("la cantidad de eventos debe estar entre %d y %d (recibido: %d)",
			MinEvents, MaxEvents, n)
	}
	return nil
}

// pair identifica una nota: un estudiante en un curso.
type pair struct{ student, course string }

// Generate crea n eventos aleatorios, ordenados por tiempo.
//
// Reglas:
//   - Dos tipos de evento: registro y modificación de nota.
//   - La nota es uniforme sobre 0.0, 0.1, ..., 5.0.
//   - Una modificación solo recae sobre una nota ya registrada: su
//     GradePrev es la nota vigente y GradeNew siempre es distinta.
//   - Cada evento sale con su PayloadHash calculado.
//
// rng y start son parámetros para que las pruebas sean reproducibles.
func Generate(n int, rng *rand.Rand, start time.Time) ([]model.Event, error) {
	if err := ValidateCount(n); err != nil {
		return nil, err
	}

	events := make([]model.Event, 0, n)
	current := make(map[pair]float64) // nota vigente por (estudiante, curso)
	var known []pair                  // pares ya registrados, para elegir modificaciones
	ts := start.UTC()

	for i := 1; i <= n; i++ {
		ts = ts.Add(time.Duration(1+rng.IntN(300)) * time.Second)

		ev := model.Event{
			EventID:   fmt.Sprintf("evt-%06d", i),
			Timestamp: ts.Format(time.RFC3339),
			ActorUID:  fmt.Sprintf("doc-%04d", 1+rng.IntN(numTeachers)),
		}

		modify := len(known) > 0 && rng.IntN(2) == 0
		if !modify {
			p, ok := newPair(rng, current)
			if ok {
				ev.EventType = model.EventGradeRegistered
				ev.StudentUID, ev.CourseUID = p.student, p.course
				ev.GradeNew = randomGrade(rng)
				current[p] = ev.GradeNew
				known = append(known, p)
			} else {
				modify = true // todos los pares ya tienen nota
			}
		}
		if modify {
			p := known[rng.IntN(len(known))]
			prev := current[p]
			ev.EventType = model.EventGradeModified
			ev.StudentUID, ev.CourseUID = p.student, p.course
			ev.GradePrev = &prev
			ev.GradeNew = differentGrade(rng, prev)
			current[p] = ev.GradeNew
		}

		h, err := hashing.PayloadHash(ev)
		if err != nil {
			return nil, err
		}
		ev.PayloadHash = h
		events = append(events, ev)
	}
	return events, nil
}

// CountByType cuenta los eventos de cada tipo.
func CountByType(events []model.Event) map[string]int {
	counts := map[string]int{
		model.EventGradeRegistered: 0,
		model.EventGradeModified:   0,
	}
	for _, e := range events {
		counts[e.EventType]++
	}
	return counts
}

// newPair elige un par (estudiante, curso) sin nota. Devuelve false si tras
// varios intentos no encuentra uno libre.
func newPair(rng *rand.Rand, taken map[pair]float64) (pair, bool) {
	for try := 0; try < 50; try++ {
		p := pair{
			student: fmt.Sprintf("est-%04d", 1+rng.IntN(numStudents)),
			course:  fmt.Sprintf("cur-%03d", 1+rng.IntN(numCourses)),
		}
		if _, used := taken[p]; !used {
			return p, true
		}
	}
	return pair{}, false
}

// randomGrade devuelve una nota uniforme en {0.0, 0.1, ..., 5.0}.
func randomGrade(rng *rand.Rand) float64 {
	return float64(rng.IntN(gradeSteps)) / 10
}

// differentGrade devuelve una nota uniforme entre todas las posibles
// excepto prev.
func differentGrade(rng *rand.Rand, prev float64) float64 {
	prevStep := int(prev*10 + 0.5)
	k := rng.IntN(gradeSteps - 1)
	if k >= prevStep {
		k++
	}
	return float64(k) / 10
}
