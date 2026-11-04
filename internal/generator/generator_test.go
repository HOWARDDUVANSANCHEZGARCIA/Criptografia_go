package generator

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"criptografia_go/internal/hashing"
	"criptografia_go/internal/model"
)

var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func newRNG(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, seed+1)) }

func TestValidateCount(t *testing.T) {
	for _, n := range []int{-5, 0, MaxEvents + 1} {
		if ValidateCount(n) == nil {
			t.Errorf("ValidateCount(%d) debería fallar", n)
		}
	}
	for _, n := range []int{1, 100, MaxEvents} {
		if err := ValidateCount(n); err != nil {
			t.Errorf("ValidateCount(%d) no debería fallar: %v", n, err)
		}
	}
}

func TestGenerateCantidadInvalida(t *testing.T) {
	if _, err := Generate(0, newRNG(1), t0); err == nil {
		t.Fatal("Generate(0) debería fallar")
	}
}

func TestGenerateCantidadYUnicidad(t *testing.T) {
	events, err := Generate(500, newRNG(1), t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 500 {
		t.Fatalf("esperaba 500 eventos, hubo %d", len(events))
	}
	seen := map[string]bool{}
	for _, e := range events {
		if seen[e.EventID] {
			t.Fatalf("event_id repetido: %s", e.EventID)
		}
		seen[e.EventID] = true
	}
}

func TestGenerateAparecenAmbosTipos(t *testing.T) {
	events, _ := Generate(500, newRNG(2), t0)
	c := CountByType(events)
	if c[model.EventGradeRegistered] == 0 || c[model.EventGradeModified] == 0 {
		t.Fatalf("deberían aparecer ambos tipos: %v", c)
	}
	if c[model.EventGradeRegistered]+c[model.EventGradeModified] != 500 {
		t.Fatalf("los conteos no suman 500: %v", c)
	}
}

func TestGenerateNotasValidas(t *testing.T) {
	events, _ := Generate(2000, newRNG(3), t0)
	for _, e := range events {
		for _, g := range []float64{e.GradeNew} {
			if g < model.GradeMin || g > model.GradeMax {
				t.Fatalf("nota fuera de rango: %v", g)
			}
			if math.Abs(g*10-math.Round(g*10)) > 1e-9 {
				t.Fatalf("la nota debe tener un decimal: %v", g)
			}
		}
		if e.GradePrev != nil && (*e.GradePrev < 0 || *e.GradePrev > 5) {
			t.Fatalf("nota previa fuera de rango: %v", *e.GradePrev)
		}
	}
}

func TestGenerateCoherenciaDeModificaciones(t *testing.T) {
	events, _ := Generate(2000, newRNG(4), t0)
	vigente := map[pair]float64{}
	for _, e := range events {
		p := pair{e.StudentUID, e.CourseUID}
		switch e.EventType {
		case model.EventGradeRegistered:
			if e.GradePrev != nil {
				t.Fatalf("%s: un registro no debe traer nota previa", e.EventID)
			}
			if _, ya := vigente[p]; ya {
				t.Fatalf("%s: registro de una nota que ya existía", e.EventID)
			}
		case model.EventGradeModified:
			if e.GradePrev == nil {
				t.Fatalf("%s: una modificación debe traer nota previa", e.EventID)
			}
			prev, ok := vigente[p]
			if !ok || prev != *e.GradePrev {
				t.Fatalf("%s: la nota previa no coincide con la vigente", e.EventID)
			}
			if *e.GradePrev == e.GradeNew {
				t.Fatalf("%s: nota nueva igual a la anterior", e.EventID)
			}
		default:
			t.Fatalf("tipo desconocido: %s", e.EventType)
		}
		vigente[p] = e.GradeNew
	}
}

func TestGenerateHashesDePayloadValidos(t *testing.T) {
	events, _ := Generate(300, newRNG(5), t0)
	for _, e := range events {
		ok, err := hashing.VerifyPayloadHash(e)
		if err != nil || !ok {
			t.Fatalf("%s: payload_hash inválido (ok=%v, err=%v)", e.EventID, ok, err)
		}
	}
}

func TestGenerateTimestampsCrecientes(t *testing.T) {
	events, _ := Generate(200, newRNG(6), t0)
	prev := t0
	for _, e := range events {
		ts, err := time.Parse(time.RFC3339, e.Timestamp)
		if err != nil {
			t.Fatal(err)
		}
		if !ts.After(prev) {
			t.Fatalf("%s: la marca de tiempo no avanza", e.EventID)
		}
		prev = ts
	}
}

func TestGenerateReproducible(t *testing.T) {
	a, _ := Generate(100, newRNG(7), t0)
	b, _ := Generate(100, newRNG(7), t0)
	for i := range a {
		if a[i].PayloadHash != b[i].PayloadHash {
			t.Fatal("misma semilla debe dar los mismos eventos")
		}
	}
}

func TestGenerateSaturaPares(t *testing.T) {
	// Más eventos que pares posibles: debe seguir generando (con modificaciones).
	events, err := Generate(numStudents*numCourses*3, newRNG(8), t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != numStudents*numCourses*3 {
		t.Fatalf("cantidad incorrecta: %d", len(events))
	}
}

func TestDifferentGradeNuncaIgualYCubreRango(t *testing.T) {
	rng := newRNG(9)
	vistos := map[float64]bool{}
	for i := 0; i < 5000; i++ {
		prev := float64(rng.IntN(gradeSteps)) / 10
		g := differentGrade(rng, prev)
		if g == prev {
			t.Fatalf("differentGrade devolvió la misma nota %v", g)
		}
		vistos[g] = true
	}
	if !vistos[0.0] || !vistos[5.0] {
		t.Fatal("los extremos 0.0 y 5.0 deberían poder aparecer")
	}
}
