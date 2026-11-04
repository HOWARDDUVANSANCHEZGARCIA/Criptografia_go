package hashing

import (
	"reflect"
	"testing"

	"criptografia_go/internal/model"
)

func ptr(f float64) *float64 { return &f }

func sampleEvent() model.Event {
	return model.Event{
		EventID:    "evt-0001",
		EventType:  model.EventGradeModified,
		Timestamp:  "2026-11-04T15:00:00Z",
		ActorUID:   "doc-1001",
		StudentUID: "est-2002",
		CourseUID:  "cur-3003",
		GradePrev:  ptr(3.2),
		GradeNew:   4.1,
	}
}

func TestSHA256HexVector(t *testing.T) {
	// Vector conocido: SHA-256("abc").
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := SHA256Hex([]byte("abc")); got != want {
		t.Fatalf("SHA256Hex(abc) = %s, quiero %s", got, want)
	}
}

func TestPayloadHashIgnoraPayloadHash(t *testing.T) {
	e := sampleEvent()
	h1, err := PayloadHash(e)
	if err != nil {
		t.Fatal(err)
	}
	e.PayloadHash = "cualquier-cosa"
	h2, _ := PayloadHash(e)
	if h1 != h2 {
		t.Fatal("el hash del payload no debe depender de PayloadHash")
	}
}

func TestPayloadHashEsDeterminista(t *testing.T) {
	a, _ := PayloadHash(sampleEvent())
	b, _ := PayloadHash(sampleEvent())
	if a != b {
		t.Fatal("el mismo evento debe producir siempre el mismo hash")
	}
}

func TestPayloadHashDetectaCambios(t *testing.T) {
	base, _ := PayloadHash(sampleEvent())
	cambios := map[string]func(*model.Event){
		"nota nueva":   func(e *model.Event) { e.GradeNew = 4.2 },
		"nota previa":  func(e *model.Event) { e.GradePrev = ptr(3.3) },
		"sin previa":   func(e *model.Event) { e.GradePrev = nil },
		"estudiante":   func(e *model.Event) { e.StudentUID = "est-9999" },
		"actor":        func(e *model.Event) { e.ActorUID = "doc-9999" },
		"curso":        func(e *model.Event) { e.CourseUID = "cur-9999" },
		"tipo":         func(e *model.Event) { e.EventType = model.EventGradeRegistered },
		"marca tiempo": func(e *model.Event) { e.Timestamp = "2026-11-04T15:00:01Z" },
		"id evento":    func(e *model.Event) { e.EventID = "evt-0002" },
	}
	for nombre, mutar := range cambios {
		e := sampleEvent()
		mutar(&e)
		h, _ := PayloadHash(e)
		if h == base {
			t.Errorf("cambiar %s no cambió el hash", nombre)
		}
	}
}

func TestVerifyPayloadHash(t *testing.T) {
	e := sampleEvent()
	e.PayloadHash, _ = PayloadHash(e)
	ok, err := VerifyPayloadHash(e)
	if err != nil || !ok {
		t.Fatalf("evento íntegro debe verificar: ok=%v err=%v", ok, err)
	}
	e.GradeNew = 5.0
	ok, _ = VerifyPayloadHash(e)
	if ok {
		t.Fatal("evento alterado no debe verificar")
	}
}

// Evita que eventPayload se desfase de model.Event: debe tener exactamente los
// mismos campos menos PayloadHash.
func TestPayloadCubreTodosLosCamposMenosElHash(t *testing.T) {
	ev := reflect.TypeOf(model.Event{})
	pl := reflect.TypeOf(eventPayload{})
	if pl.NumField() != ev.NumField()-1 {
		t.Fatalf("eventPayload tiene %d campos, Event tiene %d (debe ser uno menos)",
			pl.NumField(), ev.NumField())
	}
	for i := 0; i < pl.NumField(); i++ {
		f := pl.Field(i)
		ef, ok := ev.FieldByName(f.Name)
		if !ok || ef.Type != f.Type || ef.Tag.Get("json") != f.Tag.Get("json") {
			t.Errorf("campo %s de eventPayload no coincide con Event", f.Name)
		}
	}
}
