package crypto

import (
	"bytes"
	"errors"
	"testing"
)

var muestra = []byte(`{"schema_version":"1.0","events":[{"event_type":"GRADE_MODIFIED","grade_prev":3.2,"grade_new":4.5}]}` + "\n")

func cifrar(t *testing.T, p []byte) (c, k, n []byte) {
	t.Helper()
	c, k, n, err := Encrypt(p)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return c, k, n
}

func TestIdaYVueltaPreservaLosBytes(t *testing.T) {
	c, k, n := cifrar(t, muestra)
	got, err := Decrypt(c, k, n)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, muestra) {
		t.Fatal("el texto descifrado no es idéntico al original")
	}
}

func TestTamanosDeClaveNonceYCifrado(t *testing.T) {
	c, k, n := cifrar(t, muestra)
	if len(k) != KeySize {
		t.Fatalf("clave de %d bytes, se esperaban %d (AES-256)", len(k), KeySize)
	}
	if len(n) != NonceSize {
		t.Fatalf("nonce de %d bytes, se esperaban %d", len(n), NonceSize)
	}
	// GCM no agrega relleno: cifrado = len(plaintext) + etiqueta de 16 bytes.
	if len(c) != len(muestra)+TagSize {
		t.Fatalf("cifrado de %d bytes, se esperaban %d", len(c), len(muestra)+TagSize)
	}
}

func TestElCifradoNoEsLegible(t *testing.T) {
	c, _, _ := cifrar(t, muestra)
	for _, fragmento := range []string{"GRADE_MODIFIED", "grade_new", "schema_version"} {
		if bytes.Contains(c, []byte(fragmento)) {
			t.Fatalf("el texto cifrado deja ver %q", fragmento)
		}
	}
}

func TestClaveIncorrectaFalla(t *testing.T) {
	c, k, n := cifrar(t, muestra)
	otra := bytes.Clone(k)
	otra[0] ^= 0xFF
	if _, err := Decrypt(c, otra, n); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("con clave incorrecta se esperaba ErrAuthFailed, se obtuvo %v", err)
	}
}

func TestUnBitAlteradoEnElCifradoFalla(t *testing.T) {
	c, k, n := cifrar(t, muestra)
	// Se prueba un bit al inicio, en el medio y dentro de la etiqueta.
	for _, pos := range []int{0, len(c) / 2, len(c) - 1} {
		alterado := bytes.Clone(c)
		alterado[pos] ^= 0x01
		got, err := Decrypt(alterado, k, n)
		if !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("bit alterado en la posición %d: se esperaba ErrAuthFailed, se obtuvo %v", pos, err)
		}
		if got != nil {
			t.Fatalf("con autenticación fallida no debe entregarse texto en claro")
		}
	}
}

func TestNonceAlteradoFalla(t *testing.T) {
	c, k, n := cifrar(t, muestra)
	otro := bytes.Clone(n)
	otro[len(otro)-1] ^= 0x01
	if _, err := Decrypt(c, k, otro); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("con nonce alterado se esperaba ErrAuthFailed, se obtuvo %v", err)
	}
}

func TestCifradoTruncadoFalla(t *testing.T) {
	c, k, n := cifrar(t, muestra)
	if _, err := Decrypt(c[:len(c)-1], k, n); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("cifrado truncado: se esperaba ErrAuthFailed, se obtuvo %v", err)
	}
	if _, err := Decrypt(c[:TagSize-1], k, n); !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("cifrado sin etiqueta completa: se esperaba ErrCiphertextTooShort, se obtuvo %v", err)
	}
}

func TestDosCifradosDelMismoLogSonDistintos(t *testing.T) {
	c1, k1, n1 := cifrar(t, muestra)
	c2, k2, n2 := cifrar(t, muestra)
	if bytes.Equal(n1, n2) {
		t.Fatal("dos cifrados produjeron el mismo nonce")
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("dos cifrados produjeron la misma clave")
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("dos cifrados del mismo log produjeron el mismo texto cifrado")
	}
}

func TestNoncesUnicosEnMuchasEjecuciones(t *testing.T) {
	vistos := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		_, _, n := cifrar(t, muestra)
		if vistos[string(n)] {
			t.Fatalf("nonce repetido en la iteración %d", i)
		}
		vistos[string(n)] = true
	}
}

func TestTamanosInvalidosSeRechazan(t *testing.T) {
	c, k, n := cifrar(t, muestra)
	if _, err := Decrypt(c, k[:16], n); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("clave de 16 bytes: se esperaba ErrInvalidKey, se obtuvo %v", err)
	}
	if _, err := Decrypt(c, k, n[:8]); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("nonce de 8 bytes: se esperaba ErrInvalidNonce, se obtuvo %v", err)
	}
}

func TestLogVacioTambienSeCifra(t *testing.T) {
	c, k, n := cifrar(t, []byte{})
	got, err := Decrypt(c, k, n)
	if err != nil || len(got) != 0 {
		t.Fatalf("ida y vuelta de un texto vacío: %q, %v", got, err)
	}
}
