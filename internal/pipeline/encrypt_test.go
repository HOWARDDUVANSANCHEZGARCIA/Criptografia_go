package pipeline

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"criptografia_go/internal/crypto"
	"criptografia_go/internal/hashing"
	"criptografia_go/internal/storage"
)

// logCifrado prepara un directorio con los pasos 1 a 7 ya ejecutados.
func logCifrado(t *testing.T, n int, seed uint64) (string, PlainResult, EncryptResult) {
	t.Helper()
	dir := t.TempDir()
	plain, err := GeneratePlain(n, dir, rng(seed), now)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := EncryptStored(dir)
	if err != nil {
		t.Fatalf("EncryptStored: %v", err)
	}
	return dir, plain, enc
}

func TestEncryptStoredGeneraLosArtefactosSeparados(t *testing.T) {
	dir, _, _ := logCifrado(t, 50, 10)
	for _, name := range []string{
		storage.LogEncrypted, storage.KeyFile, storage.NonceFile, storage.HashEncrypted,
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("falta el artefacto %s: %v", name, err)
		}
	}
	key, _ := storage.Read(dir, storage.KeyFile)
	nonce, _ := storage.Read(dir, storage.NonceFile)
	if len(key) != crypto.KeySize || len(nonce) != crypto.NonceSize {
		t.Fatalf("clave de %d bytes y nonce de %d bytes", len(key), len(nonce))
	}
}

func TestElLogEnClaroOriginalNoSeModifica(t *testing.T) {
	dir, plain, _ := logCifrado(t, 30, 11)
	data, _ := storage.Read(dir, storage.LogPlain)
	if hashing.SHA256Hex(data) != plain.HashPlain {
		t.Fatal("cifrar no debe tocar log_plain.json")
	}
}

func TestHashDelCifradoEsElDelArchivo(t *testing.T) {
	dir, plain, enc := logCifrado(t, 40, 12)
	cifrado, _ := storage.Read(dir, storage.LogEncrypted)
	guardado, err := storage.ReadHash(dir, storage.HashEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	if got := hashing.SHA256Hex(cifrado); got != guardado || got != enc.HashEncrypted {
		t.Fatalf("hash inconsistente: archivo=%s guardado=%s resultado=%s", got, guardado, enc.HashEncrypted)
	}
	if enc.HashEncrypted == plain.HashPlain {
		t.Fatal("el hash del cifrado no puede ser igual al del log en claro")
	}
	if enc.HashPlain != plain.HashPlain {
		t.Fatal("EncryptResult debe reportar el hash del log que realmente cifró")
	}
	if enc.EncryptedSize != enc.PlainSize+crypto.TagSize {
		t.Fatalf("tamaños: claro=%d cifrado=%d", enc.PlainSize, enc.EncryptedSize)
	}
}

func TestElArchivoCifradoNoEsLegible(t *testing.T) {
	dir, _, _ := logCifrado(t, 40, 13)
	cifrado, _ := storage.Read(dir, storage.LogEncrypted)
	for _, f := range []string{"GRADE_", "event_id", "student_uid", "est-", "doc-"} {
		if bytes.Contains(cifrado, []byte(f)) {
			t.Fatalf("log_encrypted.bin deja ver %q", f)
		}
	}
}

func TestConLosArtefactosGuardadosSeRecuperaElLogExacto(t *testing.T) {
	// Es lo que hará Jacobo en el paso 8: solo con los tres archivos.
	dir, plain, _ := logCifrado(t, 70, 14)
	c, _ := storage.Read(dir, storage.LogEncrypted)
	k, _ := storage.Read(dir, storage.KeyFile)
	n, _ := storage.Read(dir, storage.NonceFile)
	got, err := crypto.Decrypt(c, k, n)
	if err != nil {
		t.Fatal(err)
	}
	if hashing.SHA256Hex(got) != plain.HashPlain {
		t.Fatal("el log descifrado no tiene el hash del log original")
	}
}

func TestLaClaveQuedaConPermisosRestrictivos(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows no maneja permisos tipo Unix")
	}
	dir := t.TempDir()
	if _, err := GeneratePlain(10, dir, rng(15), now); err != nil {
		t.Fatal(err)
	}
	// Una clave vieja con permisos abiertos debe quedar en 0600 tras cifrar.
	if err := os.WriteFile(filepath.Join(dir, storage.KeyFile), []byte("vieja"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptStored(dir); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(dir, storage.KeyFile))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key.bin con permisos %v, se esperaba 0600", info.Mode().Perm())
	}
}

func TestCifrarDosVecesUsaClaveYNonceNuevos(t *testing.T) {
	dir, _, enc1 := logCifrado(t, 20, 16)
	n1, _ := storage.Read(dir, storage.NonceFile)
	k1, _ := storage.Read(dir, storage.KeyFile)
	enc2, err := EncryptStored(dir)
	if err != nil {
		t.Fatal(err)
	}
	n2, _ := storage.Read(dir, storage.NonceFile)
	k2, _ := storage.Read(dir, storage.KeyFile)
	if bytes.Equal(n1, n2) || bytes.Equal(k1, k2) || enc1.HashEncrypted == enc2.HashEncrypted {
		t.Fatal("cada cifrado debe usar clave y nonce nuevos")
	}
	if enc1.HashPlain != enc2.HashPlain {
		t.Fatal("el log en claro es el mismo, su hash también debe serlo")
	}
}

func TestNoSeCifraUnLogEnClaroAlterado(t *testing.T) {
	dir := t.TempDir()
	if _, err := GeneratePlain(25, dir, rng(17), now); err != nil {
		t.Fatal(err)
	}
	data, _ := storage.Read(dir, storage.LogPlain)
	alterado := bytes.Replace(data, []byte(`"grade_new": `), []byte(`"grade_new":  `), 1)
	if err := storage.Write(dir, storage.LogPlain, alterado); err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptStored(dir); !errors.Is(err, ErrPlainLogTampered) {
		t.Fatalf("se esperaba ErrPlainLogTampered, se obtuvo %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, storage.LogEncrypted)); !os.IsNotExist(err) {
		t.Fatal("no debe quedar un log cifrado de un log alterado")
	}
}

func TestSinLogEnClaroDaErrorClaro(t *testing.T) {
	if _, err := EncryptStored(t.TempDir()); err == nil {
		t.Fatal("cifrar sin haber generado el log debe fallar")
	}
}
