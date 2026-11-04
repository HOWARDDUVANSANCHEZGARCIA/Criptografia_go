package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteYRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub", "output")
	want := []byte("hola")
	if err := Write(dir, LogPlain, want); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir, LogPlain)
	if err != nil || string(got) != "hola" {
		t.Fatalf("Read = %q, %v", got, err)
	}
}

func TestClaveConPermisosRestrictivos(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, KeyFile, []byte("secreto")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("la clave debe ser accesible solo por su dueño, permisos: %v", info.Mode().Perm())
	}
}

func TestWriteHashYReadHash(t *testing.T) {
	dir := t.TempDir()
	h := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if err := WriteHash(dir, HashPlain, h, LogPlain); err != nil {
		t.Fatal(err)
	}
	got, err := ReadHash(dir, HashPlain)
	if err != nil || got != h {
		t.Fatalf("ReadHash = %q, %v", got, err)
	}
}

func TestReadInexistente(t *testing.T) {
	if _, err := Read(t.TempDir(), "no-existe"); err == nil {
		t.Fatal("debería fallar al leer un archivo inexistente")
	}
}
