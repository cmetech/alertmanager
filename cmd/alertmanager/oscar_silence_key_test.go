package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadOscarSilenceMutationKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if _, err := readOscarSilenceMutationKey(path); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := os.WriteFile(path, []byte("short\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOscarSilenceMutationKey(path); err == nil {
		t.Fatal("short key accepted")
	}
	key := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(path, []byte(key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readOscarSilenceMutationKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != key {
		t.Fatalf("key mismatch: %q", got)
	}
}
