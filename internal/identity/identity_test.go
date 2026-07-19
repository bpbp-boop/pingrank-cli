package identity

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreatePersistentRandomID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "install.json")
	a, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || len(a) != 32 {
		t.Fatalf("ids %q %q", a, b)
	}
}

func TestCredentialsPersistSigningKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "install.json")
	a, err := LoadOrCreateCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if a.AgentID != b.AgentID || !bytes.Equal(a.PublicKey, b.PublicKey) || !bytes.Equal(a.PrivateKey, b.PrivateKey) {
		t.Fatal("credentials changed across loads")
	}
}

func TestLoadIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "install.json")
	want, err := LoadOrCreateCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if id != want.AgentID {
		t.Fatalf("Load returned %q, want %q", id, want.AgentID)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("Load modified install.json")
	}
}

func TestLoadNeverCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "install.json")
	if _, err := Load(path); err == nil {
		t.Fatal("Load of a missing file should error")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("Load created install.json")
	}
	if err := os.WriteFile(path, []byte(`{"agentId":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load of a malformed ID should error, not repair it")
	}
}

func TestLoadOrCreateReplacesMalformedID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "install.json")
	if err := os.WriteFile(path, []byte(`{"agentId":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 16 {
		t.Fatalf("replacement ID %q is invalid", id)
	}
}
