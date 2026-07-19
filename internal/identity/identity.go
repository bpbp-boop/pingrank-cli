package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type file struct {
	AgentID       string `json:"agentId"`
	PublicKey     string `json:"publicKey,omitempty"`
	ProtectedSeed string `json:"protectedSeed,omitempty"`
}

type Credentials struct {
	AgentID    string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func DefaultPath() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", fmt.Errorf("identity: %%LOCALAPPDATA%% is not set")
	}
	return filepath.Join(base, "PingRank", "install.json"), nil
}

// Load returns the existing agent ID without creating or repairing identity
// state. The tray uses it: running as the logged-in user it cannot unprotect
// the service's DPAPI seed, and LoadOrCreate would rewrite the service-owned
// install.json with a fresh keypair.
func Load(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var existing file
	if err := json.Unmarshal(raw, &existing); err != nil {
		return "", fmt.Errorf("identity: %s: %w", path, err)
	}
	decoded, err := hex.DecodeString(existing.AgentID)
	if err != nil || len(decoded) != 16 {
		return "", fmt.Errorf("identity: %s holds no valid agent id", path)
	}
	return existing.AgentID, nil
}

func LoadOrCreate(path string) (string, error) {
	c, err := LoadOrCreateCredentials(path)
	if err != nil {
		return "", err
	}
	return c.AgentID, nil
}

func LoadOrCreateCredentials(path string) (Credentials, error) {
	var existing file
	if raw, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(raw, &existing) == nil {
			decoded, decodeErr := hex.DecodeString(existing.AgentID)
			if decodeErr == nil && len(decoded) == 16 {
				if existing.ProtectedSeed != "" {
					enc, e := base64.StdEncoding.DecodeString(existing.ProtectedSeed)
					if e == nil {
						seed, e := unprotect(enc)
						if e == nil && len(seed) == ed25519.SeedSize {
							priv := ed25519.NewKeyFromSeed(seed)
							return Credentials{existing.AgentID, priv.Public().(ed25519.PublicKey), priv}, nil
						}
					}
				}
			}
		}
	} else if !os.IsNotExist(err) {
		return Credentials{}, err
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return Credentials{}, err
	}
	id := existing.AgentID
	if decoded, e := hex.DecodeString(id); e != nil || len(decoded) != 16 {
		id = hex.EncodeToString(b)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Credentials{}, err
	}
	protected, err := protect(priv.Seed())
	if err != nil {
		return Credentials{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Credentials{}, err
	}
	raw, _ := json.Marshal(file{AgentID: id, PublicKey: base64.StdEncoding.EncodeToString(pub), ProtectedSeed: base64.StdEncoding.EncodeToString(protected)})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return Credentials{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		if removeErr := os.Remove(path); removeErr == nil || os.IsNotExist(removeErr) {
			err = os.Rename(tmp, path)
		}
		if err != nil {
			_ = os.Remove(tmp)
			return Credentials{}, err
		}
	}
	return Credentials{id, pub, priv}, nil
}
