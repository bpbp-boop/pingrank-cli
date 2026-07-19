// Package agent runs PingRank's session recorder as a long-lived background
// process and publishes a small, non-sensitive status snapshot for the tray.
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	StateStarting  = "starting"
	StateWaiting   = "waiting"
	StateRecording = "recording"
	StateError     = "error"
	StateStopped   = "stopped"
)

// Status is the service-to-tray contract. It intentionally excludes player
// identity, local addresses, tokens, and raw log content.
type Status struct {
	State     string    `json:"state"`
	Message   string    `json:"message"`
	GameID    string    `json:"gameId,omitempty"`
	Game      string    `json:"game,omitempty"`
	Endpoint  string    `json:"endpoint,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
	Version   string    `json:"version"`
}

// DefaultDataDir is the machine-wide service data directory.
func DefaultDataDir() (string, error) {
	base := os.Getenv("ProgramData")
	if base == "" {
		return "", fmt.Errorf("agent: %%ProgramData%% is not set")
	}
	return filepath.Join(base, "PingRank"), nil
}

func StatusPath(dataDir string) string { return filepath.Join(dataDir, "status.json") }

// WriteStatus atomically publishes status so the tray never observes partial
// JSON while the service updates it.
func WriteStatus(path string, status Status) error {
	status.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		if removeErr := os.Remove(path); removeErr == nil || os.IsNotExist(removeErr) {
			err = os.Rename(tmp, path)
		}
		if err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return nil
}

// ReadStatus reads the latest snapshot published by the service.
func ReadStatus(path string) (Status, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Status{}, err
	}
	var status Status
	if err := json.Unmarshal(raw, &status); err != nil {
		return Status{}, err
	}
	return status, nil
}
