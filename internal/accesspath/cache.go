package accesspath

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func DefaultCachePath() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", fmt.Errorf("access path: %%LOCALAPPDATA%% is not set")
	}
	return filepath.Join(base, "PingRank", "access-path.json"), nil
}
func LoadCache(path string, maxAge time.Duration) (Result, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Result{}, false
	}
	var r Result
	if json.Unmarshal(raw, &r) != nil || r.TestedAt.IsZero() || time.Since(r.TestedAt) > maxAge {
		return Result{}, false
	}
	return r, true
}
func SaveCache(path string, r Result) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		// Windows does not replace an existing destination with Rename. The
		// cache is disposable, so fall back to a short remove-and-replace.
		if removeErr := os.Remove(path); removeErr == nil || os.IsNotExist(removeErr) {
			err = os.Rename(tmp, path)
		}
		if err != nil {
			_ = os.Remove(tmp)
		}
	}
	return err
}

type CachedDetector struct {
	Reflectors []Reflector
	MaxAge     time.Duration
	Path       string
}

func (d CachedDetector) Detect(ctx context.Context) (Result, error) {
	path := d.Path
	if path == "" {
		path, _ = DefaultCachePath()
	}
	age := d.MaxAge
	if age == 0 {
		age = 24 * time.Hour
	}
	if r, ok := LoadCache(path, age); ok {
		return r, nil
	}
	r, err := Measure(ctx, d.Reflectors)
	if err == nil {
		_ = SaveCache(path, r)
	}
	return r, err
}
