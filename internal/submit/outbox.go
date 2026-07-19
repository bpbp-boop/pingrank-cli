package submit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxOutbox caps queued payloads; oldest are pruned first, matching the
// session store's retention style.
const MaxOutbox = 100

// backoff is the retry schedule indexed by prior attempt count, capped at
// its last entry. Failure must never block or degrade recording, so the
// queue only drains opportunistically on later submit/record runs.
var backoff = []time.Duration{
	time.Minute, 5 * time.Minute, 15 * time.Minute,
	time.Hour, 3 * time.Hour, 6 * time.Hour,
}

// DefaultOutboxDir is %LOCALAPPDATA%\PingRank\outbox.
func DefaultOutboxDir() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", fmt.Errorf("outbox: %%LOCALAPPDATA%% is not set")
	}
	return filepath.Join(base, "PingRank", "outbox"), nil
}

// entry is one queued payload at rest.
type entry struct {
	V           int       `json:"v"`
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"nextAttempt"`
	Payload     Payload   `json:"payload"`
}

// Enqueue stores a payload for later delivery and returns its file path.
func Enqueue(dir string, p Payload) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("outbox: %w", err)
	}
	if err := prune(dir, MaxOutbox-1); err != nil {
		return "", err
	}
	name := time.Now().UTC().Format("20060102T150405.000") + "_" +
		sanitize(p.Session.GameID) + ".json"
	path := filepath.Join(dir, name)
	data, err := json.Marshal(entry{V: 1, Payload: p})
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("outbox: %w", err)
	}
	return path, nil
}

// FlushStats summarizes one queue drain.
type FlushStats struct {
	Sent     int // delivered (or already stored server-side)
	Dropped  int // permanently rejected, removed from the queue
	Deferred int // not yet due, or failed retryably and rescheduled
}

// Flush attempts every due entry. Retryable failures are rescheduled with
// backoff; permanent rejections are dropped so a gated client version
// doesn't retry forever.
func Flush(ctx context.Context, dir string, c *Client) (FlushStats, error) {
	var st FlushStats
	names, err := outboxFiles(dir)
	if err != nil || len(names) == 0 {
		return st, err
	}
	now := time.Now().UTC()
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var e entry
		if err := json.Unmarshal(data, &e); err != nil {
			// Corrupt queue file: remove rather than wedge the queue.
			os.Remove(path)
			st.Dropped++
			continue
		}
		if now.Before(e.NextAttempt) {
			st.Deferred++
			continue
		}
		_, err = c.Submit(ctx, e.Payload)
		switch {
		case err == nil:
			os.Remove(path)
			st.Sent++
		case IsRetryable(err):
			e.Attempts++
			idx := e.Attempts - 1
			if idx >= len(backoff) {
				idx = len(backoff) - 1
			}
			e.NextAttempt = now.Add(backoff[idx])
			if data, err := json.Marshal(e); err == nil {
				os.WriteFile(path, data, 0o644)
			}
			st.Deferred++
			if ctx.Err() != nil {
				return st, ctx.Err()
			}
		default:
			os.Remove(path)
			st.Dropped++
		}
	}
	return st, nil
}

// Pending counts queued payloads.
func Pending(dir string) int {
	names, err := outboxFiles(dir)
	if err != nil {
		return 0
	}
	return len(names)
}

func outboxFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func prune(dir string, keep int) error {
	names, err := outboxFiles(dir)
	if err != nil {
		return err
	}
	if len(names) <= keep {
		return nil
	}
	for _, name := range names[:len(names)-keep] {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("outbox: pruning %s: %w", name, err)
		}
	}
	return nil
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, s)
}
