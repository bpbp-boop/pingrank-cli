// Package store persists session logs (milestone 3): one append-only JSONL
// file per session under %LOCALAPPDATA%\PingRank\sessions, schema-versioned
// records, oldest-first retention pruning. No network anywhere.
package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"pingrank.gg/internal/session"
)

// DefaultRetain caps stored sessions; oldest are pruned first.
const DefaultRetain = 200

// DefaultDir is %LOCALAPPDATA%\PingRank\sessions.
func DefaultDir() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", fmt.Errorf("store: %%LOCALAPPDATA%% is not set")
	}
	return filepath.Join(base, "PingRank", "sessions"), nil
}

// FileName builds the per-session file name: <start-time>_<gameId>.jsonl.
// The timestamp prefix is filesystem-safe and makes lexicographic order
// chronological, which retention pruning relies on.
func FileName(start time.Time, gameID string) string {
	return start.Format("20060102T150405.000000000") + "_" + sanitize(gameID) + ".jsonl"
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

// Writer appends records to one session file as they occur, so a crash
// loses at most the record being written.
type Writer struct {
	f    *os.File
	path string
}

// NewWriter creates the session file (and the directory if needed), then
// prunes old sessions so the store never exceeds retain files.
func NewWriter(dir string, start time.Time, gameID string, retain int) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("store: creating %s: %w", dir, err)
	}
	path, f, err := createUnique(dir, FileName(start, gameID))
	if err != nil {
		return nil, err
	}
	if retain <= 0 {
		retain = DefaultRetain
	}
	if err := Prune(dir, retain); err != nil {
		f.Close()
		return nil, err
	}
	return &Writer{f: f, path: path}, nil
}

// createUnique prevents two recorder processes that start during the same
// clock tick from appending unrelated sessions to one file.
func createUnique(dir, name string) (string, *os.File, error) {
	base := strings.TrimSuffix(name, ".jsonl")
	for n := 1; ; n++ {
		candidate := name
		if n > 1 {
			candidate = fmt.Sprintf("%s-%d.jsonl", base, n)
		}
		path := filepath.Join(dir, candidate)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			return path, f, nil
		}
		if !os.IsExist(err) {
			return "", nil, fmt.Errorf("store: creating %s: %w", path, err)
		}
	}
}

func (w *Writer) Path() string { return w.path }

func (w *Writer) Append(rec session.Record) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = w.f.Write(append(line, '\n'))
	return err
}

func (w *Writer) Close() error { return w.f.Close() }

// Prune deletes oldest session files until at most retain remain.
func Prune(dir string, retain int) error {
	names, err := sessionFiles(dir)
	if err != nil {
		return err
	}
	if len(names) <= retain {
		return nil
	}
	for _, name := range names[:len(names)-retain] {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("store: pruning %s: %w", name, err)
		}
	}
	return nil
}

// sessionFiles lists *.jsonl names sorted ascending (oldest first).
func sessionFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// Entry is one stored session: its file name plus reconstructed summary.
type Entry struct {
	Name    string
	Summary session.Summary
}

// List returns all stored sessions, newest first.
func List(dir string) ([]Entry, error) {
	names, err := sessionFiles(dir)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(names))
	for i := len(names) - 1; i >= 0; i-- {
		recs, err := readRecords(filepath.Join(dir, names[i]))
		if err != nil {
			// A corrupt file shouldn't hide the rest of the store.
			continue
		}
		entries = append(entries, Entry{Name: names[i], Summary: session.Summarize(recs)})
	}
	return entries, nil
}

// Load resolves nameOrPrefix (exact file name, or unique prefix, with or
// without .jsonl) and returns the session's records.
func Load(dir, nameOrPrefix string) ([]session.Record, string, error) {
	names, err := sessionFiles(dir)
	if err != nil {
		return nil, "", err
	}
	want := strings.TrimSuffix(nameOrPrefix, ".jsonl")
	var matches []string
	for _, n := range names {
		base := strings.TrimSuffix(n, ".jsonl")
		if base == want {
			matches = []string{n}
			break
		}
		if strings.HasPrefix(base, want) {
			matches = append(matches, n)
		}
	}
	switch len(matches) {
	case 0:
		return nil, "", fmt.Errorf("store: no session matches %q", nameOrPrefix)
	case 1:
		recs, err := readRecords(filepath.Join(dir, matches[0]))
		return recs, matches[0], err
	default:
		return nil, "", fmt.Errorf("store: %q is ambiguous (%d matches: %s ...)",
			nameOrPrefix, len(matches), matches[0])
	}
}

func readRecords(path string) ([]session.Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	var recs []session.Record
	for i, line := range lines {
		var rec session.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			if i == len(lines)-1 {
				// A crash may leave only the final append partially written.
				break
			}
			return nil, fmt.Errorf("store: corrupt JSONL record %d in %s: %w", i+1, filepath.Base(path), err)
		}
		recs = append(recs, rec)
	}
	return recs, nil
}
