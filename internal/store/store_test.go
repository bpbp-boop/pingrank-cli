package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pingrank.gg/internal/session"
)

var start = time.Date(2026, 7, 13, 19, 30, 0, 0, time.Local)

func TestFileName(t *testing.T) {
	got := FileName(start, "rocketleague")
	want := "20260713T193000.000000000_rocketleague.jsonl"
	if got != want {
		t.Errorf("FileName = %q, want %q", got, want)
	}
	// Path-hostile game IDs must be sanitized.
	got = FileName(start, `../weird game\id`)
	want = "20260713T193000.000000000_---weird-game-id.jsonl"
	if got != want {
		t.Errorf("sanitized FileName = %q, want %q", got, want)
	}
}

func writeSession(t *testing.T, dir string, at time.Time, gameID string, recs []session.Record) string {
	t.Helper()
	w, err := NewWriter(dir, at, gameID, DefaultRetain)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if err := w.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return filepath.Base(w.Path())
}

func sampleRecords(at time.Time) []session.Record {
	s := session.Sample{RTTAvgMs: 12, RTTMinMs: 10, RTTMaxMs: 14, Sent: 3, Received: 3, Method: "direct"}
	return []session.Record{
		{V: 1, T: session.RecSessionStart, Time: at, GameID: "rl", DisplayName: "Rocket League", UDPDiscovery: "etw"},
		{V: 1, T: session.RecSegmentStart, Time: at.Add(5 * time.Second), Seq: 1, Proto: "udp", Endpoint: "1.2.3.4:7000"},
		{V: 1, T: session.RecSample, Time: at.Add(10 * time.Second), Seq: 1, Sample: &s},
		{V: 1, T: session.RecSessionEnd, Time: at.Add(20 * time.Second), Reason: "game-exit"},
	}
}

func TestWriteLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	name := writeSession(t, dir, start, "rl", sampleRecords(start))

	recs, resolved, err := Load(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != name {
		t.Errorf("resolved = %q, want %q", resolved, name)
	}
	if len(recs) != 4 {
		t.Fatalf("got %d records, want 4", len(recs))
	}
	if recs[0].T != session.RecSessionStart || recs[0].GameID != "rl" {
		t.Errorf("first record mangled: %+v", recs[0])
	}
	if recs[2].Sample == nil || recs[2].Sample.RTTAvgMs != 12 {
		t.Errorf("sample record mangled: %+v", recs[2])
	}

	sum := session.Summarize(recs)
	if sum.TotalSamples != 1 || len(sum.Segments) != 1 {
		t.Errorf("summary from stored records wrong: %+v", sum)
	}
}

func TestLoadPrefixAndAmbiguity(t *testing.T) {
	dir := t.TempDir()
	writeSession(t, dir, start, "rl", sampleRecords(start))
	writeSession(t, dir, start.Add(time.Hour), "cs2", sampleRecords(start.Add(time.Hour)))

	if _, name, err := Load(dir, "20260713T2030"); err != nil || name != "20260713T203000.000000000_cs2.jsonl" {
		t.Errorf("prefix load: name=%q err=%v", name, err)
	}
	if _, _, err := Load(dir, "20260713"); err == nil {
		t.Error("ambiguous prefix did not error")
	}
	if _, _, err := Load(dir, "nope"); err == nil {
		t.Error("missing session did not error")
	}
}

func TestListNewestFirst(t *testing.T) {
	dir := t.TempDir()
	writeSession(t, dir, start, "rl", sampleRecords(start))
	writeSession(t, dir, start.Add(time.Hour), "cs2", sampleRecords(start.Add(time.Hour)))

	entries, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Name != FileName(start.Add(time.Hour), "cs2") || entries[1].Name != FileName(start, "rl") {
		t.Errorf("not newest-first: %v then %v", entries[0].Name, entries[1].Name)
	}
}

func TestPruneKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	for i := range 5 {
		at := start.Add(time.Duration(i) * time.Hour)
		writeSession(t, dir, at, "rl", sampleRecords(at))
	}
	if err := Prune(dir, 2); err != nil {
		t.Fatal(err)
	}
	names, err := sessionFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("kept %d files, want 2: %v", len(names), names)
	}
	// Newest two are hours 3 and 4.
	if names[0] != FileName(start.Add(3*time.Hour), "rl") || names[1] != FileName(start.Add(4*time.Hour), "rl") {
		t.Errorf("wrong files survived pruning: %v", names)
	}
}

func TestReadTolerantOfTornFinalLine(t *testing.T) {
	dir := t.TempDir()
	name := writeSession(t, dir, start, "rl", sampleRecords(start))
	// Simulate a crash mid-write: append half a JSON object.
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"v":1,"t":"sam`)
	f.Close()

	recs, _, err := Load(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 4 {
		t.Errorf("torn line not skipped: got %d records, want 4", len(recs))
	}
}

func TestNewWriterDoesNotMergeCollidingSessionNames(t *testing.T) {
	dir := t.TempDir()
	w1, err := NewWriter(dir, start, "rl", DefaultRetain)
	if err != nil {
		t.Fatal(err)
	}
	defer w1.Close()
	w2, err := NewWriter(dir, start, "rl", DefaultRetain)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if w1.Path() == w2.Path() {
		t.Fatalf("colliding sessions shared %s", w1.Path())
	}
}

func TestReadRejectsCorruptMiddleLine(t *testing.T) {
	dir := t.TempDir()
	name := writeSession(t, dir, start, "rl", sampleRecords(start))
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	lines[1] = `{not-json}`
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(dir, name); err == nil {
		t.Fatal("corrupt middle line was silently accepted")
	}
}
